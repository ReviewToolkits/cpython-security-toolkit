"""
scan_decompression_bounds.py — Resource amplification analysis.

Invariant 3a: Decompression paths must not fully materialize output before applying
a size check. The check must occur before or during decompression, not after.

Invariant 3b: Allocation sizes from untrusted archive metadata must have an
enforced upper bound before being used for allocation.

Usage:
    python3 scan_decompression_bounds.py <cpython-lib-dir>

Output:
    JSON list of candidate findings to stdout.
"""

import ast
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

TARGET_MODULES = [
    "zipfile/__init__.py",
    "zipfile.py",
    "tarfile.py",
    "lzma.py",
    "bz2.py",
    "gzip.py",
    "plistlib.py",
    "zlib.py",
]

# Decompression calls that return unbounded data if called without a max_length
UNSAFE_DECOMP_PATTERNS = {
    "read",       # decompressor.read() with no argument
    "decompress", # zlib.decompress(), lzma.decompress()
    "readall",
}

# Safe decompression patterns (bounded)
SAFE_DECOMP_PATTERNS = {
    "read1",      # buffered read with limit
}

# Allocations with a size argument
ALLOCATION_CALLS = {
    "bytes",
    "bytearray",
    "malloc",
    "alloc",
}

# Functions/attributes that read sizes from archive metadata
METADATA_SIZE_READS = {
    "file_size",
    "compress_size",
    "dict_size",      # LZMA dict size — the CVE-2025-8194 class
    "header_offset",
    "data_offset",
    "_raw_offset",
    "block_size",
}


@dataclass
class Finding:
    module: str
    function: str
    lineno: int
    issue: str
    sub_invariant: str
    confidence: str
    evidence: str
    corpus_ref: Optional[str] = None


class DecompressionAnalyzer(ast.NodeVisitor):
    """Find decompression calls and check whether they are bounded."""

    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.findings_data: list[dict] = []
        self._current_func: Optional[str] = None
        self._current_func_lineno: int = 0

    def visit_FunctionDef(self, node):
        old_func = self._current_func
        old_lineno = self._current_func_lineno
        self._current_func = node.name
        self._current_func_lineno = node.lineno
        self.generic_visit(node)
        self._current_func = old_func
        self._current_func_lineno = old_lineno

    visit_AsyncFunctionDef = visit_FunctionDef

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _has_size_arg(self, call: ast.Call) -> bool:
        """Check if a read/decompress call has a size argument (bounded)."""
        return len(call.args) > 0 or any(
            kw.arg in ("size", "max_length", "n", "length", "maxsize")
            for kw in call.keywords
        )

    def visit_Call(self, node: ast.Call):
        name = self._get_call_name(node)

        # Pattern 1: Unbounded .read() or .decompress() call
        if name in UNSAFE_DECOMP_PATTERNS and not self._has_size_arg(node):
            # Check if this is a method call on something that looks like a decompressor
            is_decompressor_call = False
            if isinstance(node.func, ast.Attribute):
                obj_name = ""
                if isinstance(node.func.value, ast.Name):
                    obj_name = node.func.value.id.lower()
                elif isinstance(node.func.value, ast.Attribute):
                    obj_name = node.func.value.attr.lower()

                decomp_indicators = {
                    "decomp", "decompressor", "zdecompress", "lzma",
                    "bz2", "zlib", "gz", "fileobj", "fp", "f",
                }
                is_decompressor_call = any(ind in obj_name for ind in decomp_indicators)

            if is_decompressor_call:
                self.findings_data.append({
                    "function": self._current_func,
                    "func_lineno": self._current_func_lineno,
                    "call_lineno": node.lineno,
                    "issue": "Unbounded decompression read — output fully materialized before any size check",
                    "sub_invariant": "3a",
                    "confidence": "SECURITY-CANDIDATE",
                    "evidence": (
                        f"'{name}()' called without a size argument at line {node.lineno} "
                        f"in '{self._current_func}'. If this is a decompressor, the full "
                        f"decompressed output is materialized in memory before any size limit "
                        f"can be applied. Matches the amplification class in RES-005, RES-006."
                    ),
                    "corpus_ref": "RES-005 (zipfile unbounded LZMA), RES-006 (LZMA dict size)",
                })

        # Pattern 2: Allocation using a metadata-derived size
        if name in ALLOCATION_CALLS and node.args:
            size_arg = node.args[0]
            # Check if the size comes from a metadata attribute
            if isinstance(size_arg, ast.Attribute):
                if size_arg.attr in METADATA_SIZE_READS:
                    self.findings_data.append({
                        "function": self._current_func,
                        "func_lineno": self._current_func_lineno,
                        "call_lineno": node.lineno,
                        "issue": "Allocation size directly from archive metadata without upper bound",
                        "sub_invariant": "3b",
                        "confidence": "SECURITY-CANDIDATE",
                        "evidence": (
                            f"'{name}()' at line {node.lineno} uses '{size_arg.attr}' as its "
                            f"size argument. This attribute reads directly from archive metadata. "
                            f"If no upper bound is applied before this call, an attacker-controlled "
                            f"archive can trigger an arbitrarily large allocation. "
                            f"Matches RES-004 (plistlib OOM) and RES-006 (LZMA dict size)."
                        ),
                        "corpus_ref": "RES-004, RES-006",
                    })

        self.generic_visit(node)


def analyze_module(filepath: str) -> list[Finding]:
    try:
        source = Path(filepath).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=filepath)
        lines = source.splitlines()
    except (SyntaxError, OSError):
        return []

    analyzer = DecompressionAnalyzer(lines)
    analyzer.visit(tree)

    module_name = Path(filepath).name
    findings = []

    for fd in analyzer.findings_data:
        findings.append(Finding(
            module=module_name,
            function=fd["function"] or "<module>",
            lineno=fd["call_lineno"],
            issue=fd["issue"],
            sub_invariant=fd["sub_invariant"],
            confidence=fd["confidence"],
            evidence=fd["evidence"],
            corpus_ref=fd.get("corpus_ref"),
        ))

    return findings


def scan(lib_dir: str) -> list[dict]:
    all_findings = []

    for module_path in TARGET_MODULES:
        full_path = os.path.join(lib_dir, module_path.replace("/", os.sep))
        if os.path.exists(full_path):
            findings = analyze_module(full_path)
            for f in findings:
                all_findings.append({
                    "domain": "RES",
                    "module": f.module,
                    "function": f.function,
                    "lineno": f.lineno,
                    "issue": f.issue,
                    "sub_invariant": f.sub_invariant,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "corpus_ref": f.corpus_ref,
                    "invariant": "Invariant 3: Resource Amplification Bound",
                })

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cpython-lib-dir>", file=sys.stderr)
        sys.exit(1)

    results = scan(sys.argv[1])
    print(json.dumps(results, indent=2))

    print(f"\n--- scan_decompression_bounds.py summary ---", file=sys.stderr)
    by_conf = {}
    for r in results:
        by_conf.setdefault(r["confidence"], []).append(r)
    for c, items in sorted(by_conf.items()):
        print(f"  {c}: {len(items)}", file=sys.stderr)
    print(f"  Total: {len(results)}", file=sys.stderr)
