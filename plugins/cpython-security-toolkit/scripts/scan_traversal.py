"""
scan_traversal.py — Archive extraction boundary analysis.

Invariant 1a: All write paths in tarfile/zipfile/shutil must check the final,
fully-resolved output path against the destination boundary before writing.

Usage:
    python3 scan_traversal.py <cpython-lib-dir>

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
    "tarfile.py",
    "zipfile/__init__.py",
    "zipfile.py",
    "shutil.py",
]

# Functions that write files to the filesystem
WRITE_FUNCTIONS = {
    "open", "os.open", "io.open", "os.fdopen",
    "shutil.copyfileobj", "shutil.copy2",
}

# Functions that resolve paths (should appear before boundary check)
RESOLVE_FUNCTIONS = {
    "os.path.realpath", "os.path.abspath", "os.path.normpath",
    "pathlib.Path.resolve",
}

# Functions that check path boundaries
BOUNDARY_FUNCTIONS = {
    "startswith",   # destination.startswith(extract_dir)
    "is_relative_to",  # path.is_relative_to(destination)
    "commonpath",   # os.path.commonpath([destination, path])
    "commonprefix", # os.path.commonprefix
}

# Functions that extract archive members
EXTRACT_FUNCTIONS = {
    "extract", "extractall", "extractfile",
    "_extract_member", "_extract_tar_info",
    "unpack_archive", "_unpack_zipfile", "_unpack_tarfile",
}


@dataclass
class Finding:
    module: str
    function: str
    lineno: int
    issue: str
    sub_invariant: str
    confidence: str  # SECURITY | SECURITY-CANDIDATE | HARDENING
    evidence: str
    corpus_ref: Optional[str] = None


@dataclass
class FunctionAnalysis:
    name: str
    lineno: int
    has_write: bool = False
    has_resolve: bool = False
    has_boundary_check: bool = False
    resolve_before_check: bool = False
    check_before_resolve: bool = False
    write_lines: list = field(default_factory=list)
    resolve_lines: list = field(default_factory=list)
    boundary_lines: list = field(default_factory=list)


class ExtractionAnalyzer(ast.NodeVisitor):
    """Walk a function body and classify write / resolve / boundary call ordering."""

    def __init__(self, func_name: str, func_lineno: int):
        self.func_name = func_name
        self.func_lineno = func_lineno
        self.analysis = FunctionAnalysis(name=func_name, lineno=func_lineno)
        self._call_order: list[tuple[str, int]] = []  # (call_type, lineno)

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _full_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Attribute):
                return f"{node.func.value.attr}.{node.func.attr}"
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)
        full = self._full_call_name(node)

        if name in WRITE_FUNCTIONS or full in WRITE_FUNCTIONS:
            self.analysis.has_write = True
            self.analysis.write_lines.append(node.lineno)
            self._call_order.append(("write", node.lineno))

        if full in RESOLVE_FUNCTIONS or name == "realpath" or name == "resolve":
            self.analysis.has_resolve = True
            self.analysis.resolve_lines.append(node.lineno)
            self._call_order.append(("resolve", node.lineno))

        if name in BOUNDARY_FUNCTIONS or full in {"os.path.commonpath", "os.path.commonprefix"}:
            self.analysis.has_boundary_check = True
            self.analysis.boundary_lines.append(node.lineno)
            self._call_order.append(("boundary", node.lineno))

        self.generic_visit(node)

    def finalize(self):
        """Determine ordering relationships from call sequence."""
        types = [t for t, _ in self._call_order]

        if "resolve" in types and "boundary" in types:
            resolve_idx = types.index("resolve")
            boundary_idx = types.index("boundary")
            self.analysis.resolve_before_check = resolve_idx < boundary_idx
            self.analysis.check_before_resolve = boundary_idx < resolve_idx

        return self.analysis


def analyze_function(func_node: ast.FunctionDef, module_path: str) -> list[Finding]:
    """Analyze a single function for extraction boundary violations."""
    findings = []

    # Only analyze functions that look like extraction code
    func_name = func_node.name
    is_extraction_func = any(pat in func_name.lower() for pat in
                              ["extract", "unpack", "open_member", "_open"])
    if not is_extraction_func:
        return findings

    analyzer = ExtractionAnalyzer(func_name, func_node.lineno)
    analyzer.visit(func_node)
    analysis = analyzer.finalize()

    module_name = Path(module_path).name.replace(".py", "")

    # Pattern 1: Has writes but no destination boundary check
    if analysis.has_write and not analysis.has_boundary_check:
        findings.append(Finding(
            module=module_name,
            function=func_name,
            lineno=analysis.lineno,
            issue="Write path with no destination boundary check",
            sub_invariant="1a",
            confidence="SECURITY-CANDIDATE",
            evidence=(
                f"Function '{func_name}' at line {analysis.lineno} performs file writes "
                f"at line(s) {analysis.write_lines} but no destination boundary check "
                f"(startswith, is_relative_to, commonpath) was found in the function body."
            ),
            corpus_ref="ARC-001 through ARC-007",
        ))

    # Pattern 2: Boundary check before resolve (the CVE-2025-4517 / CVE-2025-4330 pattern)
    if analysis.has_boundary_check and analysis.has_resolve and analysis.check_before_resolve:
        findings.append(Finding(
            module=module_name,
            function=func_name,
            lineno=analysis.lineno,
            issue="Destination boundary check applied before path resolution",
            sub_invariant="1b",
            confidence="SECURITY",
            evidence=(
                f"Function '{func_name}': boundary check at line(s) {analysis.boundary_lines} "
                f"precedes path resolution at line(s) {analysis.resolve_lines}. "
                f"A symlink or relative-path component in the archive entry can produce "
                f"a different final path than the one validated. "
                f"Matches the pattern in CVE-2025-4330 and CVE-2025-4517."
            ),
            corpus_ref="ARC-003, ARC-005",
        ))

    return findings


def analyze_module(filepath: str) -> list[Finding]:
    """Parse a module and analyze all functions."""
    try:
        source = Path(filepath).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, OSError) as e:
        return [Finding(
            module=filepath,
            function="<parse error>",
            lineno=0,
            issue=f"Could not parse: {e}",
            sub_invariant="N/A",
            confidence="FALSE-POSITIVE",
            evidence=str(e),
        )]

    findings = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(analyze_function(node, filepath))

    return findings


def scan(lib_dir: str) -> list[dict]:
    """Main entry point. Scan all target modules."""
    all_findings = []

    for module_path in TARGET_MODULES:
        candidates = [
            os.path.join(lib_dir, module_path),
            os.path.join(lib_dir, module_path.replace("/", os.sep)),
        ]
        for path in candidates:
            if os.path.exists(path):
                findings = analyze_module(path)
                for f in findings:
                    all_findings.append({
                        "domain": "ARC",
                        "module": f.module,
                        "function": f.function,
                        "lineno": f.lineno,
                        "issue": f.issue,
                        "sub_invariant": f.sub_invariant,
                        "confidence": f.confidence,
                        "evidence": f.evidence,
                        "corpus_ref": f.corpus_ref,
                        "invariant": "Invariant 1: Extraction Boundary",
                    })
                break

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cpython-lib-dir>", file=sys.stderr)
        sys.exit(1)

    lib_dir = sys.argv[1]
    results = scan(lib_dir)
    print(json.dumps(results, indent=2))

    # Summary to stderr
    by_confidence = {}
    for r in results:
        by_confidence.setdefault(r["confidence"], []).append(r)

    print(f"\n--- scan_traversal.py summary ---", file=sys.stderr)
    for conf, items in sorted(by_confidence.items()):
        print(f"  {conf}: {len(items)} finding(s)", file=sys.stderr)
    print(f"  Total: {len(results)}", file=sys.stderr)
