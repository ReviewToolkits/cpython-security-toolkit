"""
scan_negative_offset.py — Negative offset / size field detection.

Invariant 3c: offset and size fields read from untrusted archive metadata must
be validated as non-negative before use in loop conditions or arithmetic.

Primary targets:
- Loop conditions using a field from struct.unpack or nti() without a >= 0 guard
- Arithmetic using a size or offset field that could be negative
- Infinite loops caused by a negative block count or size field

CVE anchor: CVE-2025-8194 — tarfile infinite loop from negative block count.

Usage:
    python3 scan_negative_offset.py <cpython-lib-dir>

Output:
    JSON list of candidate findings to stdout.
"""

import ast
import json
import os
import sys
from pathlib import Path

TARGET_MODULES = [
    "tarfile.py",
    "zipfile/__init__.py",
    "zipfile.py",
    "plistlib.py",
    "lzma.py",
]

# Field names that carry archive metadata and could be attacker-controlled
METADATA_FIELD_NAMES = {
    "offset", "offset_data", "blocks", "size", "compress_size",
    "file_size", "header_offset", "nti", "count", "length",
    "dict_size", "data_size", "pos", "block", "entry_size",
}

# Functions that decode integer fields from raw bytes (archive format parsers)
DECODE_FUNCTIONS = {
    "nti",           # tarfile int decode
    "unpack",        # struct.unpack
    "unpack_from",   # struct.unpack_from
    "frombytes",
    "from_bytes",
    "read_int",
}

# Guard expressions that indicate non-negative validation is present
GUARD_PATTERNS = {
    ">=",   # field >= 0
    ">",    # field > 0
    "abs",  # abs(field)
    "max",  # max(0, field)
}


class NegativeOffsetAnalyzer(ast.NodeVisitor):
    """Find loop conditions and arithmetic that use unvalidated integer metadata fields."""

    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.findings: list[dict] = []
        self._func: str | None = None
        self._func_lineno: int = 0
        # Track variables assigned from archive metadata decoding calls
        self._metadata_vars: set[str] = set()
        self._loop_conditions: list[tuple[str, int]] = []  # (var_name, lineno)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_func, old_ln = self._func, self._func_lineno
        old_meta, old_loops = self._metadata_vars, self._loop_conditions
        self._func = node.name
        self._func_lineno = node.lineno
        self._metadata_vars = set()
        self._loop_conditions = []
        self.generic_visit(node)
        self._func, self._func_lineno = old_func, old_ln
        self._metadata_vars, self._loop_conditions = old_meta, old_loops

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments from decode functions or direct metadata attribute reads."""
        self._track_metadata_assignment(node.targets, node.value, node.lineno)
        self.generic_visit(node)

    def _track_metadata_assignment(
        self, targets: list[ast.expr], value: ast.expr, lineno: int
    ) -> None:
        # Pattern: var = struct.unpack(...)[0] or var = nti(...)
        is_decode = False
        if isinstance(value, ast.Call):
            fname = ""
            if isinstance(value.func, ast.Attribute):
                fname = value.func.attr
            elif isinstance(value.func, ast.Name):
                fname = value.func.id
            if fname in DECODE_FUNCTIONS:
                is_decode = True
        # Pattern: var = info.size or var = self.offset (attribute access)
        if isinstance(value, ast.Attribute) and value.attr in METADATA_FIELD_NAMES:
            is_decode = True
        # Pattern: var = subscript of unpack result — e.g. struct.unpack(...)[0]
        if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Call):
            call = value.value
            fname = ""
            if isinstance(call.func, ast.Attribute):
                fname = call.func.attr
            elif isinstance(call.func, ast.Name):
                fname = call.func.id
            if fname in DECODE_FUNCTIONS:
                is_decode = True

        if is_decode:
            for t in targets:
                if isinstance(t, ast.Name):
                    self._metadata_vars.add(t.id)

    def visit_While(self, node: ast.While) -> None:
        """Check while-loop conditions for unvalidated metadata variables."""
        self._check_condition_for_metadata(node.test, node.lineno, "while")
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Check for-loop iters using range() with metadata variables."""
        if isinstance(node.iter, ast.Call):
            call = node.iter
            func_name = ""
            if isinstance(call.func, ast.Name):
                func_name = call.func.id
            if func_name == "range":
                for arg in call.args:
                    var = self._extract_name(arg)
                    if var and var in self._metadata_vars:
                        # Look for a non-negative guard before this loop
                        if not self._has_guard_in_source(node.lineno, var):
                            self._emit(
                                node.lineno,
                                f"range({var}) in for-loop — '{var}' from archive metadata "
                                f"without non-negative guard. Negative value → no iteration, "
                                f"but with further arithmetic can cause incorrect behavior.",
                                "HARDENING",
                                var,
                            )
        self.generic_visit(node)

    def _check_condition_for_metadata(
        self, test: ast.expr, lineno: int, loop_type: str
    ) -> None:
        """Inspect a loop condition for references to unvalidated metadata vars."""
        for node in ast.walk(test):
            var = self._extract_name(node)
            if var and var in self._metadata_vars:
                if not self._has_guard_in_source(lineno, var):
                    self._emit(
                        lineno,
                        f"{loop_type}-loop condition references '{var}' from archive metadata "
                        f"without a non-negative check before the loop. A crafted archive with "
                        f"a negative value can produce an infinite loop or incorrect arithmetic. "
                        f"Matches CVE-2025-8194 (tarfile negative block count).",
                        "SECURITY-CANDIDATE",
                        var,
                    )

    def _has_guard_in_source(self, lineno: int, var: str) -> bool:
        """Heuristic: check if lines above the loop contain a non-negative guard for var."""
        look_back = max(0, lineno - 10)
        context = "\n".join(self.source_lines[look_back : lineno - 1])
        # Crude heuristic: does the context check var >= 0, var > 0, max(0,var), abs(var)?
        checks = [
            f"{var} >= 0",
            f"{var} > 0",
            f"max(0, {var})",
            f"max(0,{var})",
            f"abs({var})",
            f"if {var} < 0",
            f"if {var} <= 0",
        ]
        return any(c in context for c in checks)

    def _extract_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _emit(
        self, lineno: int, evidence: str, confidence: str, var: str
    ) -> None:
        self.findings.append(
            {
                "function": self._func,
                "lineno": lineno,
                "var": var,
                "sub_invariant": "3c",
                "confidence": confidence,
                "evidence": evidence,
                "corpus_ref": "RES-001 (CVE-2025-8194), RES-006 (LZMA dict_size)",
                "issue": (
                    f"Metadata field '{var}' used in loop or arithmetic "
                    f"without non-negative validation"
                ),
            }
        )


def scan(lib_dir: str) -> list[dict]:
    results = []
    for module_path in TARGET_MODULES:
        full = os.path.join(lib_dir, module_path.replace("/", os.sep))
        if not os.path.exists(full):
            continue
        try:
            source = Path(full).read_text(encoding="utf-8")
            tree = ast.parse(source)
            lines = source.splitlines()
        except (SyntaxError, OSError):
            continue

        analyzer = NegativeOffsetAnalyzer(lines)
        analyzer.visit(tree)

        for f in analyzer.findings:
            results.append(
                {
                    "domain": "RES",
                    "module": Path(full).name,
                    "invariant": "Invariant 3: Resource Amplification Bound",
                    **f,
                }
            )

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cpython-lib-dir>", file=sys.stderr)
        sys.exit(1)
    results = scan(sys.argv[1])
    print(json.dumps(results, indent=2))
    print(f"\nTotal: {len(results)}", file=sys.stderr)
