"""
scan_symlink.py — Symlink and hardlink escape detection.

Invariant 1b: symlink and hardlink targets must be fully resolved before
the destination boundary check is applied.

Usage:
    python3 scan_symlink.py <cpython-lib-dir>
"""

import ast
import json
import os
import sys
from pathlib import Path

TARGET_MODULES = ["tarfile.py", "zipfile/__init__.py", "zipfile.py", "shutil.py"]

SYMLINK_HANDLING = {"readlink", "resolve_symlinks", "followlinks", "follow_symlinks"}
HARDLINK_HANDLING = {"link", "LNKTYPE", "GNUTYPE_SPARSE"}
BOUNDARY_CHECK = {"startswith", "is_relative_to", "commonpath", "commonprefix"}
RESOLVE_CALLS = {"realpath", "resolve", "abspath", "normpath"}


class SymlinkAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        self._func = None
        self._func_lineno = 0
        self._calls = []

    def visit_FunctionDef(self, node):
        old, old_ln = self._func, self._func_lineno
        old_calls = self._calls
        self._func = node.name
        self._func_lineno = node.lineno
        self._calls = []
        self.generic_visit(node)
        self._analyze_func(node)
        self._func, self._func_lineno = old, old_ln
        self._calls = old_calls

    visit_AsyncFunctionDef = visit_FunctionDef

    def _get_name(self, node):
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def visit_Call(self, node):
        name = self._get_name(node.func)
        if name:
            self._calls.append((name, node.lineno))
        self.generic_visit(node)

    def _analyze_func(self, node):
        func_name = node.name.lower()
        if not any(kw in func_name for kw in ("extract", "unpack", "member")):
            return

        names = [n for n, _ in self._calls]
        lines = {n: l for n, l in self._calls}

        has_symlink = any(n in SYMLINK_HANDLING for n in names)
        has_boundary = any(n in BOUNDARY_CHECK for n in names)
        has_resolve = any(n in RESOLVE_CALLS for n in names)

        # Pattern: handles symlinks but no boundary check
        if has_symlink and not has_boundary:
            self.findings.append({
                "function": node.name,
                "lineno": node.lineno,
                "issue": "Symlink handling without destination boundary check",
                "sub_invariant": "1b",
                "confidence": "SECURITY-CANDIDATE",
                "evidence": (
                    f"'{node.name}' handles symlinks but no destination boundary check found. "
                    f"Symlink targets may not be validated against extraction destination."
                ),
                "corpus_ref": "ARC-001 through ARC-005",
            })

        # Pattern: boundary check before resolve
        if has_boundary and has_resolve:
            boundary_lines = [l for n, l in self._calls if n in BOUNDARY_CHECK]
            resolve_lines = [l for n, l in self._calls if n in RESOLVE_CALLS]
            if boundary_lines and resolve_lines and min(boundary_lines) < min(resolve_lines):
                self.findings.append({
                    "function": node.name,
                    "lineno": node.lineno,
                    "issue": "Boundary check before path resolution — symlink escape possible",
                    "sub_invariant": "1b",
                    "confidence": "SECURITY",
                    "evidence": (
                        f"Boundary check at line {min(boundary_lines)} precedes "
                        f"path resolution at line {min(resolve_lines)}. "
                        f"Matches CVE-2025-4330 / CVE-2025-4517 pattern."
                    ),
                    "corpus_ref": "ARC-003, ARC-005",
                })


def scan(lib_dir: str) -> list[dict]:
    results = []
    for module_path in TARGET_MODULES:
        full = os.path.join(lib_dir, module_path.replace("/", os.sep))
        if not os.path.exists(full):
            continue
        try:
            tree = ast.parse(Path(full).read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            continue

        analyzer = SymlinkAnalyzer()
        analyzer.visit(tree)
        module = Path(full).name

        for f in analyzer.findings:
            results.append({
                "domain": "ARC",
                "module": module,
                **f,
                "invariant": "Invariant 1: Extraction Boundary",
            })

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cpython-lib-dir>", file=sys.stderr)
        sys.exit(1)
    results = scan(sys.argv[1])
    print(json.dumps(results, indent=2))
    print(f"\nTotal: {len(results)}", file=sys.stderr)