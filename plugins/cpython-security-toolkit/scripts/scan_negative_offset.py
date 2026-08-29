"""
scan_cpu_complexity.py — Algorithmic complexity analysis.

Invariant 3d: operations on attacker-controlled input must not exhibit
super-linear worst-case complexity without explicit bounds.

Primary targets:
- Quadratic string operations in loops
- Backtracking regex on untrusted input
- Nested loops over the same attacker-controlled string

Usage:
    python3 scan_cpu_complexity.py <cpython-lib-dir>
"""

import ast
import json
import os
import re
import sys
from pathlib import Path

TARGET_MODULES = [
    "http/cookies.py",
    "email/_parseaddr.py",
    "email/feedparser.py",
    "email/headerregistry.py",
    "http/client.py",
    "urllib/parse.py",
]

# String operations that are O(n) per call — quadratic if in a loop
QUADRATIC_STRING_OPS = {
    "find", "index", "count", "replace", "split",
    "startswith", "endswith", "strip", "lstrip", "rstrip",
}

# Regex patterns that may backtrack
BACKTRACK_RISK_PATTERNS = [
    r"\.\*\.\*",      # .*.* — catastrophic backtracking
    r"\+\.\+",        # +.+ — nested quantifiers
    r"\(\.\*\)\+",    # (.*)+
    r"\(\w\+\)\+",    # (\w+)+
]


class ComplexityAnalyzer(ast.NodeVisitor):
    def __init__(self, source_lines: list[str]):
        self.source_lines = source_lines
        self.findings = []
        self._func = None
        self._func_lineno = 0
        self._loop_depth = 0
        self._loop_var_names: list[str] = []

    def visit_FunctionDef(self, node):
        old_func, old_ln = self._func, self._func_lineno
        self._func = node.name
        self._func_lineno = node.lineno
        self.generic_visit(node)
        self._func, self._func_lineno = old_func, old_ln

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_For(self, node):
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node):
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_Call(self, node):
        if self._loop_depth >= 1:
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            elif isinstance(node.func, ast.Name):
                name = node.func.id

            if name in QUADRATIC_STRING_OPS:
                self.findings.append({
                    "function": self._func,
                    "lineno": node.lineno,
                    "issue": f"String operation '{name}()' inside loop — potential O(n²) on attacker input",
                    "sub_invariant": "3d",
                    "confidence": "HARDENING",
                    "evidence": (
                        f"'{name}()' called at line {node.lineno} inside a loop "
                        f"(depth {self._loop_depth}). If the input is attacker-controlled, "
                        f"this is O(n²). Matches gh-136063 (quadratic email parsing) "
                        f"and gh-123067 (quadratic cookie parsing)."
                    ),
                    "corpus_ref": "RES-007 (gh-136063), RES-008 (gh-123067)",
                })

        self.generic_visit(node)

    def visit_Constant(self, node):
        """Check string constants used as regex patterns for backtracking risk."""
        if isinstance(node.value, str) and len(node.value) > 3:
            for pattern in BACKTRACK_RISK_PATTERNS:
                if re.search(pattern, node.value):
                    self.findings.append({
                        "function": self._func,
                        "lineno": node.lineno,
                        "issue": "Regex pattern with potential catastrophic backtracking",
                        "sub_invariant": "3d",
                        "confidence": "SECURITY-CANDIDATE",
                        "evidence": (
                            f"Regex pattern at line {node.lineno} contains nested quantifiers "
                            f"that may cause catastrophic backtracking on attacker-controlled input."
                        ),
                        "corpus_ref": "RES-003 (CVE-2026-3276)",
                    })
        self.generic_visit(node)


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

        analyzer = ComplexityAnalyzer(lines)
        analyzer.visit(tree)

        for f in analyzer.findings:
            results.append({
                "domain": "RES",
                "module": Path(full).name,
                **f,
                "invariant": "Invariant 3: Resource Amplification Bound",
            })

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cpython-lib-dir>", file=sys.stderr)
        sys.exit(1)
    results = scan(sys.argv[1])
    print(json.dumps(results, indent=2))
    print(f"\nTotal: {len(results)}", file=sys.stderr)