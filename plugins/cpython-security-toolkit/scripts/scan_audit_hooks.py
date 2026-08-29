"""
scan_audit_hooks.py — Audit hook coverage analysis.

Invariant 4a: Any path loading Python bytecode must use io.open_code(),
not open() or builtins.open(), so that sys.audit("open", ...) fires.

Invariant 4b: Shell-calling paths with untrusted input must validate
after all template substitution, not before.

Usage:
    python3 scan_audit_hooks.py <cpython-lib-dir>

Output:
    JSON list of candidate findings to stdout.
"""

import ast
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

TARGET_MODULES = [
    "importlib/_bootstrap_external.py",
    "importlib/util.py",
    "importlib/__init__.py",
    "webbrowser.py",
    "venv/__init__.py",
    "venv/scripts/",
]

# File extensions that indicate Python bytecode or source
PYTHON_EXTENSIONS = {".py", ".pyc", ".pyo", ".pyd"}

# Safe file-open functions for Python source/bytecode
SAFE_OPEN_FUNCTIONS = {"io.open_code", "open_code"}

# Unsafe file-open functions (don't emit sys.audit)
UNSAFE_OPEN_FUNCTIONS = {"open", "builtins.open", "io.open", "io.FileIO"}

# Shell-calling functions
SHELL_CALL_FUNCTIONS = {
    "subprocess.run", "subprocess.call", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
    "os.system", "os.popen", "os.execv", "os.execve",
    "webbrowser.open", "webbrowser.open_new", "webbrowser.open_new_tab",
}

# Template substitution operations that transform a URL/command
SUBSTITUTION_PATTERNS = {
    "%",           # old-style % formatting
    "format",      # str.format()
    "replace",     # str.replace()
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


class AuditHookAnalyzer(ast.NodeVisitor):
    """Detect audit hook bypass patterns."""

    def __init__(self, module_name: str):
        self.module_name = module_name
        self.findings_data: list[dict] = []
        self._current_func: Optional[str] = None
        self._current_func_lineno: int = 0
        # Track calls within a function for ordering analysis
        self._func_calls: list[tuple[str, int]] = []

    def visit_FunctionDef(self, node):
        old_func = self._current_func
        old_lineno = self._current_func_lineno
        old_calls = self._func_calls

        self._current_func = node.name
        self._current_func_lineno = node.lineno
        self._func_calls = []

        self.generic_visit(node)

        # Analyze collected calls for ordering issues
        self._check_substitution_ordering(node)

        self._current_func = old_func
        self._current_func_lineno = old_lineno
        self._func_calls = old_calls

    visit_AsyncFunctionDef = visit_FunctionDef

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _is_python_file_open(self, call: ast.Call) -> bool:
        """Check if this open() call appears to be opening a Python file."""
        # Look for string arguments with .py or .pyc extension
        for arg in ast.walk(call):
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if any(arg.value.endswith(ext) for ext in PYTHON_EXTENSIONS):
                    return True
        # Look for variable names suggesting Python files
        for arg in call.args:
            if isinstance(arg, ast.Name):
                name = arg.id.lower()
                if any(kw in name for kw in ("path", "file", "pyc", "source", "bytecode")):
                    return True
        return False

    def visit_Call(self, node: ast.Call):
        name = self._get_call_name(node)

        # Pattern 1: open() used for Python files instead of io.open_code()
        if name in UNSAFE_OPEN_FUNCTIONS and self._is_python_file_open(node):
            self.findings_data.append({
                "function": self._current_func,
                "lineno": node.lineno,
                "issue": "Python file opened with open() instead of io.open_code()",
                "sub_invariant": "4a",
                "confidence": "SECURITY-CANDIDATE",
                "evidence": (
                    f"'{name}()' at line {node.lineno} appears to open a Python source or "
                    f"bytecode file. Using open() instead of io.open_code() means that "
                    f"sys.audit('open', ...) hooks registered by security tools will not fire. "
                    f"Matches the pattern in CVE-2026-2297 (SourcelessFileLoader)."
                ),
                "corpus_ref": "AUD-001 (CVE-2026-2297)",
            })

        # Track call ordering for substitution analysis
        if name:
            self._func_calls.append((name, node.lineno))

        self.generic_visit(node)

    def _check_substitution_ordering(self, func_node: ast.FunctionDef):
        """Check if URL/command validation occurs before template substitution."""
        # Look for the pattern: validate() before format/% substitution before shell_call()
        call_types = [(name, lineno) for name, lineno in self._func_calls]

        validation_lines = [l for n, l in call_types if "check" in n.lower() or "valid" in n.lower() or "_check" in n]
        subst_lines = [l for n, l in call_types if "format" in n.lower() or "replace" in n.lower()]
        shell_lines = [l for n, l in call_types if any(n.startswith(s) for s in ["os.system", "subprocess", "Popen"])]

        # The dangerous pattern: validate → substitute → shell
        # (should be: substitute → validate → shell)
        if validation_lines and subst_lines and shell_lines:
            min_valid = min(validation_lines)
            min_subst = min(subst_lines)
            min_shell = min(shell_lines)

            if min_valid < min_subst < min_shell:
                self.findings_data.append({
                    "function": func_node.name,
                    "lineno": func_node.lineno,
                    "issue": "URL/command validation applied before template substitution",
                    "sub_invariant": "4b",
                    "confidence": "SECURITY-CANDIDATE",
                    "evidence": (
                        f"Function '{func_node.name}': validation at line {min_valid} "
                        f"precedes template substitution at line {min_subst} which precedes "
                        f"shell invocation at line {min_shell}. "
                        f"Substitution can introduce characters that bypass the validator. "
                        f"Matches the pattern in CVE-2026-4786 (incomplete fix for CVE-2026-4519)."
                    ),
                    "corpus_ref": "AUD-002, AUD-003 (webbrowser.open %action bypass)",
                })


def analyze_module(filepath: str) -> list[Finding]:
    try:
        source = Path(filepath).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, OSError):
        return []

    module_name = Path(filepath).name
    analyzer = AuditHookAnalyzer(module_name)
    analyzer.visit(tree)

    return [
        Finding(
            module=module_name,
            function=fd["function"] or "<module>",
            lineno=fd["lineno"],
            issue=fd["issue"],
            sub_invariant=fd["sub_invariant"],
            confidence=fd["confidence"],
            evidence=fd["evidence"],
            corpus_ref=fd.get("corpus_ref"),
        )
        for fd in analyzer.findings_data
    ]


def scan(lib_dir: str) -> list[dict]:
    all_findings = []

    for module_path in TARGET_MODULES:
        if module_path.endswith("/"):
            continue  # Skip directory entries for now
        full_path = os.path.join(lib_dir, module_path.replace("/", os.sep))
        if os.path.exists(full_path):
            findings = analyze_module(full_path)
            for f in findings:
                all_findings.append({
                    "domain": "AUD",
                    "module": f.module,
                    "function": f.function,
                    "lineno": f.lineno,
                    "issue": f.issue,
                    "sub_invariant": f.sub_invariant,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "corpus_ref": f.corpus_ref,
                    "invariant": "Invariant 4: Audit Hook Coverage",
                })

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cpython-lib-dir>", file=sys.stderr)
        sys.exit(1)

    results = scan(sys.argv[1])
    print(json.dumps(results, indent=2))

    print(f"\n--- scan_audit_hooks.py summary ---", file=sys.stderr)
    by_conf = {}
    for r in results:
        by_conf.setdefault(r["confidence"], []).append(r)
    for c, items in sorted(by_conf.items()):
        print(f"  {c}: {len(items)}", file=sys.stderr)
    print(f"  Total: {len(results)}", file=sys.stderr)
