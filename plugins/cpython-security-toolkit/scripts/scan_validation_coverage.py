"""
scan_validation_coverage.py — Protocol validation coverage analysis.

Invariant 2a: All code paths that accept a security-sensitive value must apply
the same validation as the primary path.

Specifically detects the incomplete-fix pattern:
  - A validation function exists for a value type
  - Some assignment paths for that value type apply it
  - Other assignment paths do not
  - The uncovered paths are SECURITY candidates

Usage:
    python3 scan_validation_coverage.py <cpython-lib-dir>

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
    "http/cookies.py",
    "http/client.py",
    "wsgiref/headers.py",
    "urllib/request.py",
    "urllib/parse.py",
]

# Known validation functions for security-sensitive values
KNOWN_VALIDATORS = {
    # http.cookies — character validation for cookie values
    "_is_legal_key",
    "_is_legal_value",
    "_unquote",
    "_quote",
    # http.client — header validation
    "_is_illegal_header_value",
    "_check_name",
    # wsgiref — header validation
    "valid_header_name",
    "valid_header_value",
    # General
    "_check_sendfile_params",
}

# Assignment-like method names that should apply validation
ASSIGNMENT_METHODS = {
    "__setitem__",
    "__setattr__",
    "update",
    "__ior__",      # |=
    "__iadd__",     # +=
    "__reduce__",
    "__setstate__",
    "set",
    "add",
    "append",
}

# Output methods that should sanitize
OUTPUT_METHODS = {
    "output",
    "js_output",
    "__str__",
    "__repr__",
    "encode",
}


@dataclass
class MethodInfo:
    name: str
    lineno: int
    has_validation: bool = False
    validation_calls: list = field(default_factory=list)
    is_assignment: bool = False
    is_output: bool = False


@dataclass
class Finding:
    module: str
    class_name: str
    covered_methods: list
    uncovered_methods: list
    validator_used: str
    confidence: str
    evidence: str
    corpus_ref: Optional[str] = None


class ClassAnalyzer(ast.NodeVisitor):
    """Walk a class body and map methods to their validation calls."""

    def __init__(self, class_name: str):
        self.class_name = class_name
        self.methods: dict[str, MethodInfo] = {}

    def _extract_call_names(self, node: ast.AST) -> list[str]:
        """Extract all function/method call names from a node."""
        names = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    names.append(child.func.attr)
                elif isinstance(child.func, ast.Name):
                    names.append(child.func.id)
        return names

    def visit_FunctionDef(self, node: ast.FunctionDef):
        info = MethodInfo(name=node.name, lineno=node.lineno)

        if node.name in ASSIGNMENT_METHODS:
            info.is_assignment = True
        if node.name in OUTPUT_METHODS:
            info.is_output = True

        # Find all function calls in this method
        call_names = self._extract_call_names(node)
        for name in call_names:
            if name in KNOWN_VALIDATORS:
                info.has_validation = True
                info.validation_calls.append(name)

        self.methods[node.name] = info
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef


def analyze_class(class_node: ast.ClassDef, module_path: str) -> list[Finding]:
    """Analyze a class for validation coverage gaps."""
    findings = []
    module_name = Path(module_path).name

    analyzer = ClassAnalyzer(class_node.name)
    for item in class_node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            analyzer.visit_FunctionDef(item)

    # Find which validators are used in this class at all
    all_validators = set()
    for method in analyzer.methods.values():
        all_validators.update(method.validation_calls)

    if not all_validators:
        return findings  # No validators in this class — nothing to check coverage for

    # For each validator, find covered and uncovered assignment paths
    for validator in all_validators:
        covered = []
        uncovered = []

        for method_name, method_info in analyzer.methods.items():
            if not (method_info.is_assignment or method_info.is_output):
                continue
            if validator in method_info.validation_calls:
                covered.append(method_name)
            else:
                uncovered.append(method_name)

        if uncovered and covered:
            # Determine confidence based on method type
            security_uncovered = [m for m in uncovered if m in ASSIGNMENT_METHODS]

            if security_uncovered:
                confidence = "SECURITY-CANDIDATE"
                corpus_ref = "PRO-001, PRO-002 (http.cookies incomplete fix pattern)"

                # Upgrade to SECURITY if this matches the exact http.cookies pattern
                if (class_node.name in ("Morsel", "BaseCookie") and
                        "update" in uncovered or "__ior__" in uncovered):
                    confidence = "SECURITY"
                    corpus_ref = "PRO-002 (exact pattern: Morsel.update() not covered by cookie validation)"

                findings.append(Finding(
                    module=module_name,
                    class_name=class_node.name,
                    covered_methods=covered,
                    uncovered_methods=security_uncovered,
                    validator_used=validator,
                    confidence=confidence,
                    evidence=(
                        f"Class '{class_node.name}' applies '{validator}' validation on "
                        f"{covered} but not on {security_uncovered}. "
                        f"The uncovered paths accept the same value type and should apply "
                        f"the same validation. This matches the pattern behind CVE-2026-3644 "
                        f"(incomplete fix for CVE-2026-0672)."
                    ),
                    corpus_ref=corpus_ref,
                ))

    return findings


def analyze_module(filepath: str) -> list[Finding]:
    """Parse a module and analyze all classes."""
    try:
        source = Path(filepath).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=filepath)
    except (SyntaxError, OSError) as e:
        return []

    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            findings.extend(analyze_class(node, filepath))

    return findings


def scan(lib_dir: str) -> list[dict]:
    """Main entry point."""
    all_findings = []

    for module_path in TARGET_MODULES:
        full_path = os.path.join(lib_dir, module_path.replace("/", os.sep))
        if os.path.exists(full_path):
            findings = analyze_module(full_path)
            for f in findings:
                all_findings.append({
                    "domain": "PRO",
                    "module": f.module,
                    "class": f.class_name,
                    "covered_paths": f.covered_methods,
                    "uncovered_paths": f.uncovered_methods,
                    "validator": f.validator_used,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "corpus_ref": f.corpus_ref,
                    "sub_invariant": "2a",
                    "invariant": "Invariant 2: Validation Coverage",
                })

    return all_findings


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cpython-lib-dir>", file=sys.stderr)
        sys.exit(1)

    results = scan(sys.argv[1])
    print(json.dumps(results, indent=2))

    print(f"\n--- scan_validation_coverage.py summary ---", file=sys.stderr)
    by_confidence = {}
    for r in results:
        by_confidence.setdefault(r["confidence"], []).append(r)
    for conf, items in sorted(by_confidence.items()):
        print(f"  {conf}: {len(items)}", file=sys.stderr)
    print(f"  Total: {len(results)}", file=sys.stderr)
