"""Shared analysis helpers for the CPython security toolkit.

The scanners are intentionally conservative: static analysis produces candidates,
not security verdicts. This module centralizes parser compatibility, finding
fingerprints, and small interprocedural summaries so individual engines do not
invent subtly different heuristics.
"""
from __future__ import annotations

import ast
import hashlib
import re
from pathlib import Path
from typing import Any


LAZY_IMPORT_RE = re.compile(r"^(\s*)lazy\s+import\s+(.+?)\s*$")


def parse_source(source: str, filename: str = "<unknown>") -> tuple[ast.AST | None, str | None]:
    """Parse CPython source with compatibility for newer CPython-only syntax.

    The host Python may lag the checkout being reviewed.  CPython 3.16 source can
    contain ``lazy import`` syntax that older host interpreters cannot parse.  For
    static analysis only, replace that statement with an ordinary import while
    preserving line count.  If another syntax feature is encountered, return a
    structured parse error instead of silently treating the file as clean.
    """
    try:
        return ast.parse(source, filename=filename), None
    except SyntaxError as first:
        lines = source.splitlines(keepends=True)
        changed = False
        for i, line in enumerate(lines):
            match = LAZY_IMPORT_RE.match(line.rstrip("\n"))
            if match:
                lines[i] = f"{match.group(1)}import {match.group(2)}\n"
                changed = True
        if changed:
            try:
                return ast.parse("".join(lines), filename=filename), None
            except SyntaxError as second:
                return None, f"SyntaxError after CPython-syntax normalization: {second}"
        return None, f"SyntaxError: {first}"


def read_ast(path: str | Path) -> tuple[ast.AST | None, str, str | None]:
    """Read and parse a source file; return (tree, source, error)."""
    try:
        source = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return None, "", f"OSError: {exc}"
    tree, error = parse_source(source, str(path))
    return tree, source, error


def normalize_issue(issue: str) -> str:
    """Normalize volatile source locations for stable finding identity."""
    issue = re.sub(r"line(?:s)?\s+\[[^\]]*\]", "", issue, flags=re.I)
    issue = re.sub(r"line\s+\d+", "line", issue, flags=re.I)
    return " ".join(issue.lower().split())


def fingerprint(finding: dict[str, Any]) -> str:
    """Return a stable identity independent of line-number drift."""
    parts = [
        finding.get("domain", ""),
        finding.get("sub_invariant", ""),
        finding.get("module", ""),
        finding.get("function", finding.get("class", "")),
        normalize_issue(finding.get("issue", "")),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def add_fingerprint(finding: dict[str, Any]) -> dict[str, Any]:
    finding = dict(finding)
    finding["fingerprint"] = fingerprint(finding)
    return finding


def has_direct_validation(node: ast.AST, validators: set[str]) -> set[str]:
    """Return validator calls directly present in an AST subtree."""
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name) and child.func.id in validators:
                found.add(child.func.id)
            elif isinstance(child.func, ast.Attribute) and child.func.attr in validators:
                found.add(child.func.attr)
    return found


def called_method_names(node: ast.AST) -> set[str]:
    """Collect method/function names invoked by a subtree."""
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            if isinstance(child.func, ast.Name):
                names.add(child.func.id)
            elif isinstance(child.func, ast.Attribute):
                names.add(child.func.attr)
    return names
