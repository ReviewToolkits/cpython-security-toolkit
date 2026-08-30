"""
scan_incomplete_fix.py — Incomplete security fix detection.

Invariant 2: All code paths through a security invariant must be covered
by the fix. A patch that covers one path but not others is incomplete.

This script reads CPython git history for security fix commits and checks
whether all paths through the same invariant were patched.

Usage:
    python3 scan_incomplete_fix.py <cpython-repo-dir> [--months 24]
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

# Keywords that identify security fix commits
SECURITY_KEYWORDS = [
    "security", "CVE", "injection", "traversal", "bypass",
    "overflow", "smuggling", "disclosure", "arbitrary",
]

# Modules where we check for validation coverage
VALIDATION_MODULES = {
    "Lib/http/cookies.py": {
        "value_methods": [
            "__setitem__", "update", "__ior__", "__reduce__",
            "__setstate__", "set", "js_output", "output",
        ],
        "validation_indicators": [
            "_is_legal_key", "_is_legal_value", "_unquote",
            "illegal_char", "translate", "encode",
        ],
    },
    "Lib/wsgiref/headers.py": {
        "value_methods": ["__setitem__", "add_header", "get_all"],
        "validation_indicators": ["valid_header_name", "valid_header_value"],
    },
    "Lib/http/client.py": {
        "value_methods": ["putheader", "_send_output", "request"],
        "validation_indicators": [
            "_is_illegal_header_value", "_check_name", "illegal",
        ],
    },
}


def get_security_commits(repo_dir: str, months: int = 24) -> list[dict]:
    """Get recent commits that look like security fixes."""
    try:
        result = subprocess.run(
            ["git", "log", f"--since={months} months ago",
             "--format=%H %s", "--", "Lib/"],
            cwd=repo_dir, capture_output=True, text=True, timeout=30
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    commits = []
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split(" ", 1)
        if len(parts) < 2:
            continue
        sha, subject = parts[0], parts[1]

        if any(kw.lower() in subject.lower() for kw in SECURITY_KEYWORDS):
            commits.append({"sha": sha, "subject": subject})

    return commits


def get_changed_files(repo_dir: str, sha: str) -> list[str]:
    """Get files changed in a commit."""
    try:
        result = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "-r", "--name-only", sha],
            cwd=repo_dir, capture_output=True, text=True, timeout=10
        )
        return [f for f in result.stdout.strip().splitlines() if f.startswith("Lib/")]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def check_validation_coverage(repo_dir: str, module_rel: str) -> list[dict]:
    """
    For a given module, check whether all value-accepting methods
    apply the same validation.
    """
    full_path = os.path.join(repo_dir, module_rel)
    if not os.path.exists(full_path):
        return []

    module_config = VALIDATION_MODULES.get(module_rel, {})
    if not module_config:
        return []

    source = Path(full_path).read_text(encoding="utf-8")
    findings = []

    value_methods = module_config.get("value_methods", [])
    validators = module_config.get("validation_indicators", [])

    # For each value-accepting method, check if any validator is called
    covered = []
    uncovered = []

    for method in value_methods:
        # Extract the method body conservatively; final coverage requires path tracing.
        pattern = rf"def {re.escape(method)}\s*\(.*?\).*?(?=\n    def |\nclass |\Z)"
        match = re.search(pattern, source, re.DOTALL)
        if not match:
            continue
        body = match.group(0)

        has_validation = any(v in body for v in validators)
        if has_validation:
            covered.append(method)
        else:
            uncovered.append(method)

    if covered and uncovered:
        findings.append({
            "module": module_rel,
            "covered_paths": covered,
            "uncovered_paths": uncovered,
            "issue": f"Validation applied on {covered} but not on {uncovered}",
            "sub_invariant": "2a",
            "confidence": "SECURITY-CANDIDATE",
            "evidence": (
                f"Module {Path(module_rel).name}: validator found in {covered} "
                f"but not in {uncovered}. This matches the incomplete-fix pattern "
                f"(CVE-2026-0672 → CVE-2026-3644)."
            ),
            "corpus_ref": "PRO-001, PRO-002",
        })

    return findings


def scan(repo_dir: str, months: int = 24) -> list[dict]:
    all_findings = []

    # 1. Get security commits
    commits = get_security_commits(repo_dir, months)

    # 2. For each commit, check changed modules for coverage gaps
    seen_modules = set()
    for commit in commits:
        changed = get_changed_files(repo_dir, commit["sha"])
        for f in changed:
            if f in VALIDATION_MODULES and f not in seen_modules:
                seen_modules.add(f)
                findings = check_validation_coverage(repo_dir, f)
                for finding in findings:
                    finding["fix_commit"] = commit["sha"]
                    finding["fix_subject"] = commit["subject"]
                    all_findings.append({
                        "domain": "PRO",
                        **finding,
                        "invariant": "Invariant 2: Validation Coverage",
                    })

    # 3. Also check known modules unconditionally
    for module_rel in VALIDATION_MODULES:
        if module_rel not in seen_modules:
            findings = check_validation_coverage(repo_dir, module_rel)
            for finding in findings:
                finding["fix_commit"] = "none (unconditional scan)"
                all_findings.append({
                    "domain": "PRO",
                    **finding,
                    "invariant": "Invariant 2: Validation Coverage",
                })

    return all_findings


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("repo_dir", help="Path to CPython repository root")
    parser.add_argument("--months", type=int, default=24)
    args = parser.parse_args()

    results = scan(args.repo_dir, args.months)
    print(json.dumps(results, indent=2))
    print(f"\nTotal: {len(results)}", file=sys.stderr)