"""
Corpus positive fixture: RES-001 — CVE-2025-8194 class.

Invariant 3c: offset fields from untrusted archive metadata used in loop
conditions without non-negative validation, enabling infinite loops or
incorrect arithmetic.

This fixture checks whether tarfile validates block offset fields before
using them in arithmetic or loop conditions.

This is a POSITIVE fixture — it should trigger the decompression-bounds agent.
"""

import ast
import inspect
import sys


def check_negative_offset_validation():
    """
    Inspect tarfile source for offset fields used without non-negative checks.
    This is a source-level check — no live archive needed.
    """
    try:
        import tarfile
        source = inspect.getsource(tarfile)
        tree = ast.parse(source)
    except Exception as e:
        print(f"Could not inspect tarfile: {e}")
        return False

    # Look for patterns where a field named *offset* or *blocks* is used
    # in arithmetic or comparison without a preceding >= 0 check
    candidates = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id.lower()
                    if any(kw in name for kw in ("offset", "blocks", "size", "pos")):
                        # Check if right-hand side reads from a struct/unpack
                        rhs = ast.dump(node.value)
                        if "unpack" in rhs or "nti" in rhs or "calcsize" in rhs:
                            candidates.append((name, node.lineno))

    if candidates:
        print(f"POSITIVE: Found {len(candidates)} offset/size fields from struct unpacking:")
        for name, lineno in candidates[:5]:
            print(f"  '{name}' at line {lineno} — verify non-negative check before use")
        print("Manual review required to confirm CVE-2025-8194 class invariant violation")
        return True
    else:
        print("NEGATIVE: No obvious unvalidated offset fields found")
        return False


if __name__ == "__main__":
    check_negative_offset_validation()