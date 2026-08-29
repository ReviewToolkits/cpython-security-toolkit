"""
Corpus positive fixture: PRO-002 — CVE-2026-3644 (incomplete fix for CVE-2026-0672).

Invariant 2a: All code paths that accept a Morsel value must apply the same
character-set validation. The fix for CVE-2026-0672 patched __setitem__ but
not update(), |=, and unpickling.

This fixture checks whether the validation gap exists on update() and |=.
A POSITIVE result (fixture confirms the bug) means these paths accept control
characters that __setitem__ would reject.

This is a POSITIVE fixture — it should trigger the validation-coverage agent.
"""

from http.cookies import Morsel


INJECTION_VALUE = "test\r\nInjected-Header: injected-by-attacker"
CONTROL_CHAR_VALUE = "test\x00null-byte"


def test_setitem_blocks():
    """__setitem__ should reject control characters (this is the patched path)."""
    m = Morsel()
    try:
        m["value"] = INJECTION_VALUE
        return False  # Accepted — __setitem__ is not validating (unexpected)
    except (ValueError, CookieError if False else Exception):
        return True  # Rejected correctly


def test_update_blocks():
    """update() should reject control characters (may not be patched)."""
    m = Morsel()
    try:
        m.update({"value": INJECTION_VALUE})
        return False  # Accepted — INVARIANT VIOLATED
    except Exception:
        return True   # Rejected correctly


def test_ior_blocks():
    """|= should reject control characters (may not be patched)."""
    m = Morsel()
    try:
        m |= {"value": INJECTION_VALUE}
        return False  # Accepted — INVARIANT VIOLATED
    except Exception:
        return True   # Rejected correctly


def test_null_byte_update():
    """Null byte injection via update()."""
    m = Morsel()
    try:
        m.update({"value": CONTROL_CHAR_VALUE})
        return False  # Accepted — INVARIANT VIOLATED
    except Exception:
        return True   # Rejected correctly


def run_corpus_check():
    results = {
        "__setitem__ blocks CRLF": test_setitem_blocks(),
        "update() blocks CRLF": test_update_blocks(),
        "|= blocks CRLF": test_ior_blocks(),
        "update() blocks NUL": test_null_byte_update(),
    }

    violations = [name for name, blocked in results.items() if not blocked]

    if violations:
        print(f"POSITIVE: Validation gap found on: {violations}")
        print("Invariant 2a violated — matches CVE-2026-3644 class")
        return True
    else:
        print("NEGATIVE: All paths correctly block control characters")
        return False


if __name__ == "__main__":
    run_corpus_check()
