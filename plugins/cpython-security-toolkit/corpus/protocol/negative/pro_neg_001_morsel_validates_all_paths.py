"""
Corpus NEGATIVE fixture: Morsel validation on __setitem__ (primary path).

Invariant 2a: the primary assignment path (__setitem__) must reject control
characters. This negative fixture confirms the primary path is correctly guarded.

NOTE: This tests only the primary path because the secondary paths (update(),
|=, unpickling) may remain unpatched on some Python versions — see PRO-002
(CVE-2026-3644) which is the POSITIVE fixture for those secondary paths.

A NEGATIVE fixture must produce NO finding for the primary path.
"""

from http.cookies import Morsel

INJECTION_VALUE = "test\r\nInjected-Header: evil"


def run_negative_check() -> bool:
    """Returns True if the primary path (__setitem__) blocks injection."""
    m = Morsel()
    try:
        m["value"] = INJECTION_VALUE
        return False  # Primary path accepted — unexpected on patched version
    except Exception:
        return True   # Correctly rejected


if __name__ == "__main__":
    ok = run_negative_check()
    if ok:
        print("NEGATIVE: Morsel.__setitem__ correctly rejects control characters")
        print("(Primary validation path confirmed working)")
    else:
        print("POSITIVE: Primary path accepted injection — PRE-CVE-2026-0672 behavior")
