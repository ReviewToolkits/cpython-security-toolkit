"""
Corpus NEGATIVE fixture: io.open_code() correctly fires sys.audit() hook.

Invariant 4a: the correct implementation uses io.open_code() for Python file
loading, which fires the sys.audit("open", ...) event.

This fixture confirms the CORRECT path (io.open_code) fires the hook.
A NEGATIVE fixture must produce NO finding from audit-hook-coverage agent.
"""

import io
import os
import sys
import tempfile

audit_events: list = []


def record_hook(event: str, args: tuple) -> None:
    if event in ("open", "io.open_code"):
        audit_events.append((event, args))


def test_correct_audit_behavior() -> bool:
    """Returns True if io.open_code correctly fires the audit hook."""
    sys.addaudithook(record_hook)

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
        f.write("x = 42\n")
        tmppath = f.name

    try:
        before = len(audit_events)
        with io.open_code(tmppath):
            pass
        after = len(audit_events)
        return after > before
    finally:
        os.unlink(tmppath)


if __name__ == "__main__":
    ok = test_correct_audit_behavior()
    if ok:
        print("NEGATIVE: io.open_code() correctly fires audit hook (invariant satisfied)")
    else:
        print("POSITIVE: io.open_code() did NOT fire audit hook — unexpected on this platform")
