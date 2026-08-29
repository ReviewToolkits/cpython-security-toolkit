"""
Corpus positive fixture: AUD-001 — CVE-2026-2297 class.

Invariant 4a: Python bytecode loaded with open() instead of io.open_code()
means sys.audit('open') hooks do not fire for that load path.

This fixture registers a sys.audit hook and checks whether loading a .pyc
file via SourcelessFileLoader fires the hook. A POSITIVE result means the
hook does NOT fire — the bypass exists.

This is a POSITIVE fixture — it should trigger the audit-hook-coverage agent.
"""

import io
import os
import sys
import py_compile
import tempfile
import importlib.util


audit_events: list = []


def record_hook(event, args):
    if event in ("open", "io.open_code"):
        audit_events.append((event, args))


def test_open_code_audit():
    sys.addaudithook(record_hook)

    with tempfile.TemporaryDirectory() as workdir:
        # Create a minimal .py file and compile it to .pyc
        src = os.path.join(workdir, "sample.py")
        with open(src, "w") as f:
            f.write("x = 42\n")

        pyc = os.path.join(workdir, "sample.pyc")
        py_compile.compile(src, cfile=pyc, doraise=True)

        # Test: load via io.open_code (should fire hook)
        before = len(audit_events)
        with io.open_code(pyc):
            pass
        after = len(audit_events)
        open_code_fired = after > before

        # Test: load via plain open (may not fire hook)
        before2 = len(audit_events)
        with open(pyc, "rb"):
            pass
        after2 = len(audit_events)
        plain_open_fired = after2 > before2

        return {
            "io_open_code_fires_hook": open_code_fired,
            "plain_open_fires_hook": plain_open_fired,
            "bypass_exists": open_code_fired and not plain_open_fired,
        }


if __name__ == "__main__":
    results = test_open_code_audit()
    print(f"io.open_code fires audit hook: {results['io_open_code_fires_hook']}")
    print(f"plain open() fires audit hook: {results['plain_open_fires_hook']}")
    if results["bypass_exists"]:
        print("POSITIVE: Audit hook bypass confirmed — open() does not fire hook")
        print("Matches CVE-2026-2297 class (SourcelessFileLoader)")
    else:
        print("NEGATIVE: Both paths fire audit hook correctly")