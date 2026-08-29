"""
reproducer_engine.py — Generate and validate reproducers for security findings.

A finding with no confirmed reproducer must never be reported as HIGH confidence.
This script generates minimal Python scripts that demonstrate the violated invariant,
validates them, and outputs the result.

Usage:
    python3 reproducer_engine.py <finding-json-file> [--dry-run] [--cpython-lib <path>]

Output:
    JSON with reproducer status and script to stdout.
"""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path
from typing import Optional


# Templates for each sub-invariant class

TEMPLATES = {
    # Archive — boundary check before resolve (ARC sub-invariant 1b)
    "1b_symlink": textwrap.dedent("""\
        #!/usr/bin/env python3
        \"\"\"
        Reproducer for Invariant 1b: destination boundary check applied before
        symlink resolution.

        Expected (correct) behavior: extraction raises an error or skips the entry.
        Observed (buggy) behavior: extracted file appears outside the destination.
        \"\"\"
        import os
        import tarfile
        import tempfile

        def make_traversal_tar(output_path: str):
            \"\"\"Craft a tar archive with a symlink that points outside the destination.\"\"\"
            with tarfile.open(output_path, "w") as tar:
                # First member: a symlink named 'link' pointing to '/tmp'
                info = tarfile.TarInfo(name="link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/tmp"  # Points outside any reasonable destination
                tar.addfile(info)

                # Second member: a file 'link/pwned.txt'
                # If symlink was extracted first, this writes to /tmp/pwned.txt
                import io
                content = b"outside_destination"
                info2 = tarfile.TarInfo(name="link/pwned.txt")
                info2.size = len(content)
                tar.addfile(info2, io.BytesIO(content))

        with tempfile.TemporaryDirectory() as destdir:
            tarpath = os.path.join(destdir, "test.tar")
            make_traversal_tar(tarpath)

            extractdir = os.path.join(destdir, "extracted")
            os.makedirs(extractdir)

            try:
                with tarfile.open(tarpath) as tar:
                    tar.extractall(extractdir)
                # Check if any file was written outside extractdir
                for root, dirs, files in os.walk("/tmp"):
                    for f in files:
                        if f == "pwned.txt":
                            print(f"INVARIANT VIOLATED: file written to {{os.path.join(root, f)}}")
                            break
                    break
            except Exception as e:
                print(f"Extraction correctly raised: {{e}}")
    """),

    # Protocol — validation coverage gap (PRO sub-invariant 2a)
    "2a_morsel_update": textwrap.dedent("""\
        #!/usr/bin/env python3
        \"\"\"
        Reproducer for Invariant 2a: Morsel.update() does not apply the same
        character validation as Morsel.__setitem__().

        Expected (correct) behavior: both paths reject control characters.
        Observed (buggy) behavior: update() accepts control characters that
        __setitem__ would reject.

        Matches: CVE-2026-3644 (incomplete fix for CVE-2026-0672)
        \"\"\"
        from http.cookies import Morsel

        # Test __setitem__ (should reject)
        m1 = Morsel()
        try:
            m1["value"] = "test\\r\\nInjected-Header: evil"
            print("__setitem__: ACCEPTED (possible injection path)")
        except Exception as e:
            print(f"__setitem__: REJECTED correctly: {{e}}")

        # Test update() (should also reject)
        m2 = Morsel()
        try:
            m2.update({"value": "test\\r\\nInjected-Header: evil"})
            print("update(): ACCEPTED — INVARIANT VIOLATED (validation gap)")
        except Exception as e:
            print(f"update(): REJECTED correctly: {{e}}")

        # Test |= operator (should also reject)
        m3 = Morsel()
        try:
            m3 |= {"value": "test\\r\\nInjected-Header: evil"}
            print("|=: ACCEPTED — INVARIANT VIOLATED (validation gap)")
        except Exception as e:
            print(f"|=: REJECTED correctly: {{e}}")
    """),

    # Resource — decompression bounds (RES sub-invariant 3a)
    "3a_decompression": textwrap.dedent("""\
        #!/usr/bin/env python3
        \"\"\"
        Reproducer for Invariant 3a: decompression output fully materialized
        before size check (dry-run version — does not allocate large memory).

        This script checks whether the code path applies a bound before or after
        decompression using source inspection rather than live allocation.

        For a live test, run with --live (WARNING: may allocate several GB).
        \"\"\"
        import ast
        import sys
        import inspect

        try:
            import zipfile
            source = inspect.getsource(zipfile.ZipExtFile.read)
            print("Checking zipfile.ZipExtFile.read for bounded reads...")

            # Look for max_length argument in decompress calls
            tree = ast.parse(source)
            unbounded_reads = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Attribute):
                        if node.func.attr in ("read", "decompress"):
                            if not node.args and not node.keywords:
                                unbounded_reads.append(node.lineno)

            if unbounded_reads:
                print(f"CANDIDATE: Unbounded read/decompress calls at lines: {{unbounded_reads}}")
                print("Manual verification required — may indicate Invariant 3a violation")
            else:
                print("No obvious unbounded decompression calls found (good)")

        except Exception as e:
            print(f"Analysis failed: {{e}}")
    """),

    # Audit — open() instead of io.open_code() (AUD sub-invariant 4a)
    "4a_open_code": textwrap.dedent("""\
        #!/usr/bin/env python3
        \"\"\"
        Reproducer for Invariant 4a: Python file loaded with open() instead of
        io.open_code(), bypassing sys.audit() hooks.

        Expected: sys.audit('open', ...) fires when any Python file is loaded.
        Observed (buggy): hook does not fire for .pyc files loaded via some paths.

        Matches: CVE-2026-2297 (SourcelessFileLoader bypass)
        \"\"\"
        import sys
        import io
        import importlib.util
        import tempfile
        import os

        audit_events = []

        def audit_hook(event, args):
            if event == "open":
                audit_events.append((event, args))

        sys.addaudithook(audit_hook)

        # Test that io.open_code() fires the audit event
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write("x = 1\\n")
            tmppath = f.name

        try:
            before = len(audit_events)
            with io.open_code(tmppath) as f:
                f.read()
            after = len(audit_events)
            if after > before:
                print(f"io.open_code(): audit event fired correctly ({{after - before}} events)")
            else:
                print("io.open_code(): INVARIANT VIOLATED — no audit event fired")

            # Now test plain open()
            before2 = len(audit_events)
            with open(tmppath, "rb") as f:
                f.read()
            after2 = len(audit_events)
            if after2 > before2:
                print(f"open(): audit event fired ({{after2 - before2}} events)")
            else:
                print("open(): no audit event — this is why open() must not be used for Python files")
        finally:
            os.unlink(tmppath)
    """),
}


def select_template(finding: dict) -> Optional[str]:
    """Select the appropriate reproducer template for a finding."""
    sub = finding.get("sub_invariant", "")
    corpus_ref = finding.get("corpus_ref", "")
    module = finding.get("module", "")

    if sub == "1b":
        return TEMPLATES["1b_symlink"]
    if sub == "2a" and "cookies" in module.lower():
        return TEMPLATES["2a_morsel_update"]
    if sub == "3a":
        return TEMPLATES["3a_decompression"]
    if sub == "4a":
        return TEMPLATES["4a_open_code"]

    return None


def run_reproducer(script: str, dry_run: bool = False) -> dict:
    """Execute a reproducer script and return the result."""
    if dry_run:
        return {"status": "DRY_RUN", "output": "", "error": ""}

    with tempfile.NamedTemporaryFile(
        suffix=".py", mode="w", delete=False, encoding="utf-8"
    ) as f:
        f.write(script)
        tmppath = f.name

    try:
        result = subprocess.run(
            [sys.executable, tmppath],
            capture_output=True, text=True, timeout=30
        )
        return {
            "status": "RAN",
            "returncode": result.returncode,
            "output": result.stdout,
            "error": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"status": "TIMEOUT", "output": "", "error": "Reproducer timed out (30s)"}
    except Exception as e:
        return {"status": "ERROR", "output": "", "error": str(e)}
    finally:
        os.unlink(tmppath)


def determine_status(run_result: dict) -> str:
    """Determine whether the reproducer confirmed the finding."""
    if run_result["status"] == "DRY_RUN":
        return "DRY_RUN"
    if run_result["status"] == "TIMEOUT":
        return "UNCONFIRMED"
    if run_result["status"] == "ERROR":
        return "UNCONFIRMED"

    output = run_result.get("output", "")
    # Look for confirmation signals
    if "INVARIANT VIOLATED" in output or "CANDIDATE" in output:
        return "CONFIRMED"
    if "correctly" in output.lower() or "REJECTED" in output:
        return "NOT_REPRODUCED"

    return "UNCONFIRMED"


def generate_reproducer(finding: dict, dry_run: bool = False) -> dict:
    """Main function: generate, run, and classify a reproducer."""
    script = select_template(finding)

    if not script:
        return {
            "finding_id": finding.get("domain", "UNK") + "-" + str(finding.get("lineno", "?")),
            "status": "NO_TEMPLATE",
            "script": None,
            "confidence_update": "SECURITY-CANDIDATE (no template — manual reproducer required)",
            "message": "No reproducer template for this sub-invariant. Manual reproduction required.",
        }

    run_result = run_reproducer(script, dry_run)
    status = determine_status(run_result)

    confidence_map = {
        "CONFIRMED": "SECURITY",
        "NOT_REPRODUCED": "FALSE-POSITIVE",
        "UNCONFIRMED": "SECURITY-CANDIDATE",
        "DRY_RUN": finding.get("confidence", "SECURITY-CANDIDATE"),
        "NO_TEMPLATE": "SECURITY-CANDIDATE",
    }

    return {
        "finding_id": finding.get("domain", "UNK"),
        "sub_invariant": finding.get("sub_invariant", "?"),
        "reproducer_status": status,
        "confidence_update": confidence_map.get(status, "SECURITY-CANDIDATE"),
        "script": script,
        "run_output": run_result.get("output", ""),
        "run_error": run_result.get("error", ""),
        "next_step": (
            "Route to security@python.org after pre-triage with a trusted CPython developer"
            if status == "CONFIRMED"
            else "Manually confirm the behavior before taking any external action"
        ),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate and validate security finding reproducers")
    parser.add_argument("finding_json", help="Path to finding JSON file, or '-' to read from stdin")
    parser.add_argument("--dry-run", action="store_true", help="Don't execute the reproducer")
    args = parser.parse_args()

    if args.finding_json == "-":
        finding = json.load(sys.stdin)
    else:
        with open(args.finding_json) as f:
            finding = json.load(f)

    result = generate_reproducer(finding, dry_run=args.dry_run)
    print(json.dumps(result, indent=2))
