"""
Corpus positive fixture: ARC-005 — CVE-2025-4517 class.

Invariant 1b: Destination boundary check applied before symlink resolution.

This fixture demonstrates the pattern where os.path.realpath() is called on a
symlink target, the realpath result is checked against the destination, but the
symlink itself was crafted such that the final resolved path escapes the destination
after the check has already passed.

A correct implementation rejects this. A buggy implementation writes outside the
destination directory.

This is a POSITIVE fixture — it should trigger the traversal-detector.
"""

import io
import os
import tarfile
import tempfile


def make_traversal_archive(output_path: str) -> None:
    """
    Craft a tar archive that demonstrates the realpath-before-resolve pattern.

    The archive contains:
    1. A symlink 'evil' -> '../../../../tmp' (relative traversal)
    2. A file 'evil/canary.txt' that would write to /tmp if extraction is naive
    """
    with tarfile.open(output_path, "w") as tar:
        # Symlink with path traversal
        sym = tarfile.TarInfo("evil")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "../../../../tmp"
        tar.addfile(sym)

        # File that follows the symlink
        content = b"canary_outside_destination"
        fi = tarfile.TarInfo("evil/canary.txt")
        fi.size = len(content)
        tar.addfile(fi, io.BytesIO(content))


def test_extraction_boundary():
    """
    Run the extraction and check whether the boundary is correctly enforced.

    Returns True if the invariant is violated (finding confirmed).
    Returns False if the invariant is correctly enforced (finding not applicable).
    """
    with tempfile.TemporaryDirectory() as workdir:
        archive_path = os.path.join(workdir, "test.tar")
        extract_dir = os.path.join(workdir, "output")
        os.makedirs(extract_dir)

        make_traversal_archive(archive_path)

        violation_detected = False
        try:
            with tarfile.open(archive_path) as tar:
                tar.extractall(extract_dir)

            # Check for escape outside extract_dir
            for root, dirs, files in os.walk(workdir):
                if root == extract_dir or root.startswith(extract_dir + os.sep):
                    continue
                for f in files:
                    if f == "canary.txt":
                        violation_detected = True
                        break

        except (tarfile.ExtractError, PermissionError, OSError):
            # Extraction correctly refused the dangerous entry
            pass

        return violation_detected


if __name__ == "__main__":
    violated = test_extraction_boundary()
    if violated:
        print("POSITIVE: Archive extraction boundary violated (expected for buggy versions)")
    else:
        print("NEGATIVE: Archive extraction boundary correctly enforced")
