"""
Corpus NEGATIVE fixture: safe archive extraction via filter API.

Invariant 1b: a correct implementation rejects symlink traversal attempts.

This fixture constructs the same symlink-escape archive as arc_001, but
exercises it against the extraction filter API introduced in Python 3.12
(tarfile.data_filter). The filter raises LinkOutsideDestinationError, which
is the CORRECT (negative) behavior — no escape occurs.

A NEGATIVE fixture must produce NO finding when run through traversal-detector.
"""

import io
import os
import tarfile
import tempfile


def make_symlink_escape_tar(output_path: str) -> None:
    with tarfile.open(output_path, "w") as tar:
        sym = tarfile.TarInfo("escape")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "../../../tmp"
        tar.addfile(sym)

        content = b"arc_neg_001_canary"
        fi = tarfile.TarInfo("escape/arc_neg001.txt")
        fi.size = len(content)
        tar.addfile(fi, io.BytesIO(content))


def test_safe_extraction() -> bool:
    """Returns True if the boundary was correctly enforced (negative = good)."""
    with tempfile.TemporaryDirectory() as workdir:
        tar_path = os.path.join(workdir, "safe_test.tar")
        extract_dir = os.path.join(workdir, "output")
        os.makedirs(extract_dir)
        make_symlink_escape_tar(tar_path)

        correctly_blocked = False
        try:
            with tarfile.open(tar_path) as tar:
                # data_filter (Python 3.12+) blocks symlink traversal with an exception
                tar.extractall(extract_dir, filter="data")
        except (tarfile.FilterError, tarfile.ExtractError, PermissionError, OSError):
            # Any of these indicate the filter correctly blocked the dangerous entry
            correctly_blocked = True
            return True

        # If no exception: verify nothing escaped the destination
        escaped = False
        for root, dirs, files in os.walk(workdir):
            if root == extract_dir or root.startswith(extract_dir + os.sep):
                continue
            if any(f == "arc_neg001.txt" for f in files):
                escaped = True
        return not escaped


if __name__ == "__main__":
    safe = test_safe_extraction()
    if safe:
        print("NEGATIVE: Extraction boundary correctly enforced (expected for patched versions)")
    else:
        print("POSITIVE: Boundary violated — this should not happen on a patched CPython")
