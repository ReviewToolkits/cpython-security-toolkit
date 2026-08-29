"""
Corpus positive fixture: ARC-001 — CVE-2024-12718 / CVE-2025-4138 class.

Invariant 1b: symlink target not fully resolved before destination boundary check.

A tar archive contains a symlink pointing outside the destination, followed by
a file that follows that symlink. A correct implementation rejects the symlink
or refuses to follow it outside the destination. A buggy one writes the file
outside the destination.

This is a POSITIVE fixture — it should trigger the traversal-detector agent.
"""

import io
import os
import tarfile
import tempfile


def make_symlink_escape_tar(output_path: str) -> None:
    """Craft a tar archive with a symlink escape pattern."""
    with tarfile.open(output_path, "w") as tar:
        # Symlink: 'escape' -> '../../../tmp/pwned'
        sym = tarfile.TarInfo("escape")
        sym.type = tarfile.SYMTYPE
        sym.linkname = "../../../tmp"
        tar.addfile(sym)

        # File following the symlink
        content = b"arc_001_canary"
        fi = tarfile.TarInfo("escape/arc001.txt")
        fi.size = len(content)
        tar.addfile(fi, io.BytesIO(content))


def test_symlink_boundary():
    with tempfile.TemporaryDirectory() as workdir:
        tar_path = os.path.join(workdir, "arc001.tar")
        extract_dir = os.path.join(workdir, "output")
        os.makedirs(extract_dir)

        make_symlink_escape_tar(tar_path)

        escaped = False
        try:
            with tarfile.open(tar_path) as tar:
                tar.extractall(extract_dir)

            # Check if anything landed outside extract_dir
            for root, dirs, files in os.walk(workdir):
                if root == extract_dir or root.startswith(extract_dir + os.sep):
                    continue
                if any(f == "arc001.txt" for f in files):
                    escaped = True
        except (tarfile.ExtractError, PermissionError, OSError):
            pass  # Correctly refused

        return escaped


if __name__ == "__main__":
    if test_symlink_boundary():
        print("POSITIVE: Symlink escape succeeded — invariant 1b violated")
    else:
        print("NEGATIVE: Symlink escape correctly blocked")