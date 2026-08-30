# /cpython-security-toolkit:archive

Archive extraction boundary analysis. Checks whether CPython's `tarfile`, `zipfile`, and `shutil.unpack_archive` implementations correctly enforce the invariant that no extraction path may write outside the declared destination directory.

## Usage

```
/cpython-security-toolkit:archive [path] [options]
```

**Arguments:**

- `path` — path to CPython source. Defaults to current directory.
- `options`:
  - `reproduce` — generate and validate reproducers for each finding
  - `corpus` — check ARC-001 through ARC-009 corpus cases first
  - `deep` — run differential testing across tar/zip/pax parsers

## What this command checks

**traversal-detector**

Traces all write paths in `tarfile.TarFile.extractall()`, `tarfile.TarFile.extract()`, `zipfile.ZipFile.extractall()`, `zipfile.ZipFile.extract()`, and `shutil.unpack_archive()` to determine whether a destination-boundary check is applied to the final, fully-resolved output path before any file write.

Specifically checks:
- Is `os.path.realpath()` called on the resolved path or the pre-resolution path?
- Is the realpath result compared against the destination directory before the write?
- Are filter functions applied before or after symlink resolution?
- Is the boundary check applied to every write path, or only the common path?

**symlink-detector**

Checks whether symlink and hardlink targets in archive entries are fully resolved against the current extraction state before the destination-boundary check is applied. The pattern that caused CVE-2025-4330 (symlink validated against the stated target, not the resolved target) is a primary detection target.

**path-normalizer**

Checks OS-specific path normalization edge cases:
- Windows drive letter prefixes (`C:\`, `C:/`) in archive paths
- UNC path prefixes (`\\server\share`) in archive paths
- Alternate data stream notation (`:stream`) in archive paths
- Null bytes or other control characters in path components

**differential-tester**

Extracts semantically identical archives in `tar`, `zip`, and `pax` formats and compares extraction paths. A path that extracts to location A under `tarfile` but location B under `zipfile` for the same logical entry name is a parser differential that may represent a security boundary difference.

## Finding format

Each finding includes:

```
Finding ID:        ARC-<NNN>-<year>
Confidence:        SECURITY | SECURITY-CANDIDATE | HARDENING
Invariant:         [exact text from SECURITY_MODEL.md Invariant 1]
Sub-invariant:     1a | 1b | 1c | 1d
Location:          Lib/<module>.py line <N>, function <name>
Evidence:          <what the agent observed>
Reproducer:        <runnable Python script>
Reproducer status: CONFIRMED | UNCONFIRMED | PENDING
CVE reference:     <if applicable>
Next step:         <action>
```

## Corpus anchors for this engine

ARC-001 through ARC-009 (see CORPUS.md). The engine must re-detect the invariant class demonstrated by each corpus entry. Run with `corpus` option to confirm regression prevention.

## Runtime differential gate

Static archive findings should be followed by the safe differential harness:

```
python3 plugins/cpython-security-toolkit/scripts/differential_archive.py --json
```

For Windows-specific path cases, run the equivalent corpus on Windows. A POSIX
result cannot prove Windows drive-letter or UNC safety.
