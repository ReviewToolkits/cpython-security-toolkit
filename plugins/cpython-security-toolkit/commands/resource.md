# /cpython-security-toolkit:resource

Resource amplification analysis. Checks whether CPython's decompression, parsing, and processing modules correctly bound output size and algorithmic complexity when processing attacker-controlled input.

## Usage

```
/cpython-security-toolkit:resource [path] [options]
```

**Arguments:**

- `path` — path to CPython source. Defaults to current directory.
- `options`:
  - `reproduce` — generate and validate reproducers (requires a CPython build for decompression tests)
  - `corpus` — check RES-001 through RES-008 corpus cases
  - `fuzz` — generate crafted inputs for dynamic decompression bound testing

## What this command checks

**decompression-bounds**

Analyzes decompression paths in `zipfile`, `tarfile`, `lzma`, `bz2`, `gzip`, `zlib`, and `plistlib`:

1. Locate calls to decompressor `.read()`, `.decompress()`, or `.readall()` methods
2. Determine whether a size limit is applied before or after full decompression
3. Check whether the limit is enforced during decompression (via `max_length` parameter or chunked reading) or only after (by truncating the result)
4. Flag paths where the full decompressed output is materialized in memory before any size check

The key distinction: `decompressor.read(max_bytes)` is safe; `decompressor.read()[:max_bytes]` is not — the latter allocates unbounded memory before the check.

**memory-amplification**

Analyzes archive parsing in `tarfile`, `zipfile`, `lzma`, and `plistlib`:

1. Find fields read from archive metadata (dictionary size, entry size, allocation count)
2. Trace these fields to allocation calls (`bytes()`, `bytearray()`, `list * n`, `b"\x00" * n`)
3. Check whether an upper bound is applied between the read and the allocation
4. Flag allocations where the size is directly controlled by an untrusted input field

**cpu-complexity**

Analyzes string processing, regex matching, and nested iteration on attacker-controlled input:

1. Find operations on values that could be attacker-controlled (header values, archive entries, cookie strings, email content)
2. Identify operations with super-linear worst-case complexity:
   - Nested loops over the same string
   - Backtracking regex on untrusted input
   - Quadratic string concatenation in a loop
   - Repeated `str.find()` or `str.index()` in a loop
3. Flag cases where the complexity class is super-linear and the input length is attacker-controlled

Primary targets: `email` module (gh-136063: quadratic parsing), `http.cookies` (gh-123067: quadratic quoted-value parsing).

**negative-offset**

Analyzes archive parsing paths in `tarfile` and `zipfile`:

1. Find integer fields read from archive metadata (offsets, sizes, counts)
2. Trace these fields to arithmetic, indexing, or loop conditions
3. Check whether non-negative validation is applied before use
4. Flag cases where a negative value from the archive could cause an infinite loop or incorrect arithmetic

Primary target: CVE-2025-8194 (tarfile infinite loop from negative block count).

## Finding format

```
Finding ID:        RES-<NNN>-<year>
Confidence:        SECURITY | SECURITY-CANDIDATE | HARDENING
Invariant:         [exact text from SECURITY_MODEL.md Invariant 3]
Sub-invariant:     3a | 3b | 3c | 3d
Location:          Lib/<module>.py line <N>, function <name>
Evidence:          <what the agent observed>
Amplification:     <for decompression: estimated ratio before bound is applied>
Reproducer:        <runnable Python script or crafted input file>
Reproducer status: CONFIRMED | UNCONFIRMED | PENDING
CVE reference:     <if applicable>
Next step:         <action>
```

## Reproducer note

Decompression-bound reproducers require a CPython build to run (they produce large allocations). For CI use, the reproducer scripts include a `--dry-run` mode that checks the path without materializing the output.

## Corpus anchors

RES-001 through RES-008 (see CORPUS.md).
