# /cpython-security-toolkit:reproduce

Generate, minimize, and validate a reproducer for a specific finding ID.

## Usage

```
/cpython-security-toolkit:reproduce <finding-id> [cpython-path]
```

**Arguments:**

- `finding-id` — the finding ID from a previous scan (e.g., `ARC-001-2026`, `PRO-003-2026`)
- `cpython-path` — path to a CPython build directory (for dynamic tests). Optional for static-only findings.

## What this command does

### Step 1 — Load the finding

Read the finding record from the most recent scan output. If the finding ID is not in the current session, ask the user to paste the finding block.

### Step 2 — Generate a candidate reproducer

Based on the finding's sub-invariant class, generate a minimal Python script:

**For archive findings (ARC-*):**
- Generate a crafted archive (tar, zip) containing the entry that demonstrates the path violation
- Write a Python script that extracts the archive to a temp directory and checks whether the output path is within the destination

**For protocol findings (PRO-*):**
- Generate a Python script that exercises the uncovered code path (e.g., `Morsel.update()` with a control character value)
- Check whether the validation that should fire actually fires on this path

**For resource findings (RES-*):**
- Generate a crafted input (archive, plist, cookie string) that exercises the amplification path
- For decompression: generate a highly-compressed input and measure peak allocation before the bound is applied
- Include a `--dry-run` mode for CI use that checks the code path without materializing large allocations

**For audit findings (AUD-*):**
- Generate a Python script that exercises the alternative code path (e.g., `SourcelessFileLoader` loading a `.pyc`)
- Register a `sys.audit()` hook that records all events
- Check whether the expected event fires

### Step 3 — Validate the reproducer

Run the reproducer script and confirm:
- The behavior described in the finding is observed
- The violated invariant is demonstrably not satisfied
- The reproducer is self-contained (no external dependencies)

### Step 4 — Minimize the reproducer

Attempt to reduce the reproducer to the shortest script that still demonstrates the behavior:
- Remove unnecessary setup
- Reduce crafted input to minimum size
- Remove assertions that don't directly test the invariant

### Step 5 — Output

```
Finding ID:         <id>
Reproducer status:  CONFIRMED | NOT-REPRODUCED | ENVIRONMENT-DEPENDENT
Confidence update:  <new classification after confirmation>

Reproducer (validated):
---
<minimal Python script>
---

To run:
  python3 reproducer_<id>.py

Notes:
  <any environment requirements — CPython version, OS, etc.>

Next step:
  <updated action based on confirmed or not-confirmed status>
```

If NOT-REPRODUCED:
- The finding is reclassified to `FALSE-POSITIVE` or `SECURITY-CANDIDATE (unconfirmed)`
- The user is instructed not to report it externally
- The false-positive is logged to help improve engine precision

## Reproducer output files

Reproducers are written to `./reproductions/<finding-id>/`:
- `reproducer.py` — the validated Python script
- `input/` — any crafted input files (archives, cookies, etc.)
- `notes.txt` — environment requirements and run instructions
