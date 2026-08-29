# /cpython-security-toolkit:scan

Full security scan of a CPython source tree using all four engines.

## Usage

```
/cpython-security-toolkit:scan [path] [engines] [options]
```

**Arguments:**

- `path` — path to a CPython source clone. Defaults to current directory.
- `engines` — space-separated list: `archive protocol resource audit all`. Defaults to `all`.
- `options`:
  - `reproduce` — attempt reproducer generation for every finding (slower, recommended before any report)
  - `corpus` — run corpus regression check before scanning (recommended)
  - `deep` — run multi-pass analysis (2-naive + 1-informed methodology)

## Examples

```
/cpython-security-toolkit:scan                          # Scan current dir, all engines
/cpython-security-toolkit:scan ~/cpython all reproduce  # Full scan with reproducers
/cpython-security-toolkit:scan ~/cpython archive deep   # Deep archive engine only
/cpython-security-toolkit:scan ~/cpython protocol corpus # Protocol engine + corpus check
```

## What this command does

### Phase 0 — Preflight

1. Confirm the path is a CPython source tree (check for `Lib/`, `Modules/`, `Python/`)
2. Identify the CPython version from `Misc/NEWS` or `Include/patchlevel.h`
3. If `corpus` option: run `tests/test_corpus_regression.py` to confirm existing known-good fixes are still present
4. Load `SECURITY_MODEL.md` invariants
5. Load `CORPUS.md` for reference anchors

### Phase 1 — Engine dispatch

For each requested engine, dispatch the relevant agents against `Lib/`:

**archive-security agents:** traversal-detector, symlink-detector, path-normalizer, differential-tester

**protocol-security agents:** validation-coverage, incomplete-fix-detector, substitution-ordering, header-injection

**resource-security agents:** decompression-bounds, memory-amplification, cpu-complexity, negative-offset

**audit-security agents:** hook-coverage, open-code-usage, command-injection

### Phase 2 — Reproducer pass (if `reproduce` option)

For each candidate finding, attempt reproducer generation:
1. Generate a minimal Python script that demonstrates the invariant violation
2. Validate: run the script and confirm the behavior matches the finding
3. If confirmed → classify as SECURITY or HARDENING
4. If not confirmed → classify as SECURITY-CANDIDATE with note

### Phase 3 — Synthesis

1. Deduplicate findings across agents (same location, same invariant)
2. Classify each finding per the taxonomy in CLAUDE.md
3. Sort by: CORPUS-REGRESSION > SECURITY (with reproducer) > SECURITY-CANDIDATE > HARDENING
4. Produce the consolidated report

### Phase 4 — Report

Output the structured report. For every SECURITY or CORPUS-REGRESSION finding:
- Print the full finding block (all required fields)
- Print the next-step action
- Remind the user: **route to security@python.org after pre-triage, not the public tracker**

## Cost and time expectations

| Scope | Engines | Reproduce? | Approximate time | Approximate cost |
|---|---|---|---|---|
| One module | One engine | No | 5–10 min | Low |
| `Lib/` subset | One engine | No | 15–30 min | Moderate |
| Full `Lib/` | All engines | No | 45–90 min | High |
| Full `Lib/` | All engines | Yes | 90–180 min | Very high |

The `reproduce` option significantly increases cost. Use it only when you intend to report findings externally.

## After the scan

Before doing anything with findings:

1. Read `WORKING_WITH_MAINTAINERS.md`
2. Pre-triage any SECURITY findings with a trusted CPython developer (devdanzin is a good contact)
3. Run reproducers yourself and confirm the behavior
4. Then — and only then — consider contacting `security@python.org`
