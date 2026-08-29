# Changelog

## [0.1.0] — 2026-08-29

Initial release.

### Added

**Security engines (Phase 1)**
- `archive-security` engine: `scan_traversal.py` — checks write paths in `tarfile`, `zipfile`, and `shutil.unpack_archive` for destination boundary violations (sub-invariants 1a and 1b)
- `protocol-security` engine: `scan_validation_coverage.py` — checks all assignment paths for a security-sensitive value type against the validation applied on the primary path (sub-invariant 2a)
- `resource-security` engine: `scan_decompression_bounds.py` — checks for unbounded decompression and attacker-controlled allocation sizes (sub-invariants 3a and 3b)
- `audit-security` engine: `scan_audit_hooks.py` — checks for `open()` used instead of `io.open_code()` and validate-before-substitute ordering (sub-invariants 4a and 4b)

**Reproducer engine**
- `reproducer_engine.py` — generates, validates, and minimizes reproducers for findings
- Templates for sub-invariants 1b (symlink traversal), 2a (Morsel.update bypass), 3a (decompression dry-run), 4a (audit hook comparison)

**Commands**
- `/cpython-security-toolkit:scan` — full scan, all four engines
- `/cpython-security-toolkit:archive` — archive engine only
- `/cpython-security-toolkit:protocol` — protocol engine only
- `/cpython-security-toolkit:resource` — resource engine only
- `/cpython-security-toolkit:audit` — audit engine only
- `/cpython-security-toolkit:reproduce` — reproducer generation

**Corpus**
- `CORPUS.md` — full historical CVE catalogue (ARC-001–009, PRO-001–008, RES-001–008, AUD-001–004)
- Positive fixture: `arc_005_realpath_overflow.py` (CVE-2025-4517 class)
- Positive fixture: `pro_002_morsel_update_bypass.py` (CVE-2026-3644 class)

**Documentation**
- `SECURITY_MODEL.md` — four named security invariants with rationale
- `WORKING_WITH_MAINTAINERS.md` — CPython security disclosure process
- `cpython-security-toolkit-design.md` — architecture and implementation notes
- `CLAUDE.md` — Claude Code agent instructions

**Tests**
- `test_corpus_regression.py` — regression suite covering all four engines and reproducer templates
