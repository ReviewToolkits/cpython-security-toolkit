# Contributing to cpython-security-toolkit

Thanks for your interest. Because this toolkit is designed to find **security vulnerabilities** in CPython's standard library, contributing here carries extra responsibilities. Please read this carefully before submitting anything.

---

## What contributions are welcome

- **New corpus entries** — a new CVE or `type-security`-labeled CPython issue that fits one of the four invariant domains. Follow the corpus maintenance procedure in `CORPUS.md`.
- **New or improved scripts** — static analysis scripts in `plugins/cpython-security-toolkit/scripts/` that detect a corpus-anchored invariant class.
- **New reproducer templates** — templates in `reproducer_engine.py` for sub-invariants not yet covered (1a, 1c, 1d, 2b, 2c, 2d, 3b, 3c, 3d, 4b, 4c are still deferred — see design doc).
- **Test coverage** — additional tests in `tests/test_corpus_regression.py`, especially negative fixture tests.
- **Documentation improvements** — README, SECURITY_MODEL.md, CORPUS.md, reproducer-techniques.md.
- **Bug fixes** — correctness issues in existing scripts, false-positive reduction.

## What contributions are NOT welcome here

- **Actual CPython vulnerability reports.** This repo is not a place to disclose CPython security findings. See `WORKING_WITH_MAINTAINERS.md` — findings go to `security@python.org` first.
- **Detectors without a corpus anchor.** Every new detector must be built from a real CVE or confirmed `type-security` issue. Theoretical detection without a confirmed historical case is out of scope.
- **Detectors that duplicate sibling toolkits.** C-level analysis → cpython-review-toolkit. Free-threading → ft-review-toolkit. C extension API → cext-review-toolkit. This toolkit covers only `Lib/`.

---

## Contribution process

1. **Open an issue first** for anything non-trivial (new engine, new corpus domain, significant API change). Describe what you intend to add and which corpus entry anchors it.

2. **Fork and branch.** Use a descriptive branch name: `corpus/arc-010-zip64-eocd`, `script/scan-header-injection`, `fix/negative-offset-guard-heuristic`.

3. **Follow corpus maintenance rules** (from `CORPUS.md`):
   - Assign a domain prefix and sequential number
   - State the violated invariant precisely
   - Add a positive fixture to `corpus/<domain>/positive/`
   - Add a negative fixture to `corpus/<domain>/negative/`
   - Update the relevant engine

4. **All tests must pass.** Run `python3 -m pytest tests/ -v` before submitting. New scripts must have at least a syntax test and a stdlib-run test.

5. **No secrets or credentials** in any file — scripts, fixtures, or documentation.

6. **One corpus entry per PR** for new CVE additions. Batching unrelated entries makes review harder.

---

## Code style

- Python 3.11+. No third-party dependencies (stdlib only) in analysis scripts or corpus fixtures.
- Type hints on public functions.
- Docstrings on all functions and classes.
- Scripts output JSON to stdout; diagnostic messages to stderr.
- Corpus fixtures print `POSITIVE: ...` or `NEGATIVE: ...` on the last line, so automated tests can assert on the prefix.

---

## Security issues in this toolkit itself

If you find a security issue *in the toolkit code itself* (e.g., a path traversal in a reproducer template, command injection in a script argument handler), please report it via GitHub's private vulnerability reporting (Security tab → "Report a vulnerability"), not as a public issue. The toolkit handles untrusted archive data and runs subprocess calls — a bug there could be a real vulnerability.
