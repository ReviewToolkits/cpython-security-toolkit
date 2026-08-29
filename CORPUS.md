# Historical Vulnerability Corpus

This document is the foundation of cpython-security-toolkit. Every security engine is built from a real confirmed CPython security bug in this corpus. The corpus serves three purposes:

1. **Invariant derivation** — each bug class produces a named, testable security invariant
2. **Engine validation** — "can the engine automatically re-detect this?" is the benchmark
3. **Regression prevention** — if a fix is reverted or bypassed, the corpus catches it

All entries are confirmed bugs — CVEs, GHSAs, or issues with `type-security` label. No theoretical cases.

---

## Domain A: Archive / Path Security

These bugs share the violated invariant: *no archive extraction path may write a file outside the declared destination directory, regardless of path components, symlink targets, hardlink sources, or OS-specific normalization in the archive entry.*

| ID | CVE / Issue | Module | Summary | Invariant violated |
|---|---|---|---|---|
| ARC-001 | CVE-2024-12718 | tarfile | Extraction filter bypass via crafted symlinks | Symlink targets not validated after resolution |
| ARC-002 | CVE-2025-4138 | tarfile | Filter bypass — cluster with ARC-001 | Same |
| ARC-003 | CVE-2025-4330 | tarfile | Symlink targets not normalized before extraction | Path normalization applied before resolution |
| ARC-004 | CVE-2025-4435 | tarfile | Hard link emulation without destination check | Hardlink targets not checked against destination |
| ARC-005 | CVE-2025-4517 | tarfile | realpath overflow → arbitrary write outside destination | Destination check applied to pre-resolution path |
| ARC-006 | CVE-2025-8194 | tarfile | Infinite loop from negative offsets in archive entries | Offset fields not validated for non-negative before loop use |
| ARC-007 | CVE-2026-7774 | tarfile | Path traversal bypass (post-cluster, 2026) | Filter bypass regression — same invariant as ARC-001–005 |
| ARC-008 | (unnumbered) | shutil | `unpack_archive()` absolute Windows path with drive letter extracts outside target | OS-specific path normalization bypasses destination check |
| ARC-009 | (unnumbered) | zipfile | ZIP64 EOCD Locator offset not validated — differential behavior with other implementations | Parser differential exposes security boundary difference |

**ARC-001 through ARC-007 note:** Five of these (ARC-001–ARC-005) originated from a single CPython issue (gh-135034), representing five code paths through the same logical boundary check. ARC-007 appeared in 2026 after all five were fixed — demonstrating that patch coverage is not the same as invariant coverage.

---

## Domain B: Protocol / Validation Coverage

These bugs share the violated invariant: *all code paths that accept, store, or output a security-sensitive value must apply the same validation as the primary path. A security fix that patches one path but not others is incomplete by definition.*

| ID | CVE / Issue | Module | Summary | Invariant violated |
|---|---|---|---|---|
| PRO-001 | CVE-2026-0672 | http.cookies | Control characters in `Morsel` values enable header injection via `__setitem__` | Missing character validation on primary assignment path |
| PRO-002 | CVE-2026-3644 | http.cookies | **Incomplete fix for PRO-001** — `update()`, `\|=`, and unpickling not patched | Fix covered `__setitem__` but not all assignment paths |
| PRO-003 | CVE-2026-0865 | wsgiref | `Headers` class allows header newline injection | Missing newline validation in WSGI header values |
| PRO-004 | CVE-2026-1502 | http.client | HTTP header injection via CR/LF in proxy tunnel headers | Control characters accepted in proxy CONNECT headers |
| PRO-005 | CVE-2026-4519 | webbrowser | URLs with leading dashes passed as CLI flags to browser | URL validation applied before shell execution |
| PRO-006 | CVE-2026-4786 | webbrowser | **Incomplete fix for PRO-005** — `%action` substitution bypasses mitigation | Validation before substitution, not after |
| PRO-007 | (type-security) | http.cookies | Additional validation gaps identified in follow-up audit | Validation not applied to `BaseCookie.js_output()` |
| PRO-008 | (type-security) | urllib | URL parsing behavioral differences between `urllib.parse` and `http.client` | Parser differential creates security inconsistency |

**PRO-002 and PRO-006 are the key corpus anchors for the incomplete-fix engine.** Both represent cases where a security fix was applied to the most obvious code path but missed other paths through the same invariant. The incomplete-fix-detector agent is specifically built to prevent this pattern from repeating.

---

## Domain C: Resource Amplification

These bugs share the violated invariant: *decompression of attacker-controlled data must not produce output unboundedly larger than a safe limit before an error is raised or a cap is applied. Allocation sizes must not be directly controlled by attacker-supplied fields without an enforced upper bound.*

| ID | CVE / Issue | Module | Summary | Invariant violated |
|---|---|---|---|---|
| RES-001 | CVE-2025-8194 | tarfile | Infinite loop from negative offsets in archive entries | Offset fields used in loop conditions without non-negative check |
| RES-002 | CVE-2026-6100 | Multiple | Use-after-free or information disclosure via decompression modules | Decompressor state not properly bounded |
| RES-003 | CVE-2026-3276 | unicodedata | Excessive CPU in `normalize()` on crafted input | Algorithmic complexity not bounded on attacker input |
| RES-004 | (unnumbered) | plistlib | Module reads allocation sizes directly from the plist file — attacker-controlled OOM | Allocation size directly controlled by untrusted input field |
| RES-005 | (unnumbered) | zipfile | bzip2/LZMA/Zstandard ZIP members decompressed without bound before clip is applied | Decompression output fully materialized before size check |
| RES-006 | (unnumbered) | zipfile | LZMA dictionary size field read from archive metadata — multi-GB allocation | Attacker controls allocation size directly |
| RES-007 | gh-136063 | email | Quadratic complexity in email header parsing | Algorithmic complexity on attacker-controlled input |
| RES-008 | gh-123067 | http.cookies | Quadratic complexity in quoted cookie value parsing | Algorithmic complexity on attacker-controlled input |

---

## Domain D: Audit / Security Control Bypass

These bugs share the violated invariant: *any code path that reads and executes file content must emit the appropriate `sys.audit()` event via `io.open_code()`. Security controls that depend on audit hooks must not be bypassable by using an alternative code path.*

| ID | CVE / Issue | Module | Summary | Invariant violated |
|---|---|---|---|---|
| AUD-001 | CVE-2026-2297 | importlib | `SourcelessFileLoader` uses `open()` not `io.open_code()` for .pyc files — `sys.audit` hook does not fire | Audit event not emitted on alternative file-loading path |
| AUD-002 | CVE-2026-4519 | webbrowser | `webbrowser.open()` accepts URLs with leading dashes → CLI flag injection into browser | Shell-calling path with insufficiently validated untrusted input |
| AUD-003 | CVE-2026-4786 | webbrowser | **Incomplete fix for AUD-002** — `%action` substitution bypasses the mitigation | Validation before substitution, not after shell arg construction |
| AUD-004 | (type-security) | venv | Path names in venv activation scripts not quoted — attacker-controlled venv can inject commands | Shell-calling path with unsanitized path input |

---

## Corpus Maintenance

### Adding new entries

When a new CPython security bug is confirmed (CVE issued or GHSA published), add it here:

1. Assign a domain prefix (ARC / PRO / RES / AUD) and sequential number
2. State the violated invariant precisely in the table
3. Add a minimal reproducer to the appropriate `corpus/<domain>/positive/` directory
4. Add a negative fixture (correct implementation) to `corpus/<domain>/negative/`
5. Update the relevant engine to detect this class

### `type-security` issues

CPython uses the `type-security` label for security-relevant issues that did not receive a formal CVE. These are included in the corpus because they represent real invariant violations that the toolkit should detect, regardless of whether a CVE was assigned. Search the CPython issue tracker at:

```
https://github.com/python/cpython/issues?q=label%3Atype-security
```

### Regression corpus usage

The test suite at `tests/test_corpus_regression.py` runs all engines against the corpus fixtures. Every positive fixture must be detected; every negative fixture must pass clean. This is run before any engine change is committed.
