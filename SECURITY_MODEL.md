# Security Model

This document defines the security invariants this toolkit enforces — what each one means, why it matters, and which historical bugs demonstrate it.

A security invariant is a property of correct behavior that, if violated, constitutes a security defect. These are not heuristics or patterns. They are statements about what the code must guarantee. The toolkit checks whether CPython's stdlib meets each one.

---

## Invariant 1: Extraction Boundary

**Statement:** No archive extraction path may write a file outside the declared destination directory, regardless of path components in the archive entry, symlink or hardlink targets contained in the entry, or OS-specific path normalization applied during extraction.

**Sub-invariants:**

- 1a. All write paths in `tarfile`, `zipfile`, and `shutil.unpack_archive` must check the final, fully-resolved output path against the destination boundary before writing.
- 1b. Symlink and hardlink targets must be resolved fully before destination validation is applied. Validation of the pre-resolution path is insufficient.
- 1c. OS-specific path forms (Windows drive letters `C:\`, UNC paths `\\server\share`, alternate data streams) must not be usable to produce a write outside the destination.
- 1d. Archive format implementations (tar, zip, pax) must behave identically with respect to the destination boundary. A parser differential that affects the security boundary is a violation.

**Historical violations:** ARC-001 through ARC-009 (see CORPUS.md). Five CVEs from a single gh issue in 2025; a sixth in 2026.

**Why this invariant is hard to express as a pattern:** The bug is not a dangerous function call. It is the relationship between when path resolution happens and when destination checking happens. A static scanner looking for `tarfile.extractall()` cannot distinguish a safe call from an unsafe one without modeling the resolution ordering.

---

## Invariant 2: Validation Coverage

**Statement:** All code paths that accept, store, or output a security-sensitive value must apply the same input validation as the primary path. A security fix that patches one path but leaves others uncovered is an incomplete fix and a security defect.

**Sub-invariants:**

- 2a. When a character-set or format constraint is applied to a value at one assignment site, all other assignment sites for the same value type in the same security context must apply the same constraint.
- 2b. URL validation must occur after all template substitution that could transform the URL, not before. Validation before `%action` substitution, `format()`, or similar operations is insufficient.
- 2c. Control characters (CR, LF, NUL, and other characters with special semantics in HTTP) must be rejected on all paths that insert a value into an HTTP header, cookie, or WSGI header — not only on the most common path.
- 2d. Unpickling, `update()`, operator overloads (`|=`, `+=`), and `__reduce__` are assignment paths and must be treated as such in security validation logic.

**Historical violations:** PRO-001/PRO-002 (http.cookies incomplete fix), PRO-005/PRO-006 (webbrowser.open() incomplete fix).

**Why this invariant is hard to express as a pattern:** The bug is coverage — which paths exist, and which of them validate. A pattern scanner can find where validation is applied; it cannot enumerate all paths that should validate but don't. Invariant 2 requires path enumeration followed by coverage analysis.

---

## Invariant 3: Resource Amplification Bound

**Statement:** Decompression of attacker-controlled data must not produce output unboundedly larger than a configurable safe limit before the implementation raises an error or applies a cap. Allocation sizes must not be directly controlled by attacker-supplied fields without an enforced upper bound.

**Sub-invariants:**

- 3a. Decompression paths (LZMA, bzip2, Zstandard, zlib, gzip) must not fully materialize the output before applying a size check. The check must be applied before or during decompression, not after.
- 3b. Archive metadata fields (dictionary size, allocation size, entry size) read from untrusted input must have an enforced upper bound before being used for allocation.
- 3c. Offset and size fields read from untrusted archive entries must be validated as non-negative before use in loop conditions or arithmetic.
- 3d. Operations on attacker-controlled strings (parsing, matching, formatting) must not exhibit super-linear worst-case complexity without explicit documentation and mitigations.

**Historical violations:** RES-001 through RES-008 (see CORPUS.md).

**Why this invariant is hard to express as a pattern:** The bug is timing — when does the bound get applied relative to when the work is done? A scanner can find decompression calls; it cannot determine without semantic modeling whether the bound is applied before or after the expensive operation.

---

## Invariant 4: Audit Hook Coverage

**Statement:** Any code path that reads and executes file content must emit the appropriate `sys.audit()` event via `io.open_code()`. No security control that depends on audit hook events may be bypassable by using an alternative code path that omits the event.

**Sub-invariants:**

- 4a. Any path that loads Python bytecode (`.py`, `.pyc`, `.pyo`) must use the code-opening policy (`io.open_code()` / the corresponding import machinery) where an audit hook must observe code loading. A generic `open` audit event is not treated as equivalent to the dedicated code-loading policy.
- 4b. Shell-calling paths (`subprocess`, `os.system`, `webbrowser`, `os.popen`) that accept input derived from untrusted sources must validate that input at the point closest to shell invocation, after all transformation and substitution.
- 4c. The `sys.audit()` event for `webbrowser.open` must receive the final URL — the URL as it will be passed to the browser — not the URL before template substitution.

**Historical violations:** AUD-001 (`.pyc` loading bypasses `sys.audit`), AUD-002/AUD-003 (`webbrowser.open()` command injection pair).

---

## The Incomplete Fix Pattern

The incomplete-fix pattern deserves special treatment because it has produced two separate CVE pairs in 2026 alone (PRO-001/PRO-002 and AUD-002/AUD-003).

The pattern:

1. A security fix is applied to the most obvious code path.
2. Other paths that exercise the same invariant are not patched.
3. An attacker discovers the uncovered path and the bypass is filed as a new CVE.

The toolkit models this explicitly in the `incomplete-fix-detector` agent. For any security fix in the CPython commit history tagged `type-security` or associated with a CVE, the agent enumerates all code paths that touch the same invariant and checks whether the fix was applied consistently.

This is the most operationally important thing this toolkit does that no other tool does.

---

## Out of Scope

This toolkit does **not** enforce:

- C-level correctness invariants (refcounting, null safety, error paths) — covered by cpython-review-toolkit
- Free-threading safety invariants (GIL assumptions, races) — covered by ft-review-toolkit
- C extension API invariants (borrowed refs, type slots) — covered by cext-review-toolkit
- Supply chain / packaging security
- Application-level security of code that uses CPython's stdlib
- Cryptographic algorithm selection or cipher strength
