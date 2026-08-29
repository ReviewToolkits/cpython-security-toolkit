# /cpython-security-toolkit:protocol

Protocol validation coverage analysis. Checks whether security-sensitive values in CPython's HTTP, cookie, WSGI, and URL handling modules are validated consistently across all code paths — including update methods, operator overloads, unpickling, and template substitution paths.

This engine is specifically designed to detect the incomplete-fix pattern: a security fix applied to one code path that leaves other paths through the same invariant unpatched.

## Usage

```
/cpython-security-toolkit:protocol [path] [options]
```

**Arguments:**

- `path` — path to CPython source. Defaults to current directory.
- `options`:
  - `reproduce` — generate and validate reproducers
  - `corpus` — check PRO-001 through PRO-008 corpus cases
  - `fixhistory` — analyze recent security fix commits for coverage gaps (requires git access)

## What this command checks

**validation-coverage**

For each security-sensitive value type (cookie values, HTTP headers, WSGI headers, URLs), enumerate all code paths that accept or assign the value:

- `__setitem__` / `__set__`
- `update()` and `|=` and `+=`
- `__reduce__` / `__setstate__` (unpickling)
- `__init__` constructors
- `js_output()` and other output methods
- Operator overloads (`|=`, `+=`, `-=`)

For each path, check whether the same character-set or format validation is applied as on the primary path. Paths without validation matching the primary path are candidates.

**incomplete-fix-detector**

Reads CPython's git history for commits with messages containing `security`, `CVE`, `injection`, `traversal`, or `bypass` tags — and also `type-security` labeled issues — within the last 24 months. For each security fix commit:

1. Identify which invariant the fix enforces
2. Enumerate all code paths that should satisfy the same invariant
3. Check whether the fix was applied to all of them
4. Report uncovered paths as HARDENING or SECURITY-CANDIDATE depending on exploitability

This is the engine that would have detected the uncovered `Morsel.update()` path (PRO-002) and the `%action` substitution bypass (PRO-006) before the second CVE was filed.

**substitution-ordering**

For shell-calling paths (`subprocess.run`, `subprocess.Popen`, `os.system`, `os.popen`, `webbrowser._Browser.open`) that use string formatting or template substitution before invoking the shell:

1. Identify the point of URL/command validation
2. Identify the point of template substitution (`%action`, `format()`, `f-string`, `%s`)
3. Check whether validation occurs before or after substitution
4. If validation is before substitution: flag as SECURITY or SECURITY-CANDIDATE (the pattern behind CVE-2026-4786)

**header-injection**

Scans `http/cookies.py`, `http/client.py`, `wsgiref/headers.py`, and adjacent modules for:
- Assignment paths that accept control characters (CR `\r`, LF `\n`, NUL `\x00`) into header or cookie values
- Output paths (`output()`, `js_output()`, `__str__`) that do not sanitize before serializing

## Finding format

```
Finding ID:        PRO-<NNN>-<year>
Confidence:        SECURITY | SECURITY-CANDIDATE | HARDENING
Invariant:         [exact text from SECURITY_MODEL.md Invariant 2]
Sub-invariant:     2a | 2b | 2c | 2d
Location:          Lib/<module>.py line <N>, function <name>
Evidence:          <what the agent observed>
Uncovered paths:   <list of paths that lack the validation applied at the primary path>
Reproducer:        <runnable Python script>
Reproducer status: CONFIRMED | UNCONFIRMED | PENDING
CVE reference:     <if applicable>
Fix commit:        <if this is an incomplete-fix finding, the original fix commit hash>
Next step:         <action>
```

## Corpus anchors for this engine

PRO-001 through PRO-008 (see CORPUS.md). PRO-002 and PRO-006 are the primary targets for the incomplete-fix-detector — these represent the two incomplete-fix CVE pairs from 2026.
