# /cpython-security-toolkit:audit

Audit hook coverage analysis. Checks whether CPython's file-loading and shell-calling paths correctly emit `sys.audit()` events and whether security controls depending on those events can be bypassed via alternative code paths.

## Usage

```
/cpython-security-toolkit:audit [path] [options]
```

**Arguments:**

- `path` — path to CPython source. Defaults to current directory.
- `options`:
  - `reproduce` — generate and validate reproducers
  - `corpus` — check AUD-001 through AUD-004 corpus cases

## What this command checks

**hook-coverage**

Locates all code paths in `importlib`, `zipimport`, `pkgutil`, and related modules that read and execute Python source or bytecode:

1. Find `open()`, `builtins.open()`, `os.open()`, and `io.FileIO()` calls on `.py` and `.pyc` files
2. Check whether each is preceded by `io.open_code()` or an explicit `sys.audit("open", ...)` call
3. Flag paths that load executable file content without the appropriate audit event

The invariant: any path that reads Python source or bytecode is a potential security enforcement point for tools that register `sys.audit()` hooks. Using `open()` instead of `io.open_code()` silently bypasses those hooks.

**open-code-usage**

A focused scan for the exact pattern in CVE-2026-2297:

1. Locate all `FileLoader` subclasses in `importlib`
2. Check whether each `get_data()` or equivalent method uses `io.open_code()` for `.pyc` files
3. Flag classes that use `open()` for bytecode loading

**command-injection**

Analyzes shell-calling paths in `webbrowser`, `subprocess`, `os`, `venv`, and adjacent modules:

1. Find paths where a value derived from untrusted input (user-supplied URL, path argument, archive entry name) reaches a shell invocation
2. Check whether:
   - The value is sanitized or validated before the shell call
   - Validation occurs after all template substitution and string formatting
   - The value is passed as a separate argument (safe) rather than interpolated into a shell string (unsafe)
3. Flag paths where the untrusted value reaches the shell without appropriate sanitization, or where sanitization occurs before substitution rather than after

Primary targets:
- `webbrowser` module: URL validation vs `%action` substitution ordering (AUD-002/AUD-003 class)
- `venv` activation script generation: path name quoting (AUD-004 class)

## Finding format

```
Finding ID:        AUD-<NNN>-<year>
Confidence:        SECURITY | SECURITY-CANDIDATE | HARDENING
Invariant:         [exact text from SECURITY_MODEL.md Invariant 4]
Sub-invariant:     4a | 4b | 4c
Location:          Lib/<module>.py line <N>, function <name>
Evidence:          <what the agent observed>
Bypass path:       <the alternative code path that avoids the security control>
Reproducer:        <runnable Python script>
Reproducer status: CONFIRMED | UNCONFIRMED | PENDING
CVE reference:     <if applicable>
Next step:         <action>
```

## Corpus anchors

AUD-001 through AUD-004 (see CORPUS.md).
