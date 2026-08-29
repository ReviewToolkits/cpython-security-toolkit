# cpython-security-toolkit — Design Document

## Overview

cpython-security-toolkit is a Claude Code plugin that finds semantic security vulnerabilities in CPython's Python standard library (`Lib/`). Unlike pattern-based scanners, it models named security invariants and checks whether all code paths in the relevant modules satisfy those invariants.

Every detector is anchored to a confirmed historical CVE or `type-security`-labeled CPython issue. Every finding requires a runnable reproducer before it is classified above `SECURITY-CANDIDATE`.

---

## Architecture

```
.claude/
  CLAUDE.md              ← Instructions for the Claude Code agent
plugins/cpython-security-toolkit/
  commands/              ← Slash command definitions (markdown)
  agents/                ← Agent definitions (inline in commands for now)
  scripts/               ← Analysis scripts run by agents
  corpus/                ← Positive and negative fixtures
SECURITY_MODEL.md        ← Named invariants
CORPUS.md                ← Historical vulnerability catalogue
WORKING_WITH_MAINTAINERS.md  ← Disclosure process
```

---

## The Four Engines

### Engine 1: Archive Security (`/archive`)

**Scripts:** `scan_traversal.py`

**Method:** AST analysis of `tarfile.py`, `zipfile/__init__.py`, `shutil.py`. Walks function bodies to find write calls, path resolution calls, and boundary-check calls. Computes ordering: does resolution happen before or after the boundary check?

**Key detection targets:**
- Write path without any destination boundary check (sub-invariant 1a)
- Boundary check applied to pre-resolution path (sub-invariant 1b) — the CVE-2025-4517 pattern
- OS-specific path forms in archive entries (sub-invariant 1c)
- Parser differential between tar and zip (sub-invariant 1d)

**Limitations:**
- AST analysis cannot follow the call graph across function boundaries
- Cross-function path tracing requires agent reasoning, not just the script
- Windows-specific paths require testing on Windows (the script flags candidates)

---

### Engine 2: Protocol Security (`/protocol`)

**Scripts:** `scan_validation_coverage.py`

**Method:** For each class in `http/cookies.py`, `wsgiref/headers.py`, `urllib/request.py` — enumerate all methods that assign or output a security-sensitive value. Check whether each method calls the known validator functions. Report methods that lack coverage.

**Key detection targets:**
- Assignment methods without validation (sub-invariant 2a) — the CVE-2026-3644 pattern
- Substitution-before-validation ordering (sub-invariant 2b) — the CVE-2026-4786 pattern
- Control chars in header/cookie paths (sub-invariant 2c)
- Pickle/unpickling paths without validation (sub-invariant 2d)

**Limitations:**
- The `KNOWN_VALIDATORS` set must be maintained as CPython adds new validation helpers
- The method-enumeration approach only covers explicit method definitions — dynamically added methods are not detected
- `fixhistory` mode requires git access to the CPython repository

---

### Engine 3: Resource Security (`/resource`)

**Scripts:** `scan_decompression_bounds.py`

**Method:** AST analysis of `zipfile`, `tarfile`, `lzma`, `bz2`, `gzip`, `plistlib`. Finds decompressor `.read()` calls without a size argument. Finds allocation calls where the size comes from an archive metadata attribute.

**Key detection targets:**
- Unbounded `.read()` on a decompressor object (sub-invariant 3a)
- Allocation size from archive metadata (sub-invariant 3b) — the LZMA dict size class
- Negative offset fields in loop conditions (sub-invariant 3c) — the CVE-2025-8194 class
- Super-linear string operations on attacker-controlled input (sub-invariant 3d)

**Limitations:**
- The "looks like a decompressor" heuristic has false positives — not every `.read()` is a decompressor read
- The metadata size pattern requires the attribute name to match `METADATA_SIZE_READS`; dynamic attribute access is not detected
- Algorithmic complexity analysis is heuristic; formal complexity proofs are out of scope

---

### Engine 4: Audit Security (`/audit`)

**Scripts:** `scan_audit_hooks.py`

**Method:** AST analysis of `importlib/_bootstrap_external.py`, `webbrowser.py`, `venv/__init__.py`. Finds `open()` calls on Python files that should use `io.open_code()`. Analyzes call ordering in shell-calling functions for the validate-before-substitute anti-pattern.

**Key detection targets:**
- `open()` instead of `io.open_code()` for Python files (sub-invariant 4a) — CVE-2026-2297 class
- URL validation before `%action` substitution (sub-invariant 4b) — CVE-2026-4786 class
- Shell-calling paths with unsanitized input (sub-invariant 4c)

**Limitations:**
- The "looks like a Python file" heuristic checks for `.py`/`.pyc` in string literals or variable names — it misses files opened by computed path
- Call ordering analysis is intra-function only; cross-function ordering requires agent reasoning

---

## The Reproducer Engine

**Script:** `scripts/reproducer_engine.py`

Each sub-invariant class has a reproducer template. The engine:

1. Selects the template for the finding's sub-invariant
2. Runs the reproducer script in a subprocess with a 30-second timeout
3. Parses the output for confirmation signals ("INVARIANT VIOLATED", "CANDIDATE", "correctly", "REJECTED")
4. Classifies the status as CONFIRMED | NOT_REPRODUCED | UNCONFIRMED
5. Upgrades or downgrades the finding's confidence accordingly

**Reproducer templates:**

| Sub-invariant | Template |
|---|---|
| 1b | Symlink traversal via `tarfile` |
| 2a | `Morsel.update()` control character bypass |
| 3a | Dry-run decompression path analysis |
| 4a | `open()` vs `io.open_code()` audit hook comparison |

Templates for 1a, 1c, 1d, 2b, 2c, 2d, 3b, 3c, 3d, 4b, 4c are deferred to Phase 2.

---

## Classification System

| Tag | Meaning | Action |
|---|---|---|
| `SECURITY` | Violated invariant + confirmed reproducer | `security@python.org` after pre-triage |
| `SECURITY-CANDIDATE` | Likely violation, reproducer not yet confirmed | Pre-triage first |
| `HARDENING` | Security-adjacent, no confirmed exploitable path | Public CPython tracker (`type-security`) |
| `CORPUS-REGRESSION` | Previously fixed CVE class re-detected | `security@python.org` immediately |
| `FALSE-POSITIVE` | Human-confirmed not a real finding | Discard; record to improve engine |

---

## Development Principles

**Evidence first.** Every detector starts from a real CVE. If there is no corpus anchor, the detector is not built.

**Reproducers are non-optional.** A finding without a confirmed reproducer is `SECURITY-CANDIDATE`, not `SECURITY`. The `/reproduce` command is the gate between analysis and reporting.

**Concise output.** Each finding includes exactly the fields in CLAUDE.md. No additional text. Maintainers are busy.

**`type-security` coverage.** CPython issues labeled `type-security` that did not receive CVE numbers are included in the corpus alongside formal CVEs. The toolkit tracks these via CORPUS.md.

---

## Phased Implementation

### Phase 1 (current)
- Archive engine: `scan_traversal.py` (sub-invariants 1a, 1b)
- Protocol engine: `scan_validation_coverage.py` (sub-invariant 2a)
- Resource engine: `scan_decompression_bounds.py` (sub-invariants 3a, 3b)
- Audit engine: `scan_audit_hooks.py` (sub-invariants 4a, 4b)
- Reproducer templates for the above
- Corpus fixtures for ARC-005, PRO-002

### Phase 2
- Archive: symlink detector (1b, fully), path normalizer (1c), differential tester (1d)
- Protocol: incomplete-fix-detector using git history (2b, 2c, 2d)
- Resource: cpu-complexity (3d), negative-offset (3c) as a standalone agent
- Audit: command-injection (4c) standalone agent
- Additional corpus fixtures for all domains

### Phase 3
- Origin / credential security (HTTPS/HTTP credential scope confusion)
- TLS/certificate validation
- Protocol compliance differentials (HTML5, FTP)
- Free-threading security in stdlib paths (complement to ft-review-toolkit)
