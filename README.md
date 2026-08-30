# CPython Security Toolkit

A [Claude Code](https://docs.anthropic.com/en/docs/claude-code) plugin for finding semantic security flaws in CPython's standard library — the class of bug that generic SAST tools, fuzzers, and sanitizers do not model well.

Built around CPython-specific security invariants: archive extraction boundaries, protocol validation coverage, resource amplification ratios, and audit hook gaps. Every detector is anchored to a confirmed historical CVE; every finding requires a runnable reproducer before it reaches a maintainer.

---

## ⚠️ Read this before you use this toolkit on CPython

This tool finds **security vulnerabilities** in CPython's standard library. Security findings are handled differently from correctness bugs.

- **Read [WORKING_WITH_MAINTAINERS.md](./WORKING_WITH_MAINTAINERS.md).** It is the most important document in this repository.
- **Security findings go to `security@python.org` first** — never the public issue tracker. See the [CPython security policy](https://devguide.python.org/security/policy/).
- **Pre-triage with a trusted CPython developer** before submitting. One private message — "I found something that might be a security issue in `tarfile`, can you take a look?" — takes five minutes and saves everyone time.
- **Never file a finding without a runnable reproducer.** A finding with no reproducer is not a finding. The tool enforces this.
- **Concise and objective** reports only. CPython maintainers are busy. One clear sentence describing the violated invariant is worth more than three paragraphs of analysis.

---

## Why a Separate Tool?

| Concern | cpython-review-toolkit | cpython-security-toolkit |
|---|---|---|
| **Layer** | C source (Modules/, Objects/, Python/) | Python stdlib (Lib/) |
| **Question asked** | "Is this C implementation correct?" | "Does this stdlib behavior violate a security invariant?" |
| **Bug class** | Refcount leaks, null safety, error paths | Archive escapes, validation bypass, resource amplification |
| **Analysis method** | Regex static analysis | Invariant modeling + differential testing + corpus anchoring |
| **Output** | Candidates with false-positive rate | Findings with required runnable reproducers |
| **Disclosure path** | Public issue tracker | `security@python.org` first |

There is also a sibling **[ft-review-toolkit](https://github.com/ReviewToolkits/ft-review-toolkit)** for free-threading safety and **[cext-review-toolkit](https://github.com/ReviewToolkits/cext-review-toolkit)** for C extension API review. This toolkit focuses on the Python-level security semantics of CPython's stdlib — a distinct layer none of the siblings cover.

---

## Installation

### Direct install from GitHub

```
git clone https://github.com/ReviewToolkits/cpython-security-toolkit.git
cd cpython-security-toolkit
claude --plugin-dir plugins/cpython-security-toolkit
```

### Prerequisites

- **Claude Code** installed and running
- **Python 3.11+** (to match the CPython source you are reviewing)
- A local clone of [CPython](https://github.com/python/cpython)

---

## Critical safety gate: compare against baseline

A static scanner can recognize a historical vulnerability shape even after CPython has fixed it. Therefore a scan of a single checkout is **not** evidence that the issue is new. Use the comparison driver when investigating a proposed finding:

```
python3 plugins/cpython-security-toolkit/scripts/scan_compare.py \
  /path/to/baseline-cpython /path/to/target-cpython
```

`NEW` findings are present only in the target tree. `UNCHANGED` findings were already detectable in the baseline and must not be presented as new vulnerabilities. `ANALYSIS-ERROR` means the engine could not analyze a file and must not be interpreted as clean.

## Quick Start

Navigate to a local CPython clone, then:

```
/cpython-security-toolkit:scan              # Full scan — all four engines
/cpython-security-toolkit:archive           # Archive extraction boundary analysis
/cpython-security-toolkit:protocol          # Validation coverage + incomplete-fix detection
/cpython-security-toolkit:resource          # Decompression amplification + algorithmic complexity
/cpython-security-toolkit:audit             # sys.audit() hook coverage gaps
/cpython-security-toolkit:reproduce <id>    # Generate and validate a reproducer for a finding
```

Start with `/scan` for a full overview. Each engine can be run independently.

### Cost and time expectations

A full `/scan` on CPython's `Lib/` directory (around 300 modules) typically runs:

- **30–90 minutes** wall-clock for all four engines
- **Real API cost** — a thorough multi-engine scan with reproducer generation runs across many Claude Code tool calls. Budget accordingly before running on large scopes.
- **Per-engine runs** are significantly cheaper and faster for targeted analysis

---

## What's Included

### Security Engines (4)

| Engine | Invariant | Primary CVE Anchors |
|---|---|---|
| **archive-security** | No extraction path may write outside the destination directory | CVE-2024-12718, CVE-2025-4517, CVE-2026-7774 |
| **protocol-security** | All code paths accepting a security-sensitive value must apply the same validation | CVE-2026-0672, CVE-2026-3644, CVE-2026-4519, CVE-2026-4786 |
| **resource-security** | Decompression output must be bounded before materialization; allocation sizes must not be attacker-controlled | CVE-2025-8194, CVE-2026-6100 |
| **audit-security** | All file-execution paths must emit the appropriate sys.audit() event; no security control may be bypassable via an alternative path | CVE-2026-2297 |

### Agents (per engine)

#### Archive Security
| Agent | What It Finds |
|---|---|
| **traversal-detector** | Write paths in tarfile/zipfile/shutil that lack a destination-boundary check before write |
| **symlink-detector** | Symlink and hardlink targets not fully resolved before destination validation |
| **path-normalizer** | OS-specific path normalization (Windows drive letters, UNC paths) that bypasses destination checking |
| **differential-tester** | Parsing divergences between tar, zip, and pax implementations that affect the security boundary |

#### Protocol Security
| Agent | What It Finds |
|---|---|
| **validation-coverage** | Value types (cookies, headers, URLs) where one assignment path is validated but others are not |
| **incomplete-fix-detector** | Code paths not covered by a security fix — the pattern behind CVE-2026-3644 and CVE-2026-4786 |
| **substitution-ordering** | Validation applied before substitution rather than after — the exact class behind CVE-2026-4786 |
| **header-injection** | Control characters accepted in HTTP headers, cookies, or WSGI header values |

#### Resource Security
| Agent | What It Finds |
|---|---|
| **decompression-bounds** | Decompression paths where output is fully materialized before any size check |
| **memory-amplification** | Allocation sizes read directly from attacker-supplied archive metadata without an upper bound |
| **cpu-complexity** | Algorithmic complexity regressions on attacker-controlled input (quadratic, cubic) |
| **negative-offset** | Offset and size fields used in loop conditions without negative-value validation |

#### Audit Security
| Agent | What It Finds |
|---|---|
| **hook-coverage** | File-read or code-execution paths that do not emit a sys.audit() event |
| **open-code-usage** | Paths loading .py or .pyc files using open() instead of io.open_code() |
| **command-injection** | Shell-calling paths (subprocess, os.system, webbrowser) with insufficiently validated untrusted input |

### Commands

| Command | Purpose | Engines Used |
|---|---|---|
| `scan` | Full security scan with all engines and optional reproducer pass | All four |
| `archive` | Archive extraction boundary analysis | archive-security |
| `protocol` | Validation coverage and incomplete-fix detection | protocol-security |
| `resource` | Decompression and complexity analysis | resource-security |
| `audit` | sys.audit() hook coverage gaps | audit-security |
| `reproduce` | Generate and validate a reproducer for a specific finding ID | — |

---

## How It Works

### The Security Invariant Model

Generic tools follow:

```
Source code → pattern / AST / dataflow → warning
```

This toolkit follows:

```
CPython source
       +
Named security invariant
       +
Historical CVE corpus (confirmed violations)
       ↓
Invariant coverage check across all code paths
       ↓
Differential test or reproducer generation
       ↓
Validated finding with violated invariant stated explicitly
```

The key distinction: a finding is not "this function looks suspicious." It is: "the invariant *all Morsel assignment paths must validate the same character set* is violated because `update()` and `|=` are not covered — matching the incomplete-fix pattern in CVE-2026-3644."

### The Corpus Anchor Principle

Every detector is built from a confirmed CPython security bug. Before any engine code is written:

1. Real CVE or confirmed security issue
2. Named invariant (precise, testable statement)
3. Minimal reproducer (smallest input that demonstrates the violation)
4. Analyzability classification (static / dynamic / differential / specification)

This means the toolkit can answer: "can it automatically re-detect the bugs that humans already confirmed?" That is the validation benchmark, not a synthetic test suite.

### The Reproducer Requirement

A finding with no runnable reproducer is treated as `UNCONFIRMED` and is never surfaced at `HIGH` confidence. The `/reproduce` command generates, minimizes, and validates reproducers for each finding before they are reported. This is the single most important design constraint — it is what separates findings that help maintainers from findings that burden them.

### Classification

| Tag | Meaning | Disclosure path |
|---|---|---|
| **SECURITY** | Violated security invariant with confirmed reproducer | `security@python.org` → PSRT → CVE |
| **SECURITY-CANDIDATE** | Likely security violation, reproducer pending human confirmation | Pre-triage with trusted CPython developer first |
| **HARDENING** | Security-adjacent: missing defense-in-depth, incomplete fix coverage, latent risk | Public issue tracker after triage |
| **CORPUS-REGRESSION** | A previously-fixed CVE class appears to have regressed | `security@python.org` immediately |
| **FALSE-POSITIVE** | Engine fired; human review determined not a real finding | Discarded; used to improve engine precision |

### `type-security` Issue Tracking

This toolkit also tracks CPython issues and PRs tagged `type-security`. Some security-relevant bugs in this category did not receive CVE numbers but are part of the same security invariant domains. The corpus includes these alongside formal CVEs.

---

## The Historical Vulnerability Corpus

See [CORPUS.md](./CORPUS.md) for the full catalogue. The initial corpus covers confirmed CPython security bugs across four domains:

**Archive / path traversal:** CVE-2024-12718, CVE-2025-4138, CVE-2025-4330, CVE-2025-4435, CVE-2025-4517, CVE-2025-8194, CVE-2026-7774, plus the `shutil.unpack_archive()` Windows drive-letter case and the zipfile ZIP64 EOCD differential.

**Protocol / validation bypass:** CVE-2026-0672, CVE-2026-3644 (incomplete fix), CVE-2026-0865, CVE-2026-1502, CVE-2026-4519, CVE-2026-4786 (incomplete fix), plus several `type-security` tagged issues without CVE numbers.

**Resource amplification:** CVE-2025-8194, CVE-2026-6100, CVE-2026-3276, plus the plistlib OOM and unbounded zipfile/LZMA decompression cases.

**Audit / security control bypass:** CVE-2026-2297 (`.pyc` loading via `SourcelessFileLoader` bypasses `sys.audit`), CVE-2026-4519, CVE-2026-4786.

---

## Limitations

- **This is not a comprehensive security audit.** It finds the specific class of semantic invariant violation the engines are built to detect. Other security bug classes exist and are out of scope.
- **Reproducers require a CPython build.** Some findings (especially decompression bounds) require running the reproducer against a CPython build, not just against the source.
- **The engines have false positives.** Agent confidence is not a substitute for human review. Every finding must pass operator triage before reaching any external party.
- **Scope is CPython's stdlib (Lib/).** The C runtime (Modules/, Objects/, Python/) is covered by cpython-review-toolkit, not this toolkit.

---

## Documentation

| File | Purpose |
|---|---|
| **[WORKING_WITH_MAINTAINERS.md](./WORKING_WITH_MAINTAINERS.md)** | **The security disclosure process. Read first. Most important document in this repo.** |
| [CORPUS.md](./CORPUS.md) | Historical vulnerability corpus — all CVEs and type-security issues used as anchors |
| [SECURITY_MODEL.md](./SECURITY_MODEL.md) | Named invariants this toolkit enforces and the rationale for each |
| [cpython-security-toolkit-design.md](./cpython-security-toolkit-design.md) | Architecture, agents, scripts, classification system |
| [docs/reproducer-techniques.md](./docs/reproducer-techniques.md) | Catalogue of reproducer techniques for security findings |

---

## Comparison with Sibling Projects

| Dimension | cpython-review-toolkit | ft-review-toolkit | cext-review-toolkit | cpython-security-toolkit |
|---|---|---|---|---|
| **Target layer** | CPython C source | CPython free-threading | C extensions | CPython Python stdlib |
| **Question** | Correct? | Thread-safe? | API-correct? | Security invariant met? |
| **Parsing** | Regex | Specialized | Tree-sitter | AST + dynamic testing |
| **Disclosure path** | Public issue tracker | Public issue tracker | Public issue tracker | `security@python.org` first |
| **Reproducer** | Optional | Optional | 7-tier dispatch | **Required** |

---

## Author

Bhuvansh Kataria ([BHUVANSH855](https://github.com/BHUVANSH855))

## License

MIT — see [LICENSE](./LICENSE).

The MIT license disclaims warranty in the legal sense. The social contract — between this tool's user and the CPython security team — is governed by [WORKING_WITH_MAINTAINERS.md](./WORKING_WITH_MAINTAINERS.md) and CPython's [security policy](https://devguide.python.org/security/policy/).
