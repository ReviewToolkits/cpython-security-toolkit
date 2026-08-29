# cpython-security-toolkit — Claude Code Instructions

## What this toolkit does

This is a Claude Code plugin for finding semantic security vulnerabilities in CPython's standard library (`Lib/`). It models security invariants, runs differential tests, generates reproducers, and classifies findings for responsible disclosure.

## Critical constraint: reproducers are non-optional

**A finding without a runnable reproducer must never be classified as HIGH confidence or presented to the user as actionable.** This is the single most important design constraint in the toolkit.

If an engine fires on a candidate but cannot generate a confirming reproducer, classify it as `SECURITY-CANDIDATE` (unconfirmed) and instruct the user to attempt manual confirmation before taking any external action.

## Critical constraint: disclosure routing

**Never suggest filing a SECURITY or CORPUS-REGRESSION finding to the public CPython issue tracker.** Always route to `security@python.org` via `WORKING_WITH_MAINTAINERS.md`. For HARDENING findings, the public tracker is appropriate.

## Confidence classification

| Class | Condition | Action |
|---|---|---|
| `SECURITY` | Named invariant violated + confirmed reproducer | Route to `security@python.org` after pre-triage |
| `SECURITY-CANDIDATE` | Invariant likely violated, reproducer not yet confirmed | Pre-triage first; confirm reproducer before reporting |
| `HARDENING` | Security-adjacent gap without confirmed exploitable path | Public CPython tracker with `type-security` label |
| `CORPUS-REGRESSION` | A previously-fixed CVE class detected again | `security@python.org` immediately |
| `FALSE-POSITIVE` | Engine fired; human review determined not a real finding | Discard; record to improve engine precision |

## Engine structure

Each engine follows this exact sequence:

1. Read the relevant named invariants from `SECURITY_MODEL.md`
2. Load corpus positive fixtures from `corpus/<domain>/positive/`
3. Run the relevant analysis scripts against the target CPython source
4. For each candidate finding:
   a. Attempt reproducer generation via `scripts/reproducer_engine.py`
   b. Validate the reproducer (does it actually demonstrate the violation?)
   c. Classify according to the table above
5. Report findings in the structured format below

## Finding output format

Every finding must include all of these fields. Do not omit any:

```
Finding ID:        <DOMAIN>-<NNN>-<year>
Confidence:        SECURITY | SECURITY-CANDIDATE | HARDENING | CORPUS-REGRESSION
Invariant:         <exact named invariant from SECURITY_MODEL.md>
Location:          Lib/<module>.py line <N>, function <name>
Evidence:          <what the engine observed — one to three sentences, factual>
Reproducer:        <runnable Python script, pasted inline>
Reproducer status: CONFIRMED | UNCONFIRMED | PENDING
CVE reference:     <if this matches a corpus entry, state the CVE ID>
Next step:         <exactly one of: "Route to security@python.org after pre-triage" |
                   "Confirm reproducer, then pre-triage" |
                   "File as type-security on CPython tracker" |
                   "Report immediately to security@python.org">
```

## Agent parallelism

Agents within a single engine may run in parallel. Engines themselves should be run sequentially to avoid overloading the token budget on large CPython checkouts.

## Corpus regression test

Before reporting any finding, check whether the corpus positive fixture for this invariant class runs cleanly through the current CPython source. If a previously-confirmed corpus case no longer triggers, note this as a regression-fix (good) in the output rather than a new finding.

## Scope

This toolkit analyzes `Lib/` (Python stdlib). It does not analyze:
- `Modules/`, `Objects/`, `Python/` (covered by cpython-review-toolkit)
- Third-party packages
- `Doc/` or `Tools/`

If a finding requires examining C code in `Modules/` to confirm, note that the finding crosses into cpython-review-toolkit territory and flag for cross-toolkit coordination.
