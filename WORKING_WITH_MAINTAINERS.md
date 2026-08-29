# Working with Maintainers

cpython-security-toolkit finds **security vulnerabilities** in CPython's standard library. This is different from finding correctness bugs. The disclosure process, the audience, and the stakes are all different.

This document is the most important document in this repository. Read it before you do anything else with a finding.

---

## TL;DR — the five rules

1. **Security findings go to `security@python.org` first.** Never the public issue tracker. Never social media. Never a gist. The [CPython security policy](https://devguide.python.org/security/policy/) is the authority.
2. **Pre-triage with a trusted CPython developer before submitting.** One private message — *"I found something that might be a security issue in `tarfile`, can you take a look before I send to security@?"* — takes five minutes and prevents false reports from reaching the PSRT.
3. **A finding without a runnable reproducer is not a finding.** The tool enforces this. If you cannot run the reproducer and confirm the behavior yourself, do not report it.
4. **Be concise and objective.** CPython maintainers and the PSRT are busy. One clear sentence stating the violated invariant and the affected module is more useful than three paragraphs of analysis. Do not editorialize.
5. **Do not report in public until the PSRT says it is safe to do so.** The standard coordinated disclosure window is 90 days from acknowledgment.

---

## The CPython security process

### Who handles security reports

CPython security is handled by the **Python Security Response Team (PSRT)**. The PSF is a CVE Numbering Authority (CNA) — they assign CVE IDs for confirmed vulnerabilities in CPython and pip.

Contact: `security@python.org`

The PSRT uses GitHub Security Advisories (GHSAs) internally. Once a fix is merged and they are ready to publish, the advisory and CVE record go live together.

### What is in scope

CPython accepts vulnerability reports for supported versions with status "bugfix" or "security." Versions in "feature" or "prerelease" status (alphas, betas, release candidates) are not eligible for CVEs — report those as regular bugs.

Check [devguide.python.org/versions/](https://devguide.python.org/versions/) before reporting to confirm the version is still supported.

### Severity

The PSRT uses CVSSv4 to calculate severity. Severity is assessed from expected or known use, not from worst-case hypothetical scenarios. When writing your report, focus on realistic impact — what an attacker who controls the untrusted input can actually achieve.

---

## Before you report anything

A short checklist before taking any finding to any external party:

- [ ] **Run the reproducer yourself.** On a supported CPython version. Confirm the behavior you observed matches what the engine reported. If you cannot reproduce it, it is not reportable.
- [ ] **Pull the latest `main` and re-check.** A finding that exists on the version you analyzed may already be fixed on `main`. Check the commit history for the relevant file.
- [ ] **Check open GHSAs.** Some in-progress fixes are visible via [github.com/python/cpython/security/advisories](https://github.com/python/cpython/security/advisories). A finding that matches an existing in-progress GHSA is already known — do not re-report.
- [ ] **Check `type-security` labeled issues.** Some security-relevant bugs in CPython are tracked as `type-security` issues without CVE numbers. Search the CPython issue tracker before reporting.
- [ ] **Pre-triage with a trusted CPython developer.** Especially for findings in ambiguous areas (is this actually exploitable? is this design or defect?). A brief private conversation saves the PSRT triage time and reduces the chance of a false report consuming their capacity.

---

## How to write a report to security@python.org

The PSRT values **concise, objective, and reproducible** reports. The guidance in CPython's security policy is explicit on this.

A good report contains:

**1. One-sentence description of the vulnerability**
State the violated invariant and the affected module. Example:
> The `http.cookies.Morsel.update()` method and `|=` operator do not apply the control-character validation that `__setitem__` applies, allowing injection of control characters into cookie values via paths that bypass the primary validator.

**2. The affected module and function**
> `Lib/http/cookies.py` — `Morsel.update()`, `Morsel.__ior__()`, `Morsel.__reduce__()`

**3. Affected Python versions**
List only versions you confirmed. Do not speculate about versions you have not tested.

**4. The runnable reproducer**
The shortest Python script that demonstrates the behavior. Self-contained. No external dependencies. Paste inline — do not link to a gist.

**5. The expected behavior**
One sentence: what should happen instead.

**6. The observed behavior**
One sentence: what actually happens.

**7. Impact assessment**
Realistic. What can an attacker who controls the relevant input actually achieve? HTTP header injection? Arbitrary file write? Denial of service? Do not overstate.

Do not include:

- Speculation about CVSS scores (the PSRT calculates these)
- Attribution claims or CVE ID requests (the PSF CNA handles these)
- Comparisons to other tools or other languages
- Background on why you built this toolkit

---

## Pre-triage: working with a trusted CPython developer

devdanzin (David Danzin) has worked through this process with SSL security issues and is a useful contact for pre-triage. Other trusted CPython developers may also be appropriate depending on the affected module.

A pre-triage message should be:

- **Private** (direct message, not a public issue)
- **Short** — one or two sentences and the reproducer
- **Not a report** — you are asking "does this look real to you?" not requesting them to act

Example:
> Hi — I found something using cpython-security-toolkit that might be a `tarfile` security issue. Before I send to security@, can you take a quick look? Here's the reproducer: [paste]. The behavior I see is [one sentence]. Is this worth reporting?

If the trusted developer says "looks like a real issue" — proceed to `security@python.org`.
If they say "this is intentional" or "this is a known limitation" — do not report. Document the false positive to improve the engine.
If they are unavailable — wait, or consult the CPython [security policy](https://devguide.python.org/security/policy/) for guidance.

---

## Disclosure timeline

Once you have filed with `security@python.org`:

| Phase | Your role |
|---|---|
| Acknowledgment (usually within a few days) | Wait. Do not discuss publicly. |
| PSRT triage | Respond promptly to any clarifying questions. Provide additional test cases if requested. |
| Fix development | You may be offered the opportunity to review the fix draft. |
| Publication | The advisory and CVE record are published after the fix is merged. Follow PSRT's timing guidance. |
| Post-publication | You may write about the finding publicly after the advisory is published. Credit the PSRT if they were helpful. |

The standard coordinated disclosure window is 90 days from PSRT acknowledgment. If a fix takes longer, the PSRT will communicate the timeline. Do not publish early.

---

## What to do if a finding is declined

The PSRT may determine your finding is not a vulnerability — either because it does not meet CPython's security model, because the affected version is EOL, or because the behavior is intentional.

If declined:

- Accept the decision. One round of clarification is appropriate; beyond that, accept the outcome.
- If the behavior is intentional but surprising, it may still be worth filing a public documentation issue.
- If you believe the decision is wrong and the issue is serious, consult [CERT/CC's coordination guide](https://vuls.cert.org/confluence/display/Wiki/Vulnerability+Disclosure+Policy) before taking any further action.

Do not publish findings that the PSRT has declined, unless the PSRT explicitly tells you it is safe to do so.

---

## HARDENING findings: the public tracker path

Not all findings from this toolkit are security vulnerabilities. Some are `HARDENING` — security-adjacent improvements that do not meet the PSRT's severity threshold but are still worth fixing:

- Incomplete fix coverage (a security fix that did not cover all code paths)
- Missing defense-in-depth (a module that could validate input more strictly)
- Latent risk (a pattern that resembles a known vulnerability class without a confirmed exploitable path)

`HARDENING` findings go to the **public CPython issue tracker** (`bugs.python.org` / GitHub issues), not `security@python.org`. Label them `type-security` if appropriate — this is the convention CPython uses for security-adjacent improvements that are not formal vulnerabilities.

Pre-triage with a trusted developer is still recommended before filing these publicly.

---

## Anti-patterns

- **Filing in the public tracker first** for any finding the engine classifies as `SECURITY` or `SECURITY-CANDIDATE`. Even if you are not sure it is exploitable — err toward private.
- **Auto-generating PSRT reports from engine output.** Every report must pass through human triage and reproducer confirmation. The engine output is a starting point, not a finished report.
- **Overstating severity.** The PSRT uses CVSSv4. Describing a theoretical worst-case as the expected impact erodes trust in your reports.
- **Contacting PSRT members individually** rather than `security@python.org`. Use the official channel.
- **Publishing before the fix ships.** Even with good intentions, publishing an unpatched finding harms the millions of people running CPython.
- **Requesting CVE IDs directly.** CVE IDs for CPython are issued by the PSF CNA after the PSRT accepts a report. Do not contact MITRE or other CNAs for CPython issues.
- **Posting "I found N security bugs in CPython using this tool"** to social media before any of them are acknowledged. This is the highest-impact anti-pattern. Do not do this.

---

## When in doubt

Ask yourself: *"If I were a CPython user running a production system, and I saw what I'm about to do, would I be glad someone did it this way?"*

If yes, proceed.
If you can't tell, pre-triage with a trusted developer first.
If no, don't.

The CPython security team is staffed by volunteers giving their time. The goal is to make their work easier, not harder.
