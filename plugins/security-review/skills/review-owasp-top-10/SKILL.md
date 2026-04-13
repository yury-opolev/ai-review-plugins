---
name: review-owasp-top-10
description: Use when reviewing a pull request or auditing a codebase for security issues against OWASP Top 10:2025. Dispatches 10 parallel sub-agents (one per OWASP category) and produces a unified, priority-ranked findings report with four-axis scoring (Severity × Exploitability × Exposure × Confidence → Priority tier), file:line evidence, attack scenarios, and remediation guidance.
---

# OWASP Top 10:2025 Code Review

## Overview

Performs a **serious, adversarial** security review against the **OWASP Top 10:2025** by dispatching **10 specialized sub-agents in parallel**. Each sub-agent owns exactly one category and reports findings using a four-axis scoring rubric. The orchestrator (you) aggregates findings into a single **priority-ranked** report.

**Two operating modes:**
- **PR review** — analyze the diff of a specific pull request, branch, or commit range
- **Codebase audit** — analyze the entire codebase or a chosen directory subtree

## When to Use

Trigger this skill when the user:

- Asks for a "security review", "OWASP review", "security audit", or "code audit"
- Asks to review a PR/MR/branch for security issues
- Asks "is this code secure?" or similar
- Wants to harden a codebase before release
- Is onboarding to an unfamiliar codebase and wants a security baseline

**Do NOT use this skill for:**
- Single-line bug fixes (use a targeted review)
- Architecture reviews (use a design review skill)
- Penetration testing (this is static, not dynamic)
- Compliance certifications (this is a finding generator, not an attestation)

## Reviewer Discipline (How to Take This Seriously)

A serious security review is not a grep-based checklist. It is an adversarial reading of the code with three properties:

1. **Taint-aware.** For every "vulnerable" pattern flagged, you MUST trace the data from source (user input) to sink (dangerous operation) and confirm no upstream guard breaks the chain. An unreached "vulnerable" line is a false positive.

2. **Context-aware.** The same pattern has different impact in different contexts. `MD5` used for a cache key is not a finding; `MD5` used to hash a password is Critical. `int id` without ownership check is Critical on `/patients/{id}`, Low on `/products/{id}`.

3. **Honest about confidence.** If you can't articulate a specific exploit, your confidence is not "High". Say so. Low-confidence findings are valuable — they become manual-review candidates, not noise.

**The three honest questions, asked for every finding:**
- Can I write the attacker's first `curl` command (or payload)?
- Can I explain what happens server-side after that request?
- Can I name the specific data / function / system that is compromised?

If the answer to any of these is "I'm not sure", the finding's **Confidence** is **Medium** or lower — not High or Confirmed. **Every sub-agent enforces this discipline via its own Verification Checklist.**

## The 10 Categories (OWASP Top 10:2025)

| ID | Category | Sub-Agent File |
|----|----------|----------------|
| A01 | Broken Access Control | `sub-agents/A01-broken-access-control.md` |
| A02 | Security Misconfiguration | `sub-agents/A02-security-misconfiguration.md` |
| A03 | Software Supply Chain Failures | `sub-agents/A03-software-supply-chain-failures.md` |
| A04 | Cryptographic Failures | `sub-agents/A04-cryptographic-failures.md` |
| A05 | Injection | `sub-agents/A05-injection.md` |
| A06 | Insecure Design | `sub-agents/A06-insecure-design.md` |
| A07 | Authentication Failures | `sub-agents/A07-authentication-failures.md` |
| A08 | Software or Data Integrity Failures | `sub-agents/A08-software-or-data-integrity-failures.md` |
| A09 | Security Logging and Alerting Failures | `sub-agents/A09-security-logging-and-alerting-failures.md` |
| A10 | Mishandling of Exceptional Conditions | `sub-agents/A10-mishandling-of-exceptional-conditions.md` |

## Prioritization Framework (Four-Axis Rubric)

A serious review does not lump "severity" and "priority" together. **Severity is intrinsic** to the vulnerability; **Priority is the fix-order recommendation** that combines severity with how reachable and exploitable the issue is in *this* codebase, weighted by how confident the reviewer is.

Every finding is scored on four independent axes.

### Axis 1 — Severity (Intrinsic Impact)

What happens if the vulnerability is exploited to its full extent, independent of how easy it is to trigger?

| Level | Definition |
|-------|------------|
| **Critical** | Full system compromise, RCE, mass data exfiltration, direct financial loss, regulatory breach, loss of life |
| **High** | Individual account takeover, cross-tenant data access, integrity loss, significant business disruption |
| **Medium** | Limited data disclosure, single-user impact, defense-in-depth failure, reputational damage |
| **Low** | Minor information disclosure, hardening gap, non-sensitive exposure |
| **Info** | Best-practice deviation, zero direct impact |

### Axis 2 — Exploitability

How hard is it to actually trigger the vulnerability?

| Level | Definition |
|-------|------------|
| **Trivial** | Public exploit exists; attacker needs no skill (curl, browser) |
| **Easy** | Commonly understood technique (SQLi, XSS, intruder fuzzing); no special access |
| **Moderate** | Requires chaining, timing, or target-specific knowledge |
| **Hard** | Requires insider access, precise timing, or specialized skill |
| **Theoretical** | Possible under adversarial conditions but no known practical path |

### Axis 3 — Exposure

Who can reach the vulnerable code path?

| Level | Definition |
|-------|------------|
| **Internet** | Reachable by anonymous remote attacker |
| **Authenticated-user** | Reachable by any logged-in user |
| **Privileged-user** | Reachable only by admin / elevated user |
| **Internal-network** | Reachable only from VPC / internal network |
| **Local-only** | Requires local process or host access |

### Axis 4 — Confidence (Epistemic Honesty)

How sure are you this is a real vulnerability, not a false positive? **This is where reviewers most often lie to themselves.**

| Level | Definition |
|-------|------------|
| **Confirmed** | Reviewer traced taint source-to-sink, verified no upstream guard, articulated a specific exploit payload |
| **High** | Pattern matches a well-known vulnerable form; no guard found in files read; typical interpretation is exploitable |
| **Medium** | Pattern looks risky but context could make it safe; recommend manual verification |
| **Low** | Heuristic match; likely needs investigation; may well be a false positive |

### Priority Tier (Derived from All Four Axes)

Combine the four axes into a **Priority tier** for fix ordering:

| Priority | Typical combination | When to fix |
|----------|---------------------|-------------|
| **P0** | (Critical or High) × (Trivial or Easy) × Internet × (Confirmed or High) | Stop the deploy; fix immediately |
| **P1** | High × Any × (Internet or Auth) × (Confirmed or High), **or** Critical × (Moderate/Hard) × Internet | Current sprint |
| **P2** | Medium × (Trivial/Easy) × (Internet/Auth), **or** High × (Moderate/Hard) × (Auth/Internal) | Current quarter |
| **P3** | Low × Any, Medium × (Moderate/Hard) × Internal | Backlog |
| **P4** | Info × Any | Document, close |

**Ranking rules:**
- **Never P0 a Low-confidence finding.** Raise confidence through investigation, or drop priority.
- **Never downgrade severity based on "attackers would never try this."** That is not your call.
- **Always raise a High-confidence Low-exploitability Critical/High finding to at least P2** — it is still a real vulnerability, just less urgent.
- **Dropping confidence by one level drops priority by one tier** unless severity is Critical.
- **Internet exposure raises priority by one tier** versus the same issue behind authentication.

### Report Sort Order

Order findings in the final report by:

1. **Priority tier** (P0 → P4)
2. Within a tier: **Severity** (Critical → Info)
3. Within a severity: **Exposure** (Internet → Local)
4. Within an exposure: **OWASP Category** (A01 → A10)

Every finding MUST show all four axis scores plus the computed Priority.

## Workflow

### Step 1 — Determine Mode and Scope

Decide which mode applies and gather scope information.

| Trigger phrase | Mode | What to gather |
|----------------|------|----------------|
| "review this PR", "review PR #N", "review my branch" | **PR review** | List of changed files via `git diff --name-only <base>...HEAD` or `gh pr diff <num> --name-only`; a unified diff snippet for context |
| "audit the codebase", "review the project", "scan for vulnerabilities" | **Codebase audit** | Source roots; exclude `node_modules`, `bin`, `obj`, `dist`, `.git`, vendored deps |

If unclear, **ask the user** which mode they want before continuing. Also ask for an optional path filter ("just `src/api/**`") if the codebase is large.

Capture the absolute repo root path. You will pass it to every sub-agent.

### Step 2 — Dispatch 10 Sub-Agents in Parallel

**All 10 Agent calls MUST be in a single assistant message** so they run in parallel.

For each sub-agent file:

1. `Read` the sub-agent prompt file from `<this-skill-folder>/sub-agents/AXX-*.md`
2. Compose the final prompt as defined in **Sub-Agent Prompt Composition** below
3. Dispatch via the `Agent` tool with `subagent_type: general-purpose`

Use a short `description` like `"OWASP A01 review"` for each Agent call.

### Step 3 — Collect and Normalize Findings

Once all 10 sub-agents complete, collect their structured outputs. Each sub-agent returns:

- Zero or more findings in the **Standard Finding Format** (see below)
- The literal completion sentinel line `AXX-COMPLETE`

Verify all 10 sentinels are present. If any sub-agent failed or returned malformed output, re-dispatch that single one rather than the full set.

**Sanity checks to run on every finding:**
- All four axis scores are present?
- Priority matches the combination rules above?
- Critical/High findings include an **Attack scenario**?
- File paths are relative to repo root and include line numbers?

If a sub-agent reports a Critical-confidence finding without an exploit articulation, **downgrade it to Medium confidence and adjust priority** before aggregating. Enforce discipline.

### Step 4 — Aggregate Into a Priority-Ranked Report

Build a single Markdown report ordered by Priority tier, not by category:

```markdown
# OWASP Top 10:2025 Security Review

## Summary
- Mode: <PR review | Codebase audit>
- Scope: <N files reviewed across M directories>
- Total findings: <N>
- By priority: P0:X · P1:Y · P2:Z · P3:W · P4:V
- By severity: Critical:X · High:Y · Medium:Z · Low:W · Info:V
- By category: A01:X ... A10:Z

## P0 — Fix Immediately (before next deploy)
[All P0 findings, ordered by Severity → Exposure → Category]

## P1 — Fix This Sprint
[...]

## P2 — Fix This Quarter
[...]

## P3 — Backlog
[Summary list with file:line, full details on request]

## P4 — Informational
[One-line entries]

## Categories With No Findings
- A03 — Software Supply Chain Failures (clean)
- A09 — Security Logging and Alerting Failures (clean)
- ...

## Reviewer's Top 3 Priorities
1. <Most impactful concrete action>
2. <Second most impactful>
3. <Third>

## Systemic Observations
[Patterns that span multiple findings — e.g., "The whole API lacks global authorization policy; individual findings are symptoms."]

## Methodology
- OWASP Top 10:2025 (https://owasp.org/Top10/2025/)
- 10 parallel sub-agents, one per category
- Four-axis ranking: Severity × Exploitability × Exposure × Confidence → Priority
- Files reviewed: <N>
- Sub-agents that completed: 10/10
```

**Pass findings through verbatim.** Never summarize away a finding's evidence, recommendation, or attack scenario.

### Step 5 — Present and Offer Next Steps

After delivering the report, ask whether the user wants you to:
- Open the highest-priority file and implement the fix
- Generate a failing unit test that demonstrates the vulnerability
- Re-run the review after fixes
- Open issues/tickets for each finding
- Produce a remediation PR for a specific P0/P1 item

## Sub-Agent Prompt Composition

When dispatching each sub-agent, build the prompt as follows:

```
<paste the FULL contents of sub-agents/AXX-*.md here>

---

## SCOPE FOR THIS RUN

Mode: <PR review | Codebase audit>
Repo root: <absolute path>

Files in scope:
- <relative path 1>
- <relative path 2>
- ...

Language hints: <e.g. C# / .NET 10, TypeScript / React, Python 3.12>

(PR review only) Diff context:
\`\`\`diff
<unified diff or "run `git diff <base>...HEAD -- <files>` to fetch it">
\`\`\`

You have access to: Read, Grep, Glob, Bash (read-only git commands only).
Do NOT modify any files. Do NOT run tests or builds.

---

## OUTPUT REQUIREMENT

Return ONLY findings using the Standard Finding Format from the prompt above.
For every finding you MUST:
- Fill in all four axis scores (Severity, Exploitability, Exposure, Confidence) and the derived Priority
- Run the Verification Checklist from your prompt before classifying confidence as Confirmed or High
- For Critical and High severity, include the explicit Attack Scenario (step-by-step exploit walkthrough)
- Note any assumptions / caveats that would change the scoring if disproven

If you find no issues for your category in this scope, return EXACTLY:

No findings for AXX:2025 - <Category Title> in scope.

End your response with the literal sentinel line on its own:

AXX-COMPLETE

Do not include planning, progress messages, file lists, or commentary outside findings.
```

## Standard Finding Format

Every finding (from sub-agents and in the final report) MUST use this schema:

```markdown
### [P0] [CRITICAL] Brief title (≤ 80 chars)
- **Category:** A0X:2025 - <Title>
- **CWE:** CWE-XXX (primary), CWE-YYY (secondary)
- **File:** path/to/file.ext:LINE (or path/to/file.ext:LINE-LINE for ranges)
- **Severity:** Critical | High | Medium | Low | Info
- **Exploitability:** Trivial | Easy | Moderate | Hard | Theoretical
- **Exposure:** Internet | Authenticated-user | Privileged-user | Internal-network | Local-only
- **Confidence:** Confirmed | High | Medium | Low
- **Priority:** P0 | P1 | P2 | P3 | P4
- **Description:** One paragraph — what's wrong and why it matters. State the root cause clearly.
- **Evidence:**
  ```<lang>
  <minimal vulnerable code excerpt>
  ```
- **Attack scenario:** (REQUIRED for Critical/High) Step-by-step exploit walkthrough:
  1. Attacker sends <X>
  2. Application does <Y>
  3. Attacker obtains/achieves <Z>
- **Recommendation:** Concrete fix, referencing a safe API, library, or pattern. Include "how to verify the fix" where relevant.
- **Assumptions / caveats:** (OPTIONAL) Any context that would change the scoring if disproven.
- **References:**
  - https://owasp.org/Top10/2025/A0X_2025-<slug>/
  - https://cwe.mitre.org/data/definitions/XXX.html
```

## Performance Notes

- 10 parallel sub-agents finish in roughly the time of 1 — exploit the parallelism
- Each sub-agent should bound its work: cap at ~30 files read per category on very large codebases
- For codebases > 5,000 source files, ask the user for a path filter before starting
- For PR review, scope is the diff — sub-agents should refuse to expand beyond the changed files except to read definitions of symbols touched by the diff

## Invocation

This skill ships as part of the **`security-review`** Claude Code plugin. After installing the plugin, the skill is auto-discovered and can be triggered by natural-language requests like:

> "Run an OWASP review on this PR."
> "Audit this codebase for security issues."
> "Do a security review of the current branch."

Or invoked explicitly:

```
/security-review:review-owasp-top-10
```

Sub-agent prompt files are located at `skills/review-owasp-top-10/sub-agents/AXX-*.md` relative to this `SKILL.md`. The orchestrator reads each of the 10 files and dispatches one Agent per file in a single parallel message.

## Out of Scope for This Skill

- Dynamic analysis (DAST), fuzzing, runtime tracing
- Dependency CVE scanning at scale (use Dependabot/Snyk/OSV-Scanner)
- Secret scanning at scale (use gitleaks/trufflehog)
- Compliance frameworks (PCI-DSS, HIPAA, SOC2)
- LLM-specific risks (use the OWASP LLM Top 10 instead)
