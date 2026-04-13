# security-review

A Claude Code plugin that performs a serious, adversarial security review against the **OWASP Top 10:2025**.

The plugin ships one skill, `review-owasp-top-10`, which dispatches **10 specialized sub-agents in parallel** — one per OWASP category — and produces a unified, priority-ranked findings report.

## Features

- **Two modes**: PR review (diff-scoped) or codebase audit (full tree)
- **10 parallel sub-agents**, one per OWASP Top 10:2025 category
- **Four-axis ranking**: Severity x Exploitability x Exposure x Confidence -> Priority (P0-P4)
- **Required Attack Scenario** for every Critical/High finding (forces exploit articulation, kills false positives)
- **Per-category verification checklists** and common-false-positive guards
- **Real-world CVE and breach references** per category (Equifax, Log4Shell, SolarWinds, Capital One, etc.)
- **Exhaustive code examples** across C#/.NET, Java, Python, JavaScript/TypeScript, Go, PHP, Ruby

## The 10 Categories (OWASP Top 10:2025)

| ID | Category |
|----|----------|
| A01 | Broken Access Control |
| A02 | Security Misconfiguration |
| A03 | Software Supply Chain Failures |
| A04 | Cryptographic Failures |
| A05 | Injection |
| A06 | Insecure Design |
| A07 | Authentication Failures |
| A08 | Software or Data Integrity Failures |
| A09 | Security Logging and Alerting Failures |
| A10 | Mishandling of Exceptional Conditions |

## Installation

This plugin ships as part of the [`ai-review-plugins`](https://github.com/yury-opolev/ai-review-plugins) Claude Code marketplace.

```
/plugin marketplace add yury-opolev/ai-review-plugins
/plugin install security-review@ai-review-plugins
```

### Verify

```
/help
```

You should see the `review-owasp-top-10` skill listed under the `security-review` plugin namespace.

## Usage

Just ask Claude Code for a security review:

> "Run an OWASP review on this PR."
> "Audit this codebase for security issues."
> "Do a security review of the changes on this branch."

Or invoke the skill explicitly:

```
/security-review:review-owasp-top-10
```

Claude will:

1. Determine mode (PR review vs. codebase audit) and scope
2. Dispatch all 10 sub-agents in parallel, each given the relevant sub-agent prompt from `skills/review-owasp-top-10/sub-agents/`
3. Collect findings in the standardized four-axis format
4. Aggregate into a priority-ranked report (P0 first, down to P4)

## Output Format

Every finding shows all four axis scores plus the derived Priority tier:

```markdown
### [P0] [CRITICAL] Missing authorization on DELETE /api/users/{id}
- Category: A01:2025 - Broken Access Control
- CWE: CWE-862, CWE-285
- File: src/api/users.controller.cs:42
- Severity: Critical
- Exploitability: Trivial
- Exposure: Internet
- Confidence: Confirmed
- Priority: P0
- Description: ...
- Evidence: <code snippet>
- Attack scenario:
  1. Attacker sends `DELETE /api/users/1`
  2. Server deletes user without any auth check
  3. Full user database can be wiped in a loop
- Recommendation: ...
- References:
  - https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
  - https://cwe.mitre.org/data/definitions/862.html
```

Findings are grouped in the final report by priority tier, then severity, then exposure, then OWASP category.

## Scope and Limits

**What this plugin does:**

- Static code review against OWASP Top 10:2025 categories
- Judgment-based scoring and prioritization
- Attack-scenario articulation for high-severity findings

**What it does NOT do:**

- Dynamic analysis (DAST), fuzzing, or runtime tracing
- Dependency CVE scanning at scale (use Dependabot, Snyk, OSV-Scanner)
- Secret scanning at scale (use gitleaks, trufflehog)
- Compliance certification (PCI-DSS, HIPAA, SOC2)
- LLM-specific risks (use OWASP LLM Top 10 instead)

## Plugin Layout

This plugin sits inside the `ai-review-plugins` marketplace repo:

```
ai-review-plugins/                           (marketplace repo root)
├── .claude-plugin/
│   └── marketplace.json
├── plugins/
│   └── security-review/                     ← THIS PLUGIN
│       ├── .claude-plugin/
│       │   └── plugin.json
│       ├── skills/
│       │   └── review-owasp-top-10/
│       │       ├── SKILL.md
│       │       └── sub-agents/
│       │           ├── A01-broken-access-control.md
│       │           ├── A02-security-misconfiguration.md
│       │           ├── A03-software-supply-chain-failures.md
│       │           ├── A04-cryptographic-failures.md
│       │           ├── A05-injection.md
│       │           ├── A06-insecure-design.md
│       │           ├── A07-authentication-failures.md
│       │           ├── A08-software-or-data-integrity-failures.md
│       │           ├── A09-security-logging-and-alerting-failures.md
│       │           └── A10-mishandling-of-exceptional-conditions.md
│       └── README.md                        ← you are here
├── README.md
└── LICENSE
```

## References

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [Claude Code plugin documentation](https://code.claude.com/docs/en/plugins.md)
- [Claude Code skills documentation](https://code.claude.com/docs/en/skills.md)

## License

MIT - see [LICENSE](LICENSE).
