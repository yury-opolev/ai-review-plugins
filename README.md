# ai-review-plugins

A Claude Code marketplace of AI-powered code review plugins.

## Plugins

| Plugin | Version | Description |
|--------|---------|-------------|
| [`security-review`](./plugins/security-review) | `1.0.0` | OWASP Top 10:2025 security review — dispatches 10 parallel sub-agents with four-axis priority ranking (Severity × Exploitability × Exposure × Confidence → Priority P0-P4) |

Future plugins planned: `privacy-review`, `accessibility-review`, `performance-review`.

## Installation

Add this marketplace to your Claude Code:

```
/plugin marketplace add yury-opolev/ai-review-plugins
```

Then install any plugin from it:

```
/plugin install security-review@ai-review-plugins
```

Verify it loaded:

```
/help
```

You should see the plugin's skills available under the plugin namespace.

## Usage

After installing `security-review`, just ask Claude Code for a security review:

> "Run an OWASP review on this PR."
>
> "Audit this codebase for security issues."
>
> "Do a security review of the current branch."

Or invoke the skill explicitly:

```
/security-review:review-owasp-top-10
```

See the [plugin README](./plugins/security-review/README.md) for details on output format, the four-axis ranking system, and scope.

## Repository Layout

```
ai-review-plugins/
├── .claude-plugin/
│   └── marketplace.json              ← marketplace catalog
├── plugins/
│   └── security-review/              ← one plugin per directory
│       ├── .claude-plugin/
│       │   └── plugin.json
│       ├── skills/
│       │   └── review-owasp-top-10/
│       │       ├── SKILL.md
│       │       └── sub-agents/
│       │           └── A01-..A10-*.md
│       ├── README.md
│       └── LICENSE (optional, inherits from repo root)
├── README.md
└── LICENSE
```

## Adding a new plugin to this marketplace

1. Create `plugins/<your-plugin-name>/` with `.claude-plugin/plugin.json`, `skills/`, `commands/`, etc.
2. Add an entry to `.claude-plugin/marketplace.json` under the `plugins` array.
3. Bump the plugin's `version` in `plugin.json` every time you change anything (cache busting).
4. Commit and push.

## Versioning

Each plugin has its own `version` field in `plugin.json`. Claude Code caches plugins at `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/`, so **you must bump the version** before pushing changes or users will get stale content.

GitHub tags and releases can be used on top of this for human-readable release notes (e.g. tag `security-review-v1.0.0`), though Claude Code itself tracks versions from `plugin.json`, not from git tags.

## License

MIT — see [LICENSE](LICENSE).
