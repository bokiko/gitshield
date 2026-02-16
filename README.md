# GitShield

**Secret scanner for developers + AI coding assistants.**

Catches API keys, passwords, and tokens at three layers: in your editor, before commit, and in CI/CD. The first secret scanner with native [Claude Code](https://claude.ai/claude-code) integration.

[![CI](https://github.com/bokiko/gitshield/actions/workflows/ci.yml/badge.svg)](https://github.com/bokiko/gitshield/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/gitshield)](https://pypi.org/project/gitshield/)
[![Python](https://img.shields.io/pypi/pyversions/gitshield)](https://pypi.org/project/gitshield/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

---

## Quick Start

```bash
pip install gitshield

# Scan a repo
gitshield scan .

# Install pre-commit hook
gitshield hook install

# Protect Claude Code sessions
gitshield claude install
```

---

## Why GitShield?

23.8M secrets leaked on public GitHub in 2024. 70% remain active 2 years later. Repos using AI coding assistants have a **6.4% leakage rate** — higher than average.

GitShield is:
- **Native detection** — 58 built-in patterns + Shannon entropy analysis. No external binary required.
- **AI-assistant-aware** — Scans Claude Code tool calls before files are written. First tool to do this.
- **Local-first** — Everything runs on your machine. No cloud, no telemetry, no API keys needed.
- **Fast** — 51 tests pass in 0.14s. Full repo scan in milliseconds.

---

## Feature Comparison

| Feature | GitShield | Gitleaks | TruffleHog | ggshield |
|---------|-----------|----------|------------|----------|
| Native detection engine | 58 patterns + entropy | 150+ patterns | 800+ patterns | ML scoring |
| Claude Code integration | `gitshield claude install` | - | - | - |
| Pre-commit hook | `gitshield hook install` | Manual | Manual | `ggshield install` |
| Gitleaks as optional boost | Merges both engines | N/A | N/A | N/A |
| SARIF output | `--sarif` | `--report-format sarif` | `--json` | `--format sarif` |
| Inline allowlist | `# gitshield:ignore` | `.gitleaksignore` | - | `ggshield:ignore` |
| Config file | `.gitshield.toml` | `.gitleaks.toml` | - | `.gitguardian.yaml` |
| Price | Free | Free | Free tier | $50+/user/mo |

---

## Three Layers of Protection

```
Layer 1: Claude Code Hook          Layer 2: Pre-commit Hook       Layer 3: CI/CD
  Claude writes code                 git commit                     GitHub Actions
       │                                  │                              │
       ▼                                  ▼                              ▼
  gitshield-claude-hook              gitshield scan --staged        gitshield scan --sarif
       │                                  │                              │
  Block before file is written       Block before commit            Fail PR + SARIF upload
```

---

## Commands

### Scanning

```bash
gitshield scan .                    # Scan current directory
gitshield scan --staged             # Scan only staged files
gitshield scan --json               # JSON output
gitshield scan --sarif              # SARIF output (GitHub Code Scanning)
gitshield scan --quiet              # Minimal output (for hooks)
gitshield scan --no-git             # Scan as plain files
```

### Git Pre-commit Hook

```bash
gitshield hook install              # Add pre-commit hook
gitshield hook install -p /path     # Install in specific repo
gitshield hook uninstall            # Remove hook
```

### Claude Code Integration

```bash
gitshield claude install            # Register PreToolUse hook
gitshield claude uninstall          # Remove hook
gitshield claude status             # Check if hook is active
```

Once installed, GitShield intercepts every `Write`, `Edit`, and `Bash` tool call from Claude Code. If a secret is detected, the tool call is blocked with a clear message:

```
GITSHIELD: Blocked — secrets detected in config.py
  Found: aws-access-key-id
  Count: 1 finding(s)

  To allowlist: add '# gitshield:ignore' to the line,
  or add the path to .gitshield.toml [allowlist] paths.
```

### Configuration

```bash
gitshield init                      # Create .gitshield.toml with defaults
```

### Public Repo Patrol

```bash
gitshield patrol                    # Scan recent public GitHub commits
gitshield patrol -r owner/name     # Scan specific repo
gitshield patrol --dry-run          # Test without sending notifications
gitshield patrol --stats            # View scanning statistics
```

---

## Configuration

### `.gitshield.toml`

```toml
[scan]
entropy_threshold = 4.5             # Shannon entropy cutoff (0.0-8.0)
scan_tests = false                  # Skip test files by default

[allowlist]
paths = ["*.test.*", "*.example", "fixtures/**"]
rules = ["generic-api-key"]         # Disable specific rules
fingerprints = []                   # Specific findings to ignore

[[custom_patterns]]
name = "internal-api-key"
regex = "MYCO_[A-Z0-9]{32}"
description = "MyCompany internal API key"
severity = "high"
```

### `.gitshieldignore`

One fingerprint per line. Simpler alternative to TOML config for just ignoring findings:

```
# Example key in docs
README.md:generic-api-key:42

# Test fixtures
tests/fixtures/secret_file.py:aws-access-key-id:2
```

### Inline Suppression

Add a comment to suppress a finding on that line:

```python
API_KEY = "AKIA..."  # gitshield:ignore
```

Supported comment styles: `# gitshield:ignore`, `// gitshield:ignore`, `-- gitshield:ignore`

---

## What It Detects

**58 patterns across 14 categories:**

| Category | Patterns | Examples |
|----------|----------|---------|
| AWS | 5 | `AKIA...` access keys, secret keys, session tokens |
| GCP | 3 | `AIza...` API keys, service account keys, OAuth secrets |
| Azure | 3 | Storage keys, connection strings, SAS tokens |
| GitHub | 5 | `ghp_`, `gho_`, `ghs_`, `ghr_`, `github_pat_` |
| GitLab | 3 | `glpat-` tokens, pipeline triggers, runner tokens |
| Slack | 3 | `xoxb-`, `xoxp-` tokens, webhook URLs |
| Stripe | 2 | `sk_live_`, `sk_test_`, `rk_live_`, `rk_test_` |
| Twilio | 2 | Account SIDs, auth tokens |
| SendGrid | 1 | `SG.xxx.xxx` API keys |
| Database | 3 | MongoDB, PostgreSQL, MySQL connection strings |
| Private Keys | 5 | RSA, EC, DSA, OpenSSH, PGP |
| JWT | 1 | `eyJ...` tokens |
| Generic | 7 | `api_key=`, `password=`, `secret=`, `token=` (entropy-gated) |
| Other | 15 | npm, PyPI, Heroku, Telegram, Discord, Firebase, Vault, etc. |

Plus **Shannon entropy analysis** for catching generic high-entropy secrets that regex alone misses.

If [gitleaks](https://github.com/gitleaks/gitleaks) is installed, GitShield runs both engines and merges results — best of both worlds.

---

## pre-commit Framework

Add GitShield to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/bokiko/gitshield
    rev: v1.0.0
    hooks:
      - id: gitshield
```

---

## GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    pip install gitshield
    gitshield scan --sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Sample Output

```
  2 secrets found

  config.py:15
    Type: aws-access-key-id
    Secret: AKIA1234567890AB...
    Fingerprint: config.py:aws-access-key-id:15

  .env:3
    Type: stripe-secret-key
    Secret: sk_live_ABCDEFgh...
    Fingerprint: .env:stripe-secret-key:3

  False positive? Copy & paste to ignore:

    echo "config.py:aws-access-key-id:15" >> .gitshieldignore
    echo ".env:stripe-secret-key:3" >> .gitshieldignore

  Commit blocked. Remove secrets before committing.
```

---

## Architecture

```
gitshield/
├── cli.py           # Click-based CLI (scan, hook, claude, init, patrol)
├── engine.py        # Native detection engine (regex + entropy)
├── patterns.py      # 58 pattern definitions across 14 categories
├── scanner.py       # Orchestrator (native engine + optional gitleaks)
├── hook.py          # Claude Code hook handler (stdin/stdout JSON)
├── claude.py        # Claude Code hook management (install/uninstall)
├── config.py        # .gitshield.toml + .gitshieldignore support
├── formatter.py     # Terminal, JSON, and SARIF output
├── monitor.py       # GitHub Events API client (patrol mode)
├── notifier.py      # Email (Resend) + GitHub issue sender
└── db.py            # SQLite tracking (patrol stats)
```

---

## Requirements

- Python 3.9+
- gitleaks (optional — enhances detection when installed)

---

## Credits

- [gitleaks](https://github.com/gitleaks/gitleaks) — Optional detection engine supplement
- [Click](https://click.palletsprojects.com/) — CLI framework

---

Built by [bokiko](https://github.com/bokiko) | MIT License
