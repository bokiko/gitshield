# GitShield

Prevent accidental secret commits before they happen.

A developer-friendly wrapper around [gitleaks](https://github.com/gitleaks/gitleaks) that catches API keys, passwords, and tokens before they enter your git history.

## Why GitShield?

Once a secret is committed to git, it lives forever in history—even after deletion. Attackers scrape public repos within seconds of a push. GitShield blocks the commit before it happens.

## GitShield vs Gitleaks

[Gitleaks](https://github.com/gitleaks/gitleaks) is an excellent detection engine with 100+ patterns. GitShield wraps it with a better developer experience:

| Feature | Gitleaks | GitShield |
|---------|----------|-----------|
| Detection engine | ✓ | Uses gitleaks |
| Output | Verbose, technical | Clean, colored, actionable |
| Pre-commit hook | Manual setup required | `gitshield hook install` |
| Ignore false positives | Complex `.gitleaksignore` | Simple `.gitshieldignore` |
| Learning curve | Steeper | Minimal |

**In short:** Gitleaks is the engine. GitShield is the better steering wheel.

## FAQ

<details>
<summary><strong>🔒 What secrets does it detect?</strong></summary>

GitShield uses gitleaks' 100+ battle-tested patterns:

- AWS Access Keys (`AKIA...`)
- GitHub Tokens (`ghp_...`, `gho_...`)
- Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
- API Keys (Stripe, Twilio, SendGrid, etc.)
- Database URLs with credentials
- Generic high-entropy strings

</details>

<details>
<summary><strong>⚡ How does it work?</strong></summary>

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│  git commit     │────▶│  pre-commit  │────▶│  gitleaks   │
│                 │     │  hook        │     │  scan       │
└─────────────────┘     └──────────────┘     └─────────────┘
                               │
                        ┌──────▼──────┐
                        │ Secret found │──▶ BLOCK COMMIT
                        │ No secrets   │──▶ Allow commit
                        └─────────────┘
```

The pre-commit hook runs automatically before every commit, scanning only staged files for speed.

</details>

<details>
<summary><strong>🎯 What about false positives?</strong></summary>

Add fingerprints to `.gitshieldignore` in your repo root:

```
# Example API key in documentation (not real)
README.md:generic-api-key:42

# Test fixtures
tests/fixtures.py:private-key:15
```

GitShield will skip these in future scans.

</details>

<details>
<summary><strong>🔓 Is this open source?</strong></summary>

Yes. 100% open source, no tracking, no telemetry. Inspect every line of code.

</details>

---

## Requirements

- Python 3.8+
- gitleaks binary

---

## Install

### 1. Install gitleaks

<details>
<summary><strong>macOS</strong></summary>

```bash
brew install gitleaks
```
</details>

<details>
<summary><strong>Linux</strong></summary>

```bash
# Download latest release
wget https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
tar -xzf gitleaks_8.21.2_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

Or check [gitleaks releases](https://github.com/gitleaks/gitleaks/releases) for latest version.
</details>

### 2. Install GitShield

```bash
# Clone the repo
git clone https://gitlab.com/bokiko/gitshield.git
cd gitshield

# Install
pip install -e .
```

<details>
<summary><strong>PATH issues?</strong></summary>

If `gitshield` command not found after install:

```bash
# macOS
echo 'export PATH="$PATH:$HOME/Library/Python/3.9/bin"' >> ~/.zshrc
source ~/.zshrc

# Linux
echo 'export PATH="$PATH:$HOME/.local/bin"' >> ~/.bashrc
source ~/.bashrc
```
</details>

---

## Quick Start

```bash
# 1. Scan a repo
cd ~/your-project
gitshield scan .

# 2. Install pre-commit hook (recommended)
gitshield hook install

# Done. Secrets are now blocked before commit.
```

---

## Commands

| Command | Description |
|---------|-------------|
| `gitshield scan .` | Scan current directory |
| `gitshield scan --staged` | Scan only staged files |
| `gitshield scan --json` | JSON output for CI/CD |
| `gitshield hook install` | Add pre-commit hook |
| `gitshield hook uninstall` | Remove hook |

---

## Sample Output

```
  2 secrets found

  config.py:15
    Type: aws-access-key
    Secret: AKIA...EXAMPLE
    Fingerprint: config.py:aws-access-key:15

  .env:3
    Type: generic-api-key
    Secret: sk_live_...
    Fingerprint: .env:generic-api-key:3

  To ignore false positives:
    Add fingerprints to .gitshieldignore

  Commit blocked. Remove secrets before committing.
```

---

## Architecture

```
gitshield/
├── cli.py           # Click-based CLI
├── scanner.py       # Wraps gitleaks binary
├── formatter.py     # Pretty terminal output
└── config.py        # .gitshieldignore handling
```

---

## Roadmap

- [x] Pre-commit hook integration
- [x] Ignore file support
- [ ] CI/CD GitHub Action
- [ ] Public repo scanner (Phase 2)
- [ ] Email notifications for leaked secrets

---

## Credits

- [gitleaks](https://github.com/gitleaks/gitleaks) - Detection engine
- [Click](https://click.palletsprojects.com/) - CLI framework

---

Built by [bokiko](https://gitlab.com/bokiko)
