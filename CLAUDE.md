# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GitShield is a secret scanner for developers and AI coding assistants. It detects API keys, passwords, and tokens at three layers: Claude Code PreToolUse hook, git pre-commit hook, and CI/CD (SARIF output). 65+ patterns across 15 categories including AI services (OpenAI, Anthropic, HuggingFace, Groq). Python 3.9+, MIT license.

## Development Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run all tests
pytest

# Run a single test file
pytest tests/test_engine.py

# Run a single test
pytest tests/test_engine.py::test_scan_text_finds_aws_key -v

# Run with coverage (as CI does)
pytest --cov=gitshield --cov-report=xml -v

# Lint
ruff check gitshield/ tests/

# CLI entry points (after pip install -e .)
gitshield scan .
gitshield-claude-hook  # reads JSON from stdin, writes JSON to stdout
```

## Architecture

### Scan Pipeline

```
CLI (cli.py) or Hook (hook.py)
    |
    v
scanner.scan_path()          # orchestrator: runs native engine, optionally merges gitleaks
    |
    +--> engine.scan_directory/scan_file/scan_text()   # native: regex + entropy per line
    +--> scanner._scan_with_gitleaks()                 # optional: shells out to gitleaks binary
    |
    v
config.filter_findings()     # removes allowlisted/ignored findings
    |
    v
formatter.print_findings/print_json/print_sarif()
```

### Claude Code Hook Flow

The hook runs as a **PreToolUse** handler via `gitshield-claude-hook` entry point:
1. Loads `.gitshield.toml` config (custom patterns, entropy threshold)
2. Reads JSON from stdin (`tool_name` + `tool_input`)
3. For Write/Edit: scans `content` or `new_string` for secrets
4. For Bash: scans `command` string
5. Returns `{"result": "approve"}` or `{"result": "block", "reason": "..."}` to stdout
6. Fails open on errors (never blocks on hook crashes)

Hook allowlist is intentionally restrictive (only `.env.example`/`.env.template`/`.env.sample`) since the filepath comes from untrusted AI model input. Registered in `~/.claude/settings.json` under `hooks.PreToolUse`.

### Dual Engine Design

`scanner.scan_path()` always runs the native engine. If `gitleaks` binary is on PATH (detected once via `shutil.which`, cached with `lru_cache`), it also runs gitleaks and merges results by fingerprint deduplication. Native findings take priority.

### Key Data Types

- **`models.Finding`** — core dataclass shared everywhere (file, line, rule_id, secret, fingerprint, entropy, severity)
- **`patterns.Pattern`** — frozen dataclass with compiled regex, optional entropy_threshold, severity
- **`config.GitShieldConfig`** — parsed `.gitshield.toml` (entropy threshold, allowlists, custom patterns)

### Entropy Gating

The `config_threshold` from `.gitshield.toml` only overrides patterns that already have `entropy_threshold` set (generic patterns). Precise regex patterns (e.g., AWS `AKIA...`) are not entropy-gated — they rely solely on regex matching.

### Module Dependency Notes

- `models.py` exists to break circular imports between `scanner.py` and `engine.py`
- `scanner.py` re-exports `Finding`, `ScannerError`, `GitleaksNotFound` for backward compatibility
- `config.py` uses `tomllib` (3.11+) with `tomli` fallback; degrades gracefully if neither available
- `requests` is an optional dependency (only needed for `patrol` feature): `pip install gitshield[patrol]`

## Configuration

- `.gitshield.toml` — main config (entropy threshold, allowlists, custom patterns)
- `.gitshieldignore` — legacy fingerprint-based ignore file
- Inline suppression: `# gitshield:ignore` / `// gitshield:ignore` / `-- gitshield:ignore`

## CI

GitHub Actions runs pytest on Python 3.9-3.13 and ruff lint on 3.12. See `.github/workflows/ci.yml`.
