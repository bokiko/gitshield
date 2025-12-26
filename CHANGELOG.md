# Changelog

All notable changes to GitShield will be documented in this file.

## [0.3.0] - 2025-12-26

### Added
- **Phase 2: Public repo scanner** (`gitshield patrol`)
- Scan public GitHub repos for leaked secrets
- Email notifications via Resend API
- GitHub issue creation for alerts
- SQLite database to track scanned repos and avoid re-notifying
- `--dry-run` flag for testing without notifications
- `--stats` flag to view scanning statistics

### Dependencies
- Added `requests` for GitHub API
- Added `resend` for email notifications

## [0.2.0] - 2025-12-26

### Added
- Copy-paste commands for ignoring false positives
- GitShield vs Gitleaks comparison in README
- Step-by-step guide for .gitshieldignore
- setup.py for older pip compatibility

### Fixed
- Installation on Linux with older pip versions
- PATH instructions for macOS and Linux

## [0.1.0] - 2025-12-26

### Added
- Initial release
- `gitshield scan` command with gitleaks integration
- `gitshield hook install/uninstall` for pre-commit hooks
- `.gitshieldignore` support for false positives
- Colored terminal output
- JSON output for CI/CD (`--json` flag)
- Staged-only scanning (`--staged` flag)
