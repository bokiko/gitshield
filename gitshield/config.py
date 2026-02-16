"""Configuration and ignore file handling.

Supports two config formats:
  - .gitshieldignore  (legacy) -- fingerprint-based ignore list
  - .gitshield.toml   (new)    -- full config with thresholds, allowlists, custom patterns
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .scanner import Finding

# ---------------------------------------------------------------------------
# TOML parser import -- gracefully degrade when unavailable
# ---------------------------------------------------------------------------
try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]  # pip install tomli for 3.8-3.10
    except ImportError:
        tomllib = None  # type: ignore[assignment]  # Config file won't be loaded

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
IGNORE_FILE = ".gitshieldignore"
CONFIG_FILE = ".gitshield.toml"

_DEFAULT_CONFIG_TOML = """\
# GitShield configuration
# Docs: https://github.com/bokiko/gitshield

[scan]
# Shannon entropy threshold for generic high-entropy detection (0.0-8.0)
entropy_threshold = 4.5

# Scan test files (normally skipped for speed)
scan_tests = false

[allowlist]
# Glob patterns -- matched against the file path relative to the repo root
paths = [
    "*.test.*",
    "*.example",
    "fixtures/**",
]

# Rule IDs to disable globally
rules = []

# Specific finding fingerprints to ignore (same as .gitshieldignore entries)
fingerprints = []

# Uncomment to add custom secret patterns:
# [[custom_patterns]]
# name = "internal-api-key"
# regex = "MYCO_[A-Z0-9]{32}"
# description = "MyCompany internal API key"
# severity = "high"
"""


# ---------------------------------------------------------------------------
# GitShieldConfig dataclass
# ---------------------------------------------------------------------------
@dataclass
class GitShieldConfig:
    """Parsed representation of .gitshield.toml."""

    entropy_threshold: float = 4.5
    scan_tests: bool = False
    allowlist_paths: List[str] = field(default_factory=list)
    allowlist_rules: List[str] = field(default_factory=list)
    allowlist_fingerprints: Set[str] = field(default_factory=set)
    custom_patterns: List[Dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Git root discovery
# ---------------------------------------------------------------------------
def find_git_root(start: Path) -> Path:
    """Find the git repository root."""
    current = start.resolve()
    while current != current.parent:
        if (current / ".git").exists():
            return current
        current = current.parent
    return start.resolve()


# ---------------------------------------------------------------------------
# Legacy .gitshieldignore support
# ---------------------------------------------------------------------------
def load_ignore_list(path: Path) -> Set[str]:
    """
    Load fingerprints to ignore from .gitshieldignore.

    File format:
    - One fingerprint per line
    - Lines starting with # are comments
    - Empty lines are skipped
    """
    ignore_file = find_git_root(path) / IGNORE_FILE

    if not ignore_file.exists():
        return set()

    ignores = set()
    with open(ignore_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                ignores.add(line)

    return ignores


# ---------------------------------------------------------------------------
# TOML config loading
# ---------------------------------------------------------------------------
def _parse_toml(filepath: Path) -> Optional[Dict[str, Any]]:
    """Parse a TOML file, returning None if parsing is unavailable or fails."""
    if tomllib is None:
        return None
    if not filepath.exists():
        return None
    try:
        with open(filepath, "rb") as f:
            return tomllib.load(f)
    except Exception:
        # Malformed TOML -- fall back to defaults rather than crashing
        return None


def load_config(path: Path) -> GitShieldConfig:
    """
    Load configuration from .gitshield.toml at the repo root.

    Falls back to defaults when:
      - The file doesn't exist
      - tomllib / tomli is not available
      - The file is malformed
    """
    root = find_git_root(path)
    config_file = root / CONFIG_FILE

    data = _parse_toml(config_file)
    if data is None:
        return GitShieldConfig()

    scan = data.get("scan", {})
    allowlist = data.get("allowlist", {})

    fingerprints_raw = allowlist.get("fingerprints", [])
    if isinstance(fingerprints_raw, list):
        fingerprints = set(fingerprints_raw)
    else:
        fingerprints = set()

    return GitShieldConfig(
        entropy_threshold=float(scan.get("entropy_threshold", 4.5)),
        scan_tests=bool(scan.get("scan_tests", False)),
        allowlist_paths=list(allowlist.get("paths", [])),
        allowlist_rules=list(allowlist.get("rules", [])),
        allowlist_fingerprints=fingerprints,
        custom_patterns=list(data.get("custom_patterns", [])),
    )


# ---------------------------------------------------------------------------
# Default config creation
# ---------------------------------------------------------------------------
def create_default_config(path: Path) -> Path:
    """
    Create a .gitshield.toml with sensible defaults and inline comments.

    Returns the path to the created file.
    """
    root = find_git_root(path)
    config_file = root / CONFIG_FILE
    config_file.write_text(_DEFAULT_CONFIG_TOML, encoding="utf-8")
    return config_file


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------
def _matches_any_glob(filepath: str, patterns: List[str]) -> bool:
    """Check if *filepath* matches any of the given glob patterns."""
    for pattern in patterns:
        # Match against the full relative path
        if fnmatch.fnmatch(filepath, pattern):
            return True
        # Also match against just the filename
        if fnmatch.fnmatch(Path(filepath).name, pattern):
            return True
    return False


def filter_findings(
    findings: List[Finding],
    ignores: Set[str],
    config: Optional[GitShieldConfig] = None,
) -> List[Finding]:
    """
    Remove ignored findings.

    A finding is filtered out when ANY of the following is true:
      - Its fingerprint is in *ignores* (legacy .gitshieldignore)
      - Its fingerprint is in config.allowlist_fingerprints
      - Its rule_id is in config.allowlist_rules
      - Its file path matches a config.allowlist_paths glob
    """
    # Merge legacy ignores with config fingerprints
    all_fingerprints = set(ignores)
    if config is not None:
        all_fingerprints |= config.allowlist_fingerprints

    filtered: List[Finding] = []
    for f in findings:
        # Fingerprint check (legacy + toml)
        if f.fingerprint in all_fingerprints:
            continue

        if config is not None:
            # Rule allowlist
            if f.rule_id in config.allowlist_rules:
                continue

            # Path allowlist
            if config.allowlist_paths and _matches_any_glob(f.file, config.allowlist_paths):
                continue

        filtered.append(f)

    return filtered


# ---------------------------------------------------------------------------
# Legacy ignore file creation (unchanged API)
# ---------------------------------------------------------------------------
def create_ignore_file(path: Path, findings: List[Finding]) -> Path:
    """Create a .gitshieldignore file with current findings."""
    ignore_file = find_git_root(path) / IGNORE_FILE

    lines = [
        "# GitShield ignore file",
        "# Add fingerprints of false positives below",
        "",
    ]

    for f in findings:
        lines.append(f"# {f.file}:{f.line} ({f.rule_id})")
        lines.append(f.fingerprint)
        lines.append("")

    with open(ignore_file, "w") as file:
        file.write("\n".join(lines))

    return ignore_file
