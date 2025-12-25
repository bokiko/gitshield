"""Configuration and ignore file handling."""

from pathlib import Path
from typing import List, Set

from .scanner import Finding


IGNORE_FILE = ".gitshieldignore"


def find_git_root(start: Path) -> Path:
    """Find the git repository root."""
    current = start.resolve()
    while current != current.parent:
        if (current / ".git").exists():
            return current
        current = current.parent
    return start.resolve()


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


def filter_findings(
    findings: List[Finding],
    ignores: Set[str],
) -> List[Finding]:
    """Remove ignored findings."""
    return [f for f in findings if f.fingerprint not in ignores]


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
