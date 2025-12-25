"""Wraps gitleaks binary for secret detection."""

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class Finding:
    """A detected secret."""
    file: str
    line: int
    rule_id: str
    secret: str
    fingerprint: str
    entropy: float = 0.0
    commit: Optional[str] = None
    author: Optional[str] = None


class ScannerError(Exception):
    """Scanner-related errors."""
    pass


class GitleaksNotFound(ScannerError):
    """Gitleaks binary not installed."""
    pass


def check_gitleaks() -> str:
    """Check if gitleaks is installed, return path."""
    path = shutil.which("gitleaks")
    if not path:
        raise GitleaksNotFound(
            "gitleaks not found. Install with: brew install gitleaks"
        )
    return path


def scan_path(
    path: str,
    staged_only: bool = False,
    no_git: bool = False,
) -> List[Finding]:
    """
    Scan a path for secrets.

    Args:
        path: Directory or file to scan
        staged_only: Only scan staged git files
        no_git: Scan as plain files (not git repo)

    Returns:
        List of Finding objects
    """
    gitleaks = check_gitleaks()

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        report_path = f.name

    try:
        cmd = [gitleaks]

        if staged_only:
            cmd.extend(["protect", "--staged"])
        elif no_git:
            cmd.extend(["detect", "--no-git"])
        else:
            cmd.append("detect")

        cmd.extend([
            "--source", path,
            "--report-format", "json",
            "--report-path", report_path,
            "--exit-code", "0",  # Don't fail, we'll check results
        ])

        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
        )

        # Parse results
        report_file = Path(report_path)
        if not report_file.exists() or report_file.stat().st_size == 0:
            return []

        with open(report_path) as f:
            data = json.load(f)

        if not data:
            return []

        findings = []
        for item in data:
            findings.append(Finding(
                file=item.get("File", ""),
                line=item.get("StartLine", 0),
                rule_id=item.get("RuleID", "unknown"),
                secret=_truncate_secret(item.get("Secret", "")),
                fingerprint=item.get("Fingerprint", ""),
                entropy=item.get("Entropy", 0.0),
                commit=item.get("Commit"),
                author=item.get("Author"),
            ))

        return findings

    finally:
        Path(report_path).unlink(missing_ok=True)


def _truncate_secret(secret: str, max_len: int = 20) -> str:
    """Truncate secret for display, keeping start and end."""
    if len(secret) <= max_len:
        return secret
    keep = (max_len - 3) // 2
    return f"{secret[:keep]}...{secret[-keep:]}"
