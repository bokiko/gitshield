"""Secret detection — native engine + optional gitleaks fallback."""

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
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
    severity: str = "medium"


class ScannerError(Exception):
    """Scanner-related errors."""
    pass


class GitleaksNotFound(ScannerError):
    """Gitleaks binary not installed (non-fatal — native engine still works)."""
    pass


def _has_gitleaks() -> Optional[str]:
    """Return gitleaks binary path if installed, else None."""
    return shutil.which("gitleaks")


def _scan_with_gitleaks(
    path: str,
    staged_only: bool = False,
    no_git: bool = False,
) -> List[Finding]:
    """Run gitleaks and return findings. Raises GitleaksNotFound if missing."""
    gitleaks = _has_gitleaks()
    if not gitleaks:
        raise GitleaksNotFound(
            "gitleaks not found. Install with: brew install gitleaks\n"
            "  (GitShield's native engine is still active)"
        )

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
            "--exit-code", "0",
        ])

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.stderr and "error" in result.stderr.lower():
            raise ScannerError(f"Gitleaks error: {result.stderr.strip()}")

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


def scan_path(
    path: str,
    staged_only: bool = False,
    no_git: bool = False,
) -> List[Finding]:
    """Scan a path for secrets using native engine + optional gitleaks.

    The native engine always runs. If gitleaks is installed, both engines
    run and results are merged (deduplicated by fingerprint).
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise ScannerError(f"Path does not exist: {path}")

    # Import here to avoid circular imports at module level
    from .engine import scan_directory, scan_file

    # Always run native engine
    if resolved.is_file():
        native_findings = scan_file(resolved)
    else:
        native_findings = scan_directory(
            resolved,
            staged_only=staged_only,
            no_git=no_git,
        )

    # Try gitleaks as supplement (not required)
    gitleaks_findings: List[Finding] = []
    if _has_gitleaks():
        try:
            gitleaks_findings = _scan_with_gitleaks(path, staged_only, no_git)
        except (ScannerError, GitleaksNotFound):
            pass  # Native engine already has results

    # Merge: native findings take priority, add gitleaks-only findings
    seen_fingerprints = {f.fingerprint for f in native_findings}
    merged = list(native_findings)
    for f in gitleaks_findings:
        if f.fingerprint not in seen_fingerprints:
            merged.append(f)
            seen_fingerprints.add(f.fingerprint)

    return merged


def _truncate_secret(secret: str, max_len: int = 20) -> str:
    """Truncate secret for display, keeping start and end."""
    if len(secret) <= max_len:
        return secret
    keep = (max_len - 3) // 2
    return f"{secret[:keep]}...{secret[-keep:]}"
