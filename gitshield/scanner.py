"""Secret detection — native engine + optional gitleaks fallback."""

import functools
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional

from .models import Finding, GitleaksNotFound, ScannerError, truncate_secret
from .engine import scan_directory, scan_file, _is_test_file  # noqa: F401


@functools.lru_cache(maxsize=None)
def _has_gitleaks() -> Optional[str]:
    """Return gitleaks binary path if installed, else None.

    Cached for the process lifetime — the binary won't appear or disappear
    during a single run, and this is called on every hook invocation.
    """
    return shutil.which("gitleaks")


def _scan_with_gitleaks(
    path: str,
    staged_only: bool = False,
    no_git: bool = False,
    gitleaks_path: Optional[str] = None,
) -> List[Finding]:
    """Run gitleaks and return findings. Raises GitleaksNotFound if missing."""
    gitleaks = gitleaks_path or _has_gitleaks()
    if not gitleaks:
        raise GitleaksNotFound(
            "gitleaks not found. Install with: brew install gitleaks\n"
            "  (GitShield's native engine is still active)"
        )

    tmp_dir = tempfile.mkdtemp()
    report_path = str(Path(tmp_dir) / "report.json")
    # Restrict report file permissions on multi-user systems.
    os.chmod(tmp_dir, 0o700)

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

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.stderr and "error" in result.stderr.lower():
            raise ScannerError(f"Gitleaks error: {result.stderr.strip()}")

        report_file = Path(report_path)
        if report_file.exists():
            os.chmod(report_path, 0o600)
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
                secret=truncate_secret(item.get("Secret", "")),
                fingerprint=item.get("Fingerprint", ""),
                entropy=item.get("Entropy", 0.0),
                commit=item.get("Commit"),
                author=item.get("Author"),
            ))

        return findings

    except subprocess.TimeoutExpired:
        import sys
        print("gitshield: gitleaks timed out, using native engine only", file=sys.stderr)
        return []
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def scan_path(
    path: str,
    staged_only: bool = False,
    no_git: bool = False,
    config_threshold: Optional[float] = None,
    extra_patterns: Optional[List] = None,
    scan_tests: bool = True,
) -> List[Finding]:
    """Scan a path for secrets using native engine + optional gitleaks.

    The native engine always runs. If gitleaks is installed, both engines
    run and results are merged (deduplicated by fingerprint).

    Args:
        path: File or directory path to scan.
        staged_only: Scan only git-staged files.
        no_git: Ignore git entirely.
        config_threshold: Entropy threshold override for patterns without one.
        extra_patterns: Additional Pattern objects beyond the built-in list.
    """
    resolved = Path(path).resolve()
    if not resolved.exists():
        raise ScannerError(f"Path does not exist: {path}")

    # Always run native engine
    if resolved.is_file():
        # Respect scan_tests flag for single-file scans (consistent with scan_directory).
        if not scan_tests and _is_test_file(resolved.name):
            return []
        native_findings = scan_file(
            resolved,
            config_threshold=config_threshold,
            extra_patterns=extra_patterns,
        )
    else:
        native_findings = scan_directory(
            resolved,
            staged_only=staged_only,
            no_git=no_git,
            config_threshold=config_threshold,
            extra_patterns=extra_patterns,
            scan_tests=scan_tests,
        )

    # Try gitleaks as supplement (not required)
    gitleaks_findings: List[Finding] = []
    gitleaks_bin = _has_gitleaks()
    if gitleaks_bin:
        try:
            # Pass resolved absolute path to prevent flag injection (e.g. path="--help")
            gitleaks_findings = _scan_with_gitleaks(str(resolved), staged_only, no_git, gitleaks_path=gitleaks_bin)
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


