"""Pretty terminal output for scan results."""

import json
import sys
from typing import List

from . import __version__
from .scanner import Finding


# ANSI colors
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def supports_color() -> bool:
    """Check if terminal supports color."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def colorize(text: str, *codes: str) -> str:
    """Apply color codes if supported."""
    if not supports_color():
        return text
    return "".join(codes) + text + Colors.RESET


def print_findings(findings: List[Finding], quiet: bool = False) -> None:
    """Print findings in human-readable format."""
    if not findings:
        if not quiet:
            print(colorize("No secrets found.", Colors.GREEN, Colors.BOLD))
        return

    count = len(findings)
    header = f"{count} secret{'s' if count != 1 else ''} found"

    print()
    print(colorize(f"  {header}", Colors.RED, Colors.BOLD))
    print()

    for f in findings:
        # File and line
        location = f"{f.file}:{f.line}"
        print(colorize(f"  {location}", Colors.CYAN))

        # Rule type
        print(colorize("    Type: ", Colors.DIM) + f.rule_id)

        # Truncated secret
        print(colorize("    Secret: ", Colors.DIM) + colorize(f.secret, Colors.RED))

        # Fingerprint for ignoring
        print(colorize("    Fingerprint: ", Colors.DIM) + colorize(f.fingerprint, Colors.DIM))

        print()

    # Footer with copy-paste commands
    print(colorize("  False positive? Copy & paste to ignore:", Colors.YELLOW))
    print()
    for f in findings:
        cmd = f'echo "{f.fingerprint}" >> .gitshieldignore'
        print(colorize(f"    {cmd}", Colors.DIM))
    print()


def print_json(findings: List[Finding]) -> None:
    """Print findings as JSON."""
    data = [
        {
            "file": f.file,
            "line": f.line,
            "rule_id": f.rule_id,
            "secret": f.secret,
            "fingerprint": f.fingerprint,
        }
        for f in findings
    ]
    print(json.dumps(data, indent=2))


def format_findings_json(findings: List[Finding]) -> str:
    """Return findings as a JSON string.

    Same data as print_json but returns the string instead of printing.
    """
    data = [
        {
            "file": f.file,
            "line": f.line,
            "rule_id": f.rule_id,
            "secret": f.secret,
            "fingerprint": f.fingerprint,
        }
        for f in findings
    ]
    return json.dumps(data, indent=2)


def _severity_to_sarif_level(severity: str) -> str:
    """Map gitshield severity to SARIF level.

    SARIF defines three result levels: error, warning, note.
    """
    severity_lower = severity.lower()
    if severity_lower in ("critical", "high"):
        return "error"
    if severity_lower == "medium":
        return "warning"
    return "note"


def print_sarif(findings: List[Finding]) -> None:
    """Print findings in SARIF v2.1.0 format.

    SARIF (Static Analysis Results Interchange Format) is GitHub's
    native format for code scanning alerts. This produces a complete
    SARIF log object with a single run containing all findings.
    """
    # Collect unique rules from findings
    seen_rules = {}
    for f in findings:
        if f.rule_id not in seen_rules:
            seen_rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.rule_id},
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(f.severity),
                },
            }

    # Build results array
    results = []
    for f in findings:
        result = {
            "ruleId": f.rule_id,
            "message": {"text": f"Secret detected: {f.rule_id}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file},
                        "region": {"startLine": f.line},
                    }
                }
            ],
            "fingerprints": {"gitshield": f.fingerprint},
        }
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GitShield",
                        "version": __version__,
                        "informationUri": "https://github.com/bokiko/gitshield",
                        "rules": list(seen_rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    print(json.dumps(sarif, indent=2))


def print_blocked_message() -> None:
    """Print message when commit is blocked."""
    print()
    print(colorize("  Commit blocked. Remove secrets before committing.", Colors.RED, Colors.BOLD))
    print()
