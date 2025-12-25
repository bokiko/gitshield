"""Pretty terminal output for scan results."""

import json
import sys
from typing import List

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
        print(colorize(f"    Type: ", Colors.DIM) + f.rule_id)

        # Truncated secret
        print(colorize(f"    Secret: ", Colors.DIM) + colorize(f.secret, Colors.RED))

        # Fingerprint for ignoring
        print(colorize(f"    Fingerprint: ", Colors.DIM) + colorize(f.fingerprint, Colors.DIM))

        print()

    # Footer with help
    print(colorize("  To ignore false positives:", Colors.YELLOW))
    print(colorize("    Add fingerprints to .gitshieldignore", Colors.DIM))
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


def print_blocked_message() -> None:
    """Print message when commit is blocked."""
    print()
    print(colorize("  Commit blocked. Remove secrets before committing.", Colors.RED, Colors.BOLD))
    print()
