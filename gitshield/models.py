"""Core data types shared across the GitShield package.

Extracted to break the circular import between scanner.py and engine.py.
"""

from dataclasses import dataclass
from typing import Optional


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


def truncate_secret(secret: str, max_len: int = 20) -> str:
    """Truncate a secret value for safe display, keeping both start and end.

    For long secrets this produces ``start...end`` which is more useful for
    identification than a start-only truncation (both engines now use the same
    format regardless of whether the finding came from the native engine or
    gitleaks).
    """
    if len(secret) <= max_len:
        return secret
    keep = (max_len - 3) // 2
    return f"{secret[:keep]}...{secret[-keep:]}"


class ScannerError(Exception):
    """Scanner-related errors."""
    pass


class GitleaksNotFound(ScannerError):
    """Gitleaks binary not installed (non-fatal — native engine still works)."""
    pass
