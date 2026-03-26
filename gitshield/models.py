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


class ScannerError(Exception):
    """Scanner-related errors."""
    pass


class GitleaksNotFound(ScannerError):
    """Gitleaks binary not installed (non-fatal — native engine still works)."""
    pass
