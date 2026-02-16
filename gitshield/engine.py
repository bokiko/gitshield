"""Native secret detection engine for GitShield.

Replaces the gitleaks binary dependency with pure Python regex + entropy
detection. Operates on text, files, and directory trees.
"""

import fnmatch
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set

from .patterns import ENTROPY_THRESHOLD, Pattern, entropy, PATTERNS
from .scanner import Finding

# Directories to always skip during tree walks.
_SKIP_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".env",
}

# Binary file extensions — never worth scanning.
_BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class",
}

# Inline ignore markers recognised in source code.
_IGNORE_MARKERS = (
    "# gitshield:ignore",
    "// gitshield:ignore",
    "-- gitshield:ignore",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _truncate(text: str, max_len: int = 20) -> str:
    """Truncate secret for safe display."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."


def _is_binary_file(filepath: Path) -> bool:
    """Return True if *filepath* looks like a binary file (null byte in first 8 KB)."""
    try:
        with open(filepath, "rb") as fh:
            chunk = fh.read(8192)
        return b"\x00" in chunk
    except (OSError, IOError):
        return True  # unreadable — treat as binary


def _should_skip_path(path: Path) -> bool:
    """Return True if *path* should be skipped based on directory name or extension."""
    # Check each component for skip-listed directory names.
    for part in path.parts:
        if part in _SKIP_DIRS:
            return True
    # Check binary extensions.
    if path.suffix.lower() in _BINARY_EXTENSIONS:
        return True
    return False


def _parse_gitignore(root: Path) -> List[str]:
    """Return a list of gitignore glob patterns from *root*/.gitignore."""
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []
    patterns: List[str] = []
    try:
        for line in gitignore.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
    except OSError:
        pass
    return patterns


def _matches_gitignore(rel_path: str, ignore_patterns: List[str]) -> bool:
    """Return True if *rel_path* matches any gitignore pattern."""
    for pattern in ignore_patterns:
        # Directory-only pattern (trailing slash): match against path components.
        if pattern.endswith("/"):
            dir_pattern = pattern.rstrip("/")
            if any(fnmatch.fnmatch(part, dir_pattern) for part in Path(rel_path).parts):
                return True
        else:
            # Match against full relative path and also the basename.
            if fnmatch.fnmatch(rel_path, pattern):
                return True
            if fnmatch.fnmatch(Path(rel_path).name, pattern):
                return True
    return False


# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------

def scan_text(
    text: str,
    filename: str = "<stdin>",
    line_offset: int = 0,
) -> List[Finding]:
    """Scan a text string line-by-line against all patterns.

    Args:
        text: The full text to scan.
        filename: Logical filename for reporting.
        line_offset: Added to every reported line number.

    Returns:
        List of Finding objects (one per pattern match per line).
    """
    findings: List[Finding] = []
    lines = text.splitlines()

    for idx, line in enumerate(lines, start=1):
        # Honour inline ignore directives.
        if any(marker in line for marker in _IGNORE_MARKERS):
            continue

        for pattern in PATTERNS:
            match = pattern.regex.search(line)
            if match is None:
                continue

            matched_text = match.group(0)

            # If the pattern specifies an entropy threshold, enforce it.
            if pattern.entropy_threshold is not None:
                ent = entropy(matched_text)
                if ent < pattern.entropy_threshold:
                    continue
            else:
                ent = entropy(matched_text)

            line_number = idx + line_offset

            findings.append(Finding(
                file=filename,
                line=line_number,
                rule_id=pattern.id,
                secret=_truncate(matched_text),
                fingerprint=f"{filename}:{pattern.id}:{line_number}",
                entropy=ent,
                severity=pattern.severity,
            ))

    return findings


def scan_file(filepath: str | Path) -> List[Finding]:
    """Scan a single file for secrets.

    Binary files (null bytes in the first 8 KB) are silently skipped.
    Files that cannot be decoded are silently skipped.

    Args:
        filepath: Path to the file to scan.

    Returns:
        List of Finding objects.
    """
    filepath = Path(filepath)

    if not filepath.is_file():
        return []

    if _is_binary_file(filepath):
        return []

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except (OSError, IOError):
        return []

    return scan_text(text, filename=str(filepath))


def scan_directory(
    path: str | Path,
    staged_only: bool = False,
    no_git: bool = False,
    respect_gitignore: bool = True,
) -> List[Finding]:
    """Walk a directory tree and scan every eligible file.

    Args:
        path: Root directory to scan.
        staged_only: If True, only scan files staged in git (``git diff --cached``).
        no_git: If True, ignore git entirely (no gitignore, no staged filter).
        respect_gitignore: Honour ``.gitignore`` patterns (unless *no_git*).

    Returns:
        Aggregated list of Finding objects.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        return []

    # ---- staged-only mode: delegate to git for the file list ----
    if staged_only:
        return _scan_staged(root)

    # ---- full tree walk ----
    ignore_patterns: List[str] = []
    if respect_gitignore and not no_git:
        ignore_patterns = _parse_gitignore(root)

    findings: List[Finding] = []

    for file_path in root.rglob("*"):
        if not file_path.is_file():
            continue

        if _should_skip_path(file_path):
            continue

        # Gitignore filtering.
        if ignore_patterns:
            try:
                rel = str(file_path.relative_to(root))
            except ValueError:
                rel = str(file_path)
            if _matches_gitignore(rel, ignore_patterns):
                continue

        findings.extend(scan_file(file_path))

    return findings


def scan_content(content: str, context: str = "content") -> List[Finding]:
    """Quick scan of arbitrary content (convenience wrapper for hooks).

    No file I/O — purely in-memory.

    Args:
        content: The text to scan.
        context: Label used as the ``file`` field in findings.

    Returns:
        List of Finding objects.
    """
    return scan_text(content, filename=context)


# ---------------------------------------------------------------------------
# Internal: staged-file scanning
# ---------------------------------------------------------------------------

def _scan_staged(root: Path) -> List[Finding]:
    """Scan only files staged in git inside *root*."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            cwd=str(root),
        )
    except (OSError, FileNotFoundError):
        return []

    if result.returncode != 0:
        return []

    findings: List[Finding] = []
    for rel_name in result.stdout.strip().splitlines():
        rel_name = rel_name.strip()
        if not rel_name:
            continue
        file_path = root / rel_name
        if _should_skip_path(file_path):
            continue
        findings.extend(scan_file(file_path))

    return findings
