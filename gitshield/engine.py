"""Native secret detection engine for GitShield.

Replaces the gitleaks binary dependency with pure Python regex + entropy
detection. Operates on text, files, and directory trees.
"""

import fnmatch
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Union

from .models import Finding, truncate_secret
from .patterns import entropy, PATTERNS

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

# ReDoS mitigations: cap gitignore pattern count and length.
_MAX_GITIGNORE_PATTERNS: int = 500
_MAX_GITIGNORE_PATTERN_LEN: int = 200

# Skip files larger than this (generated code, data files, etc.)
_MAX_FILE_SIZE: int = 1_048_576  # 1 MB

# Test file patterns -- skipped when scan_tests=False.
_TEST_FILE_PATTERNS = ("test_*.py", "*_test.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _should_skip_path(path: Path) -> bool:
    """Return True if *path* should be skipped based on directory name or extension."""
    # Check only directory components for skip-listed directory names (not filename).
    for part in path.parent.parts:
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
            # Skip pathologically long patterns that could cause ReDoS.
            if len(line) > _MAX_GITIGNORE_PATTERN_LEN:
                continue
            patterns.append(line)
    except OSError:
        pass
    return patterns[:_MAX_GITIGNORE_PATTERNS]


def _compile_gitignore_patterns(patterns: List[str]) -> List[tuple]:
    """Pre-compile gitignore patterns into (is_dir, compiled_regex) tuples."""
    compiled = []
    for pattern in patterns:
        if pattern.endswith("/"):
            dir_pattern = pattern.rstrip("/")
            compiled.append((True, re.compile(fnmatch.translate(dir_pattern))))
        else:
            compiled.append((False, re.compile(fnmatch.translate(pattern))))
    return compiled


def _matches_gitignore(rel_path: str, ignore_patterns: List[tuple]) -> bool:
    """Return True if *rel_path* matches any pre-compiled gitignore pattern."""
    path_obj = Path(rel_path)
    parts = path_obj.parts
    name = path_obj.name
    for is_dir, compiled_re in ignore_patterns:
        if is_dir:
            # Directory-only pattern: match against path components.
            if any(compiled_re.fullmatch(part) for part in parts):
                return True
        else:
            # Match against full relative path and also the basename.
            if compiled_re.fullmatch(rel_path):
                return True
            if compiled_re.fullmatch(name):
                return True
    return False


# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------

def scan_text(
    text: str,
    filename: str = "<stdin>",
    line_offset: int = 0,
    config_threshold: Optional[float] = None,
    extra_patterns: Optional[List] = None,
) -> List[Finding]:
    """Scan a text string line-by-line against all patterns.

    Args:
        text: The full text to scan.
        filename: Logical filename for reporting.
        line_offset: A 0-based offset added to the 1-based line index when
            computing the reported line number (``line_number = idx + line_offset``
            where ``idx`` starts at 1).  The default of 0 means the first line
            of *text* is reported as line 1.  To report absolute line numbers
            when *text* is a slice starting at line N of a larger file, pass
            ``line_offset=N-1`` so that the first scanned line is reported as N.

    Returns:
        List of Finding objects (one per pattern match per line).
    """
    findings: List[Finding] = []
    lines = text.splitlines()
    all_patterns = PATTERNS if not extra_patterns else list(PATTERNS) + list(extra_patterns)

    for idx, line in enumerate(lines, start=1):
        # Honour inline ignore directives.
        if any(marker in line for marker in _IGNORE_MARKERS):
            continue

        for pattern in all_patterns:
            match = pattern.regex.search(line)
            if match is None:
                continue

            matched_text = match.group(0)
            # Use the first capturing group for entropy/display when available.
            # This avoids prefix inflation (e.g. 'api_key = ' before the value).
            secret_text = (
                match.group(1)
                if match.lastindex and match.lastindex >= 1
                else matched_text
            )

            # Entropy gating: only applies to patterns that opt in via
            # entropy_threshold.  config_threshold overrides the pattern's
            # built-in threshold but does NOT add entropy gating to patterns
            # that don't request it (e.g. precise regex patterns like AWS keys).
            if pattern.entropy_threshold is not None:
                threshold = (
                    config_threshold
                    if config_threshold is not None
                    else pattern.entropy_threshold
                )
                ent = entropy(secret_text)
                if ent < threshold:
                    continue
            else:
                ent = 0.0

            line_number = idx + line_offset

            findings.append(Finding(
                file=filename,
                line=line_number,
                rule_id=pattern.id,
                secret=truncate_secret(secret_text),
                fingerprint=f"{filename}:{pattern.id}:{line_number}",
                entropy=ent,
                severity=pattern.severity,
            ))

    return findings


def scan_file(
    filepath: Union[str, Path],
    config_threshold: Optional[float] = None,
    extra_patterns: Optional[List] = None,
) -> List[Finding]:
    """Scan a single file for secrets.

    Binary files (null bytes in the first 8 KB) are silently skipped.
    Files that cannot be decoded are silently skipped.

    Args:
        filepath: Path to the file to scan.
        config_threshold: Entropy threshold override for patterns without one.
        extra_patterns: Additional Pattern objects beyond the built-in list.

    Returns:
        List of Finding objects.
    """
    filepath = Path(filepath)

    if not filepath.is_file():
        return []

    # Skip oversized files (generated code, data files, etc.)
    try:
        if filepath.stat().st_size > _MAX_FILE_SIZE:
            return []
    except OSError:
        return []

    # Single-read: check for binary (null bytes in first 8 KB) and decode in one pass.
    try:
        with open(filepath, "rb") as fh:
            raw = fh.read()
    except (OSError, IOError):
        return []

    if b"\x00" in raw[:8192]:
        return []

    try:
        text = raw.decode("utf-8", errors="replace")
    except (UnicodeDecodeError, ValueError):
        return []

    return scan_text(
        text,
        filename=str(filepath),
        config_threshold=config_threshold,
        extra_patterns=extra_patterns,
    )


def _is_test_file(filename: str) -> bool:
    """Return True if *filename* matches a test file pattern."""
    for pattern in _TEST_FILE_PATTERNS:
        if fnmatch.fnmatch(filename, pattern):
            return True
    return False


def scan_directory(
    path: Union[str, Path],
    staged_only: bool = False,
    no_git: bool = False,
    respect_gitignore: bool = True,
    config_threshold: Optional[float] = None,
    extra_patterns: Optional[List] = None,
    scan_tests: bool = True,
) -> List[Finding]:
    """Walk a directory tree and scan every eligible file.

    Args:
        path: Root directory to scan.
        staged_only: If True, only scan files staged in git (``git diff --cached``).
        no_git: If True, ignore git entirely (no gitignore, no staged filter).
        respect_gitignore: Honour ``.gitignore`` patterns (unless *no_git*).
        config_threshold: Entropy threshold override for patterns without one.
        extra_patterns: Additional Pattern objects beyond the built-in list.
        scan_tests: If False, skip test files (test_*.py, *_test.py).

    Returns:
        Aggregated list of Finding objects.
    """
    root = Path(path).resolve()
    if not root.is_dir():
        return []

    # ---- staged-only mode: delegate to git for the file list ----
    if staged_only:
        return _scan_staged(
            root,
            config_threshold=config_threshold,
            extra_patterns=extra_patterns,
            scan_tests=scan_tests,
        )

    # ---- full tree walk ----
    ignore_patterns: List[tuple] = []
    if respect_gitignore and not no_git:
        raw_patterns = _parse_gitignore(root)
        ignore_patterns = _compile_gitignore_patterns(raw_patterns)

    findings: List[Finding] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip directories in-place to prevent descending into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for filename in filenames:
            file_path = Path(dirpath) / filename

            if _should_skip_path(file_path):
                continue

            # Skip test files when scan_tests is disabled.
            if not scan_tests and _is_test_file(filename):
                continue

            # Gitignore filtering.
            if ignore_patterns:
                try:
                    rel = str(file_path.relative_to(root))
                except ValueError:
                    rel = str(file_path)
                if _matches_gitignore(rel, ignore_patterns):
                    continue

            findings.extend(
                scan_file(
                    file_path,
                    config_threshold=config_threshold,
                    extra_patterns=extra_patterns,
                )
            )

    return findings


def scan_content(
    content: str,
    context: str = "content",
    config_threshold: Optional[float] = None,
    extra_patterns: Optional[List] = None,
) -> List[Finding]:
    """Quick scan of arbitrary content (convenience wrapper for hooks).

    No file I/O — purely in-memory.

    Args:
        content: The text to scan.
        context: Label used as the ``file`` field in findings.
        config_threshold: Entropy threshold override for patterns without a threshold.
        extra_patterns: Additional Pattern objects beyond the built-in list.

    Returns:
        List of Finding objects.
    """
    return scan_text(
        content,
        filename=context,
        config_threshold=config_threshold,
        extra_patterns=extra_patterns,
    )


# ---------------------------------------------------------------------------
# Internal: staged-file scanning
# ---------------------------------------------------------------------------

def _scan_staged(
    root: Path,
    config_threshold: Optional[float] = None,
    extra_patterns: Optional[List] = None,
    scan_tests: bool = True,
) -> List[Finding]:
    """Scan only files staged in git inside *root*."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            cwd=str(root),
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return []
    except (OSError, FileNotFoundError):
        return []

    if result.returncode != 0:
        return []

    findings: List[Finding] = []
    for rel_name in result.stdout.strip().splitlines():
        rel_name = rel_name.strip()
        if not rel_name:
            continue
        file_path = (root / rel_name).resolve()
        if not file_path.is_relative_to(root):
            continue
        if _should_skip_path(file_path):
            continue
        if not scan_tests and _is_test_file(file_path.name):
            continue
        findings.extend(
            scan_file(
                file_path,
                config_threshold=config_threshold,
                extra_patterns=extra_patterns,
            )
        )

    return findings
