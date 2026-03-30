"""Claude Code hook handler — scans tool inputs for secrets before execution."""

import json
import sys
from pathlib import Path
from typing import List

from .config import build_custom_patterns, load_config
from .engine import scan_content
from .models import Finding


# Files that should legitimately contain secrets (don't block).
# NOTE: This is intentionally more restrictive than the scan allowlist.
# Directory-based entries are excluded because the filepath comes from
# untrusted AI model input — a model could write secrets to a path like
# "fixtures/leaked.py" to bypass scanning.
ALLOWED_PATHS = [
    ".env.example",
    ".env.template",
    ".env.sample",
]

# Sensitive file paths (always block if secrets detected)
SENSITIVE_PATHS = [
    ".env",
    "credentials",
    "secret",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".htpasswd",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
]


def _is_allowed_path(filepath: str) -> bool:
    """Check if filepath is in the allowlist (example env files only).

    Matches only the basename to prevent bypass via paths like
    '/app/secrets/malicious.env.example'.
    """
    basename = Path(filepath).name.lower()
    return basename in ALLOWED_PATHS


def _is_sensitive_path(filepath: str) -> bool:
    """Check if filepath is sensitive (env files, keys, etc.)."""
    lower = filepath.lower()
    for pattern in SENSITIVE_PATHS:
        if lower.endswith(pattern) or f"/{pattern}" in lower:
            return True
    return False


def _format_block_reason(findings: List[Finding], filepath: str = "") -> str:
    """Build a human-readable block reason message."""
    types = sorted(set(f.rule_id for f in findings))
    type_list = ", ".join(types)

    parts = ["GITSHIELD: Blocked — secrets detected"]
    if filepath:
        parts[0] += f" in {filepath}"
    parts.append(f"  Found: {type_list}")
    parts.append(f"  Count: {len(findings)} finding(s)")
    parts.append("")
    parts.append("  To allowlist: add '# gitshield:ignore' to the line,")
    parts.append("  or add the path to .gitshield.toml [allowlist] paths.")

    return "\n".join(parts)


def handle_hook(input_data: dict) -> dict:
    """Process a single hook invocation.

    Args:
        input_data: Parsed JSON from Claude Code with tool_name and tool_input.

    Returns:
        Dict with "result" ("approve" or "block") and optional "reason".
    """
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # Load config for custom patterns and entropy threshold.
    try:
        config = load_config(Path("."))
        custom = build_custom_patterns(config) or None
        threshold = config.entropy_threshold
    except Exception:
        config = None
        custom = None
        threshold = None

    # Handle Write / Edit / NotebookEdit tools
    if tool_name in ("Write", "Edit", "NotebookEdit"):
        filepath = str(tool_input.get("file_path", tool_input.get("notebook_path", tool_input.get("path", ""))))

        # Skip allowed paths
        if _is_allowed_path(filepath):
            return {"result": "approve"}

        # Get content to scan
        content = str(tool_input.get("content", ""))
        if not content:
            content = str(tool_input.get("new_string", ""))
        if not content:
            content = str(tool_input.get("cell_source", ""))

        if not content:
            return {"result": "approve"}

        findings = scan_content(
            content, context=filepath or "file",
            config_threshold=threshold, extra_patterns=custom,
        )

        if findings:
            if _is_sensitive_path(filepath):
                return {
                    "result": "block",
                    "reason": _format_block_reason(findings, filepath),
                }
            # Non-sensitive path: block on critical/high/medium
            critical = [f for f in findings if f.severity in ("critical", "high", "medium")]
            if critical:
                return {
                    "result": "block",
                    "reason": _format_block_reason(critical, filepath),
                }

        return {"result": "approve"}

    # Handle Bash tool
    if tool_name == "Bash":
        command = str(tool_input.get("command", ""))
        if not command:
            return {"result": "approve"}

        findings = scan_content(
            command, context="bash-command",
            config_threshold=threshold, extra_patterns=custom,
        )

        if findings:
            critical = [f for f in findings if f.severity in ("critical", "high", "medium")]
            if critical:
                return {
                    "result": "block",
                    "reason": _format_block_reason(critical),
                }

        return {"result": "approve"}

    # Unknown tool — approve
    return {"result": "approve"}


def main() -> None:
    """Entry point for `gitshield claude-hook` command."""
    try:
        raw = sys.stdin.read()
        input_data = json.loads(raw)
        result = handle_hook(input_data)
        print(json.dumps(result))
    except Exception as e:
        # Fail open — never block on hook errors.
        print(json.dumps({"result": "approve"}))
        print(
            f"gitshield: scanning failed ({type(e).__name__}), "
            f"tool call approved without scan: {e}",
            file=sys.stderr,
        )
    sys.exit(0)


if __name__ == "__main__":
    main()
