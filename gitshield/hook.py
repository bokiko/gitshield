"""Claude Code hook handler — scans tool inputs for secrets before execution."""

import json
import sys
from typing import List

from .engine import scan_content
from .scanner import Finding


# Files that should legitimately contain secrets (don't block)
ALLOWED_PATHS = [
    ".env.example",
    ".env.template",
    ".env.sample",
    "*.test.*",
    "*.spec.*",
    "fixtures/",
    "__fixtures__/",
    "testdata/",
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
]


def _is_allowed_path(filepath: str) -> bool:
    """Check if filepath is in the allowlist (test files, examples, etc.)."""
    import fnmatch
    lower = filepath.lower()
    for pattern in ALLOWED_PATHS:
        if pattern.endswith("/"):
            if f"/{pattern}" in lower or lower.startswith(pattern):
                return True
        elif "*" in pattern:
            if fnmatch.fnmatch(filepath.split("/")[-1], pattern):
                return True
        elif lower.endswith(pattern):
            return True
    return False


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

    # Handle Write / Edit tools
    if tool_name in ("Write", "Edit"):
        filepath = str(tool_input.get("file_path", tool_input.get("path", "")))

        # Skip allowed paths
        if _is_allowed_path(filepath):
            return {"result": "approve"}

        # Get content to scan
        content = str(tool_input.get("content", ""))
        if not content:
            content = str(tool_input.get("new_string", ""))

        if not content:
            return {"result": "approve"}

        findings = scan_content(content, context=filepath or "file")

        if findings:
            if _is_sensitive_path(filepath):
                return {
                    "result": "block",
                    "reason": _format_block_reason(findings, filepath),
                }
            # Non-sensitive path: block on critical/high, warn on medium/low
            critical = [f for f in findings if f.severity in ("critical", "high")]
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

        findings = scan_content(command, context="bash-command")

        if findings:
            critical = [f for f in findings if f.severity in ("critical", "high")]
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
    except Exception:
        # Fail open — never block on hook errors
        print(json.dumps({"result": "approve"}))
    sys.exit(0)


if __name__ == "__main__":
    main()
