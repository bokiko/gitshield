"""Tests for the Claude Code hook handler (hook.py)."""


from gitshield.hook import handle_hook, _format_block_reason
from gitshield.scanner import Finding


# ---------------------------------------------------------------------------
# Write tool: approve / block
# ---------------------------------------------------------------------------

class TestWriteToolHook:
    """Verify handle_hook behaviour for the Write tool."""

    def test_handle_hook_approve_clean(self):
        """Write with no secrets should be approved."""
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/main.py",
                "content": "print('hello world')\n",
            },
        })
        assert result["result"] == "approve"

    def test_handle_hook_block_aws_key(self):
        """Write containing an AWS access key should be blocked."""
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/config.py",
                "content": 'AWS_KEY = "AKIA1234567890ABCDEF"\n',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result

    def test_handle_hook_approve_test_file(self):
        """Write to a .test.js file (allowlisted) should be approved even with secrets."""
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/auth.test.js",
                "content": 'const key = "AKIA1234567890ABCDEF";\n',
            },
        })
        assert result["result"] == "approve"

    def test_handle_hook_block_sensitive_path(self):
        """Write to .env with any finding should be blocked (sensitive path)."""
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/.env",
                "content": 'AWS_KEY="AKIA1234567890ABCDEF"\n',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result

    def test_handle_hook_empty_content(self):
        """Write with empty content should be approved."""
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/empty.py",
                "content": "",
            },
        })
        assert result["result"] == "approve"


# ---------------------------------------------------------------------------
# Bash tool: approve / block
# ---------------------------------------------------------------------------

class TestBashToolHook:
    """Verify handle_hook behaviour for the Bash tool."""

    def test_handle_hook_bash_approve_clean(self):
        """Bash command with no secrets should be approved."""
        result = handle_hook({
            "tool_name": "Bash",
            "tool_input": {
                "command": "ls -la /tmp",
            },
        })
        assert result["result"] == "approve"

    def test_handle_hook_bash_block_secret(self):
        """Bash command containing an embedded AWS key should be blocked."""
        result = handle_hook({
            "tool_name": "Bash",
            "tool_input": {
                "command": 'export AWS_ACCESS_KEY_ID="AKIA1234567890ABCDEF"',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result


# ---------------------------------------------------------------------------
# Unknown tools and edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Test unknown tools and boundary conditions."""

    def test_handle_hook_unknown_tool(self):
        """An unknown tool name should be approved (fail open)."""
        result = handle_hook({
            "tool_name": "SomeUnknownTool",
            "tool_input": {
                "data": "AKIA1234567890ABCDEF",
            },
        })
        assert result["result"] == "approve"

    def test_handle_hook_missing_tool_name(self):
        """Missing tool_name should be approved."""
        result = handle_hook({
            "tool_input": {"content": "AKIA1234567890ABCDEF"},
        })
        assert result["result"] == "approve"

    def test_handle_hook_empty_input(self):
        """Completely empty input should be approved."""
        result = handle_hook({})
        assert result["result"] == "approve"


# ---------------------------------------------------------------------------
# Block reason formatting
# ---------------------------------------------------------------------------

class TestFormatBlockReason:
    """Verify the human-readable block reason message."""

    def test_format_block_reason(self):
        """Block reason should contain rule IDs and actionable guidance."""
        findings = [
            Finding(
                file="config.py",
                line=10,
                rule_id="aws-access-key-id",
                secret="AKIA1234...",
                fingerprint="config.py:aws-access-key-id:10",
                severity="critical",
            ),
            Finding(
                file="config.py",
                line=12,
                rule_id="github-pat",
                secret="ghp_ABCD...",
                fingerprint="config.py:github-pat:12",
                severity="critical",
            ),
        ]
        reason = _format_block_reason(findings, filepath="config.py")

        # Should contain rule IDs
        assert "aws-access-key-id" in reason
        assert "github-pat" in reason

        # Should contain the filepath
        assert "config.py" in reason

        # Should contain guidance on how to allowlist
        assert "gitshield:ignore" in reason
        assert ".gitshield.toml" in reason

        # Should mention the GITSHIELD prefix
        assert "GITSHIELD" in reason

    def test_format_block_reason_no_filepath(self):
        """Block reason without filepath should still be valid."""
        findings = [
            Finding(
                file="bash-command",
                line=1,
                rule_id="aws-access-key-id",
                secret="AKIA1234...",
                fingerprint="bash:aws-access-key-id:1",
                severity="critical",
            ),
        ]
        reason = _format_block_reason(findings)
        assert "GITSHIELD" in reason
        assert "aws-access-key-id" in reason
