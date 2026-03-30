"""Tests for the Claude Code hook handler (hook.py)."""


from gitshield.hook import handle_hook, _format_block_reason, _is_sensitive_path
from gitshield.models import Finding


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

    def test_handle_hook_block_test_file(self):
        """Write to a .test.js file should still block secrets (hook allowlist is restrictive)."""
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/auth.test.js",
                "content": 'const key = "AKIA1234567890ABCDEF";\n',
            },
        })
        assert result["result"] == "block"

    def test_handle_hook_approve_env_example(self):
        """Write to .env.example (allowlisted) should be approved even with secrets."""
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/.env.example",
                "content": 'AWS_KEY="AKIA1234567890ABCDEF"\n',
            },
        })
        assert result["result"] == "approve"

    def test_handle_hook_blocks_allowlist_bypass_via_suffix(self):
        """Write to a path like /secrets/malicious.env.example should NOT be allowlisted.

        SEC-001 regression: basename check prevents suffix-based bypass.
        """
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/secrets/malicious.env.example",
                "content": 'AWS_KEY="AKIA1234567890ABCDEF"\n',
            },
        })
        assert result["result"] == "block"

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


# ---------------------------------------------------------------------------
# Edit tool: approve / block
# ---------------------------------------------------------------------------

class TestEditToolHook:
    """Verify handle_hook behaviour for the Edit tool."""

    def test_handle_hook_edit_block_aws_key(self):
        """Edit with an AWS access key in new_string should be blocked."""
        result = handle_hook({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/app/src/config.py",
                "old_string": "AWS_KEY = None",
                "new_string": 'AWS_KEY = "AKIA1234567890ABCDEF"',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result

    def test_handle_hook_edit_approve_clean(self):
        """Edit with no secrets in new_string should be approved."""
        result = handle_hook({
            "tool_name": "Edit",
            "tool_input": {
                "file_path": "/app/src/config.py",
                "old_string": "DEBUG = False",
                "new_string": "DEBUG = True",
            },
        })
        assert result["result"] == "approve"


# ---------------------------------------------------------------------------
# Sensitive path detection
# ---------------------------------------------------------------------------

class TestSensitivePathDetection:
    """Verify _is_sensitive_path classification."""

    def test_pem_file_is_sensitive(self):
        """.pem extension should be recognised as sensitive."""
        assert _is_sensitive_path("/home/user/.ssh/server.pem") is True

    def test_key_file_is_sensitive(self):
        """.key extension should be recognised as sensitive."""
        assert _is_sensitive_path("/etc/ssl/private/mysite.key") is True

    def test_credentials_in_path_is_sensitive(self):
        """Path containing 'credentials' should be recognised as sensitive."""
        assert _is_sensitive_path("/app/config/credentials") is True

    def test_normal_path_is_not_sensitive(self):
        """Ordinary source file should not be flagged as sensitive."""
        assert _is_sensitive_path("/app/src/main.py") is False


# ---------------------------------------------------------------------------
# AI provider pattern detection
# ---------------------------------------------------------------------------

class TestAIPatternDetection:
    """Verify that AI-provider secrets are detected and blocked by the hook."""

    def test_openai_key_is_blocked(self):
        """OpenAI legacy API key (sk-...T3BlbkFJ...) should be blocked."""
        # Pattern: sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}
        # Split to avoid GitHub push protection flagging as a real secret.
        openai_key = "sk-" + "aBcDeFgHiJkLmNoPqRsT" + "T3BlbkFJ" + "aBcDeFgHiJkLmNoPqRsT"
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/client.py",
                "content": f'OPENAI_API_KEY = "{openai_key}"\n',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result

    def test_anthropic_key_is_blocked(self):
        """Anthropic API key (sk-ant-api03-...) should be blocked."""
        # Pattern: sk-ant-api03-[A-Za-z0-9\-_]{90,}
        anthropic_key = "sk-ant-api03-" + "A" * 95
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/client.py",
                "content": f'ANTHROPIC_API_KEY = "{anthropic_key}"\n',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result

    def test_huggingface_token_is_blocked(self):
        """Hugging Face token (hf_ followed by 34 alpha chars) should be blocked."""
        # Pattern: hf_[a-zA-Z]{34}
        hf_token = "hf_" + "A" * 34
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/model.py",
                "content": f'HF_TOKEN = "{hf_token}"\n',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result

    def test_groq_key_is_blocked(self):
        """Groq API key (gsk_ followed by 48 chars) should be blocked."""
        # Pattern: gsk_[A-Za-z0-9]{48,}
        groq_key = "gsk_" + "A" * 48
        result = handle_hook({
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/app/src/inference.py",
                "content": f'GROQ_API_KEY = "{groq_key}"\n',
            },
        })
        assert result["result"] == "block"
        assert "reason" in result
