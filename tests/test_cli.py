"""Tests for the CLI interface (cli.py) using click.testing.CliRunner."""

import json

import pytest
from click.testing import CliRunner

from gitshield.cli import main


@pytest.fixture
def runner():
    """Provide a CliRunner instance for every test."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------

class TestScanCommand:
    """Test the `gitshield scan` subcommand."""

    def test_scan_no_secrets(self, runner, tmp_path):
        """Scanning a clean directory should exit 0."""
        clean_file = tmp_path / "hello.py"
        clean_file.write_text("print('hello')\n")

        result = runner.invoke(main, ["scan", str(tmp_path), "--no-git"])
        assert result.exit_code == 0

    def test_scan_with_secrets(self, runner, tmp_path):
        """Scanning a directory with secrets should exit 1."""
        secret_file = tmp_path / "creds.py"
        secret_file.write_text('KEY = "AKIA1234567890ABCDEF"\n')

        result = runner.invoke(main, ["scan", str(tmp_path), "--no-git"])
        assert result.exit_code == 1

    def test_scan_json_output(self, runner, tmp_path):
        """--json flag should produce valid JSON output."""
        secret_file = tmp_path / "creds.py"
        secret_file.write_text('KEY = "AKIA1234567890ABCDEF"\n')

        result = runner.invoke(main, ["scan", str(tmp_path), "--no-git", "--json"])
        # JSON mode should still exit 1 when findings exist
        assert result.exit_code == 1

        # Output should be valid JSON
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert "rule_id" in data[0]
        assert "file" in data[0]

    def test_scan_sarif_output(self, runner, tmp_path):
        """--sarif flag should produce valid SARIF JSON output."""
        secret_file = tmp_path / "creds.py"
        secret_file.write_text('KEY = "AKIA1234567890ABCDEF"\n')

        result = runner.invoke(main, ["scan", str(tmp_path), "--no-git", "--sarif"])
        assert result.exit_code == 1

        sarif = json.loads(result.output)
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "GitShield"
        assert len(run["results"]) >= 1

    def test_scan_clean_json_output(self, runner, tmp_path):
        """--json on a clean directory should output an empty JSON array."""
        clean_file = tmp_path / "hello.py"
        clean_file.write_text("print('hello')\n")

        result = runner.invoke(main, ["scan", str(tmp_path), "--no-git", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data == []


# ---------------------------------------------------------------------------
# Version and help
# ---------------------------------------------------------------------------

class TestMetaCommands:
    """Test --version and --help flags."""

    def test_version(self, runner):
        """--version should display the version string."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_help(self, runner):
        """--help should display usage information."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Secret scanner" in result.output or "Usage" in result.output


# ---------------------------------------------------------------------------
# Init command
# ---------------------------------------------------------------------------

class TestInitCommand:
    """Test the `gitshield init` subcommand."""

    def test_init_creates_config(self, runner, tmp_path):
        """init command should create .gitshield.toml in the repo root."""
        # Create a .git dir so find_git_root resolves to tmp_path
        (tmp_path / ".git").mkdir()

        result = runner.invoke(main, ["init", "--path", str(tmp_path)])
        assert result.exit_code == 0

        config_path = tmp_path / ".gitshield.toml"
        assert config_path.exists()

        content = config_path.read_text()
        assert "[scan]" in content
        assert "[allowlist]" in content
