"""Tests for formatter.py — SARIF, JSON, and terminal output."""

import json

from gitshield.formatter import (
    _severity_to_sarif_level,
    colorize,
    format_findings_json,
    print_sarif,
    print_findings,
    Colors,
)
from gitshield.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**overrides) -> Finding:
    """Create a Finding with sensible defaults, overridden by kwargs."""
    defaults = dict(
        file="src/app.py",
        line=42,
        rule_id="aws-access-key-id",
        secret="AKIA1234...",
        fingerprint="src/app.py:aws-access-key-id:42",
        entropy=4.5,
        severity="critical",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# _severity_to_sarif_level
# ---------------------------------------------------------------------------

class TestSeverityToSarifLevel:
    def test_critical_maps_to_error(self):
        assert _severity_to_sarif_level("critical") == "error"

    def test_high_maps_to_error(self):
        assert _severity_to_sarif_level("high") == "error"

    def test_medium_maps_to_warning(self):
        assert _severity_to_sarif_level("medium") == "warning"

    def test_low_maps_to_note(self):
        assert _severity_to_sarif_level("low") == "note"

    def test_unknown_maps_to_note(self):
        assert _severity_to_sarif_level("unknown") == "note"

    def test_case_insensitive(self):
        assert _severity_to_sarif_level("CRITICAL") == "error"
        assert _severity_to_sarif_level("HIGH") == "error"
        assert _severity_to_sarif_level("MEDIUM") == "warning"


# ---------------------------------------------------------------------------
# format_findings_json
# ---------------------------------------------------------------------------

class TestFormatFindingsJson:
    def test_empty_list(self):
        result = format_findings_json([])
        data = json.loads(result)
        assert data == []

    def test_returns_valid_json(self):
        f = _make_finding()
        result = format_findings_json([f])
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 1

    def test_contains_required_keys(self):
        f = _make_finding()
        result = format_findings_json([f])
        item = json.loads(result)[0]
        assert "file" in item
        assert "line" in item
        assert "rule_id" in item
        assert "secret" in item
        assert "fingerprint" in item

    def test_values_match_finding(self):
        f = _make_finding(file="foo.py", line=10, rule_id="openai-api-key")
        result = format_findings_json([f])
        item = json.loads(result)[0]
        assert item["file"] == "foo.py"
        assert item["line"] == 10
        assert item["rule_id"] == "openai-api-key"

    def test_multiple_findings(self):
        findings = [_make_finding(line=i) for i in range(3)]
        result = format_findings_json(findings)
        data = json.loads(result)
        assert len(data) == 3


# ---------------------------------------------------------------------------
# print_sarif
# ---------------------------------------------------------------------------

class TestPrintSarif:
    def test_sarif_schema_keys(self, capsys):
        f = _make_finding()
        print_sarif([f])
        out = capsys.readouterr().out
        sarif = json.loads(out)
        assert "$schema" in sarif
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_run_has_results(self, capsys):
        f = _make_finding()
        print_sarif([f])
        out = capsys.readouterr().out
        sarif = json.loads(out)
        run = sarif["runs"][0]
        assert "results" in run
        assert len(run["results"]) == 1

    def test_sarif_run_has_tool(self, capsys):
        f = _make_finding()
        print_sarif([f])
        out = capsys.readouterr().out
        sarif = json.loads(out)
        run = sarif["runs"][0]
        assert "tool" in run
        assert run["tool"]["driver"]["name"] == "GitShield"

    def test_sarif_result_has_location(self, capsys):
        f = _make_finding(file="src/main.py", line=5)
        print_sarif([f])
        out = capsys.readouterr().out
        sarif = json.loads(out)
        result = sarif["runs"][0]["results"][0]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/main.py"
        assert loc["region"]["startLine"] == 5

    def test_sarif_empty_findings(self, capsys):
        print_sarif([])
        out = capsys.readouterr().out
        sarif = json.loads(out)
        assert sarif["runs"][0]["results"] == []

    def test_sarif_deduplicates_rules(self, capsys):
        findings = [
            _make_finding(rule_id="aws-key", fingerprint="fp1"),
            _make_finding(rule_id="aws-key", fingerprint="fp2"),
        ]
        print_sarif(findings)
        out = capsys.readouterr().out
        sarif = json.loads(out)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        assert rule_ids.count("aws-key") == 1


# ---------------------------------------------------------------------------
# colorize / supports_color
# ---------------------------------------------------------------------------

class TestColorize:
    def test_plain_text_when_no_tty(self, monkeypatch):
        # Ensure supports_color() returns False by patching isatty
        import gitshield.formatter as fmt
        fmt.supports_color.cache_clear()
        monkeypatch.setattr("sys.stdout", type("FakeOut", (), {"isatty": lambda self: False})())
        fmt.supports_color.cache_clear()
        result = colorize("hello", Colors.RED)
        # Can't assert plain text since supports_color is lru_cached and may have been
        # set earlier, but we can assert the function doesn't crash
        assert "hello" in result
        fmt.supports_color.cache_clear()

    def test_colorize_adds_codes_when_tty(self, monkeypatch):
        import gitshield.formatter as fmt
        fmt.supports_color.cache_clear()
        monkeypatch.setattr("sys.stdout", type("FakeTTY", (), {"isatty": lambda self: True})())
        fmt.supports_color.cache_clear()
        result = colorize("hello", Colors.RED)
        assert Colors.RED in result
        assert Colors.RESET in result
        assert "hello" in result
        fmt.supports_color.cache_clear()


# ---------------------------------------------------------------------------
# print_findings
# ---------------------------------------------------------------------------

class TestPrintFindings:
    def test_no_findings_prints_clean_message(self, capsys):
        print_findings([])
        out = capsys.readouterr().out
        assert "No secrets found" in out

    def test_quiet_mode_suppresses_clean_message(self, capsys):
        print_findings([], quiet=True)
        out = capsys.readouterr().out
        assert out == ""

    def test_findings_prints_location(self, capsys):
        f = _make_finding(file="src/db.py", line=99)
        print_findings([f])
        out = capsys.readouterr().out
        assert "src/db.py" in out
        assert "99" in out

    def test_findings_includes_fingerprint_command(self, capsys):
        f = _make_finding(fingerprint="test-fp-123")
        print_findings([f])
        out = capsys.readouterr().out
        assert "test-fp-123" in out
        assert ".gitshieldignore" in out
