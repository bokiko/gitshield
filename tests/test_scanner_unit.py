"""Unit tests for the scanner orchestrator (gitshield/scanner.py)."""

import shutil

import pytest

import gitshield.scanner as scanner_mod
from gitshield.models import ScannerError
from gitshield.scanner import scan_path, _has_gitleaks


# ---------------------------------------------------------------------------
# scan_path: error handling
# ---------------------------------------------------------------------------

class TestScanPathErrors:
    """scan_path should raise ScannerError for bad inputs."""

    def test_raises_on_nonexistent_path(self, tmp_path):
        missing = str(tmp_path / "does_not_exist.py")
        with pytest.raises(ScannerError, match="does not exist"):
            scan_path(missing)

    def test_raises_on_nonexistent_directory(self, tmp_path):
        missing_dir = str(tmp_path / "ghost_dir")
        with pytest.raises(ScannerError):
            scan_path(missing_dir)


# ---------------------------------------------------------------------------
# scan_path: single file
# ---------------------------------------------------------------------------

class TestScanPathFile:
    """scan_path on a single file should delegate to the native engine."""

    def test_returns_findings_for_secret_file(self, tmp_path):
        """A file containing an AWS key should yield at least one finding."""
        secret_file = tmp_path / "config.py"
        secret_file.write_text('AWS_KEY = "AKIA1234567890ABCDEF"\n')

        findings = scan_path(str(secret_file))

        assert len(findings) >= 1
        rule_ids = [f.rule_id for f in findings]
        assert "aws-access-key-id" in rule_ids

    def test_returns_empty_list_for_clean_file(self, tmp_path):
        """A file with no secrets should return an empty list."""
        clean_file = tmp_path / "main.py"
        clean_file.write_text("def hello():\n    print('hello world')\n")

        findings = scan_path(str(clean_file))

        assert findings == []

    def test_returns_empty_list_for_empty_file(self, tmp_path):
        """An empty file should return an empty list without error."""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        findings = scan_path(str(empty_file))

        assert findings == []

    def test_findings_have_expected_fields(self, tmp_path):
        """Each Finding should expose file, line, rule_id, secret, fingerprint."""
        secret_file = tmp_path / "secrets.env"
        secret_file.write_text('KEY="AKIA1234567890ABCDEF"\n')

        findings = scan_path(str(secret_file))
        assert findings, "Expected at least one finding"

        f = findings[0]
        assert hasattr(f, "file")
        assert hasattr(f, "line")
        assert hasattr(f, "rule_id")
        assert hasattr(f, "secret")
        assert hasattr(f, "fingerprint")


# ---------------------------------------------------------------------------
# scan_path: directory
# ---------------------------------------------------------------------------

class TestScanPathDirectory:
    """scan_path on a directory should walk and find secrets."""

    def test_detects_secret_in_subdirectory(self, tmp_path):
        subdir = tmp_path / "src"
        subdir.mkdir()
        (subdir / "creds.py").write_text('token = "AKIA1234567890ABCDEF"\n')

        findings = scan_path(str(tmp_path), no_git=True)

        rule_ids = [f.rule_id for f in findings]
        assert "aws-access-key-id" in rule_ids

    def test_clean_directory_returns_empty(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")

        findings = scan_path(str(tmp_path), no_git=True)

        assert findings == []


# ---------------------------------------------------------------------------
# _has_gitleaks: caching
# ---------------------------------------------------------------------------

class TestHasGitleaksCaching:
    """_has_gitleaks uses lru_cache — verify it caches and respects shutil.which."""

    def test_returns_none_when_gitleaks_missing(self, monkeypatch):
        """When shutil.which returns None, _has_gitleaks should return None."""
        # Clear cache so the monkeypatch takes effect
        _has_gitleaks.cache_clear()
        monkeypatch.setattr(shutil, "which", lambda name: None)

        result = _has_gitleaks()
        assert result is None

        _has_gitleaks.cache_clear()

    def test_returns_path_when_gitleaks_present(self, monkeypatch):
        """When shutil.which finds the binary, _has_gitleaks returns its path."""
        _has_gitleaks.cache_clear()
        monkeypatch.setattr(shutil, "which", lambda name: "/usr/local/bin/gitleaks")

        result = _has_gitleaks()
        assert result == "/usr/local/bin/gitleaks"

        _has_gitleaks.cache_clear()

    def test_result_is_cached(self, monkeypatch):
        """shutil.which should be called only once across multiple invocations."""
        _has_gitleaks.cache_clear()

        call_count = 0

        def counting_which(name):
            nonlocal call_count
            call_count += 1
            return "/usr/bin/gitleaks"

        monkeypatch.setattr(shutil, "which", counting_which)

        _has_gitleaks()
        _has_gitleaks()
        _has_gitleaks()

        assert call_count == 1, (
            f"shutil.which called {call_count} times — cache is not working"
        )

        _has_gitleaks.cache_clear()


# ---------------------------------------------------------------------------
# Verify _truncate_secret was removed from scanner.py
# ---------------------------------------------------------------------------

class TestDeadCodeRemoved:
    """Confirm the dead _truncate_secret function is gone from scanner.py."""

    def test_truncate_secret_not_in_scanner_module(self):
        """scanner.py must not define _truncate_secret as a module-level attribute."""
        assert not hasattr(scanner_mod, "_truncate_secret"), (
            "_truncate_secret was supposed to be removed from scanner.py "
            "but is still present as a module attribute."
        )

    def test_truncate_secret_source_not_in_scanner(self):
        """Verify by reading the source that _truncate_secret is absent."""
        import inspect
        source = inspect.getsource(scanner_mod)
        assert "def _truncate_secret" not in source, (
            "Found 'def _truncate_secret' in scanner.py source — "
            "this dead function should have been removed."
        )
