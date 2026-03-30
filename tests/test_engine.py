"""Tests for the native secret detection engine (engine.py)."""


from gitshield.engine import scan_content, scan_file, scan_directory, scan_text, _parse_gitignore
from gitshield.patterns import entropy


# ---------------------------------------------------------------------------
# Detection: specific secret types
# ---------------------------------------------------------------------------

class TestDetection:
    """Verify that known secret patterns are correctly detected."""

    def test_detect_aws_access_key(self):
        findings = scan_content("my key is AKIA1234567890ABCDEF")
        rule_ids = [f.rule_id for f in findings]
        assert "aws-access-key-id" in rule_ids

    def test_detect_github_pat(self):
        findings = scan_content("token=ghp_ABCDEFghijklmn1234567890abcdefghij")
        rule_ids = [f.rule_id for f in findings]
        assert "github-pat" in rule_ids

    def test_detect_private_key(self):
        findings = scan_content("-----BEGIN RSA PRIVATE KEY-----")
        rule_ids = [f.rule_id for f in findings]
        assert "rsa-private-key" in rule_ids

    def test_detect_mongodb_url(self):
        findings = scan_content("mongodb://user:pass@host:27017/db")
        rule_ids = [f.rule_id for f in findings]
        assert "mongodb-connection-string" in rule_ids

    def test_detect_slack_token(self):
        # Built via concat to avoid GitHub push protection false positive
        token = "xoxb-" + "1234567890-1234567890-ABCDEFghijklmnopqrstuvwx"
        findings = scan_content(token)
        rule_ids = [f.rule_id for f in findings]
        assert "slack-bot-token" in rule_ids

    def test_detect_stripe_key(self):
        # Built via concat to avoid GitHub push protection false positive
        key = "sk_" + "live_ABCDEFghijklmnopqrstuvwx"
        findings = scan_content(key)
        rule_ids = [f.rule_id for f in findings]
        assert "stripe-secret-key" in rule_ids


# ---------------------------------------------------------------------------
# False positive prevention
# ---------------------------------------------------------------------------

class TestFalsePositives:
    """Ensure benign content does not trigger detections."""

    def test_no_false_positive_plain_text(self):
        findings = scan_content("This is just normal text with no secrets.")
        assert findings == []

    def test_no_false_positive_short_password(self):
        findings = scan_content("password=abc")
        assert findings == []


# ---------------------------------------------------------------------------
# Inline ignore directives
# ---------------------------------------------------------------------------

class TestInlineIgnore:
    """Verify that gitshield:ignore comments suppress findings."""

    def test_inline_ignore(self):
        findings = scan_content("AKIA1234567890ABCDEF # gitshield:ignore")
        assert findings == []

    def test_inline_ignore_js(self):
        findings = scan_content("AKIA1234567890ABCDEF // gitshield:ignore")
        assert findings == []


# ---------------------------------------------------------------------------
# Entropy function
# ---------------------------------------------------------------------------

class TestEntropy:
    """Validate the Shannon entropy helper."""

    def test_entropy_function(self):
        low = entropy("aaaa")
        high = entropy("a1b2c3d4e5f6")
        assert low < high, f"Expected entropy('aaaa')={low} < entropy('a1b2c3d4e5f6')={high}"

    def test_entropy_empty_string(self):
        assert entropy("") == 0.0


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

class TestFileScanning:
    """Test scan_file and scan_directory behaviour."""

    def test_scan_file(self, tmp_path):
        """A temp file containing a secret should produce at least one finding."""
        secret_file = tmp_path / "creds.py"
        secret_file.write_text('AWS_KEY = "AKIA1234567890ABCDEF"\n')

        findings = scan_file(str(secret_file))
        assert len(findings) >= 1
        rule_ids = [f.rule_id for f in findings]
        assert "aws-access-key-id" in rule_ids

    def test_scan_file_binary_skip(self, tmp_path):
        """Files with null bytes in the first 8 KB should be silently skipped."""
        binary_file = tmp_path / "data.bin"
        binary_file.write_bytes(b"AKIA1234567890ABCDEF\x00binary junk")

        findings = scan_file(str(binary_file))
        assert findings == []

    def test_scan_directory(self, tmp_path):
        """scan_directory should recurse and find secrets in child files."""
        subdir = tmp_path / "src"
        subdir.mkdir()
        secret_file = subdir / "config.py"
        secret_file.write_text('TOKEN = "ghp_ABCDEFghijklmn1234567890abcdefghij"\n')

        findings = scan_directory(str(tmp_path))
        assert len(findings) >= 1
        rule_ids = [f.rule_id for f in findings]
        assert "github-pat" in rule_ids

    def test_scan_directory_skips_git(self, tmp_path):
        """Files inside .git/ should be skipped, even if they contain secrets."""
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        config_file = git_dir / "config"
        config_file.write_text('key = "AKIA1234567890ABCDEF"\n')

        # Also create a clean file outside .git so the scan has something to walk
        clean = tmp_path / "readme.txt"
        clean.write_text("Nothing secret here.\n")

        findings = scan_directory(str(tmp_path))
        files_with_findings = [f.file for f in findings]
        assert not any(".git" in p for p in files_with_findings)

    def test_scan_file_fixture(self, fixtures_dir):
        """The bundled secret_file.py fixture should produce findings."""
        findings = scan_file(str(fixtures_dir / "secret_file.py"))
        assert len(findings) >= 2  # AWS key + GitHub PAT

    def test_scan_file_clean_fixture(self, fixtures_dir):
        """The bundled clean_file.py fixture should produce no findings."""
        findings = scan_file(str(fixtures_dir / "clean_file.py"))
        assert findings == []


# ---------------------------------------------------------------------------
# Multiple findings on a single line
# ---------------------------------------------------------------------------

class TestMultipleFindings:
    """Lines with multiple secret types should produce multiple findings."""

    def test_multiple_findings_per_line(self):
        line = "AKIA1234567890ABCDEF -----BEGIN RSA PRIVATE KEY-----"
        findings = scan_content(line)
        rule_ids = [f.rule_id for f in findings]
        assert "aws-access-key-id" in rule_ids
        assert "rsa-private-key" in rule_ids
        assert len(findings) >= 2


# ---------------------------------------------------------------------------
# .gitignore parsing
# ---------------------------------------------------------------------------

class TestGitignoreParsing:
    """Test _parse_gitignore reads and filters .gitignore correctly."""

    def test_parse_gitignore_returns_patterns(self, tmp_path):
        """_parse_gitignore should return the non-comment, non-blank patterns."""
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("*.pyc\ndist/\nbuild/\n")

        patterns = _parse_gitignore(tmp_path)
        assert "*.pyc" in patterns
        assert "dist/" in patterns
        assert "build/" in patterns
        assert len(patterns) == 3

    def test_parse_gitignore_skips_comments_and_blank_lines(self, tmp_path):
        """Comments (# ...) and blank lines must not appear in the returned list."""
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text(
            "# This is a comment\n"
            "\n"
            "*.log\n"
            "\n"
            "# Another comment\n"
            "secret.txt\n"
        )

        patterns = _parse_gitignore(tmp_path)
        assert "*.log" in patterns
        assert "secret.txt" in patterns
        for p in patterns:
            assert not p.startswith("#"), f"Comment leaked into patterns: {p!r}"
        assert len(patterns) == 2

    def test_parse_gitignore_missing_returns_empty(self, tmp_path):
        """When no .gitignore exists, _parse_gitignore should return an empty list."""
        patterns = _parse_gitignore(tmp_path)
        assert patterns == []


# ---------------------------------------------------------------------------
# scan_directory options
# ---------------------------------------------------------------------------

class TestScanDirectoryOptions:
    """Test optional behaviours of scan_directory."""

    def test_scan_directory_skips_test_files_when_scan_tests_false(self, tmp_path):
        """With scan_tests=False, test_*.py files must not be scanned."""
        test_file = tmp_path / "test_secrets.py"
        test_file.write_text('KEY = "AKIA1234567890ABCDEF"\n')

        findings = scan_directory(str(tmp_path), scan_tests=False, no_git=True)
        scanned_files = [f.file for f in findings]
        assert not any("test_secrets" in fp for fp in scanned_files), (
            "test_secrets.py should have been skipped but findings were returned"
        )

    def test_scan_text_line_offset_produces_correct_line_numbers(self):
        """line_offset should shift reported line numbers by the given amount."""
        # The secret is on the first line of this text snippet, but it lives at
        # absolute line 10 in its source file, so we pass line_offset=9.
        text = 'KEY = "AKIA1234567890ABCDEF"\n'
        findings = scan_text(text, filename="src/config.py", line_offset=9)
        assert len(findings) >= 1
        for f in findings:
            # line_offset=9 means first line (idx=1) -> reported as 10
            assert f.line >= 10, (
                f"Expected line >= 10 with offset 9, got {f.line}"
            )


# ---------------------------------------------------------------------------
# File size cap
# ---------------------------------------------------------------------------

class TestFileSizeCap:
    """scan_file must silently skip files larger than 1 MB."""

    def test_scan_file_skips_oversized_file(self, tmp_path):
        """A file larger than 1 MB should return an empty findings list."""
        large_file = tmp_path / "huge.py"
        # Write slightly more than 1 MB of text that would otherwise trigger a
        # pattern (embed a fake AWS key repeated throughout).
        chunk = 'KEY = "AKIA1234567890ABCDEF"\n' * 100  # ~2.8 KB per 100 lines
        repeats = (1_048_576 // len(chunk)) + 2          # enough to exceed 1 MB
        large_file.write_text(chunk * repeats)

        assert large_file.stat().st_size > 1_048_576, "Pre-condition: file must exceed 1 MB"

        findings = scan_file(str(large_file))
        assert findings == [], (
            f"Expected no findings for oversized file, got {len(findings)}"
        )
