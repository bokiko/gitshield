"""Tests for the native secret detection engine (engine.py)."""



from gitshield.engine import scan_content, scan_file, scan_directory
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
