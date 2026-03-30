"""Tests for configuration loading and finding filtering (config.py)."""


from gitshield.config import (
    GitShieldConfig,
    load_config,
    filter_findings,
    create_default_config,
    find_git_root,
    load_ignore_list,
    build_custom_patterns,
    CONFIG_FILE,
)
from gitshield.scanner import Finding


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
# Config loading
# ---------------------------------------------------------------------------

class TestLoadConfig:
    """Test config loading from .gitshield.toml."""

    def test_load_config_defaults(self, tmp_path):
        """When no config file exists, load_config returns default GitShieldConfig."""
        # Create a .git directory so find_git_root resolves to tmp_path
        (tmp_path / ".git").mkdir()

        config = load_config(tmp_path)
        assert isinstance(config, GitShieldConfig)
        assert config.entropy_threshold == 4.5
        assert config.scan_tests is False
        assert config.allowlist_paths == []
        assert config.allowlist_rules == []
        assert config.allowlist_fingerprints == set()
        assert config.custom_patterns == []

    def test_load_config_toml(self, tmp_path):
        """Loading a valid .gitshield.toml populates the config correctly."""
        (tmp_path / ".git").mkdir()

        toml_content = """\
[scan]
entropy_threshold = 5.0
scan_tests = true

[allowlist]
paths = ["*.test.*", "docs/**"]
rules = ["generic-password"]
fingerprints = ["fp1", "fp2"]
"""
        (tmp_path / CONFIG_FILE).write_text(toml_content)

        config = load_config(tmp_path)
        assert config.entropy_threshold == 5.0
        assert config.scan_tests is True
        assert "*.test.*" in config.allowlist_paths
        assert "docs/**" in config.allowlist_paths
        assert "generic-password" in config.allowlist_rules
        assert config.allowlist_fingerprints == {"fp1", "fp2"}


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

class TestFilterFindings:
    """Test the filter_findings function with various ignore/allowlist configs."""

    def test_filter_findings_fingerprint(self):
        """Findings matching an ignored fingerprint should be removed."""
        f1 = _make_finding(fingerprint="keep-me")
        f2 = _make_finding(fingerprint="drop-me")

        result = filter_findings([f1, f2], ignores={"drop-me"})
        assert len(result) == 1
        assert result[0].fingerprint == "keep-me"

    def test_filter_findings_rule(self):
        """Findings matching an allowlisted rule_id should be removed."""
        f1 = _make_finding(rule_id="aws-access-key-id")
        f2 = _make_finding(rule_id="generic-password")

        config = GitShieldConfig(allowlist_rules=["generic-password"])
        result = filter_findings([f1, f2], ignores=set(), config=config)
        assert len(result) == 1
        assert result[0].rule_id == "aws-access-key-id"

    def test_filter_findings_path(self):
        """Findings whose file path matches an allowlist glob should be removed."""
        f1 = _make_finding(file="src/app.py")
        f2 = _make_finding(file="tests/test_app.test.py")

        config = GitShieldConfig(allowlist_paths=["*.test.*"])
        result = filter_findings([f1, f2], ignores=set(), config=config)
        assert len(result) == 1
        assert result[0].file == "src/app.py"

    def test_filter_findings_config_fingerprints(self):
        """Fingerprints in config.allowlist_fingerprints should also be filtered."""
        f1 = _make_finding(fingerprint="toml-ignore")
        f2 = _make_finding(fingerprint="keep")

        config = GitShieldConfig(allowlist_fingerprints={"toml-ignore"})
        result = filter_findings([f1, f2], ignores=set(), config=config)
        assert len(result) == 1
        assert result[0].fingerprint == "keep"

    def test_filter_findings_no_config(self):
        """With no config and no ignores, all findings pass through."""
        f1 = _make_finding()
        result = filter_findings([f1], ignores=set())
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Default config creation
# ---------------------------------------------------------------------------

class TestCreateDefaultConfig:
    """Test creation of .gitshield.toml with defaults."""

    def test_create_default_config(self, tmp_path):
        """create_default_config should write a .gitshield.toml file."""
        (tmp_path / ".git").mkdir()

        config_path = create_default_config(tmp_path)
        assert config_path.exists()
        assert config_path.name == CONFIG_FILE

        content = config_path.read_text()
        assert "entropy_threshold" in content
        assert "[scan]" in content
        assert "[allowlist]" in content


# ---------------------------------------------------------------------------
# Git root discovery
# ---------------------------------------------------------------------------

class TestFindGitRoot:
    """Test git root discovery."""

    def test_find_git_root(self, tmp_path):
        """find_git_root should find the nearest ancestor with a .git directory."""
        (tmp_path / ".git").mkdir()
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)

        root = find_git_root(nested)
        assert root == tmp_path.resolve()

    def test_find_git_root_no_git(self, tmp_path):
        """Without a .git dir, find_git_root returns the start path resolved."""
        result = find_git_root(tmp_path)
        assert result == tmp_path.resolve()


# ---------------------------------------------------------------------------
# .gitshieldignore loading
# ---------------------------------------------------------------------------

class TestLoadIgnoreList:
    """Test loading of .gitshieldignore files."""

    def test_load_ignore_list(self, tmp_path):
        """.gitshieldignore with comments and blank lines should parse correctly."""
        (tmp_path / ".git").mkdir()

        ignore_content = """\
# Comment line
fingerprint-one

# Another comment
fingerprint-two

"""
        (tmp_path / ".gitshieldignore").write_text(ignore_content)

        ignores = load_ignore_list(tmp_path)
        assert "fingerprint-one" in ignores
        assert "fingerprint-two" in ignores
        assert len(ignores) == 2

    def test_load_ignore_list_missing(self, tmp_path):
        """Missing .gitshieldignore should return an empty set."""
        (tmp_path / ".git").mkdir()
        ignores = load_ignore_list(tmp_path)
        assert ignores == set()


# ---------------------------------------------------------------------------
# Custom pattern builder
# ---------------------------------------------------------------------------

class TestBuildCustomPatterns:
    """Test build_custom_patterns converts config dicts into Pattern objects."""

    def test_valid_pattern_produces_pattern_object(self):
        """A well-formed custom pattern dict should produce a Pattern with correct fields."""
        config = GitShieldConfig(custom_patterns=[
            {
                "name": "my-api-key",
                "regex": r"MYCO_[A-Z0-9]{32}",
                "description": "Internal API key",
                "severity": "high",
            }
        ])
        patterns = build_custom_patterns(config)
        assert len(patterns) == 1
        p = patterns[0]
        assert p.id == "my-api-key"
        assert p.name == "my-api-key"
        assert p.description == "Internal API key"
        assert p.severity == "high"
        assert p.regex is not None
        # 32 uppercase/digit characters after the "MYCO_" prefix (A*28 + 1234)
        assert p.regex.search("MYCO_" + "A" * 28 + "1234") is not None

    def test_missing_regex_skips_and_prints_stderr(self, capsys):
        """A pattern dict without a 'regex' key should be skipped with a stderr message."""
        config = GitShieldConfig(custom_patterns=[
            {"name": "no-regex-pattern", "severity": "low"}
        ])
        patterns = build_custom_patterns(config)
        assert patterns == []
        captured = capsys.readouterr()
        assert "no-regex-pattern" in captured.err
        assert "no regex" in captured.err

    def test_invalid_regex_skips_and_prints_stderr(self, capsys):
        """A pattern dict with an un-compilable regex should be skipped with a stderr message."""
        config = GitShieldConfig(custom_patterns=[
            {"name": "bad-regex", "regex": r"(unclosed[group", "severity": "medium"}
        ])
        patterns = build_custom_patterns(config)
        assert patterns == []
        captured = capsys.readouterr()
        assert "bad-regex" in captured.err
        assert "invalid regex" in captured.err

    def test_regex_too_long_skips_and_prints_stderr(self, capsys):
        """A pattern whose regex exceeds 500 characters should be skipped with a stderr message."""
        long_regex = "A" * 501
        config = GitShieldConfig(custom_patterns=[
            {"name": "long-pattern", "regex": long_regex, "severity": "low"}
        ])
        patterns = build_custom_patterns(config)
        assert patterns == []
        captured = capsys.readouterr()
        assert "long-pattern" in captured.err
        assert "too long" in captured.err

    def test_entropy_threshold_set_correctly(self):
        """A custom pattern with entropy_threshold should carry that value on the Pattern."""
        config = GitShieldConfig(custom_patterns=[
            {
                "name": "high-entropy-token",
                "regex": r"TOKEN_[A-Za-z0-9]{16}",
                "severity": "medium",
                "entropy_threshold": 3.5,
            }
        ])
        patterns = build_custom_patterns(config)
        assert len(patterns) == 1
        assert patterns[0].entropy_threshold == 3.5

    def test_empty_custom_patterns_returns_empty_list(self):
        """When config.custom_patterns is empty, build_custom_patterns returns []."""
        config = GitShieldConfig(custom_patterns=[])
        patterns = build_custom_patterns(config)
        assert patterns == []
