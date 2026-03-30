"""Tests for monitor.py (GitHub patrol feature)."""

import sys
from unittest.mock import MagicMock, patch

import pytest

import gitshield.monitor as monitor_module
from gitshield.monitor import (
    GitHubError,
    RepoInfo,
    clone_and_scan,
    fetch_public_events,
)


# ---------------------------------------------------------------------------
# RepoInfo validation
# ---------------------------------------------------------------------------

class TestRepoInfoValidation:
    """Verify __post_init__ rejects invalid owner/name."""

    def test_valid_repo_info(self):
        repo = RepoInfo(
            owner="octocat",
            name="hello-world",
            url="https://github.com/octocat/hello-world",
            clone_url="https://github.com/octocat/hello-world.git",
        )
        assert repo.owner == "octocat"
        assert repo.name == "hello-world"

    def test_invalid_owner_raises(self):
        with pytest.raises(ValueError, match="Invalid GitHub owner"):
            RepoInfo(
                owner="bad owner!",
                name="repo",
                url="https://github.com/bad/repo",
                clone_url="https://github.com/bad/repo.git",
            )

    def test_invalid_name_raises(self):
        with pytest.raises(ValueError, match="Invalid GitHub repo name"):
            RepoInfo(
                owner="octocat",
                name="repo with spaces",
                url="https://github.com/octocat/repo",
                clone_url="https://github.com/octocat/repo.git",
            )

    def test_owner_with_slash_raises(self):
        with pytest.raises(ValueError, match="Invalid GitHub owner"):
            RepoInfo(
                owner="bad/owner",
                name="repo",
                url="https://github.com/bad/owner/repo",
                clone_url="https://github.com/bad/owner/repo.git",
            )


# ---------------------------------------------------------------------------
# clone_and_scan: skip recently-scanned repos
# ---------------------------------------------------------------------------

class TestCloneAndScan:
    """Verify clone_and_scan behaviour with mocked subprocess and db."""

    def _make_repo(self, clone_url="https://github.com/octocat/hello-world.git"):
        return RepoInfo(
            owner="octocat",
            name="hello-world",
            url="https://github.com/octocat/hello-world",
            clone_url=clone_url,
        )

    def test_skips_recently_scanned(self):
        """clone_and_scan returns [] without cloning if repo was recently scanned."""
        repo = self._make_repo()
        with patch("gitshield.monitor.was_scanned_recently", return_value=True) as mock_recent:
            result = clone_and_scan(repo, skip_recent=True)
        assert result == []
        mock_recent.assert_called_once_with(repo.url)

    def test_does_not_skip_when_skip_recent_false(self):
        """clone_and_scan does not check was_scanned_recently when skip_recent=False."""
        repo = self._make_repo()
        with patch("gitshield.monitor.was_scanned_recently") as mock_recent, \
             patch("gitshield.monitor.subprocess.run") as mock_run, \
             patch("gitshield.monitor.shutil.rmtree"), \
             patch("gitshield.monitor.scan_path", return_value=[]), \
             patch("gitshield.monitor.mark_scanned"):
            mock_run.return_value = MagicMock(returncode=0)
            result = clone_and_scan(repo, skip_recent=False)
        mock_recent.assert_not_called()

    def test_rejects_non_github_clone_url(self):
        """clone_and_scan raises GitHubError for non-GitHub clone URLs."""
        repo = self._make_repo(clone_url="https://evil.com/repo.git")
        with patch("gitshield.monitor.was_scanned_recently", return_value=False):
            with pytest.raises(GitHubError, match="Invalid clone URL"):
                clone_and_scan(repo, skip_recent=True)

    def test_rejects_http_clone_url(self):
        """clone_and_scan raises GitHubError for http:// URLs."""
        repo = self._make_repo(clone_url="http://github.com/octocat/hello-world.git")
        with patch("gitshield.monitor.was_scanned_recently", return_value=False):
            with pytest.raises(GitHubError, match="Invalid clone URL"):
                clone_and_scan(repo, skip_recent=True)

    def test_returns_empty_on_clone_failure(self):
        """clone_and_scan returns [] when git clone fails."""
        repo = self._make_repo()
        with patch("gitshield.monitor.was_scanned_recently", return_value=False), \
             patch("gitshield.monitor.subprocess.run") as mock_run, \
             patch("gitshield.monitor.shutil.rmtree"), \
             patch("gitshield.monitor.mark_scanned"):
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found")
            result = clone_and_scan(repo, skip_recent=True)
        assert result == []


# ---------------------------------------------------------------------------
# fetch_public_events: raises when requests is missing
# ---------------------------------------------------------------------------

class TestFetchPublicEvents:
    """Verify fetch_public_events raises GitHubError when requests is missing."""

    def test_raises_when_requests_none(self):
        """fetch_public_events raises GitHubError if requests package is not installed."""
        with patch.object(monitor_module, "requests", None):
            with pytest.raises(GitHubError, match="requests package required"):
                fetch_public_events()
