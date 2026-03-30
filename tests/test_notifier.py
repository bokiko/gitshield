"""Tests for notifier.py — email and GitHub issue notifications."""

import os
from unittest.mock import MagicMock, patch

import pytest

import gitshield.db as db_module
from gitshield.db import get_connection
from gitshield.models import Finding
from gitshield.monitor import RepoInfo
from gitshield.notifier import (
    NotifierError,
    create_github_issue,
    notify,
    send_email,
)


# ---------------------------------------------------------------------------
# Fixture: isolated DB per test (mirrors test_db.py pattern)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect DB_DIR/DB_PATH to a tmp dir and reset the singleton per test."""
    test_db = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    monkeypatch.setattr(db_module, "_conn", None)
    yield
    if db_module._conn is not None:
        db_module._conn.close()
        db_module._conn = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(rule_id: str = "aws-access-key-id", fingerprint: str = "fp1") -> Finding:
    return Finding(
        file="config.py",
        line=10,
        rule_id=rule_id,
        secret="AKIA****",
        fingerprint=fingerprint,
        entropy=3.5,
        severity="high",
    )


def _make_repo(author_email: str = "owner@example.com") -> RepoInfo:
    return RepoInfo(
        owner="testowner",
        name="testrepo",
        url="https://github.com/testowner/testrepo",
        clone_url="https://github.com/testowner/testrepo.git",
        author_email=author_email,
    )


# ---------------------------------------------------------------------------
# send_email
# ---------------------------------------------------------------------------

class TestSendEmail:
    def test_raises_when_no_api_key(self, monkeypatch):
        monkeypatch.delenv("RESEND_API_KEY", raising=False)
        with pytest.raises(NotifierError, match="RESEND_API_KEY"):
            send_email(_make_repo(), [_make_finding()], "x@example.com")

    def test_dry_run_skips_api_call(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "test-key")
        with patch("gitshield.notifier.requests") as mock_requests:
            result = send_email(_make_repo(), [_make_finding()], "x@example.com", dry_run=True)
        assert result is True
        mock_requests.post.assert_not_called()

    def test_sends_correct_payload(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "test-key")
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            result = send_email(_make_repo(), [_make_finding()], "owner@example.com")

        assert result is True
        call_kwargs = mock_requests.post.call_args
        payload = call_kwargs.kwargs["json"] if call_kwargs.kwargs else call_kwargs[1]["json"]
        assert payload["to"] == ["owner@example.com"]
        assert "testowner/testrepo" in payload["subject"]

    def test_marks_notified_after_send(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "test-key")
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        finding = _make_finding(fingerprint="fp-email-1")

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            send_email(_make_repo(), [finding], "owner@example.com")

        conn = get_connection()
        row = conn.execute(
            "SELECT fingerprint FROM notifications WHERE fingerprint = ?",
            ("fp-email-1",),
        ).fetchone()
        assert row is not None

    def test_raises_notifier_error_on_request_exception(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "test-key")

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.post.side_effect = Exception("connection error")
            with pytest.raises(NotifierError, match="Failed to send email"):
                send_email(_make_repo(), [_make_finding()], "x@example.com")


# ---------------------------------------------------------------------------
# create_github_issue
# ---------------------------------------------------------------------------

class TestCreateGithubIssue:
    def test_raises_when_no_token(self, monkeypatch):
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        with pytest.raises(NotifierError, match="GITHUB_TOKEN"):
            create_github_issue(_make_repo(), [_make_finding()])

    def test_dry_run_skips_api_call(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "test" * 10)
        with patch("gitshield.notifier.requests") as mock_requests:
            result = create_github_issue(_make_repo(), [_make_finding()], dry_run=True)
        assert result is True
        mock_requests.post.assert_not_called()

    def test_sends_correct_payload(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "test" * 10)
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            result = create_github_issue(_make_repo(), [_make_finding()])

        assert result is True
        call_kwargs = mock_requests.post.call_args
        url_arg = call_kwargs.args[0] if call_kwargs.args else call_kwargs[0][0]
        assert "testowner/testrepo/issues" in url_arg

    def test_returns_false_on_403(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "test" * 10)

        mock_err_response = MagicMock()
        mock_err_response.status_code = 403

        exc = Exception("403 Forbidden")
        exc.response = mock_err_response

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.post.side_effect = exc
            result = create_github_issue(_make_repo(), [_make_finding()])

        assert result is False

    def test_returns_false_on_404(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "test" * 10)

        mock_err_response = MagicMock()
        mock_err_response.status_code = 404

        exc = Exception("404 Not Found")
        exc.response = mock_err_response

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.RequestException = Exception
            mock_requests.post.side_effect = exc
            result = create_github_issue(_make_repo(), [_make_finding()])

        assert result is False


# ---------------------------------------------------------------------------
# notify orchestrator
# ---------------------------------------------------------------------------

class TestNotify:
    def test_skips_already_notified(self, monkeypatch):
        """notify() must filter findings already recorded in DB."""
        finding = _make_finding(fingerprint="fp-already-1")
        repo = _make_repo()

        # Pre-mark the finding as notified
        from gitshield.db import mark_notified
        mark_notified(repo.url, "fp-already-1", method="email")

        result = notify(repo, [finding])
        assert result.get("skipped") is True
        assert result.get("reason") == "already_notified"

    def test_dry_run_prevents_api_calls(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "test-key")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "test" * 10)

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_response = MagicMock()
            mock_response.raise_for_status.return_value = None
            mock_requests.post.return_value = mock_response
            result = notify(_make_repo(), [_make_finding(fingerprint="fp-new-1")], dry_run=True)

        mock_requests.post.assert_not_called()
        assert result["findings_count"] == 1

    def test_new_findings_are_processed(self, monkeypatch):
        monkeypatch.setenv("RESEND_API_KEY", "test-key")
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "test" * 10)

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.RequestException = Exception
            result = notify(_make_repo(), [_make_finding(fingerprint="fp-fresh-1")])

        assert result["findings_count"] == 1

    def test_no_email_sent_without_author_email(self, monkeypatch):
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_" + "test" * 10)
        repo = _make_repo(author_email="")  # no email

        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None

        with patch("gitshield.notifier.requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            mock_requests.RequestException = Exception
            result = notify(repo, [_make_finding(fingerprint="fp-noemail-1")])

        # email should not appear in results (or be False)
        assert result.get("email") is False or "email" not in result or result.get("email") is False
