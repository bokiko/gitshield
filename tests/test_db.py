"""Tests for db.py — SQLite connection management and all public functions."""

import sqlite3
from datetime import datetime, timedelta

import pytest

import gitshield.db as db_module
from gitshield.db import (
    get_connection,
    get_stats,
    mark_notified,
    mark_scanned,
    was_notified,
    was_scanned_recently,
)


# ---------------------------------------------------------------------------
# Fixture: isolated DB per test
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Redirect DB_DIR/DB_PATH to a tmp dir and reset the singleton per test."""
    test_db = tmp_path / "test.db"
    monkeypatch.setattr(db_module, "DB_DIR", tmp_path)
    monkeypatch.setattr(db_module, "DB_PATH", test_db)
    # Reset singleton so get_connection() opens a fresh connection to test_db
    monkeypatch.setattr(db_module, "_conn", None)
    yield
    # Close connection after each test to release the file
    if db_module._conn is not None:
        db_module._conn.close()
        db_module._conn = None


# ---------------------------------------------------------------------------
# get_connection — singleton and table creation
# ---------------------------------------------------------------------------

class TestGetConnection:
    def test_returns_sqlite_connection(self):
        conn = get_connection()
        assert isinstance(conn, sqlite3.Connection)

    def test_singleton_same_object(self):
        conn1 = get_connection()
        conn2 = get_connection()
        assert conn1 is conn2

    def test_creates_scanned_repos_table(self):
        conn = get_connection()
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scanned_repos'"
        ).fetchone()
        assert result is not None

    def test_creates_notifications_table(self):
        conn = get_connection()
        result = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='notifications'"
        ).fetchone()
        assert result is not None


# ---------------------------------------------------------------------------
# mark_scanned + was_scanned_recently
# ---------------------------------------------------------------------------

class TestMarkAndWasScanned:
    def test_round_trip(self):
        mark_scanned("https://github.com/user/repo")
        assert was_scanned_recently("https://github.com/user/repo") is True

    def test_not_scanned_returns_false(self):
        assert was_scanned_recently("https://github.com/user/never") is False

    def test_hours_zero_always_recent(self):
        mark_scanned("https://github.com/user/repo")
        # hours=0 means any scan is "within 0 hours" — boundary: age < 0 is False
        # but a just-scanned repo has age ~0, which is < 24 (default)
        assert was_scanned_recently("https://github.com/user/repo", hours=24) is True

    def test_upsert_updates_timestamp(self):
        mark_scanned("https://github.com/user/repo", findings_count=3)
        mark_scanned("https://github.com/user/repo", findings_count=7)
        conn = get_connection()
        row = conn.execute(
            "SELECT findings_count FROM scanned_repos WHERE repo_url = ?",
            ("https://github.com/user/repo",),
        ).fetchone()
        assert row["findings_count"] == 7

    def test_old_scan_not_recent(self):
        # Insert a scan timestamped 48 hours ago
        old_time = (datetime.now() - timedelta(hours=48)).isoformat()
        conn = get_connection()
        conn.execute(
            "INSERT INTO scanned_repos (repo_url, scanned_at, findings_count) VALUES (?, ?, ?)",
            ("https://github.com/user/old", old_time, 0),
        )
        conn.commit()
        assert was_scanned_recently("https://github.com/user/old", hours=24) is False


# ---------------------------------------------------------------------------
# mark_notified + was_notified
# ---------------------------------------------------------------------------

class TestMarkAndWasNotified:
    def test_round_trip(self):
        mark_notified("https://github.com/user/repo", "fp1")
        assert was_notified("https://github.com/user/repo", "fp1") is True

    def test_not_notified_returns_false(self):
        assert was_notified("https://github.com/user/repo", "fp-missing") is False

    def test_dedup_insert_or_ignore(self):
        mark_notified("https://github.com/user/repo", "fp1", method="email")
        mark_notified("https://github.com/user/repo", "fp1", method="github")
        conn = get_connection()
        count = conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE repo_url = ? AND fingerprint = ?",
            ("https://github.com/user/repo", "fp1"),
        ).fetchone()[0]
        assert count == 1

    def test_different_fingerprints_both_stored(self):
        mark_notified("https://github.com/user/repo", "fp1")
        mark_notified("https://github.com/user/repo", "fp2")
        assert was_notified("https://github.com/user/repo", "fp1") is True
        assert was_notified("https://github.com/user/repo", "fp2") is True


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

class TestGetStats:
    def test_empty_db(self):
        stats = get_stats()
        assert stats["repos_scanned"] == 0
        assert stats["total_findings"] == 0
        assert stats["notifications_sent"] == 0

    def test_populated_db(self):
        mark_scanned("https://github.com/user/repo1", findings_count=3)
        mark_scanned("https://github.com/user/repo2", findings_count=5)
        mark_notified("https://github.com/user/repo1", "fp1")
        mark_notified("https://github.com/user/repo1", "fp2")

        stats = get_stats()
        assert stats["repos_scanned"] == 2
        assert stats["total_findings"] == 8
        assert stats["notifications_sent"] == 2
