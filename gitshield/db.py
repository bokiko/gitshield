"""SQLite database for tracking scanned repos and notifications."""

import atexit
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

# Database location
DB_DIR = Path.home() / ".gitshield"
DB_PATH = DB_DIR / "gitshield.db"

# Module-level singleton connection — initialized on first use.
_conn: Optional[sqlite3.Connection] = None
_lock = threading.Lock()


def _close_connection() -> None:
    """Close the singleton connection on process exit."""
    global _conn
    if _conn is not None:
        _conn.close()
        _conn = None


atexit.register(_close_connection)


def get_connection() -> sqlite3.Connection:
    """Return the module-level DB connection, creating it on first call."""
    global _conn
    if _conn is None:
        with _lock:
            if _conn is None:
                DB_DIR.mkdir(parents=True, exist_ok=True)
                DB_DIR.chmod(0o700)
                _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                os.chmod(DB_PATH, 0o600)
                _conn.row_factory = sqlite3.Row
                _init_tables(_conn)
    return _conn


def _init_tables(conn: sqlite3.Connection) -> None:
    """Create tables if they don't exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scanned_repos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_url TEXT UNIQUE NOT NULL,
            scanned_at TEXT NOT NULL,
            findings_count INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_url TEXT NOT NULL,
            email TEXT,
            fingerprint TEXT NOT NULL,
            notified_at TEXT NOT NULL,
            method TEXT NOT NULL,
            UNIQUE(repo_url, fingerprint)
        )
    """)
    conn.commit()


def was_scanned_recently(repo_url: str, hours: int = 24) -> bool:
    """Check if repo was scanned within the last N hours."""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT scanned_at FROM scanned_repos WHERE repo_url = ?",
        (repo_url,)
    )
    row = cursor.fetchone()

    if not row:
        return False

    scanned_at = datetime.fromisoformat(row["scanned_at"])
    age_hours = (datetime.now() - scanned_at).total_seconds() / 3600
    return age_hours < hours


def mark_scanned(repo_url: str, findings_count: int = 0) -> None:
    """Mark a repo as scanned."""
    conn = get_connection()
    conn.execute("""
        INSERT INTO scanned_repos (repo_url, scanned_at, findings_count)
        VALUES (?, ?, ?)
        ON CONFLICT(repo_url) DO UPDATE SET
            scanned_at = excluded.scanned_at,
            findings_count = excluded.findings_count
    """, (repo_url, datetime.now().isoformat(), findings_count))
    conn.commit()


def was_notified(repo_url: str, fingerprint: str) -> bool:
    """Check if we already notified about this specific finding."""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT id FROM notifications WHERE repo_url = ? AND fingerprint = ?",
        (repo_url, fingerprint)
    )
    return cursor.fetchone() is not None


def mark_notified(
    repo_url: str,
    fingerprint: str,
    email: Optional[str] = None,
    method: str = "email"
) -> None:
    """Record that we notified about a finding."""
    conn = get_connection()
    conn.execute("""
        INSERT OR IGNORE INTO notifications
        (repo_url, email, fingerprint, notified_at, method)
        VALUES (?, ?, ?, ?, ?)
    """, (repo_url, email, fingerprint, datetime.now().isoformat(), method))
    conn.commit()


def mark_notified_batch(
    repo_url: str,
    fingerprints: List[str],
    email: Optional[str] = None,
    method: str = "email",
) -> None:
    """Record that we notified about multiple findings in a single transaction."""
    if not fingerprints:
        return
    conn = get_connection()
    now = datetime.now().isoformat()
    conn.executemany("""
        INSERT OR IGNORE INTO notifications
        (repo_url, email, fingerprint, notified_at, method)
        VALUES (?, ?, ?, ?, ?)
    """, [(repo_url, email, fp, now, method) for fp in fingerprints])
    conn.commit()


def get_notified_fingerprints(repo_url: str, fingerprints: List[str]) -> Set[str]:
    """Return the subset of *fingerprints* that have already been notified."""
    if not fingerprints:
        return set()
    conn = get_connection()
    # Batch into chunks of 500 to stay well under SQLite's SQLITE_MAX_VARIABLE_NUMBER limit.
    _CHUNK_SIZE = 500
    result: Set[str] = set()
    for i in range(0, len(fingerprints), _CHUNK_SIZE):
        chunk = fingerprints[i:i + _CHUNK_SIZE]
        placeholders = ",".join("?" * len(chunk))
        cursor = conn.execute(
            f"SELECT fingerprint FROM notifications WHERE repo_url = ? AND fingerprint IN ({placeholders})",
            (repo_url, *chunk),
        )
        result.update(row["fingerprint"] for row in cursor.fetchall())
    return result


def get_stats() -> dict:
    """Get scanning statistics."""
    conn = get_connection()

    repos = conn.execute("SELECT COUNT(*) FROM scanned_repos").fetchone()[0]
    findings = conn.execute("SELECT SUM(findings_count) FROM scanned_repos").fetchone()[0] or 0
    notifications = conn.execute("SELECT COUNT(*) FROM notifications").fetchone()[0]

    return {
        "repos_scanned": repos,
        "total_findings": findings,
        "notifications_sent": notifications,
    }
