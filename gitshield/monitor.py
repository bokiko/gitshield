"""GitHub Events API client for monitoring public repos."""

import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import subprocess

import requests

from .db import was_scanned_recently, mark_scanned
from .scanner import scan_path, Finding


@dataclass
class RepoInfo:
    """Information about a GitHub repository."""
    owner: str
    name: str
    url: str
    clone_url: str
    author_email: Optional[str] = None
    author_name: Optional[str] = None


class GitHubError(Exception):
    """GitHub API error."""
    pass


def get_github_token() -> Optional[str]:
    """Get GitHub token from environment."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def fetch_public_events(limit: int = 30) -> List[RepoInfo]:
    """
    Fetch recent public push events from GitHub.

    Args:
        limit: Maximum number of repos to return

    Returns:
        List of RepoInfo objects
    """
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        response = requests.get(
            "https://api.github.com/events",
            headers=headers,
            params={"per_page": 100},
            timeout=30,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise GitHubError(f"Failed to fetch events: {e}")

    repos = []
    seen = set()

    for event in response.json():
        if event.get("type") != "PushEvent":
            continue

        repo = event.get("repo", {})
        repo_name = repo.get("name", "")

        if not repo_name or repo_name in seen:
            continue

        # Skip forks (they usually mirror the parent)
        if "/" not in repo_name:
            continue

        owner, name = repo_name.split("/", 1)

        # Get author info from commits
        payload = event.get("payload", {})
        commits = payload.get("commits", [])
        author_email = None
        author_name = None

        if commits:
            author = commits[0].get("author", {})
            author_email = author.get("email")
            author_name = author.get("name")

        repos.append(RepoInfo(
            owner=owner,
            name=name,
            url=f"https://github.com/{owner}/{name}",
            clone_url=f"https://github.com/{owner}/{name}.git",
            author_email=author_email,
            author_name=author_name,
        ))

        seen.add(repo_name)

        if len(repos) >= limit:
            break

    return repos


def fetch_repo_info(owner: str, name: str) -> RepoInfo:
    """Fetch info for a specific repository."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{name}",
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as e:
        raise GitHubError(f"Failed to fetch repo: {e}")

    return RepoInfo(
        owner=owner,
        name=name,
        url=data.get("html_url", f"https://github.com/{owner}/{name}"),
        clone_url=data.get("clone_url", f"https://github.com/{owner}/{name}.git"),
    )


def clone_and_scan(repo: RepoInfo, skip_recent: bool = True) -> List[Finding]:
    """
    Clone a repo and scan for secrets.

    Args:
        repo: Repository to scan
        skip_recent: Skip if scanned in last 24 hours

    Returns:
        List of findings
    """
    if skip_recent and was_scanned_recently(repo.url):
        return []

    # Create temp directory for clone
    temp_dir = tempfile.mkdtemp(prefix="gitshield_")

    try:
        # Shallow clone (faster, less disk space)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo.clone_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            # Clone failed (private repo, deleted, etc.)
            mark_scanned(repo.url, 0)
            return []

        # Scan the cloned repo
        findings = scan_path(temp_dir, no_git=True)

        # Enrich findings with repo info
        for f in findings:
            # Make paths relative to repo root
            f.file = str(Path(f.file).relative_to(temp_dir))

        mark_scanned(repo.url, len(findings))
        return findings

    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []
    finally:
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)


def get_author_email(owner: str, name: str) -> Optional[str]:
    """Get email of the most recent committer."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    token = get_github_token()
    if token:
        headers["Authorization"] = f"token {token}"

    try:
        response = requests.get(
            f"https://api.github.com/repos/{owner}/{name}/commits",
            headers=headers,
            params={"per_page": 1},
            timeout=30,
        )
        response.raise_for_status()
        commits = response.json()

        if commits:
            commit = commits[0].get("commit", {})
            author = commit.get("author", {})
            return author.get("email")

    except requests.RequestException:
        pass

    return None
