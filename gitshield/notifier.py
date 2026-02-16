"""Send notifications via email and GitHub issues."""

import os
from typing import List, Optional

import requests

from .scanner import Finding
from .monitor import RepoInfo
from .db import was_notified, mark_notified


class NotifierError(Exception):
    """Notification error."""
    pass


def get_resend_key() -> Optional[str]:
    """Get Resend API key from environment."""
    return os.environ.get("RESEND_API_KEY")


def get_github_token() -> Optional[str]:
    """Get GitHub token from environment."""
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def send_email(
    repo: RepoInfo,
    findings: List[Finding],
    to_email: str,
    dry_run: bool = False,
) -> bool:
    """
    Send email notification about leaked secrets.

    Args:
        repo: Repository info
        findings: List of findings
        to_email: Recipient email
        dry_run: If True, don't actually send

    Returns:
        True if sent successfully
    """
    api_key = get_resend_key()
    if not api_key:
        raise NotifierError("RESEND_API_KEY not set")

    # Build findings list for email
    findings_text = "\n".join([
        f"  - {f.file}:{f.line} ({f.rule_id})"
        for f in findings
    ])

    subject = f"Security Alert: Secrets exposed in {repo.owner}/{repo.name}"

    body = f"""Hi,

GitShield detected potential secrets in your public repository:

Repository: {repo.url}

Findings:
{findings_text}

These secrets are now exposed in your git history and may have been scraped by attackers.

Recommended actions:
1. Revoke/rotate the exposed credentials immediately
2. Remove from git history: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

---
This is an automated security notification from GitShield.
https://gitlab.com/bokiko/gitshield

To stop receiving these alerts, rotate your credentials and remove them from git history.
"""

    if dry_run:
        print(f"[DRY RUN] Would send email to: {to_email}")
        print(f"Subject: {subject}")
        return True

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": "GitShield <security@resend.dev>",
                "to": [to_email],
                "subject": subject,
                "text": body,
            },
            timeout=30,
        )
        response.raise_for_status()

        # Mark as notified
        for f in findings:
            mark_notified(repo.url, f.fingerprint, to_email, "email")

        return True

    except requests.RequestException as e:
        raise NotifierError(f"Failed to send email: {e}")


def create_github_issue(
    repo: RepoInfo,
    findings: List[Finding],
    dry_run: bool = False,
) -> bool:
    """
    Create GitHub issue about leaked secrets.

    Args:
        repo: Repository info
        findings: List of findings
        dry_run: If True, don't actually create

    Returns:
        True if created successfully
    """
    token = get_github_token()
    if not token:
        raise NotifierError("GITHUB_TOKEN not set")

    # Build findings table
    findings_table = "\n".join([
        f"| `{f.file}` | {f.line} | {f.rule_id} |"
        for f in findings
    ])

    title = "[Security] Potential secrets exposed in repository"

    body = f"""## GitShield Security Alert

Potential secrets were detected in this repository:

| File | Line | Type |
|------|------|------|
{findings_table}

### Recommended actions

1. **Revoke/rotate** the exposed credentials immediately
2. **Remove from git history** using [BFG Repo-Cleaner](https://rtyley.github.io/bfg-repo-cleaner/) or [git-filter-repo](https://github.com/newren/git-filter-repo)

### Resources

- [Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)

---
*Automated alert from [GitShield](https://gitlab.com/bokiko/gitshield)*
"""

    if dry_run:
        print(f"[DRY RUN] Would create issue on: {repo.url}")
        print(f"Title: {title}")
        return True

    try:
        response = requests.post(
            f"https://api.github.com/repos/{repo.owner}/{repo.name}/issues",
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
            },
            json={
                "title": title,
                "body": body,
                "labels": ["security"],
            },
            timeout=30,
        )
        response.raise_for_status()

        # Mark as notified
        for f in findings:
            mark_notified(repo.url, f.fingerprint, method="github_issue")

        return True

    except requests.RequestException as e:
        # 403/404 likely means we don't have permission
        if hasattr(e, "response") and e.response is not None:
            if e.response.status_code in (403, 404):
                return False
        raise NotifierError(f"Failed to create issue: {e}")


def notify(
    repo: RepoInfo,
    findings: List[Finding],
    dry_run: bool = False,
) -> dict:
    """
    Send all notifications for findings.

    Returns dict with results.
    """
    # Filter out already-notified findings
    new_findings = [
        f for f in findings
        if not was_notified(repo.url, f.fingerprint)
    ]

    if not new_findings:
        return {"skipped": True, "reason": "already_notified"}

    results = {
        "email": False,
        "github_issue": False,
        "findings_count": len(new_findings),
    }

    # Try to send email if we have author email
    if repo.author_email and "@" in repo.author_email:
        try:
            results["email"] = send_email(repo, new_findings, repo.author_email, dry_run)
        except NotifierError as e:
            results["email_error"] = str(e)

    # Try to create GitHub issue
    try:
        results["github_issue"] = create_github_issue(repo, new_findings, dry_run)
    except NotifierError as e:
        results["github_issue_error"] = str(e)

    return results
