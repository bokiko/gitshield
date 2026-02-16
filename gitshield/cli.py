"""GitShield CLI — Prevent accidental secret commits."""

import sys
from pathlib import Path

import click

from . import __version__
from .config import filter_findings, load_ignore_list, find_git_root
from .formatter import print_findings, print_json, print_blocked_message, colorize, Colors
from .scanner import scan_path, ScannerError


@click.group()
@click.version_option(__version__, prog_name="gitshield")
def main():
    """Secret scanner for developers + AI coding assistants."""
    pass


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--staged", is_flag=True, help="Scan only staged files")
@click.option("--no-git", is_flag=True, help="Scan as plain files (not git repo)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--sarif", is_flag=True, help="Output as SARIF")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output (for hooks)")
def scan(path: str, staged: bool, no_git: bool, as_json: bool, sarif: bool, quiet: bool):
    """Scan for secrets in PATH (default: current directory)."""
    try:
        findings = scan_path(path, staged_only=staged, no_git=no_git)

        # Filter ignored
        ignores = load_ignore_list(Path(path))
        findings = filter_findings(findings, ignores)

        # Output
        if sarif:
            from .formatter import print_sarif
            print_sarif(findings)
        elif as_json:
            print_json(findings)
        else:
            print_findings(findings, quiet=quiet)

        # Exit code
        if findings:
            if not as_json and not sarif and not quiet:
                print_blocked_message()
            sys.exit(1)

    except ScannerError as e:
        click.echo(colorize(f"Error: {e}", Colors.RED), err=True)
        sys.exit(2)


@main.group()
def hook():
    """Manage git pre-commit hook."""
    pass


@hook.command("install")
@click.option("--path", "-p", default=".", type=click.Path(exists=True),
              help="Repository path")
def hook_install(path: str):
    """Install pre-commit hook in repository."""
    git_root = find_git_root(Path(path))
    hooks_dir = git_root / ".git" / "hooks"

    if not hooks_dir.exists():
        click.echo(colorize("Error: Not a git repository", Colors.RED), err=True)
        sys.exit(1)

    hook_path = hooks_dir / "pre-commit"

    # GitShield hook content
    gitshield_hook = '\n\n# GitShield secret scan\nexport PATH="$PATH:$HOME/Library/Python/3.9/bin:$HOME/.local/bin"\ngitshield scan --staged --quiet\n'

    if hook_path.exists():
        content = hook_path.read_text()
        if "gitshield" in content:
            click.echo("GitShield hook already installed.")
            return
        click.echo(colorize("Existing pre-commit hook found. Appending GitShield.", Colors.YELLOW))
        with open(hook_path, "a") as f:
            f.write(gitshield_hook)
    else:
        hook_content = """#!/bin/sh
# GitShield pre-commit hook

export PATH="$PATH:$HOME/Library/Python/3.9/bin:$HOME/.local/bin"
gitshield scan --staged --quiet
"""
        hook_path.write_text(hook_content)
        hook_path.chmod(0o755)

    click.echo(colorize("Pre-commit hook installed.", Colors.GREEN))
    click.echo(f"Location: {hook_path}")


@hook.command("uninstall")
@click.option("--path", "-p", default=".", type=click.Path(exists=True),
              help="Repository path")
def hook_uninstall(path: str):
    """Remove pre-commit hook from repository."""
    git_root = find_git_root(Path(path))
    hook_path = git_root / ".git" / "hooks" / "pre-commit"

    if not hook_path.exists():
        click.echo("No pre-commit hook found.")
        return

    content = hook_path.read_text()

    if "gitshield" not in content:
        click.echo("GitShield hook not installed.")
        return

    lines = content.split("\n")
    new_lines = []
    skip_next = False

    for line in lines:
        if "# GitShield" in line:
            skip_next = True
            continue
        if skip_next and "gitshield" in line:
            skip_next = False
            continue
        skip_next = False
        new_lines.append(line)

    new_content = "\n".join(new_lines).strip()

    if new_content in ("#!/bin/sh", "#!/bin/bash", ""):
        hook_path.unlink()
        click.echo(colorize("Pre-commit hook removed.", Colors.GREEN))
    else:
        hook_path.write_text(new_content + "\n")
        click.echo(colorize("GitShield removed from pre-commit hook.", Colors.GREEN))


# ---- Claude Code integration ----

@main.group()
def claude():
    """Manage Claude Code hook integration."""
    pass


@claude.command("install")
def claude_install():
    """Install GitShield as a Claude Code PreToolUse hook."""
    from .claude import install_hook
    install_hook()


@claude.command("uninstall")
def claude_uninstall():
    """Remove GitShield hook from Claude Code."""
    from .claude import uninstall_hook
    uninstall_hook()


@claude.command("status")
def claude_status():
    """Show Claude Code hook status."""
    from .claude import show_status
    show_status()


# ---- Init command ----

@main.command()
@click.option("--path", "-p", default=".", type=click.Path(exists=True),
              help="Repository path")
def init(path: str):
    """Create a .gitshield.toml config file with sensible defaults."""
    from .config import create_default_config
    config_path = create_default_config(Path(path))
    click.echo(colorize(f"Created {config_path}", Colors.GREEN))
    click.echo("Edit this file to customize patterns, allowlists, and thresholds.")


# ---- Patrol command (existing) ----

@main.command()
@click.option("--repo", "-r", help="Specific repo to scan (owner/name)")
@click.option("--limit", "-l", default=10, help="Max repos to scan from events")
@click.option("--dry-run", is_flag=True, help="Don't send notifications")
@click.option("--stats", is_flag=True, help="Show scanning statistics")
def patrol(repo: str, limit: int, dry_run: bool, stats: bool):
    """Scan public GitHub repos for leaked secrets."""
    from .monitor import fetch_public_events, fetch_repo_info, clone_and_scan, GitHubError
    from .notifier import notify
    from .db import get_stats

    if stats:
        s = get_stats()
        click.echo(f"Repos scanned: {s['repos_scanned']}")
        click.echo(f"Total findings: {s['total_findings']}")
        click.echo(f"Notifications sent: {s['notifications_sent']}")
        return

    try:
        if repo:
            if "/" not in repo:
                click.echo(colorize("Error: Use format owner/name", Colors.RED), err=True)
                sys.exit(1)
            owner, name = repo.split("/", 1)
            repos = [fetch_repo_info(owner, name)]
            click.echo(f"Scanning {repo}...")
        else:
            click.echo(f"Fetching recent public events...")
            repos = fetch_public_events(limit=limit)
            click.echo(f"Found {len(repos)} repos to scan")

        total_findings = 0
        notified_count = 0

        for r in repos:
            click.echo(f"\n{colorize('Scanning:', Colors.CYAN)} {r.owner}/{r.name}")

            try:
                findings = clone_and_scan(r)
            except ScannerError as e:
                click.echo(colorize(f"  Skip: {e}", Colors.YELLOW))
                continue

            if not findings:
                click.echo(colorize("  No secrets found", Colors.GREEN))
                continue

            total_findings += len(findings)
            click.echo(colorize(f"  {len(findings)} secrets found!", Colors.RED))

            for f in findings:
                click.echo(f"    - {f.file}:{f.line} ({f.rule_id})")

            result = notify(r, findings, dry_run=dry_run)

            if result.get("skipped"):
                click.echo(colorize("  Already notified", Colors.YELLOW))
            else:
                if result.get("email"):
                    click.echo(colorize("  Email sent", Colors.GREEN))
                    notified_count += 1
                if result.get("github_issue"):
                    click.echo(colorize("  GitHub issue created", Colors.GREEN))
                    notified_count += 1

        click.echo(f"\n{colorize('Summary:', Colors.BOLD)}")
        click.echo(f"  Repos scanned: {len(repos)}")
        click.echo(f"  Secrets found: {total_findings}")
        click.echo(f"  Notifications: {notified_count}")

    except Exception as e:
        if "GitHubError" in type(e).__name__:
            click.echo(colorize(f"Error: {e}", Colors.RED), err=True)
            sys.exit(1)
        click.echo(colorize(f"Error: {e}", Colors.RED), err=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
