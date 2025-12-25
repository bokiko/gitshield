"""GitShield CLI - Prevent accidental secret commits."""

import sys
from pathlib import Path

import click

from . import __version__
from .config import filter_findings, load_ignore_list, find_git_root
from .formatter import print_findings, print_json, print_blocked_message, colorize, Colors
from .scanner import scan_path, GitleaksNotFound


@click.group()
@click.version_option(__version__, prog_name="gitshield")
def main():
    """Prevent accidental secret commits."""
    pass


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--staged", is_flag=True, help="Scan only staged files")
@click.option("--no-git", is_flag=True, help="Scan as plain files (not git repo)")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Minimal output (for hooks)")
def scan(path: str, staged: bool, no_git: bool, as_json: bool, quiet: bool):
    """Scan for secrets in PATH (default: current directory)."""
    try:
        # Run scan
        findings = scan_path(path, staged_only=staged, no_git=no_git)

        # Filter ignored
        ignores = load_ignore_list(Path(path))
        findings = filter_findings(findings, ignores)

        # Output
        if as_json:
            print_json(findings)
        else:
            print_findings(findings, quiet=quiet)

        # Exit code
        if findings:
            if not as_json and not quiet:
                print_blocked_message()
            sys.exit(1)

    except GitleaksNotFound as e:
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

    # GitShield hook content (safe, no user input)
    gitshield_hook = '\n\n# GitShield secret scan\nexport PATH="$PATH:$HOME/Library/Python/3.9/bin:$HOME/.local/bin"\ngitshield scan --staged --quiet\n'

    # Check if hook exists
    if hook_path.exists():
        content = hook_path.read_text()
        if "gitshield" in content:
            click.echo("GitShield hook already installed.")
            return
        # Warn user about existing hook
        click.echo(colorize("Existing pre-commit hook found. Appending GitShield.", Colors.YELLOW))
        with open(hook_path, "a") as f:
            f.write(gitshield_hook)
    else:
        # Create new hook
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

    # Remove gitshield lines
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
        # Hook is now empty, remove it
        hook_path.unlink()
        click.echo(colorize("Pre-commit hook removed.", Colors.GREEN))
    else:
        # Keep other hooks
        hook_path.write_text(new_content + "\n")
        click.echo(colorize("GitShield removed from pre-commit hook.", Colors.GREEN))


if __name__ == "__main__":
    main()
