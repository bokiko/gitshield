"""Claude Code hook management for GitShield."""

import json
from pathlib import Path

import click

from .formatter import colorize, Colors

SETTINGS_PATH = Path.home() / ".claude" / "settings.json"
HOOK_COMMAND = "gitshield-claude-hook"
HOOK_MATCHER = "Write|Edit|Bash"
HOOK_TIMEOUT = 5


def _load_settings() -> dict:
    """Load Claude Code settings.json, return empty dict if missing."""
    if not SETTINGS_PATH.exists():
        return {}
    try:
        return json.loads(SETTINGS_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_settings(settings: dict) -> None:
    """Write settings.json, creating parent dirs if needed."""
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2) + "\n")


def _is_installed(settings: dict) -> bool:
    """Check if gitshield hook is already registered."""
    hooks = settings.get("hooks", {}).get("PreToolUse", [])
    for group in hooks:
        for h in group.get("hooks", []):
            if "gitshield" in h.get("command", ""):
                return True
    return False


def install_hook() -> None:
    """Register GitShield as a Claude Code PreToolUse hook."""
    settings = _load_settings()

    if _is_installed(settings):
        click.echo("GitShield hook already installed in Claude Code.")
        return

    # Build the hook entry
    hook_group = {
        "matcher": HOOK_MATCHER,
        "hooks": [{
            "type": "command",
            "command": HOOK_COMMAND,
            "timeout": HOOK_TIMEOUT,
        }]
    }

    # Add to settings
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "PreToolUse" not in settings["hooks"]:
        settings["hooks"]["PreToolUse"] = []

    settings["hooks"]["PreToolUse"].append(hook_group)
    _save_settings(settings)

    click.echo(colorize("GitShield hook installed in Claude Code.", Colors.GREEN))
    click.echo(f"  Settings: {SETTINGS_PATH}")
    click.echo(f"  Matcher: {HOOK_MATCHER}")
    click.echo(f"  Command: {HOOK_COMMAND}")
    click.echo()
    click.echo("Claude Code will now scan for secrets before writing files or running commands.")


def uninstall_hook() -> None:
    """Remove GitShield hook from Claude Code settings."""
    settings = _load_settings()

    if not _is_installed(settings):
        click.echo("GitShield hook not found in Claude Code settings.")
        return

    # Remove any hook group containing gitshield
    pre_tool = settings.get("hooks", {}).get("PreToolUse", [])
    filtered = []
    for group in pre_tool:
        hooks = group.get("hooks", [])
        remaining = [h for h in hooks if "gitshield" not in h.get("command", "")]
        if remaining:
            group["hooks"] = remaining
            filtered.append(group)

    settings["hooks"]["PreToolUse"] = filtered

    # Clean up empty structures
    if not settings["hooks"]["PreToolUse"]:
        del settings["hooks"]["PreToolUse"]
    if not settings["hooks"]:
        del settings["hooks"]

    _save_settings(settings)
    click.echo(colorize("GitShield hook removed from Claude Code.", Colors.GREEN))


def show_status() -> None:
    """Display Claude Code hook status."""
    settings = _load_settings()

    if not SETTINGS_PATH.exists():
        click.echo(colorize("Claude Code settings not found.", Colors.YELLOW))
        click.echo(f"  Expected: {SETTINGS_PATH}")
        click.echo("  Run 'gitshield claude install' to set up.")
        return

    installed = _is_installed(settings)

    if installed:
        click.echo(colorize("GitShield hook: active", Colors.GREEN))
        click.echo(f"  Settings: {SETTINGS_PATH}")
        click.echo(f"  Scanning: Write, Edit, and Bash tool calls")
    else:
        click.echo(colorize("GitShield hook: not installed", Colors.YELLOW))
        click.echo("  Run 'gitshield claude install' to enable.")
