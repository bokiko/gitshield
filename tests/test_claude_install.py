"""Tests for the Claude Code hook management module (gitshield/claude.py)."""

import json

import gitshield.claude as claude_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_settings(path, data):
    """Write a settings dict to the given path as JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def _read_settings(path):
    """Load and return the settings dict from the given path."""
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# _is_installed
# ---------------------------------------------------------------------------

class TestIsInstalled:
    """Unit tests for the _is_installed predicate."""

    def test_returns_false_on_empty_settings(self):
        """Empty dict means no hooks at all — should return False."""
        assert claude_mod._is_installed({}) is False

    def test_returns_false_when_hooks_key_missing(self):
        assert claude_mod._is_installed({"someOtherKey": True}) is False

    def test_returns_false_when_pre_tool_use_empty(self):
        settings = {"hooks": {"PreToolUse": []}}
        assert claude_mod._is_installed(settings) is False

    def test_returns_true_when_gitshield_hook_present(self):
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write|Edit|Bash",
                        "hooks": [
                            {"type": "command", "command": "gitshield-claude-hook"}
                        ],
                    }
                ]
            }
        }
        assert claude_mod._is_installed(settings) is True

    def test_returns_false_when_only_other_hooks_present(self):
        """Other hooks that do not mention 'gitshield' must not trigger True."""
        settings = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Write",
                        "hooks": [
                            {"type": "command", "command": "some-other-tool"}
                        ],
                    }
                ]
            }
        }
        assert claude_mod._is_installed(settings) is False


# ---------------------------------------------------------------------------
# install_hook
# ---------------------------------------------------------------------------

class TestInstallHook:
    """Tests for install_hook()."""

    def test_install_creates_correct_structure(self, tmp_path, monkeypatch):
        """install_hook writes the expected hook group into settings.json."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        claude_mod.install_hook()

        assert settings_file.exists(), "settings.json should be created"
        data = _read_settings(settings_file)

        pre_tool = data["hooks"]["PreToolUse"]
        assert len(pre_tool) == 1

        group = pre_tool[0]
        assert group["matcher"] == claude_mod.HOOK_MATCHER

        hooks = group["hooks"]
        assert len(hooks) == 1
        h = hooks[0]
        assert h["type"] == "command"
        assert h["command"] == claude_mod.HOOK_COMMAND
        assert h["timeout"] == claude_mod.HOOK_TIMEOUT

    def test_install_into_existing_settings_preserves_other_keys(self, tmp_path, monkeypatch):
        """install_hook should not remove unrelated top-level keys."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        _write_settings(settings_file, {"theme": "dark"})

        claude_mod.install_hook()

        data = _read_settings(settings_file)
        assert data.get("theme") == "dark"

    def test_install_is_idempotent(self, tmp_path, monkeypatch):
        """Calling install_hook twice must not create duplicate entries."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        claude_mod.install_hook()
        claude_mod.install_hook()

        data = _read_settings(settings_file)
        pre_tool = data["hooks"]["PreToolUse"]

        # Collect all hook commands across all groups
        all_commands = [
            h["command"]
            for group in pre_tool
            for h in group.get("hooks", [])
        ]
        gitshield_commands = [c for c in all_commands if "gitshield" in c]
        assert len(gitshield_commands) == 1, (
            f"Expected exactly 1 gitshield hook command after two installs, got {gitshield_commands}"
        )


# ---------------------------------------------------------------------------
# uninstall_hook
# ---------------------------------------------------------------------------

class TestUninstallHook:
    """Tests for uninstall_hook()."""

    def test_uninstall_removes_gitshield_hook(self, tmp_path, monkeypatch):
        """uninstall_hook should remove the gitshield hook entry."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        claude_mod.install_hook()
        assert _is_installed_on_disk(settings_file)

        claude_mod.uninstall_hook()
        data = _read_settings(settings_file)
        assert not claude_mod._is_installed(data)

    def test_uninstall_preserves_other_hooks(self, tmp_path, monkeypatch):
        """Other hook groups must survive uninstall_hook."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        other_group = {
            "matcher": "Read",
            "hooks": [{"type": "command", "command": "some-other-hook"}],
        }
        initial = {
            "hooks": {
                "PreToolUse": [
                    other_group,
                    {
                        "matcher": claude_mod.HOOK_MATCHER,
                        "hooks": [{"type": "command", "command": claude_mod.HOOK_COMMAND}],
                    },
                ]
            }
        }
        _write_settings(settings_file, initial)

        claude_mod.uninstall_hook()

        data = _read_settings(settings_file)
        pre_tool = data["hooks"]["PreToolUse"]
        remaining_commands = [
            h["command"]
            for group in pre_tool
            for h in group.get("hooks", [])
        ]
        assert "some-other-hook" in remaining_commands
        assert claude_mod.HOOK_COMMAND not in remaining_commands

    def test_uninstall_cleans_up_empty_pre_tool_use(self, tmp_path, monkeypatch):
        """When the last hook is removed, PreToolUse key should be dropped."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        claude_mod.install_hook()
        claude_mod.uninstall_hook()

        data = _read_settings(settings_file)
        assert "PreToolUse" not in data.get("hooks", {})

    def test_uninstall_cleans_up_empty_hooks_key(self, tmp_path, monkeypatch):
        """When no hooks remain at all, the top-level 'hooks' key should be dropped."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        claude_mod.install_hook()
        claude_mod.uninstall_hook()

        data = _read_settings(settings_file)
        assert "hooks" not in data

    def test_uninstall_when_not_installed_is_safe(self, tmp_path, monkeypatch):
        """Calling uninstall when not installed should not raise."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        # settings file does not exist — should handle gracefully
        claude_mod.uninstall_hook()


# ---------------------------------------------------------------------------
# show_status
# ---------------------------------------------------------------------------

class TestShowStatus:
    """Tests for show_status() output."""

    def test_show_status_not_installed(self, tmp_path, monkeypatch, capsys):
        """show_status should report hook as not installed when absent."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        # settings.json does not exist
        claude_mod.show_status()

        captured = capsys.readouterr()
        output = captured.out
        # Should mention that settings are not found or hook is not installed
        assert "not" in output.lower() or "settings" in output.lower()

    def test_show_status_installed(self, tmp_path, monkeypatch, capsys):
        """show_status should report hook as active when installed."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        claude_mod.install_hook()
        # Reset capsys buffer so install output does not bleed in
        capsys.readouterr()

        claude_mod.show_status()

        captured = capsys.readouterr()
        output = captured.out
        assert "active" in output.lower()

    def test_show_status_not_installed_with_existing_file(self, tmp_path, monkeypatch, capsys):
        """show_status on an existing settings.json that lacks gitshield should say not installed."""
        settings_file = tmp_path / ".claude" / "settings.json"
        monkeypatch.setattr(claude_mod, "SETTINGS_PATH", settings_file)

        _write_settings(settings_file, {"theme": "dark"})

        claude_mod.show_status()

        captured = capsys.readouterr()
        output = captured.out
        assert "not installed" in output.lower()


# ---------------------------------------------------------------------------
# Internal helper (used only within this test module)
# ---------------------------------------------------------------------------

def _is_installed_on_disk(settings_file) -> bool:
    """Read settings from disk and check whether gitshield is installed."""
    data = json.loads(settings_file.read_text())
    return claude_mod._is_installed(data)
