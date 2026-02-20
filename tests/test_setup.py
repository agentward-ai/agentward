"""Tests for the MCP config wrapping/unwrapping setup module."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentward.setup import (
    BACKUP_SUFFIX,
    _is_already_wrapped,
    _is_stdio_server,
    format_diff,
    read_config,
    unwrap_config,
    wrap_config,
    write_config,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _basic_config() -> dict:
    """A minimal MCP config with one stdio server."""
    return {
        "mcpServers": {
            "my-server": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                "env": {"LOG_LEVEL": "info"},
            }
        }
    }


def _mixed_config() -> dict:
    """Config with both stdio and HTTP servers."""
    return {
        "mcpServers": {
            "stdio-server": {
                "command": "python",
                "args": ["-m", "my_server"],
            },
            "http-server": {
                "type": "http",
                "url": "https://api.example.com/mcp",
            },
        }
    }


def _vscode_config() -> dict:
    """VS Code format config (uses 'servers' key)."""
    return {
        "servers": {
            "memory": {
                "type": "stdio",
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-memory"],
            }
        }
    }


def _multi_server_config() -> dict:
    """Config with multiple stdio servers."""
    return {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
            },
            "github": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_TOKEN": "ghp_xxx"},
            },
            "clawdbot": {
                "command": "clawdbot",
                "args": ["acp"],
            },
        }
    }


# ---------------------------------------------------------------------------
# Tests: _is_stdio_server
# ---------------------------------------------------------------------------


class TestIsStdioServer:
    def test_stdio_with_command(self) -> None:
        assert _is_stdio_server({"command": "npx", "args": ["-y", "server"]}) is True

    def test_explicit_stdio_type(self) -> None:
        assert _is_stdio_server({"type": "stdio", "command": "npx"}) is True

    def test_http_server(self) -> None:
        assert _is_stdio_server({"type": "http", "url": "https://example.com"}) is False

    def test_url_without_type(self) -> None:
        assert _is_stdio_server({"url": "https://example.com"}) is False

    def test_no_command(self) -> None:
        assert _is_stdio_server({"type": "stdio"}) is False


# ---------------------------------------------------------------------------
# Tests: _is_already_wrapped
# ---------------------------------------------------------------------------


class TestIsAlreadyWrapped:
    def test_unwrapped_server(self) -> None:
        assert _is_already_wrapped({"command": "npx"}) is False

    def test_wrapped_by_marker(self) -> None:
        assert _is_already_wrapped({
            "command": "agentward",
            "_agentward_original_command": "npx",
        }) is True

    def test_wrapped_by_command(self) -> None:
        assert _is_already_wrapped({"command": "agentward"}) is True


# ---------------------------------------------------------------------------
# Tests: wrap_config
# ---------------------------------------------------------------------------


class TestWrapConfig:
    def test_wraps_stdio_server(self) -> None:
        config = _basic_config()
        wrapped, count = wrap_config(config, Path("/path/to/agentward.yaml"))
        assert count == 1
        server = wrapped["mcpServers"]["my-server"]
        assert server["command"] == "agentward"
        assert server["args"][0] == "inspect"
        assert "--policy" in server["args"]
        assert "--" in server["args"]
        # Original command should be after "--"
        dash_idx = server["args"].index("--")
        assert server["args"][dash_idx + 1] == "npx"

    def test_preserves_env(self) -> None:
        config = _basic_config()
        wrapped, _ = wrap_config(config, Path("/path/to/policy.yaml"))
        server = wrapped["mcpServers"]["my-server"]
        assert server["env"] == {"LOG_LEVEL": "info"}

    def test_skips_http_servers(self) -> None:
        config = _mixed_config()
        wrapped, count = wrap_config(config, Path("/path/to/policy.yaml"))
        assert count == 1  # Only stdio server wrapped
        assert wrapped["mcpServers"]["http-server"]["url"] == "https://api.example.com/mcp"

    def test_skips_already_wrapped(self) -> None:
        config = _basic_config()
        wrapped1, count1 = wrap_config(config, Path("/path/to/policy.yaml"))
        assert count1 == 1
        # Wrap again
        wrapped2, count2 = wrap_config(wrapped1, Path("/path/to/policy.yaml"))
        assert count2 == 0  # Nothing new to wrap

    def test_stores_markers(self) -> None:
        config = _basic_config()
        wrapped, _ = wrap_config(config, Path("/path/to/policy.yaml"))
        server = wrapped["mcpServers"]["my-server"]
        assert server["_agentward_original_command"] == "npx"
        assert server["_agentward_original_args"] == [
            "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
        ]

    def test_policy_path_resolved_absolute(self) -> None:
        config = _basic_config()
        wrapped, _ = wrap_config(config, Path("agentward.yaml"))
        server = wrapped["mcpServers"]["my-server"]
        policy_idx = server["args"].index("--policy")
        policy_path = server["args"][policy_idx + 1]
        assert Path(policy_path).is_absolute()

    def test_wraps_multiple_servers(self) -> None:
        config = _multi_server_config()
        wrapped, count = wrap_config(config, Path("/path/to/policy.yaml"))
        assert count == 3

    def test_wraps_vscode_format(self) -> None:
        config = _vscode_config()
        wrapped, count = wrap_config(config, Path("/path/to/policy.yaml"))
        assert count == 1
        assert wrapped["servers"]["memory"]["command"] == "agentward"

    def test_includes_log_path(self) -> None:
        config = _basic_config()
        wrapped, _ = wrap_config(
            config, Path("/path/to/policy.yaml"), log_path=Path("/tmp/audit.jsonl")
        )
        server = wrapped["mcpServers"]["my-server"]
        assert "--log" in server["args"]

    def test_does_not_mutate_original(self) -> None:
        config = _basic_config()
        original_cmd = config["mcpServers"]["my-server"]["command"]
        wrap_config(config, Path("/path/to/policy.yaml"))
        assert config["mcpServers"]["my-server"]["command"] == original_cmd

    def test_invalid_config_raises(self) -> None:
        with pytest.raises(ValueError, match="No 'mcpServers'"):
            wrap_config({"other_key": {}}, Path("/path/to/policy.yaml"))


# ---------------------------------------------------------------------------
# Tests: unwrap_config
# ---------------------------------------------------------------------------


class TestUnwrapConfig:
    def test_unwrap_restores_original(self) -> None:
        config = _basic_config()
        wrapped, _ = wrap_config(config, Path("/path/to/policy.yaml"))
        restored, count = unwrap_config(wrapped)
        assert count == 1
        server = restored["mcpServers"]["my-server"]
        assert server["command"] == "npx"
        assert server["args"] == [
            "-y", "@modelcontextprotocol/server-filesystem", "/tmp"
        ]

    def test_unwrap_removes_markers(self) -> None:
        config = _basic_config()
        wrapped, _ = wrap_config(config, Path("/path/to/policy.yaml"))
        restored, _ = unwrap_config(wrapped)
        server = restored["mcpServers"]["my-server"]
        assert "_agentward_original_command" not in server
        assert "_agentward_original_args" not in server

    def test_unwrap_on_unwrapped_config(self) -> None:
        config = _basic_config()
        restored, count = unwrap_config(config)
        assert count == 0

    def test_unwrap_multiple_servers(self) -> None:
        config = _multi_server_config()
        wrapped, _ = wrap_config(config, Path("/path/to/policy.yaml"))
        restored, count = unwrap_config(wrapped)
        assert count == 3
        for name in ("filesystem", "github", "clawdbot"):
            assert restored["mcpServers"][name]["command"] != "agentward"


# ---------------------------------------------------------------------------
# Tests: read_config / write_config
# ---------------------------------------------------------------------------


class TestReadWriteConfig:
    def test_read_valid_config(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps(_basic_config()))
        result = read_config(cfg)
        assert "mcpServers" in result

    def test_read_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            read_config(Path("/nonexistent/mcp.json"))

    def test_read_invalid_json(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text("not json")
        with pytest.raises(ValueError, match="Invalid JSON"):
            read_config(cfg)

    def test_write_creates_file(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        write_config(cfg, _basic_config(), backup=False)
        assert cfg.exists()
        loaded = json.loads(cfg.read_text())
        assert "mcpServers" in loaded

    def test_write_creates_backup(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps({"original": True}))
        backup_path = write_config(cfg, _basic_config(), backup=True)
        assert backup_path is not None
        assert backup_path.exists()
        backup_content = json.loads(backup_path.read_text())
        assert backup_content["original"] is True

    def test_write_no_backup_when_absent(self, tmp_path: Path) -> None:
        cfg = tmp_path / "new.json"
        backup_path = write_config(cfg, _basic_config(), backup=True)
        assert backup_path is None  # No existing file to back up


# ---------------------------------------------------------------------------
# Tests: format_diff
# ---------------------------------------------------------------------------


class TestFormatDiff:
    def test_shows_changes(self) -> None:
        original = _basic_config()
        wrapped, _ = wrap_config(original, Path("/path/to/policy.yaml"))
        diff = format_diff(original, wrapped)
        assert "my-server" in diff
        assert "npx" in diff
        assert "agentward" in diff

    def test_no_changes(self) -> None:
        config = _basic_config()
        diff = format_diff(config, config)
        assert "No changes" in diff


# ---------------------------------------------------------------------------
# Tests: Round-trip (wrap → write → read → unwrap)
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_full_round_trip(self, tmp_path: Path) -> None:
        """Wrap → write → read → unwrap should restore original."""
        original = _multi_server_config()

        # Wrap
        wrapped, wrap_count = wrap_config(original, Path("/path/to/policy.yaml"))
        assert wrap_count == 3

        # Write
        cfg_path = tmp_path / "mcp.json"
        write_config(cfg_path, wrapped, backup=False)

        # Read back
        loaded = read_config(cfg_path)

        # Unwrap
        restored, unwrap_count = unwrap_config(loaded)
        assert unwrap_count == 3

        # Verify restoration
        for name in ("filesystem", "github", "clawdbot"):
            orig = original["mcpServers"][name]
            rest = restored["mcpServers"][name]
            assert rest["command"] == orig["command"]
            assert rest["args"] == orig.get("args", [])
