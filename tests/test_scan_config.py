"""Tests for MCP config file parsing across all client formats."""

from pathlib import Path

import pytest

from agentward.scan.config import (
    ConfigParseError,
    ServerConfig,
    TransportType,
    detect_client,
    discover_configs,
    parse_config_file,
)

CONFIGS = Path(__file__).parent / "fixtures" / "configs"


class TestParseClaudeDesktop:
    """Tests for Claude Desktop config format."""

    def test_parse_servers(self) -> None:
        servers = parse_config_file(CONFIGS / "claude_desktop.json")
        assert len(servers) == 2

    def test_filesystem_server(self) -> None:
        servers = parse_config_file(CONFIGS / "claude_desktop.json")
        fs = next(s for s in servers if s.name == "filesystem")
        assert fs.transport == TransportType.STDIO
        assert fs.command == "npx"
        assert "-y" in fs.args
        assert "@modelcontextprotocol/server-filesystem" in fs.args
        assert fs.env.get("LOG_LEVEL") == "info"

    def test_github_server(self) -> None:
        servers = parse_config_file(CONFIGS / "claude_desktop.json")
        gh = next(s for s in servers if s.name == "github")
        assert gh.transport == TransportType.STDIO
        assert "GITHUB_PERSONAL_ACCESS_TOKEN" in gh.env

    def test_client_detection(self) -> None:
        servers = parse_config_file(CONFIGS / "claude_desktop.json")
        # This file is in tests/fixtures, so client detection won't match
        # Claude Desktop path. That's correct — detection is path-based.
        for s in servers:
            assert isinstance(s.client, str)


class TestParseCursor:
    """Tests for Cursor config format."""

    def test_parse_mixed_transports(self) -> None:
        servers = parse_config_file(CONFIGS / "cursor_mcp.json")
        assert len(servers) == 2

    def test_stdio_server(self) -> None:
        servers = parse_config_file(CONFIGS / "cursor_mcp.json")
        local = next(s for s in servers if s.name == "local-files")
        assert local.transport == TransportType.STDIO
        assert local.command == "python"

    def test_http_server(self) -> None:
        servers = parse_config_file(CONFIGS / "cursor_mcp.json")
        remote = next(s for s in servers if s.name == "remote-api")
        assert remote.transport == TransportType.HTTP
        assert remote.url == "https://api.example.com/mcp"
        assert "Authorization" in remote.headers


class TestParseVSCode:
    """Tests for VS Code config format (uses 'servers' root key)."""

    def test_parse_servers_key(self) -> None:
        servers = parse_config_file(CONFIGS / "vscode_mcp.json")
        assert len(servers) == 1

    def test_memory_server(self) -> None:
        servers = parse_config_file(CONFIGS / "vscode_mcp.json")
        mem = servers[0]
        assert mem.name == "memory-server"
        assert mem.transport == TransportType.STDIO
        assert mem.command == "npx"


class TestParseWindsurf:
    """Tests for Windsurf config format (uses 'serverUrl' for HTTP)."""

    def test_parse_servers(self) -> None:
        servers = parse_config_file(CONFIGS / "windsurf_mcp.json")
        assert len(servers) == 2

    def test_stdio_server(self) -> None:
        servers = parse_config_file(CONFIGS / "windsurf_mcp.json")
        slack = next(s for s in servers if s.name == "slack-bot")
        assert slack.transport == TransportType.STDIO
        assert "SLACK_BOT_TOKEN" in slack.env

    def test_http_via_server_url(self) -> None:
        servers = parse_config_file(CONFIGS / "windsurf_mcp.json")
        db = next(s for s in servers if s.name == "remote-db")
        assert db.transport == TransportType.HTTP
        assert db.url == "https://db-proxy.internal.example.com/mcp"
        assert "X-API-Key" in db.headers


class TestParseErrors:
    """Tests for error handling in config parsing."""

    def test_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError, match="Config file not found"):
            parse_config_file(Path("/nonexistent/config.json"))

    def test_invalid_json(self, tmp_path: Path) -> None:
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("not json {{{")
        with pytest.raises(ConfigParseError, match="Failed to parse JSON"):
            parse_config_file(bad_json)

    def test_not_an_object(self, tmp_path: Path) -> None:
        array_json = tmp_path / "array.json"
        array_json.write_text('[1, 2, 3]')
        with pytest.raises(ConfigParseError, match="must contain a JSON object"):
            parse_config_file(array_json)

    def test_no_servers_key(self, tmp_path: Path) -> None:
        empty_obj = tmp_path / "empty.json"
        empty_obj.write_text('{"someOtherKey": true}')
        servers = parse_config_file(empty_obj)
        assert servers == []

    def test_empty_servers(self, tmp_path: Path) -> None:
        empty_servers = tmp_path / "empty_servers.json"
        empty_servers.write_text('{"mcpServers": {}}')
        servers = parse_config_file(empty_servers)
        assert servers == []


class TestDetectClient:
    """Tests for client detection from file paths."""

    def test_claude_desktop_macos(self) -> None:
        path = Path("/Users/dev/Library/Application Support/Claude/claude_desktop_config.json")
        assert detect_client(path) == "claude_desktop"

    def test_cursor_global(self) -> None:
        path = Path("/Users/dev/.cursor/mcp.json")
        assert detect_client(path) == "cursor"

    def test_claude_code_project(self) -> None:
        path = Path("/Users/dev/project/.mcp.json")
        assert detect_client(path) == "claude_code"

    def test_vscode(self) -> None:
        path = Path("/Users/dev/project/.vscode/mcp.json")
        assert detect_client(path) == "vscode"

    def test_windsurf(self) -> None:
        path = Path("/Users/dev/.codeium/windsurf/mcp_config.json")
        assert detect_client(path) == "windsurf"

    def test_unknown(self) -> None:
        path = Path("/some/random/config.json")
        assert detect_client(path) == "unknown"


class TestDiscoverConfigs:
    """Tests for auto-discovery of config files."""

    def test_discover_returns_existing_only(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Discovery only returns paths that exist on disk."""
        # Monkey-patch Path.home and Path.cwd to temp dirs so we
        # control which files exist
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path / "project")

        # Create one config file
        cursor_dir = tmp_path / "home" / ".cursor"
        cursor_dir.mkdir(parents=True)
        config_file = cursor_dir / "mcp.json"
        config_file.write_text('{"mcpServers": {}}')

        configs = discover_configs()
        assert config_file in configs
        # Should not include non-existent paths
        assert all(p.exists() for p in configs)


class TestTransportInference:
    """Tests for transport type inference from config fields."""

    def test_infer_stdio_from_command(self, tmp_path: Path) -> None:
        config = tmp_path / "test.json"
        config.write_text('{"mcpServers": {"s1": {"command": "python", "args": ["server.py"]}}}')
        servers = parse_config_file(config)
        assert servers[0].transport == TransportType.STDIO

    def test_infer_http_from_url(self, tmp_path: Path) -> None:
        config = tmp_path / "test.json"
        config.write_text('{"mcpServers": {"s1": {"url": "https://example.com/mcp"}}}')
        servers = parse_config_file(config)
        assert servers[0].transport == TransportType.HTTP

    def test_infer_http_from_server_url(self, tmp_path: Path) -> None:
        config = tmp_path / "test.json"
        config.write_text('{"mcpServers": {"s1": {"serverUrl": "https://example.com/mcp"}}}')
        servers = parse_config_file(config)
        assert servers[0].transport == TransportType.HTTP

    def test_explicit_type_overrides(self, tmp_path: Path) -> None:
        config = tmp_path / "test.json"
        config.write_text('{"mcpServers": {"s1": {"type": "sse", "url": "https://example.com"}}}')
        servers = parse_config_file(config)
        assert servers[0].transport == TransportType.SSE

    def test_explicit_streamable_http(self, tmp_path: Path) -> None:
        config = tmp_path / "test.json"
        config.write_text('{"mcpServers": {"s1": {"type": "streamable-http", "url": "https://example.com"}}}')
        servers = parse_config_file(config)
        assert servers[0].transport == TransportType.HTTP
