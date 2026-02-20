"""Tests for the MCP server tool enumerator.

Live enumeration tests are limited to unit-testable components.
Full live enumeration requires real MCP servers and is tested manually.
"""

from pathlib import Path

import pytest

from agentward.scan.config import ServerConfig, TransportType
from agentward.scan.enumerator import (
    EnumerationResult,
    ServerCapabilities,
    ToolAnnotations,
    ToolInfo,
    _parse_capabilities,
    _parse_tools_list,
    _static_inference,
)


def _make_server(
    name: str = "test",
    command: str | None = "test-cmd",
    args: list[str] | None = None,
    transport: TransportType = TransportType.STDIO,
    url: str | None = None,
) -> ServerConfig:
    return ServerConfig(
        name=name,
        transport=transport,
        command=command,
        args=args or [],
        source_file=Path("/test/config.json"),
        client="test",
        url=url,
    )


class TestParseCapabilities:
    """Tests for parsing initialize response capabilities."""

    def test_full_capabilities(self) -> None:
        result = {
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True},
                "prompts": {},
            },
            "serverInfo": {
                "name": "test-server",
                "version": "1.0.0",
            },
        }
        caps = _parse_capabilities(result)
        assert caps.has_tools is True
        assert caps.has_resources is True
        assert caps.has_prompts is True
        assert caps.tools_list_changed is True
        assert caps.server_name == "test-server"
        assert caps.server_version == "1.0.0"
        assert caps.protocol_version == "2025-11-25"

    def test_minimal_capabilities(self) -> None:
        result = {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
        }
        caps = _parse_capabilities(result)
        assert caps.has_tools is False
        assert caps.has_resources is False
        assert caps.tools_list_changed is False
        assert caps.server_name is None

    def test_empty_result(self) -> None:
        caps = _parse_capabilities({})
        assert caps.has_tools is False
        assert caps.protocol_version is None


class TestParseToolsList:
    """Tests for parsing tools/list response."""

    def test_parse_multiple_tools(self) -> None:
        result = {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a text file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                    "annotations": {
                        "readOnlyHint": True,
                    },
                },
                {
                    "name": "write_file",
                    "description": "Write a text file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"},
                        },
                    },
                    "annotations": {
                        "destructiveHint": True,
                        "idempotentHint": True,
                    },
                },
            ]
        }
        tools = _parse_tools_list(result)
        assert len(tools) == 2
        assert tools[0].name == "read_file"
        assert tools[0].annotations is not None
        assert tools[0].annotations.read_only_hint is True
        assert tools[1].name == "write_file"
        assert tools[1].annotations is not None
        assert tools[1].annotations.destructive_hint is True

    def test_parse_tool_without_annotations(self) -> None:
        result = {
            "tools": [
                {
                    "name": "simple_tool",
                    "inputSchema": {"type": "object"},
                },
            ]
        }
        tools = _parse_tools_list(result)
        assert len(tools) == 1
        assert tools[0].annotations is None

    def test_parse_empty_tools(self) -> None:
        result = {"tools": []}
        tools = _parse_tools_list(result)
        assert tools == []

    def test_parse_missing_tools_key(self) -> None:
        tools = _parse_tools_list({})
        assert tools == []

    def test_skip_invalid_tool_entries(self) -> None:
        result = {
            "tools": [
                {"name": "valid_tool"},
                "not a dict",
                {"no_name_field": True},
                {"name": 42},  # name must be string
            ]
        }
        tools = _parse_tools_list(result)
        assert len(tools) == 1
        assert tools[0].name == "valid_tool"


class TestStaticInference:
    """Tests for static inference fallback."""

    def test_filesystem_command(self) -> None:
        server = _make_server(
            name="fs",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
        )
        result = _static_inference(server)
        assert result.enumeration_method == "static_inference"
        assert result.tools == []
        assert result.error is not None
        assert "filesystem" in result.error.lower()

    def test_github_command(self) -> None:
        server = _make_server(
            name="gh",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-github"],
        )
        result = _static_inference(server)
        assert "github" in result.error.lower() or "GitHub" in result.error

    def test_unknown_command(self) -> None:
        server = _make_server(
            name="mystery",
            command="my-custom-server",
            args=["--port", "8080"],
        )
        result = _static_inference(server)
        assert "Could not infer" in result.error

    def test_slack_command(self) -> None:
        server = _make_server(
            name="slack",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-slack"],
        )
        result = _static_inference(server)
        assert "slack" in result.error.lower() or "Slack" in result.error

    def test_http_server_inference(self) -> None:
        server = _make_server(
            name="remote",
            command=None,
            transport=TransportType.HTTP,
            url="https://db-postgres.example.com/mcp",
        )
        result = _static_inference(server)
        assert "postgres" in result.error.lower()
