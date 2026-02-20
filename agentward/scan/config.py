"""MCP configuration file parser.

Parses MCP config files from all major clients (Claude Desktop, Claude Code,
Cursor, VS Code, Windsurf) into a unified ServerConfig list.

Supported formats:
  - Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json
  - Claude Code:    .mcp.json (project-level)
  - Cursor:         ~/.cursor/mcp.json (global), .cursor/mcp.json (project)
  - VS Code:        .vscode/mcp.json
  - Windsurf:       ~/.codeium/windsurf/mcp_config.json

All use a similar structure with minor variations in root keys and field names.
"""

from __future__ import annotations

import json
import platform
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class TransportType(str, Enum):
    """MCP server transport type."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    PYTHON = "python"
    OPENCLAW = "openclaw"


class ServerConfig(BaseModel):
    """Unified configuration for a single MCP server.

    Normalizes the various client-specific config formats into
    a single structure that the rest of the scan pipeline can use.
    """

    name: str
    transport: TransportType

    # stdio fields
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)

    # http/sse fields
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)

    # metadata
    source_file: Path
    client: str  # "claude_desktop", "claude_code", "cursor", "vscode", "windsurf", "unknown"


class ConfigParseError(Exception):
    """Raised when a config file cannot be parsed.

    Attributes:
        path: The config file that failed.
    """

    def __init__(self, path: Path, message: str) -> None:
        self.path = path
        super().__init__(message)


def parse_config_file(path: Path) -> list[ServerConfig]:
    """Parse an MCP config file into a list of server configurations.

    Auto-detects the config format by examining root keys. Supports:
      - `mcpServers` root key (Claude Desktop, Claude Code, Cursor, Windsurf)
      - `servers` root key (VS Code)
      - `customizations.vscode.mcp.servers` nested key (VS Code devcontainer)

    Args:
        path: Path to the MCP config JSON file.

    Returns:
        A list of ServerConfig objects, one per server defined in the file.

    Raises:
        FileNotFoundError: If the config file doesn't exist.
        ConfigParseError: If the file is malformed or unrecognized.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found at {path}. "
            f"Check that the path is correct, or run `agentward scan` "
            f"without arguments to auto-discover config files."
        )

    raw_text = path.read_text(encoding="utf-8")

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ConfigParseError(
            path, f"Failed to parse JSON in {path}: {e}"
        ) from e

    if not isinstance(data, dict):
        raise ConfigParseError(
            path, f"Config file {path} must contain a JSON object at the top level."
        )

    client = detect_client(path)
    servers_dict = _extract_servers_dict(data, path)

    if not servers_dict:
        return []

    results: list[ServerConfig] = []
    for name, server_data in servers_dict.items():
        if not isinstance(server_data, dict):
            continue  # Skip malformed entries silently
        config = _parse_single_server(name, server_data, path, client)
        results.append(config)

    return results


def discover_configs() -> list[Path]:
    """Find all MCP config files on the system.

    Checks known paths for each supported client. Returns only
    paths that actually exist on disk.

    Returns:
        A list of existing config file paths, ordered by client.
    """
    candidates: list[Path] = []

    system = platform.system()

    # Claude Desktop
    if system == "Darwin":
        candidates.append(
            Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
    elif system == "Windows":
        appdata = Path.home() / "AppData" / "Roaming"
        candidates.append(appdata / "Claude" / "claude_desktop_config.json")
    else:  # Linux
        xdg = Path.home() / ".config"
        candidates.append(xdg / "Claude" / "claude_desktop_config.json")

    # Cursor (global)
    candidates.append(Path.home() / ".cursor" / "mcp.json")

    # Cursor (project-level — check cwd)
    candidates.append(Path.cwd() / ".cursor" / "mcp.json")

    # Claude Code (project-level)
    candidates.append(Path.cwd() / ".mcp.json")

    # VS Code (project-level)
    candidates.append(Path.cwd() / ".vscode" / "mcp.json")

    # Windsurf
    candidates.append(Path.home() / ".codeium" / "windsurf" / "mcp_config.json")

    return [p for p in candidates if p.exists()]


def detect_client(path: Path) -> str:
    """Infer which MCP client a config file belongs to from its path.

    Args:
        path: Path to the config file.

    Returns:
        A client identifier string.
    """
    resolved = str(path.resolve())

    if "Application Support/Claude" in resolved or "AppData/Roaming/Claude" in resolved:
        return "claude_desktop"
    if ".config/Claude" in resolved:
        return "claude_desktop"
    if ".cursor" in resolved:
        return "cursor"
    if ".mcp.json" in resolved and ".cursor" not in resolved:
        return "claude_code"
    if ".vscode" in resolved:
        return "vscode"
    if ".codeium" in resolved or "windsurf" in resolved:
        return "windsurf"

    return "unknown"


def _extract_servers_dict(data: dict[str, Any], path: Path) -> dict[str, Any]:
    """Extract the servers dictionary from a config file, handling format variations.

    Args:
        data: Parsed JSON data.
        path: Path for error messages.

    Returns:
        The servers dictionary, or empty dict if none found.
    """
    # Most common: mcpServers root key (Claude Desktop, Claude Code, Cursor, Windsurf)
    if "mcpServers" in data:
        servers = data["mcpServers"]
        if isinstance(servers, dict):
            return servers

    # VS Code: servers root key
    if "servers" in data:
        servers = data["servers"]
        if isinstance(servers, dict):
            return servers

    # VS Code devcontainer: customizations.vscode.mcp.servers
    customizations = data.get("customizations", {})
    if isinstance(customizations, dict):
        vscode = customizations.get("vscode", {})
        if isinstance(vscode, dict):
            mcp = vscode.get("mcp", {})
            if isinstance(mcp, dict):
                servers = mcp.get("servers", {})
                if isinstance(servers, dict):
                    return servers

    return {}


def _parse_single_server(
    name: str,
    data: dict[str, Any],
    source_file: Path,
    client: str,
) -> ServerConfig:
    """Parse a single server entry from the config.

    Transport type detection:
      - Explicit `type` field takes priority
      - Has `command` → stdio
      - Has `url` or `serverUrl` → http (or sse if type says so)
      - Otherwise → stdio (default)

    Args:
        name: The server name key.
        data: The server config dict.
        source_file: Which file this came from.
        client: Which client this belongs to.

    Returns:
        A ServerConfig object.
    """
    # Detect transport type
    explicit_type = data.get("type", "").lower()
    transport: TransportType

    if explicit_type in ("http", "streamable-http"):
        transport = TransportType.HTTP
    elif explicit_type == "sse":
        transport = TransportType.SSE
    elif explicit_type == "stdio":
        transport = TransportType.STDIO
    elif "command" in data:
        transport = TransportType.STDIO
    elif "url" in data or "serverUrl" in data:
        # Windsurf uses serverUrl, others use url
        transport = TransportType.HTTP
    else:
        transport = TransportType.STDIO

    # Extract fields based on transport
    command: str | None = None
    args: list[str] = []
    env: dict[str, str] = {}
    url: str | None = None
    headers: dict[str, str] = {}

    if transport == TransportType.STDIO:
        command = data.get("command")
        raw_args = data.get("args", [])
        if isinstance(raw_args, list):
            args = [str(a) for a in raw_args]
        raw_env = data.get("env", {})
        if isinstance(raw_env, dict):
            env = {str(k): str(v) for k, v in raw_env.items()}
    else:
        # HTTP or SSE
        url = data.get("url") or data.get("serverUrl")
        raw_headers = data.get("headers", {})
        if isinstance(raw_headers, dict):
            headers = {str(k): str(v) for k, v in raw_headers.items()}

    return ServerConfig(
        name=name,
        transport=transport,
        command=command,
        args=args,
        env=env,
        url=url,
        headers=headers,
        source_file=source_file,
        client=client,
    )
