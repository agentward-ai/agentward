"""MCP server tool enumerator.

Discovers tools exposed by MCP servers through live enumeration
(spawning the server and calling tools/list) or static inference
(guessing capabilities from the command name) as fallback.
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.request
from typing import Any

from pydantic import BaseModel, Field
from rich.console import Console

from agentward.proxy.protocol import (
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    ProtocolError,
    parse_message,
    serialize_message,
)
from agentward.scan.config import ServerConfig, TransportType

_console = Console(stderr=True)

# MCP protocol version we advertise during enumeration
_PROTOCOL_VERSION = "2025-11-25"


class ToolAnnotations(BaseModel):
    """MCP tool annotation hints about behavior."""

    read_only_hint: bool | None = None
    destructive_hint: bool | None = None
    idempotent_hint: bool | None = None
    open_world_hint: bool | None = None


class ToolInfo(BaseModel):
    """Metadata about a single MCP tool, captured from tools/list."""

    name: str
    description: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: ToolAnnotations | None = None


class ServerCapabilities(BaseModel):
    """Capabilities reported by the server during initialization."""

    has_tools: bool = False
    has_resources: bool = False
    has_prompts: bool = False
    tools_list_changed: bool = False
    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None


class EnumerationResult(BaseModel):
    """Result of enumerating a single MCP server's tools."""

    server: ServerConfig
    tools: list[ToolInfo] = Field(default_factory=list)
    capabilities: ServerCapabilities | None = None
    enumeration_method: str  # "live_stdio", "live_http", "static_inference", "failed"
    error: str | None = None


async def enumerate_server(
    server: ServerConfig, timeout: float = 15.0
) -> EnumerationResult:
    """Enumerate tools from an MCP server.

    Attempts live enumeration first (spawn + tools/list for stdio,
    HTTP POST for http/sse). Falls back to static inference on failure.

    Args:
        server: The server configuration.
        timeout: Maximum seconds to wait for server response.

    Returns:
        An EnumerationResult with discovered tools or fallback inference.
    """
    if server.transport == TransportType.STDIO:
        try:
            result = await asyncio.wait_for(
                _enumerate_stdio(server), timeout=timeout
            )
            if result.enumeration_method != "failed":
                return result
        except asyncio.TimeoutError:
            _console.print(
                f"  [#ffcc00]⏱ {server.name}:[/#ffcc00] Timed out after {timeout}s",
                highlight=False,
            )
        except Exception as e:
            _console.print(
                f"  [#ffcc00]⚠ {server.name}:[/#ffcc00] Live enumeration failed: {e}",
                highlight=False,
            )
    elif server.transport in (TransportType.HTTP, TransportType.SSE):
        try:
            result = await asyncio.wait_for(
                _enumerate_http(server), timeout=timeout
            )
            if result.enumeration_method != "failed":
                return result
        except asyncio.TimeoutError:
            _console.print(
                f"  [#ffcc00]⏱ {server.name}:[/#ffcc00] HTTP timed out after {timeout}s",
                highlight=False,
            )
        except Exception as e:
            _console.print(
                f"  [#ffcc00]⚠ {server.name}:[/#ffcc00] HTTP enumeration failed: {e}",
                highlight=False,
            )

    # Fallback to static inference
    return _static_inference(server)


async def enumerate_all(
    servers: list[ServerConfig], timeout: float = 15.0
) -> list[EnumerationResult]:
    """Enumerate tools from all servers concurrently.

    Args:
        servers: List of server configurations.
        timeout: Maximum seconds per server.

    Returns:
        A list of EnumerationResults, one per server.
    """
    tasks = [enumerate_server(s, timeout=timeout) for s in servers]
    return list(await asyncio.gather(*tasks))


async def _enumerate_stdio(server: ServerConfig) -> EnumerationResult:
    """Enumerate tools from a stdio MCP server.

    Spawns the server process, performs the MCP initialization handshake,
    calls tools/list to get tool metadata, then terminates the process.

    Args:
        server: The server configuration (must be stdio transport).

    Returns:
        EnumerationResult with live-discovered tools.
    """
    if not server.command:
        return EnumerationResult(
            server=server,
            enumeration_method="failed",
            error="No command specified for stdio server.",
        )

    cmd = [server.command, *server.args]
    env = os.environ.copy()
    env.update(server.env)

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
    except FileNotFoundError:
        return EnumerationResult(
            server=server,
            enumeration_method="failed",
            error=f"Command not found: {server.command}",
        )
    except PermissionError:
        return EnumerationResult(
            server=server,
            enumeration_method="failed",
            error=f"Permission denied: {server.command}",
        )

    assert process.stdin is not None
    assert process.stdout is not None

    try:
        # Step 1: Send initialize request
        init_request = JSONRPCRequest(
            id=1,
            method="initialize",
            params={
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentward-scanner", "version": "0.1.0"},
            },
        )
        process.stdin.write(serialize_message(init_request))
        await process.stdin.drain()

        # Read initialize response
        init_line = await process.stdout.readline()
        if not init_line:
            return EnumerationResult(
                server=server,
                enumeration_method="failed",
                error="Server closed connection before responding to initialize.",
            )

        init_msg = parse_message(init_line)
        if not isinstance(init_msg, JSONRPCResponse):
            return EnumerationResult(
                server=server,
                enumeration_method="failed",
                error=f"Expected initialize response, got {type(init_msg).__name__}.",
            )

        capabilities = _parse_capabilities(init_msg.result)

        # Step 2: Send initialized notification
        initialized_notif = JSONRPCNotification(
            method="notifications/initialized",
        )
        process.stdin.write(serialize_message(initialized_notif))
        await process.stdin.drain()

        # Step 3: Send tools/list request
        tools_request = JSONRPCRequest(
            id=2,
            method="tools/list",
            params={},
        )
        process.stdin.write(serialize_message(tools_request))
        await process.stdin.drain()

        # Read tools/list response (may need to skip notifications)
        tools: list[ToolInfo] = []
        for _ in range(10):  # read up to 10 lines looking for the response
            line = await process.stdout.readline()
            if not line:
                break
            try:
                msg = parse_message(line)
                if isinstance(msg, JSONRPCResponse) and msg.id == 2:
                    tools = _parse_tools_list(msg.result)
                    break
            except ProtocolError:
                continue

        return EnumerationResult(
            server=server,
            tools=tools,
            capabilities=capabilities,
            enumeration_method="live_stdio",
        )

    except ProtocolError as e:
        return EnumerationResult(
            server=server,
            enumeration_method="failed",
            error=f"Protocol error during enumeration: {e}",
        )
    finally:
        # Always clean up the subprocess
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()


async def _enumerate_http(server: ServerConfig) -> EnumerationResult:
    """Enumerate tools from an HTTP/SSE MCP server.

    Sends HTTP POST requests for initialize and tools/list.

    Args:
        server: The server configuration (must be http/sse transport).

    Returns:
        EnumerationResult with live-discovered tools.
    """
    if not server.url:
        return EnumerationResult(
            server=server,
            enumeration_method="failed",
            error="No URL specified for HTTP server.",
        )

    loop = asyncio.get_running_loop()

    # Run blocking HTTP calls in executor to avoid blocking the event loop
    try:
        # Step 1: Initialize
        init_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentward-scanner", "version": "0.1.0"},
            },
        }).encode("utf-8")

        init_result = await loop.run_in_executor(
            None, _http_post, server.url, init_body, server.headers
        )

        capabilities = _parse_capabilities(init_result.get("result", {}))

        # Step 2: tools/list
        tools_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }).encode("utf-8")

        tools_result = await loop.run_in_executor(
            None, _http_post, server.url, tools_body, server.headers
        )

        tools = _parse_tools_list(tools_result.get("result", {}))

        return EnumerationResult(
            server=server,
            tools=tools,
            capabilities=capabilities,
            enumeration_method="live_http",
        )

    except Exception as e:
        return EnumerationResult(
            server=server,
            enumeration_method="failed",
            error=f"HTTP enumeration failed: {e}",
        )


def _http_post(url: str, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    """Send an HTTP POST request and return the parsed JSON response.

    Args:
        url: The endpoint URL.
        body: JSON body bytes.
        headers: Additional HTTP headers.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        Exception on network errors or non-JSON responses.
    """
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            **headers,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            response_body = resp.read()
            # HTTP MCP servers may return newline-delimited JSON
            # Take the last non-empty line as the response
            lines = response_body.strip().split(b"\n")
            for line in reversed(lines):
                line = line.strip()
                if line:
                    return json.loads(line)
            return {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed: {e.reason}") from e


def _static_inference(server: ServerConfig) -> EnumerationResult:
    """Infer basic server capabilities from command name/args when live enumeration fails.

    This is a best-effort fallback — it can't discover actual tools, but it
    can flag likely capability categories based on well-known package names.

    Args:
        server: The server configuration.

    Returns:
        An EnumerationResult with enumeration_method="static_inference"
        and an empty tools list (we don't fake tool names).
    """
    # Build a searchable string from command + args
    if server.transport == TransportType.STDIO:
        search_str = " ".join([server.command or "", *server.args]).lower()
    else:
        search_str = (server.url or "").lower()

    # Infer what kind of server this likely is
    inferred_notes: list[str] = []

    keyword_patterns = {
        "filesystem": "Likely provides filesystem read/write tools",
        "github": "Likely provides GitHub API tools (repos, issues, PRs)",
        "slack": "Likely provides Slack messaging tools",
        "postgres": "Likely provides PostgreSQL database query tools",
        "sqlite": "Likely provides SQLite database tools",
        "gmail": "Likely provides Gmail email tools",
        "email": "Likely provides email tools",
        "browser": "Likely provides web browsing tools",
        "playwright": "Likely provides browser automation tools",
        "puppeteer": "Likely provides browser automation tools",
        "fetch": "Likely provides HTTP fetch/web scraping tools",
        "memory": "Likely provides knowledge/memory storage tools",
        "git": "Likely provides Git version control tools",
        "docker": "Likely provides Docker container management tools",
        "shell": "Likely provides shell command execution tools",
        "exec": "Likely provides command execution tools",
    }

    for keyword, note in keyword_patterns.items():
        if keyword in search_str:
            inferred_notes.append(note)

    warning = "Live enumeration failed. "
    if inferred_notes:
        warning += "Static inference: " + "; ".join(inferred_notes)
    else:
        warning += "Could not infer capabilities from command name."

    return EnumerationResult(
        server=server,
        tools=[],
        capabilities=None,
        enumeration_method="static_inference",
        error=warning,
    )


def _parse_capabilities(result: dict[str, Any]) -> ServerCapabilities:
    """Parse server capabilities from an initialize response.

    Args:
        result: The `result` field from the initialize response.

    Returns:
        A ServerCapabilities object.
    """
    caps = result.get("capabilities", {})
    server_info = result.get("serverInfo", {})

    tools_cap = caps.get("tools", {})

    return ServerCapabilities(
        has_tools="tools" in caps,
        has_resources="resources" in caps,
        has_prompts="prompts" in caps,
        tools_list_changed=tools_cap.get("listChanged", False) if isinstance(tools_cap, dict) else False,
        server_name=server_info.get("name") if isinstance(server_info, dict) else None,
        server_version=server_info.get("version") if isinstance(server_info, dict) else None,
        protocol_version=result.get("protocolVersion"),
    )


def _parse_tools_list(result: dict[str, Any]) -> list[ToolInfo]:
    """Parse tools from a tools/list response.

    Args:
        result: The `result` field from the tools/list response.

    Returns:
        A list of ToolInfo objects.
    """
    raw_tools = result.get("tools", [])
    if not isinstance(raw_tools, list):
        return []

    tools: list[ToolInfo] = []
    for raw in raw_tools:
        if not isinstance(raw, dict):
            continue

        name = raw.get("name")
        if not isinstance(name, str):
            continue

        annotations = None
        raw_annotations = raw.get("annotations")
        if isinstance(raw_annotations, dict):
            annotations = ToolAnnotations(
                read_only_hint=raw_annotations.get("readOnlyHint"),
                destructive_hint=raw_annotations.get("destructiveHint"),
                idempotent_hint=raw_annotations.get("idempotentHint"),
                open_world_hint=raw_annotations.get("openWorldHint"),
            )

        tools.append(
            ToolInfo(
                name=name,
                description=raw.get("description"),
                input_schema=raw.get("inputSchema", {}),
                annotations=annotations,
            )
        )

    return tools
