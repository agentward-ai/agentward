"""Standalone MCP server that exposes AgentWard capabilities as tools.

Used for:
- Glama inspectability (Docker stdio)
- MCP clients that want to invoke AgentWard scan/configure/comply directly

Speaks JSON-RPC 2.0 over stdio, implements the MCP server protocol.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any


# MCP protocol version
PROTOCOL_VERSION = "2025-11-05"
SERVER_NAME = "agentward"
SERVER_VERSION = "0.3.2"

# Tool definitions exposed to MCP clients
TOOLS = [
    {
        "name": "agentward_scan",
        "description": (
            "Scan MCP server configurations and Python tool definitions for security risks. "
            "Discovers tools, rates risk levels, detects dangerous skill chains, and generates "
            "a permission map with recommendations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to an MCP config file (e.g., claude_desktop_config.json, mcp.json) "
                        "or a directory to scan for tool definitions. Defaults to auto-discovery."
                    ),
                },
                "format": {
                    "type": "string",
                    "enum": ["text", "json", "markdown"],
                    "description": "Output format. Defaults to text.",
                },
            },
        },
    },
    {
        "name": "agentward_configure",
        "description": (
            "Generate a smart-default agentward.yaml policy file based on scan results. "
            "Produces security-aware defaults with skill restrictions, approval gates, "
            "and chaining rules tailored to detected use-case patterns."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to scan for generating the policy. Defaults to auto-discovery.",
                },
                "output": {
                    "type": "string",
                    "description": "Output path for the generated policy YAML.",
                },
            },
        },
    },
    {
        "name": "agentward_comply",
        "description": (
            "Evaluate an AgentWard policy against a compliance framework (HIPAA, SOX, GDPR, PCI-DSS). "
            "Generates a compliance delta report with specific gaps and auto-fix suggestions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "enum": ["hipaa"],
                    "description": "Compliance framework to evaluate against. Currently supports HIPAA.",
                },
                "policy": {
                    "type": "string",
                    "description": "Path to the agentward.yaml policy file.",
                },
                "fix": {
                    "type": "boolean",
                    "description": "If true, generate a corrected policy file with all required changes applied.",
                },
            },
            "required": ["framework"],
        },
    },
    {
        "name": "agentward_map",
        "description": (
            "Generate a permission graph visualization showing tool access patterns, "
            "risk ratings, and data flow between skills."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to scan for generating the permission map.",
                },
                "format": {
                    "type": "string",
                    "enum": ["text", "mermaid", "json"],
                    "description": "Output format. Defaults to text.",
                },
            },
        },
    },
]


def _make_response(request_id: int | str, result: dict[str, Any]) -> bytes:
    """Serialize a JSON-RPC 2.0 response."""
    msg = {"jsonrpc": "2.0", "id": request_id, "result": result}
    return json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"


def _make_error(request_id: int | str | None, code: int, message: str) -> bytes:
    """Serialize a JSON-RPC 2.0 error response."""
    msg = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    return json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"


async def _run_scan(params: dict[str, Any]) -> dict[str, Any]:
    """Execute agentward scan and return results."""
    from agentward.scan.config import discover_configs, parse_config
    from agentward.scan.permissions import build_permission_map
    from agentward.scan.recommendations import generate_recommendations

    path = params.get("path")
    output_format = params.get("format", "json")

    try:
        if path:
            target = Path(path)
            if target.is_file():
                configs = [parse_config(target)]
            else:
                configs = discover_configs(target)
        else:
            configs = discover_configs()

        all_servers: list[dict[str, Any]] = []
        for config in configs:
            for name, server in config.servers.items():
                all_servers.append({
                    "name": name,
                    "command": server.command,
                    "args": server.args,
                    "source": str(config.path),
                })

        permission_map = build_permission_map(configs)
        recommendations = generate_recommendations(permission_map)

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "servers_found": len(all_servers),
                        "servers": all_servers,
                        "permissions": [p.model_dump() if hasattr(p, "model_dump") else str(p) for p in permission_map],
                        "recommendations": [r.model_dump() if hasattr(r, "model_dump") else str(r) for r in recommendations],
                    }, indent=2),
                }
            ]
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Scan error: {e}"}],
            "isError": True,
        }


async def _run_configure(params: dict[str, Any]) -> dict[str, Any]:
    """Execute agentward configure and return generated policy."""
    from agentward.scan.config import discover_configs
    from agentward.scan.permissions import build_permission_map
    from agentward.configure.generator import generate_policy

    try:
        path = params.get("path")
        configs = discover_configs(Path(path)) if path else discover_configs()
        permission_map = build_permission_map(configs)
        policy_yaml = generate_policy(permission_map)

        output_path = params.get("output")
        if output_path:
            Path(output_path).write_text(policy_yaml)

        return {
            "content": [{"type": "text", "text": policy_yaml}]
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Configure error: {e}"}],
            "isError": True,
        }


async def _run_comply(params: dict[str, Any]) -> dict[str, Any]:
    """Execute agentward comply and return compliance report."""
    from agentward.comply.controls import evaluate_compliance, apply_fixes
    from agentward.comply.frameworks import get_framework
    from agentward.policy.loader import load_policy

    framework_name = params.get("framework", "hipaa")
    policy_path = params.get("policy", "agentward.yaml")
    fix = params.get("fix", False)

    try:
        policy = load_policy(Path(policy_path))
        controls = get_framework(framework_name)
        report = evaluate_compliance(policy, controls)

        result: dict[str, Any] = {
            "framework": framework_name,
            "overall_rating": report.overall_rating,
            "findings_count": len(report.findings),
            "findings": [
                {
                    "control": f.control_id,
                    "status": f.status,
                    "message": f.message,
                    "severity": f.severity,
                }
                for f in report.findings
            ],
        }

        if fix:
            fixed_policy = apply_fixes(policy, report)
            result["fixed_policy"] = fixed_policy

        return {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
        }
    except FileNotFoundError:
        return {
            "content": [{"type": "text", "text": f"Policy file not found: {policy_path}. Run agentward_configure first."}],
            "isError": True,
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Comply error: {e}"}],
            "isError": True,
        }


async def _run_map(params: dict[str, Any]) -> dict[str, Any]:
    """Execute agentward map and return permission graph."""
    from agentward.scan.config import discover_configs
    from agentward.scan.permissions import build_permission_map

    try:
        path = params.get("path")
        configs = discover_configs(Path(path)) if path else discover_configs()
        permission_map = build_permission_map(configs)

        output_format = params.get("format", "json")
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        [p.model_dump() if hasattr(p, "model_dump") else str(p) for p in permission_map],
                        indent=2,
                    ),
                }
            ]
        }
    except Exception as e:
        return {
            "content": [{"type": "text", "text": f"Map error: {e}"}],
            "isError": True,
        }


TOOL_HANDLERS = {
    "agentward_scan": _run_scan,
    "agentward_configure": _run_configure,
    "agentward_comply": _run_comply,
    "agentward_map": _run_map,
}


async def handle_message(data: dict[str, Any]) -> bytes | None:
    """Handle a single JSON-RPC 2.0 message and return the response bytes (or None for notifications)."""
    method = data.get("method")
    request_id = data.get("id")
    params = data.get("params", {})

    # Notifications (no id) — no response
    if request_id is None and method:
        return None

    if method == "initialize":
        return _make_response(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        })

    elif method == "tools/list":
        return _make_response(request_id, {"tools": TOOLS})

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})
        handler = TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return _make_error(request_id, -32601, f"Unknown tool: {tool_name}")
        result = await handler(tool_args)
        return _make_response(request_id, result)

    elif method == "ping":
        return _make_response(request_id, {})

    elif method is not None:
        return _make_error(request_id, -32601, f"Method not found: {method}")

    else:
        return _make_error(request_id, -32600, "Invalid request")


def serve_stdio() -> None:
    """Run the MCP server over stdio, reading JSON-RPC messages line by line."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            resp = _make_error(None, -32700, "Parse error")
            sys.stdout.buffer.write(resp)
            sys.stdout.buffer.flush()
            continue

        resp = asyncio.run(handle_message(data))
        if resp is not None:
            sys.stdout.buffer.write(resp)
            sys.stdout.buffer.flush()


def main() -> None:
    """Entry point for the MCP server."""
    serve_stdio()


if __name__ == "__main__":
    main()
