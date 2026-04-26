#!/usr/bin/env python3
"""Minimal MCP stdio stub for the FlowTraders demo.

Responds to ``initialize`` and ``tools/list`` with a fixed tool set
chosen by the ``--skill`` argument. Not a real implementation — it
exists so ``agentward scan`` produces a populated Scan Inventory in
the Evidence Pack without us needing to ship a real trading-firm
MCP server stack.

Usage in demo-mcp.json:
    {"command": "python3", "args": ["mock-mcp-server.py", "--skill", "trading-engine"]}
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

# Tool definitions per demo skill. Mirrors the SKILL.md capabilities so
# the Evidence Pack inventory matches the policy's skill names.
SKILLS: dict[str, list[dict[str, Any]]] = {
    "trading-engine": [
        {
            "name": "submit_order",
            "description": "Submit an order to the broker FIX gateway",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "symbol": {"type": "string"},
                    "side": {"type": "string", "enum": ["BUY", "SELL"]},
                    "size": {"type": "integer"},
                    "limit_price": {"type": "number"},
                },
                "required": ["symbol", "side", "size"],
            },
        },
        {
            "name": "read_positions",
            "description": "Read current position book from broker API",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "cancel_order",
            "description": "Cancel an open order via the broker",
            "inputSchema": {
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            },
        },
    ],
    "market-data-feed": [
        {
            "name": "subscribe_quotes",
            "description": "Stream Level-1 quotes from the data vendor",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "symbols": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["symbols"],
            },
        },
        {
            "name": "snapshot_book",
            "description": "Single-shot depth-of-book snapshot",
            "inputSchema": {
                "type": "object",
                "properties": {"symbol": {"type": "string"}},
                "required": ["symbol"],
            },
        },
        {
            "name": "list_symbols",
            "description": "List available instruments from the vendor catalogue",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ],
    "fix-gateway": [
        {
            "name": "session_init",
            "description": "Open a FIX 4.4 session to the prime broker",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "session_close",
            "description": "Send Logout and close the FIX session cleanly",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "resend_request",
            "description": "Issue ResendRequest to recover missed sequence numbers",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "begin_seq": {"type": "integer"},
                    "end_seq": {"type": "integer"},
                },
                "required": ["begin_seq", "end_seq"],
            },
        },
    ],
    "research-notebook": [
        {
            "name": "read_notebook",
            "description": "Read a notebook file from the local research directory",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
        {
            "name": "append_note",
            "description": "Append a markdown cell to a notebook file",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        },
        {
            "name": "list_notebooks",
            "description": "List notebook files under the research directory",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skill", required=True, choices=sorted(SKILLS.keys()))
    args = parser.parse_args()
    tools = SKILLS[args.skill]

    # MCP stdio: newline-delimited JSON-RPC. Read until stdin closes.
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": args.skill, "version": "demo-1.0"},
                },
            }
        elif method == "notifications/initialized":
            # Notification — no response expected.
            continue
        elif method == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools},
            }
        else:
            response = {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }

        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
