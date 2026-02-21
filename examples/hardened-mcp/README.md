# Hardened MCP Profile

A security-first AgentWard policy for 6 popular MCP servers. Works with Claude Desktop, Cursor, VS Code, or Claude Code — no additional software required.

## What's Included

| File | Purpose |
|------|---------|
| `agentward.yaml` | Hardened policy — file writes gated, deletes blocked, chaining restricted |
| `mcp.json.template` | MCP config with 6 servers, all routed through AgentWard |
| `setup.sh` | One-command installer — detects your MCP host, copies everything |

## MCP Servers

| Server | What It Does | Policy |
|--------|-------------|--------|
| **filesystem** | Read/write local files | Read allowed, write requires approval |
| **github** | GitHub issues, PRs, repos | Read/create allowed, merge/delete blocked |
| **slack** | Slack messages, reactions | Read/send allowed, delete blocked |
| **memory** | Local knowledge graph | Unrestricted (low risk) |
| **brave-search** | Web search | Unrestricted (read-only) |
| **puppeteer** | Browser automation | Browsing allowed, file/email access denied |

## Prerequisites

```bash
pip install agentward    # AgentWard CLI
brew install node        # npx (for MCP servers) — or: apt install nodejs npm
```

Plus one of: [Claude Desktop](https://claude.ai/download), [Cursor](https://cursor.com), or [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

## Install

```bash
git clone https://github.com/agentward-ai/agentward.git
cd agentward/examples/hardened-mcp
chmod +x setup.sh && ./setup.sh
```

The script will:
1. Detect which MCP host you have installed
2. Copy the policy and MCP config to the right location
3. Run `agentward scan` to verify everything works

## What Happens After Install

Every tool call from your MCP host now routes through AgentWard:

```
Your Agent (Claude, Cursor, etc.)
  ↓ tools/call
AgentWard (policy check)
  ↓ ALLOW / BLOCK / APPROVE
MCP Server (filesystem, github, etc.)
```

- **Allowed** calls pass through transparently
- **Blocked** calls return an error to the agent
- **Approval-gated** calls pause for your confirmation

## Customizing

Edit the policy after install:

```bash
# The setup script tells you where it copied the policy.
# For Claude Desktop on macOS:
vim ~/Library/Application\ Support/Claude/agentward.yaml

# Then rescan to verify:
agentward scan
```
