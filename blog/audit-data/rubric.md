# Scoring Rubric — MCP Server Audit (March 2026)

## Classification Method

Each tool enumerated via `tools/list` is classified across five dimensions.

### 1. Default Authority

What the tool can do out of the box, with no policy or restrictions applied.

**Detection:** MCP `tools/list` response provides the tool name, description, and `inputSchema`. The input schema's property names and types indicate what data the tool operates on.

### 2. Write Capability

Whether the tool can modify, create, or delete data.

**Detection:**
- Tool name verb patterns: `write`, `create`, `delete`, `edit`, `push`, `update`, `send`, `post`, `put`, `patch`, `move`, `remove`, `drop`, `kill`, `terminate`
- MCP annotation: `destructiveHint: true` (server-declared)
- MCP annotation: `readOnlyHint: true` (server-declared, inverted)
- Input schema analysis: presence of body/content/data parameters alongside target parameters

### 3. Credential Exposure

Whether the tool handles, transmits, or has access to secrets, tokens, or session state.

**Detection:**
- Input schema property names: `token`, `key`, `password`, `auth`, `secret`, `credential`, `api_key`
- Data access type classification: if tool accesses `credentials` type
- Server environment requirements: tokens passed via env vars (noted but not scored per-tool)

### 4. Cross-Server Escalation Potential

Whether this tool's declared capabilities could pair with capabilities of another server to create an escalation path.

**Detection:** Capability pair analysis using 9 source→sink patterns implemented in `agentward/scan/chains.py`:

| # | Source Type | Sink Type | Risk | Description |
|---|-----------|----------|------|-------------|
| 1 | email | browser | HIGH | Email content could leak via browsing |
| 2 | email | shell | CRITICAL | Email content could trigger code execution |
| 3 | browser | shell | CRITICAL | Web content could trigger code execution |
| 4 | browser | email | HIGH | Web content could trigger email actions |
| 5 | messaging | shell | CRITICAL | Chat messages could trigger code execution |
| 6 | messaging | browser | HIGH | Chat messages could leak via browsing |
| 7 | filesystem | shell | CRITICAL | File content could trigger code execution |
| 8 | database | shell | CRITICAL | Database content could trigger code execution |
| 9 | network | shell | CRITICAL | Network responses could trigger code execution |

These patterns identify *structural possibility* based on declared data-access types, not demonstrated runtime exploits. A pairing is flagged when one tool has the source data-access type and another tool (on the same or a different server) has the sink type.

The analysis operates at the **tool-to-tool** level: each tool's data-access types are matched against every other tool's types. Multiple pairings can originate from the same server pair if both servers expose many tools. Same-server pairings are also counted (e.g., desktop-commander's filesystem tools pairing with its own `start_process`).

### 5. Human Approval Gap

Whether this tool's blast radius warrants human confirmation that MCP does not provide.

**Detection:** Flagged when a tool has write + network access, shell access, or credential access, and the MCP protocol provides no mechanism for the host to require confirmation before execution. (Note: some host applications like Claude Desktop do implement their own confirmation dialogs, but this is not part of the MCP specification.)

## Risk Level Assignment

| Level | Criteria |
|-------|----------|
| **CRITICAL** | Shell/code execution capability, OR network + credentials combined |
| **HIGH** | Write + destructive capability on sensitive data (filesystem, database), OR tools self-annotated as destructive |
| **MEDIUM** | Write capability on non-destructive data, OR network/browser access, OR messaging write access |
| **LOW** | Read-only access, OR tools self-annotated as read-only, OR no sensitive data access detected |

## Data Access Type Inference

Tool data access types are inferred from:
- Tool name: `read_file` → filesystem, `query` → database, `navigate` → browser + network
- Input schema property names: `path` → filesystem, `url` → network, `query`/`sql` → database
- Server name context: tools on a server named "slack" default to messaging access

## Tool Surface Source

All tool data comes from live MCP enumeration:
1. Server started as subprocess (stdio transport)
2. MCP handshake: `initialize` request → response → `notifications/initialized`
3. `tools/list` request → response containing tool names, descriptions, input schemas, and annotations
4. No tools were invoked. Classification is based entirely on declared metadata.
