# I Audited 10 Popular MCP Servers and Mapped Their Default Blast Radius

MCP (Model Context Protocol) lets AI agents call tools; read files, query databases, browse the web, post messages. If you use Claude Desktop, Cursor, or VS Code with an AI assistant, you probably have MCP servers installed.

I wanted to understand what a typical MCP setup actually authorizes at the tool level. Not what the README says. What the server declares when you connect to it, perform the protocol handshake, and enumerate its tools.

I selected 10 widely-used MCP servers, started each one, called `tools/list`, and classified every tool by its default authority, write capability, credential exposure, and cross-server escalation potential.

Everything needed to reproduce or challenge this audit; the exact configuration, scoring rubric, chain analysis, and scan commands; is included in this post.

---

## Server Selection

I chose servers that meet at least two of these criteria:

- **(a)** Included in the official [`modelcontextprotocol/servers`](https://github.com/modelcontextprotocol/servers) repository (82K+ GitHub stars)
- **(b)** Referenced in Anthropic's [MCP quickstart documentation](https://modelcontextprotocol.io/docs/develop/connect-local-servers)
- **(c)** Ranked in the top 20 on [mcp.directory](https://mcp.directory) or [Smithery](https://smithery.ai) by installs or views
- **(d)** Listed in the [`awesome-mcp-servers`](https://github.com/wong2/awesome-mcp-servers) curated list

| Server | Package | Criteria Met | Version Tested |
|--------|---------|:------------:|----------------|
| filesystem | `@modelcontextprotocol/server-filesystem` | a, b, c | 2026.1.14 |
| github | `@modelcontextprotocol/server-github` | a, b | 2025.4.8 |
| playwright | `@playwright/mcp` | c, d | 0.0.68 |
| desktop-commander | `@wonderwhy-er/desktop-commander` | c, d | 0.2.38 |
| fetch | `mcp-server-fetch` (PyPI) | a, b | 2025.4.7 |
| postgres | `@modelcontextprotocol/server-postgres` | a, d | 0.6.2 |
| sqlite | `mcp-server-sqlite-npx` | a, b | 0.8.0 |
| slack | `@modelcontextprotocol/server-slack` | a, d | 2025.4.25 |
| git | `mcp-server-git` (PyPI) | a, d | 2026.1.14 |
| memory | `@modelcontextprotocol/server-memory` | a, b | 2026.1.26 |

The set covers filesystem, network, browser automation, shell execution, databases, messaging, version control, and persistent storage. I limited browser automation to one server (Microsoft's official Playwright) to avoid skewing the sample toward a single capability category. Desktop Commander is included as a community-maintained server with a different authority profile.

---

## Scoring Rubric

Each tool was classified across five dimensions:

| Dimension | What It Measures | How It's Detected |
|-----------|-----------------|-------------------|
| **Default Authority** | What the tool can do out of the box, with no policy applied | MCP `tools/list` enumeration + input schema analysis |
| **Write Capability** | Can the tool modify, create, or delete data? | Tool name patterns (`write`, `create`, `delete`, `edit`, `push`) + MCP `destructiveHint` annotation |
| **Credential Exposure** | Does the tool handle or transmit secrets, tokens, or session state? | Input schema property names (`token`, `key`, `password`, `auth`) + data access classification |
| **Cross-Server Escalation** | Could this tool's output plausibly feed into a higher-privilege tool on another server? | Capability pair analysis: 9 source→sink patterns (see [Chain Analysis Method](#chain-analysis-method)) |
| **Human Approval Gap** | Does this action's blast radius warrant human confirmation that MCP doesn't provide? | Write + network + shell access without MCP-level approval gates |

**Risk level assignment:**

| Level | Criteria |
|-------|----------|
| CRITICAL | Shell/code execution capability, OR network + credentials combined |
| HIGH | Write + destructive capability on sensitive data (filesystem, database), OR tools self-annotated as destructive |
| MEDIUM | Write capability on non-destructive data, OR network/browser access, OR messaging write access |
| LOW | Read-only access, OR tools self-annotated as read-only, OR no sensitive data access detected |

---

## Findings

### 1. Two of 10 servers expose arbitrary code execution tools with no approval gate

Desktop Commander's `start_process` runs arbitrary shell commands on the host. Playwright's `browser_evaluate` and `browser_run_code` execute arbitrary JavaScript in the browser context.

These tools accept code as input and execute it. That's their purpose; and if you've installed these servers, you've authorized this capability.

| Server | Tool | Execution Type | Self-Annotated Destructive? |
|--------|------|---------------|:---------------------------:|
| desktop-commander | `start_process` | Shell commands on host | Yes |
| playwright | `browser_evaluate` | JavaScript in browser | Yes |
| playwright | `browser_run_code` | JavaScript in browser | Yes |

Desktop Commander is transparent about the risk: of its 26 tools, **9 are self-annotated as DESTRUCTIVE** (`set_config_value`, `write_file`, `write_pdf`, `move_file`, `edit_block`, `start_process`, `interact_with_process`, `force_terminate`, `kill_process`). The server authors know these tools can cause irreversible damage.

Microsoft's Playwright server is similarly honest: **17 of 22 tools** carry `destructiveHint: true`. This matters because it gives downstream tools; policy engines, approval gates; a signal to act on. But MCP itself defines no mechanism for requiring human confirmation before a destructive tool executes. That's left to the host application.

The implication: if either of these servers is active and an attacker can influence what arguments reach these tools; through prompt injection in a webpage, a Slack message, a GitHub issue, or a file on disk; the result is code execution with the user's permissions. The MCP protocol provides no guard against this.

### 2. Cross-server capability combinations create escalation paths that no individual server review surfaces

This is the finding I think matters most, because it's the one that per-server review misses entirely.

When I analyzed all 10 servers as a combined configuration, capability pair analysis identified **84 capability pairings** where a unit with a data-reading capability could feed into a unit with a higher-privilege capability (such as shell execution). A "unit" is either a single tool (for servers with heterogeneous capabilities) or an entire server (for servers with one tool or a single capability type; see [Chain Analysis Method](#chain-analysis-method) for details). Of those 84, 75 are cross-server and 9 are same-server (desktop-commander's own filesystem tools pairing with its own `start_process`).

**Important caveat:** These are *inferred from declared capabilities*, not demonstrated runtime exploits. The analysis identifies that the capability pairing *exists*; Unit A can read external content, Unit B can execute code; but does not prove that any specific LLM would actually complete the chain in practice. Real-world exploitability depends on the model's susceptibility to prompt injection, the host application's safeguards, and how the agent orchestrates tool calls. What this analysis surfaces is the *structural possibility*; the blast radius if the agent does bridge these capabilities.

In this 10-server configuration, the 84 pairings cluster around two sinks: desktop-commander's `start_process` (62 pairings; it's the only shell-execution tool in the set) and playwright's browser tools (22 pairings from slack's messaging capability, via the messaging→browser pattern).

At the server level, that's **10 distinct cross-server pairs** (plus 9 same-server pairings within desktop-commander):

| Source Server | Sink Server | Pattern | Unit-Level Pairings |
|--------------|-------------|---------|--------------------:|
| playwright | desktop-commander | browser/network → shell | 24 |
| slack | playwright | messaging → browser | 22 |
| git | desktop-commander | filesystem → shell | 12 |
| filesystem | desktop-commander | filesystem → shell | 6 |
| sqlite | desktop-commander | database → shell | 4 |
| github | desktop-commander | filesystem/database → shell | 3 |
| fetch | desktop-commander | network → shell | 1 |
| postgres | desktop-commander | database → shell | 1 |
| slack | desktop-commander | messaging → shell | 1 |
| memory | desktop-commander | database → shell | 1 |

Some server pairs produce many unit-level pairings because one server exposes many tools with the matching data-access type. The [complete 84-line listing](#appendix-b-complete-chain-listing-84-pairings) is in the appendix.

None of these require any single server to be misconfigured. Each server works as designed. The risk is in the combination; and no part of MCP tooling currently surfaces it.

### 3. The filesystem server's security model depends entirely on the directory argument

The `@modelcontextprotocol/server-filesystem` exposes 14 tools. Two (`write_file`, `edit_file`) are annotated DESTRUCTIVE. The server accepts an allowlist of directories as command-line arguments; this is its only access control mechanism.

The server itself enforces this boundary correctly. But the security is only as good as the directory you pass. A configuration like:

```json
{
  "command": "npx",
  "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/you"]
}
```

...authorizes read and write access to your entire home directory. That scope includes `~/.ssh/`, `~/.aws/`, `~/.config/`, browser profile directories, and any secrets stored as files.

The official [MCP quickstart guide](https://modelcontextprotocol.io/docs/develop/connect-local-servers) uses scoped paths like `/Users/username/Desktop` as examples, which is reasonable. But a [security best-practices guide](https://toolradar.com/blog/mcp-server-security-best-practices) explicitly calls out `/Users/you` (full home directory) as a common misconfiguration pattern and recommends project-scoped paths instead. Additionally, two CVEs disclosed in 2025 ([CVE-2025-53109 and CVE-2025-53110](https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/)) demonstrated that path validation in versions before 2025.7.1 could be bypassed via symlinks and prefix matching; meaning even correctly scoped configurations were not always enforced.

The server can't protect users from overly-broad configurations, and historically didn't fully protect them from correctly-scoped ones either.

### 4. The memory server has no access boundaries; any server can read or delete the knowledge graph

The `@modelcontextprotocol/server-memory` exposes 9 tools. Three are rated HIGH: `delete_entities`, `delete_observations`, and `delete_relations`. The tool `read_graph` returns the entire knowledge graph in a single call.

There is no scoping mechanism. Any MCP session that includes the memory server can read all stored entities, add to them, or delete them. In a multi-server setup, this means any other server; or an agent influenced by content from another server; can access or destroy the full persistent knowledge store.

This is worth noting because the memory server is designed for cross-session persistence. The data it stores may span conversations, contain user preferences, project context, or accumulated knowledge; and all of it is accessible to every tool in the current session with no granularity control.

### 5. SQLite is the only server that declares dynamic tool registration

The SQLite server (`mcp-server-sqlite-npx`) reports `listChanged: true` in its MCP capabilities response. This means it supports **dynamic tool registration**; new tools can appear after the initial handshake, and the server will notify the client via `notifications/tools/list_changed`.

No other server in this audit declares this capability.

The practical implication: the tool surface you see at connection time isn't necessarily the tool surface five minutes later. A policy or allowlist based on a point-in-time `tools/list` snapshot may not cover tools that appear dynamically.

This isn't a vulnerability in SQLite's server. It's a protocol feature used correctly. But it's worth knowing about, because most users assume the tool list is static.

---

## Summary Table

| Server | Tools | Critical | High | Self-Declared Destructive | Data Access Types |
|--------|------:|:--------:|:----:|:------------------------:|-------------------|
| filesystem | 14 | 0 | 2 | 2 | filesystem |
| github | 26 | 0 | 0 | 0 | filesystem, code, database |
| playwright | 22 | 0 | 17 | 17 | browser, network, filesystem, code |
| desktop-commander | 26 | 1 | 8 | 9 | filesystem, shell |
| fetch | 1 | 0 | 0 | 0 | network |
| postgres | 1 | 0 | 0 | 0 | database |
| sqlite | 5 | 0 | 2 | 0 | database |
| slack | 8 | 0 | 0 | 0 | messaging |
| git | 12 | 0 | 0 | 0 | filesystem, code |
| memory | 9 | 0 | 3 | 0 | database |
| **Total** | **124** | **1** | **32** | **28** | |

Capability pair analysis: **84 unit-to-unit pairings** (75 cross-server, 9 same-server).

---

## Limitations

**Chain analysis is heuristic, not empirical.** The 84 figure counts unit-to-unit capability pairings (75 cross-server, 9 same-server) where one unit's data-access type matches a source pattern and another's matches a sink pattern. A "unit" is either a single tool or an entire server, depending on whether the server has heterogeneous capabilities. The pairings cluster around two sinks: desktop-commander's `start_process` (62) and playwright's browser tools (22, from slack's messaging capability). The number represents structural exposure, not confirmed vulnerabilities.

**Risk classification is based on metadata, not execution.** Tools are classified by analyzing their names, input schemas, and MCP annotations; not by invoking them and observing behavior. A tool with an innocuous name and schema could be more dangerous than it appears; a tool with a dangerous-sounding name could have runtime guards not visible in its metadata.

**Server versions are pinned to this audit.** Tool surfaces can change between versions. The findings here apply to the specific versions listed in the selection table.

**Selection is not exhaustive.** There are hundreds of MCP servers. These 10 were chosen because they are widely referenced, not because they are the most or least secure.

---

## What This Suggests

This audit doesn't mean these servers are broken. Most are well-built and do what they say. The issue is structural:

**1. MCP has no per-tool authorization.** When you add a server, you authorize every tool it exposes. There's no mechanism to say "I want `browser_screenshot` but not `browser_evaluate`."

**2. Cross-server authority is invisible.** No part of the MCP protocol or its tooling surfaces the compound risk of running multiple servers together. Each server's README describes its own capabilities. Nobody describes the interactions.

**3. The protocol lacks approval gates.** MCP defines tool annotations (`destructiveHint`, `readOnlyHint`) but doesn't define a mechanism for requiring human confirmation before a tool executes. That's left to the host application; and most hosts don't implement it.

**4. Static analysis tells you what's possible. Runtime enforcement tells you what's allowed.** You can audit tool lists all day. But unless something is enforcing policy at the moment of each `tools/call`, the audit is a snapshot of authority, not a control.

---

## Reproducing This Audit

**MCP configuration used** (the exact file passed to the scanner):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "<your-token>" }
    },
    "playwright": {
      "command": "npx",
      "args": ["-y", "@playwright/mcp"]
    },
    "desktop-commander": {
      "command": "npx",
      "args": ["-y", "@wonderwhy-er/desktop-commander"]
    },
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch"]
    },
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/postgres"]
    },
    "sqlite": {
      "command": "npx",
      "args": ["-y", "mcp-server-sqlite-npx", "/tmp/audit-test.db"]
    },
    "slack": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-slack"],
      "env": { "SLACK_BOT_TOKEN": "<your-token>", "SLACK_TEAM_ID": "<your-team>" }
    },
    "git": {
      "command": "uvx",
      "args": ["mcp-server-git"]
    },
    "memory": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
```

**Tool used:** [AgentWard](https://github.com/agentward-ai/agentward) v0.4.0 (`pip install agentward`)

```bash
agentward scan mcp-config.json --json > results.json    # raw scan data (tool lists + risk)
agentward scan mcp-config.json                           # terminal output (includes chain count)
```

**Scan method:** Each server started as a subprocess via stdio transport. MCP handshake performed (`initialize` → `notifications/initialized`), then `tools/list` called to enumerate all declared tools with input schemas and annotations.

**Classification method:** Tool risk scored by input schema property analysis, tool name pattern matching (verb + resource detection), MCP annotation parsing (`readOnlyHint`, `destructiveHint`, `idempotentHint`), and data access type inference.

**Chain analysis:** Computed separately by `agentward/scan/chains.py` using the 9 source→sink patterns listed below. The terminal output includes chain counts inline; the `--json` output contains scan data only (tool lists, risk classifications, server metadata), not chain results. Chain analysis can be reproduced by loading the JSON scan output and calling `detect_chains()`.

**Date:** March 29, 2026. Server versions listed in the selection table.

The raw JSON scan output (250KB, containing full tool enumerations with input schemas and annotations) is published at [`blog/audit-data/scan-results.json`](https://github.com/agentward-ai/agentward/blob/main/blog/audit-data/scan-results.json) in the AgentWard repository.

---

## Chain Analysis Method

The chain analyzer (`agentward/scan/chains.py`) works as follows:

1. **Build capability units.** For each server, if it has multiple tools AND multiple distinct data-access types, each tool becomes its own unit with its own capability set. Otherwise the entire server is one unit. This means heterogeneous servers (like playwright with 22 browser-typed tools plus some filesystem/network tools) are broken into per-tool units, while homogeneous or single-tool servers (like slack, fetch, postgres) remain a single server-name unit.

2. **Check all ordered pairs** (A→B ≠ B→A) against 9 source→sink patterns.

3. **Deduplicate** by (source_name, target_name, description).

**The 9 patterns:**

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

These are all source→sink patterns (data source to execution/action sink). Broader exfiltration and credential-leakage patterns are not implemented in this version of the analyzer.

Note: Playwright's `browser_evaluate` and `browser_run_code` execute JavaScript in the browser context but are classified as `browser` data-access type, not `shell`. If the pattern set treated browser JS execution as a shell-equivalent sink, additional pairings would appear. The current implementation is conservative.

---

## Appendix B: Complete Chain Listing (84 pairings)

Source unit → Sink unit. Server pair annotated. Same-server and multi-type duplicates noted.

```
browser_click → start_process                    (playwright → desktop-commander)
browser_close → start_process                    (playwright → desktop-commander)
browser_console_messages → start_process         (playwright → desktop-commander)
browser_drag → start_process                     (playwright → desktop-commander)
browser_evaluate → start_process                 (playwright → desktop-commander)
browser_file_upload → start_process              (playwright → desktop-commander) [via browser type]
browser_file_upload → start_process              (playwright → desktop-commander) [via filesystem type]
browser_fill_form → start_process                (playwright → desktop-commander)
browser_handle_dialog → start_process            (playwright → desktop-commander)
browser_hover → start_process                    (playwright → desktop-commander)
browser_install → start_process                  (playwright → desktop-commander)
browser_navigate → start_process                 (playwright → desktop-commander) [via browser type]
browser_navigate → start_process                 (playwright → desktop-commander) [via network type]
browser_navigate_back → start_process            (playwright → desktop-commander)
browser_network_requests → start_process         (playwright → desktop-commander)
browser_press_key → start_process                (playwright → desktop-commander)
browser_resize → start_process                   (playwright → desktop-commander)
browser_run_code → start_process                 (playwright → desktop-commander)
browser_select_option → start_process            (playwright → desktop-commander)
browser_snapshot → start_process                 (playwright → desktop-commander)
browser_tabs → start_process                     (playwright → desktop-commander)
browser_take_screenshot → start_process          (playwright → desktop-commander)
browser_type → start_process                     (playwright → desktop-commander)
browser_wait_for → start_process                 (playwright → desktop-commander)
create_directory → start_process                 (desktop-commander → desktop-commander) [same-server]
create_or_update_file → start_process            (github → desktop-commander)
create_table → start_process                     (sqlite → desktop-commander)
describe_table → start_process                   (sqlite → desktop-commander)
directory_tree → start_process                   (filesystem → desktop-commander)
edit_block → start_process                       (desktop-commander → desktop-commander) [same-server]
edit_file → start_process                        (filesystem → desktop-commander)
fetch → start_process                            (fetch → desktop-commander)
get_file_contents → start_process                (github → desktop-commander)
get_file_info → start_process                    (desktop-commander → desktop-commander) [same-server]
git_add → start_process                          (git → desktop-commander)
git_branch → start_process                       (git → desktop-commander)
git_checkout → start_process                     (git → desktop-commander)
git_commit → start_process                       (git → desktop-commander)
git_create_branch → start_process                (git → desktop-commander)
git_diff → start_process                         (git → desktop-commander)
git_diff_staged → start_process                  (git → desktop-commander)
git_diff_unstaged → start_process                (git → desktop-commander)
git_log → start_process                          (git → desktop-commander)
git_reset → start_process                        (git → desktop-commander)
git_show → start_process                         (git → desktop-commander)
git_status → start_process                       (git → desktop-commander)
list_directory → start_process                   (desktop-commander → desktop-commander) [same-server]
list_directory_with_sizes → start_process        (filesystem → desktop-commander)
move_file → start_process                        (desktop-commander → desktop-commander) [same-server]
postgres → start_process                         (postgres → desktop-commander)
read_file → start_process                        (desktop-commander → desktop-commander) [same-server]
read_media_file → start_process                  (filesystem → desktop-commander)
read_query → start_process                       (sqlite → desktop-commander)
read_text_file → start_process                   (filesystem → desktop-commander)
search_files → start_process                     (filesystem → desktop-commander)
search_nodes → start_process                     (memory → desktop-commander)
search_repositories → start_process              (github → desktop-commander)
slack → browser_click                            (slack → playwright)
slack → browser_close                            (slack → playwright)
slack → browser_console_messages                 (slack → playwright)
slack → browser_drag                             (slack → playwright)
slack → browser_evaluate                         (slack → playwright)
slack → browser_file_upload                      (slack → playwright)
slack → browser_fill_form                        (slack → playwright)
slack → browser_handle_dialog                    (slack → playwright)
slack → browser_hover                            (slack → playwright)
slack → browser_install                          (slack → playwright)
slack → browser_navigate                         (slack → playwright)
slack → browser_navigate_back                    (slack → playwright)
slack → browser_network_requests                 (slack → playwright)
slack → browser_press_key                        (slack → playwright)
slack → browser_resize                           (slack → playwright)
slack → browser_run_code                         (slack → playwright)
slack → browser_select_option                    (slack → playwright)
slack → browser_snapshot                         (slack → playwright)
slack → browser_tabs                             (slack → playwright)
slack → browser_take_screenshot                  (slack → playwright)
slack → browser_type                             (slack → playwright)
slack → browser_wait_for                         (slack → playwright)
slack → start_process                            (slack → desktop-commander)
start_search → start_process                     (desktop-commander → desktop-commander) [same-server]
write_file → start_process                       (desktop-commander → desktop-commander) [same-server]
write_pdf → start_process                        (desktop-commander → desktop-commander) [same-server]
write_query → start_process                      (sqlite → desktop-commander)
```

---

*If you find errors in the classification or methodology, [open an issue](https://github.com/agentward-ai/agentward/issues). I'll correct the data and update this post.*
