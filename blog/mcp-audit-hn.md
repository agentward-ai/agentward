# I Audited 10 Popular MCP Servers and Mapped Their Default Blast Radius

If you use Claude Desktop, Cursor, or VS Code with an AI assistant, you probably have MCP servers installed. They let your agent read files, query databases, browse the web, post messages.

I wanted to know what a typical setup actually authorizes — not what the README says, but what each server declares when you connect to it and enumerate its tools.

I selected 10 widely-used servers (from the official MCP repo, Anthropic's docs, and the top of mcp.directory), started each one, performed the MCP handshake, called `tools/list`, and classified every tool by default authority, write capability, and cross-server escalation potential.

**124 tools. 28 self-declared destructive. 84 structural escalation paths.**

Here's what stood out.

---

### Playwright and Desktop Commander hand your agent code execution — with no approval gate

Two of the 10 servers expose tools that accept and execute arbitrary code. Desktop Commander's `start_process` runs shell commands on your host. Playwright's `browser_evaluate` runs JavaScript in the browser — with your session cookies.

Desktop Commander self-annotates 9 of its 26 tools as DESTRUCTIVE. Playwright marks 17 of 22. The server authors know these are dangerous. But MCP defines no mechanism for requiring human confirmation before a destructive tool fires. That's left to the host app, and most don't implement it.

### The real risk is the combination, not the individual servers

This is the finding that surprised me most. Each server looks reasonable in isolation. The risk shows up when you analyze them together.

Capability pair analysis found 84 structural pairings where a data-reading unit on one server could feed into a code-execution unit on another. Every server that reads external data — filesystem, GitHub, Slack, fetch, Postgres, SQLite, git, memory — has at least one capability that structurally pairs with desktop-commander's `start_process`.

These are inferred from declared capabilities, not demonstrated exploits. But the structural exposure is real: if the agent bridges them, the blast radius is code execution with your user permissions. No individual server is misconfigured. The risk is emergent.

### The filesystem server's boundary is whatever you configured — and it's been bypassed before

The most popular MCP server (filesystem, from the official repo) does exactly one thing for access control: check the directory you passed as an argument. Common guides use `/Users/you`. That gives your agent read/write to `~/.ssh/`, `~/.aws/`, and everything else in your home directory.

Two CVEs in 2025 (CVE-2025-53109, CVE-2025-53110) showed that even scoped configurations could be bypassed via symlinks and prefix matching. Fixed in 2025.7.1, but it illustrates how thin the boundary is.

### The memory server has no boundaries at all

The memory server stores a persistent knowledge graph across sessions. Any server in the same MCP session can read the entire graph or delete entities from it. There's no scoping, no access control, no per-server isolation. If an agent is influenced by content from another server, it can access or destroy the full store.

### SQLite can add tools after you've connected

SQLite is the only server in this audit that declares `listChanged: true` — meaning new tools can appear after the initial handshake. The tool surface you reviewed at connection time may not be the tool surface five minutes later.

---

## The structural takeaway

These servers aren't broken. Most are well-built. The issue is the protocol:

- **No per-tool auth.** You authorize every tool a server exposes in one step. No way to say "screenshot yes, evaluate no."
- **No cross-server visibility.** Nothing surfaces the compound risk of running multiple servers together.
- **No approval gates.** `destructiveHint` exists but nothing enforces it.

Static analysis tells you what's *possible*. Runtime enforcement tells you what's *allowed*. Right now, most MCP setups have the first and none of the second.

---

**[Full methodology, scoring rubric, and complete 84-pairing chain listing →](https://github.com/agentward-ai/agentward/blob/main/blog/mcp-audit.md)**

The audit used [AgentWard](https://github.com/agentward-ai/agentward), an open-source permission scanner for MCP tool calls. To run the same audit on your own config:

```bash
pip install agentward
agentward scan ~/.cursor/mcp.json
```
