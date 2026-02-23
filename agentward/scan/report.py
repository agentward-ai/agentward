"""Rich CLI output for scan results.

Renders permission maps, risk trees, and recommendations as beautiful
terminal output using the rich library. Visual style matches agentward.ai.

Color palette (website parity):
  - Neon green (#00ff88): LOW risk, success indicators
  - Cyan (#5eead4): found/discovered items, info
  - Yellow (#ffcc00): MEDIUM risk, warnings
  - Orange (#ff6b35): HIGH risk
  - Hot pink (#ff3366): CRITICAL risk
  - Dim (#555555): borders, secondary text
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.padding import Padding
from rich.panel import Panel

from agentward.scan.chains import ChainDetection, ChainRisk
from agentward.scan.permissions import (
    DataAccessType,
    RiskLevel,
    ScanResult,
    ServerPermissionMap,
    ToolPermission,
)
from agentward.scan.explainer import RiskExplanation, explain_risk
from agentward.scan.recommendations import (
    Recommendation,
    RecommendationSeverity,
)


# ---------------------------------------------------------------------------
# Color palette — matches agentward.ai
# ---------------------------------------------------------------------------

_CLR_LOW = "#00ff88"
_CLR_MEDIUM = "#ffcc00"
_CLR_HIGH = "#ff6b35"
_CLR_CRITICAL = "#ff3366"
_CLR_CYAN = "#5eead4"
_CLR_DIM = "#555555"
_CLR_GREEN = "#00ff88"


# Data access type → display icon
_ACCESS_ICONS: dict[DataAccessType, str] = {
    DataAccessType.FILESYSTEM: "\U0001f4c1",   # 📁
    DataAccessType.NETWORK: "\U0001f310",       # 🌐
    DataAccessType.DATABASE: "\U0001f5c4",      # 🗄️
    DataAccessType.EMAIL: "\u2709\ufe0f",       # ✉️
    DataAccessType.MESSAGING: "\U0001f4ac",     # 💬
    DataAccessType.CREDENTIALS: "\U0001f511",   # 🔑
    DataAccessType.SHELL: "\U0001f4bb",         # 💻
    DataAccessType.CODE: "\U0001f4dd",          # 📝
    DataAccessType.BROWSER: "\U0001f30d",       # 🌍
    DataAccessType.FINANCIAL: "\U0001f4b0",     # 💰
    DataAccessType.UNKNOWN: "\u2753",           # ❓
}

# Risk level → (emoji badge, rich style)
_RISK_BADGES: dict[RiskLevel, tuple[str, str]] = {
    RiskLevel.CRITICAL: ("\U0001f534", f"bold {_CLR_CRITICAL}"),  # 🔴
    RiskLevel.HIGH: ("\u26a0", f"{_CLR_HIGH}"),                    # ⚠
    RiskLevel.MEDIUM: ("\u26a0", f"{_CLR_MEDIUM}"),                # ⚠
    RiskLevel.LOW: ("\u2713", f"{_CLR_LOW}"),                      # ✓
}


def print_scan_report(
    scan: ScanResult,
    recommendations: list[Recommendation],
    console: Console,
    chains: list[ChainDetection] | None = None,
) -> None:
    """Render the full scan report to the console.

    Args:
        scan: The complete scan result.
        recommendations: Generated recommendations.
        console: Rich console to print to (should be stderr).
        chains: Detected skill chains (optional, computed if not provided).
    """
    from agentward.banner import print_banner

    print_banner(console)

    # Count totals
    total_servers = len(scan.servers)
    total_tools = sum(len(s.tools) for s in scan.servers)

    # Unified scan table (all tools in one table, like the website)
    if total_tools > 0:
        _print_unified_table(scan, console)
    elif total_servers > 0:
        # We found servers but got 0 tools from all of them — tell the user
        console.print(
            f"[{_CLR_MEDIUM}]⚠ Found {total_servers} server(s) but could not enumerate any tools.[/{_CLR_MEDIUM}]",
        )
        # Show any server-level warnings (e.g., from static inference)
        for server_map in scan.servers:
            if server_map.warning:
                console.print(
                    f"  [{_CLR_DIM}]{server_map.server.name}: {server_map.warning}[/{_CLR_DIM}]",
                )
        console.print(
            f"\n[{_CLR_DIM}]This usually means the MCP server(s) are not currently running.[/{_CLR_DIM}]",
        )
        console.print(
            f"[{_CLR_DIM}]Try: agentward scan --timeout 30  (give servers more time to start)[/{_CLR_DIM}]",
        )

    # Skill chain analysis
    if chains is None:
        from agentward.scan.chains import detect_chains

        chains = detect_chains(scan)
    if chains:
        _print_chain_analysis(chains, console)

    # Risk summary footer (compact, website-style)
    _print_risk_footer(scan, chains, console)

    # Recommendations (with risk explanations)
    if recommendations:
        _print_recommendations(recommendations, scan, console)

    console.print()


def print_scan_json(scan: ScanResult, console: Console) -> None:
    """Print the scan result as JSON for piping.

    Args:
        scan: The complete scan result.
        console: Rich console to print to.
    """
    data = json.loads(scan.model_dump_json())
    console.print_json(json.dumps(data, indent=2))


def generate_scan_markdown(
    scan: ScanResult,
    recommendations: list[Recommendation],
    chains: list[ChainDetection] | None = None,
) -> str:
    """Generate a markdown scan report suitable for sharing on GitHub.

    Includes: timestamp, AgentWard version, summary counts, permission map
    table, detected chains, and grouped recommendations.

    Args:
        scan: The complete scan result.
        recommendations: Generated recommendations.
        chains: Detected skill chains (optional, computed if not provided).

    Returns:
        Complete markdown string.
    """
    from datetime import datetime, timezone

    import agentward

    if chains is None:
        from agentward.scan.chains import detect_chains

        chains = detect_chains(scan)

    lines: list[str] = []

    # Header
    lines.append("# AgentWard Scan Report")
    lines.append("")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines.append(f"**Generated:** {ts}  ")
    lines.append(f"**AgentWard version:** {agentward.__version__}  ")
    total_tools = sum(len(s.tools) for s in scan.servers)
    lines.append(f"**Tools scanned:** {total_tools}")
    lines.append("")

    # Risk summary
    counts: dict[RiskLevel, int] = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.LOW: 0,
    }
    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            counts[tool_perm.risk_level] += 1

    risk_parts: list[str] = []
    risk_emoji = {
        RiskLevel.CRITICAL: "🔴",
        RiskLevel.HIGH: "🟠",
        RiskLevel.MEDIUM: "🟡",
        RiskLevel.LOW: "🟢",
    }
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        if counts[level] > 0:
            risk_parts.append(f"{risk_emoji[level]} {counts[level]} {level.value.lower()}")
    if chains:
        risk_parts.append(f"⚠️ {len(chains)} chain(s)")

    lines.append(f"> {' · '.join(risk_parts)}")
    lines.append("")

    # Permission map table — collect rows first to compute column widths
    _md_risk_label = {
        RiskLevel.CRITICAL: "🔴 CRITICAL",
        RiskLevel.HIGH: "⚠️ HIGH",
        RiskLevel.MEDIUM: "⚠️ MEDIUM",
        RiskLevel.LOW: "✅ LOW",
    }
    table_rows: list[tuple[str, str, str, str, str]] = []
    for server_map in scan.servers:
        source = _source_badge(server_map)
        for tool_perm in server_map.tools:
            caps = _capabilities_label(tool_perm)
            risk_label = _md_risk_label[tool_perm.risk_level]
            why = _risk_reason_summary(tool_perm)
            table_rows.append((source, f"`{tool_perm.tool.name}`", caps, risk_label, why))

    headers = ("Source", "Tool/Skill", "Capabilities", "Risk", "Why")
    # Compute column widths (min of header width or content)
    col_widths = [len(h) for h in headers]
    for row in table_rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    def _md_row(cells: tuple[str, ...]) -> str:
        parts = [cell.ljust(col_widths[i]) for i, cell in enumerate(cells)]
        return "| " + " | ".join(parts) + " |"

    def _md_sep() -> str:
        return "| " + " | ".join("-" * w for w in col_widths) + " |"

    lines.append("## Permission Map")
    lines.append("")
    lines.append(_md_row(headers))
    lines.append(_md_sep())
    for row in table_rows:
        lines.append(_md_row(row))
    lines.append("")

    # Chains (grouped)
    if chains:
        lines.append("## Skill Chains Detected")
        lines.append("")

        from collections import defaultdict

        chain_groups: dict[tuple[str, str, str], list[ChainDetection]] = defaultdict(list)
        for chain in chains:
            key = (
                _skill_parent(chain.source_server),
                _skill_parent(chain.target_server),
                chain.description,
            )
            chain_groups[key].append(chain)

        sorted_keys = sorted(
            chain_groups.keys(),
            key=lambda k: (
                0 if any(c.risk == ChainRisk.CRITICAL for c in chain_groups[k]) else 1,
                k[0],
                k[1],
            ),
        )

        for src, tgt, desc in sorted_keys:
            group = chain_groups[(src, tgt, desc)]
            count = len(group)
            risk = "CRITICAL" if any(c.risk == ChainRisk.CRITICAL for c in group) else "HIGH"
            if count > 1:
                lines.append(f"- **{risk}:** `{src}` → `{tgt}` ({count} chains) — {desc}")
            else:
                lines.append(f"- **{risk}:** `{group[0].label}` — {desc}")
        lines.append("")

    # Recommendations (grouped)
    if recommendations:
        lines.append("## Recommendations")
        lines.append("")
        grouped = _group_recommendations(recommendations)
        for i, (group, display_target) in enumerate(grouped, 1):
            rep = group[0]
            lines.append(f"### {i}. {rep.severity.value} — {display_target}")
            lines.append("")
            lines.append(rep.message)
            lines.append("")
            if rep.suggested_policy:
                if len(group) > 1 and "require_approval:" in rep.suggested_policy:
                    tool_names = []
                    for r in group:
                        t = r.target
                        tool_name = t.rsplit("/", 1)[-1] if "/" in t else t
                        tool_names.append(tool_name)
                    merged = "require_approval:\n" + "\n".join(
                        f"  - {name}" for name in tool_names
                    )
                    lines.append("```yaml")
                    lines.append(merged)
                    lines.append("```")
                else:
                    lines.append("```yaml")
                    lines.append(rep.suggested_policy)
                    lines.append("```")
            lines.append("")

    # Developer fixes — grouped by parent skill, only for HIGH+ tools
    dev_fixes: list[tuple[str, str, str, str]] = []  # (parent, tool, reason, fix)
    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            if tool_perm.risk_level in (RiskLevel.LOW, RiskLevel.MEDIUM):
                continue
            reason = _risk_reason_summary(tool_perm)
            fix = _dev_fix_for_reasons(tool_perm.risk_reasons)
            if fix:
                parent = _skill_parent(tool_perm.tool.name)
                dev_fixes.append((parent, tool_perm.tool.name, reason, fix))

    if dev_fixes:
        lines.append("## Fixes for Skill Developers")
        lines.append("")
        lines.append("If you maintain these skills, here's how to reduce their risk rating:")
        lines.append("")

        # Group by parent skill
        from collections import OrderedDict

        by_parent: OrderedDict[str, list[tuple[str, str, str]]] = OrderedDict()
        for parent, tool, reason, fix in dev_fixes:
            by_parent.setdefault(parent, []).append((tool, reason, fix))

        for parent, entries in by_parent.items():
            lines.append(f"### `{parent}`")
            lines.append("")
            # Deduplicate fixes (multiple tools may have the same fix)
            seen_fixes: set[str] = set()
            for tool, reason, fix in entries:
                if fix in seen_fixes:
                    continue
                seen_fixes.add(fix)
                # List the tools this fix applies to
                affected = [t for t, _r, f in entries if f == fix]
                if len(affected) > 1:
                    tool_list = ", ".join(f"`{t}`" for t in affected)
                    lines.append(f"**Affects:** {tool_list}  ")
                else:
                    lines.append(f"**Affects:** `{affected[0]}`  ")
                lines.append(f"**Issue:** {reason}  ")
                lines.append(f"**Fix:** {fix}")
                lines.append("")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("*Generated by [AgentWard](https://agentward.ai) — open-source permission control plane for AI agents.*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unified scan table
# ---------------------------------------------------------------------------


def _source_badge(server_map: ServerPermissionMap) -> str:
    """Classify a server into a source badge: MCP, Skill, or SDK."""
    transport = server_map.server.transport.value
    if transport == "openclaw":
        return "Skill"
    if transport == "python":
        return "SDK"
    return "MCP"


def _risk_reason_summary(tool_perm: ToolPermission) -> str:
    """Return a concise primary risk reason for display.

    Filters out internal annotations and returns the most significant
    reason. Returns empty string for LOW risk tools.
    """
    if tool_perm.risk_level == RiskLevel.LOW:
        return ""
    # Skip internal annotations — only show substantive reasons
    meaningful = [
        r for r in tool_perm.risk_reasons
        if not r.startswith("Annotations ")
        and r != "No specific risk signals detected"
        and r != "Read-only operation"
    ]
    if not meaningful:
        return ""
    # Return the last (highest-priority) reason, trimmed
    return meaningful[-1]


# Mapping: risk reason substring → developer-facing fix for SKILL.md
_DEV_FIXES: list[tuple[str, str]] = [
    (
        "Financial operations with credential access",
        "Separate credential management from financial operations into "
        "distinct skills. Credential-handling capabilities should not share "
        "a skill with value-transfer operations.",
    ),
    (
        "Financial operations",
        "Mark read-only capabilities (e.g. balance checks, price lookups) "
        "explicitly in SKILL.md. Add a `## Security` section documenting "
        "authentication requirements and value-transfer limits.",
    ),
    (
        "Network access combined with credentials",
        "Document which external endpoints are called and why. Avoid "
        "bundling credential storage with network-calling capabilities. "
        "Consider splitting into a credential-manager skill and a "
        "network-calling skill.",
    ),
    (
        "Can execute shell commands",
        "Restrict execution to a specific allowlist of commands. Document "
        "exactly what gets executed in SKILL.md. Avoid accepting "
        "arbitrary command strings from agent input.",
    ),
    (
        "Accesses credentials/secrets",
        "Document which credentials are accessed and their scope. Use "
        "environment variables or a secret manager instead of inline "
        "credential storage. Declare minimum required permissions.",
    ),
    (
        "Email access",
        "Declare read-only if the skill only reads email. If sending is "
        "required, document the send scope (drafts only, specific "
        "recipients, etc.) in SKILL.md.",
    ),
    (
        "Messaging access",
        "Declare read-only if the skill only reads messages. Document "
        "which channels/conversations the skill accesses.",
    ),
    (
        "Browser access",
        "Document which URLs/domains the skill navigates to. Avoid "
        "navigating to URLs from untrusted input without validation.",
    ),
    (
        "Tool name indicates destructive",
        "Add a `## Destructive Operations` section to SKILL.md listing "
        "what can be deleted/modified and under what conditions. Consider "
        "requiring explicit confirmation before destructive actions.",
    ),
    (
        "Tool can modify data",
        "Separate read and write capabilities into distinct sections in "
        "SKILL.md. Mark read-only operations explicitly so scanners "
        "can distinguish them.",
    ),
    (
        "Can modify database",
        "Document which tables/collections are modified. Declare "
        "read-only for query-only capabilities.",
    ),
    (
        "Can modify files",
        "Document which directories/file patterns are written to. "
        "Restrict write paths in the skill definition.",
    ),
]


def _dev_fix_for_reasons(risk_reasons: list[str]) -> str:
    """Return a developer-facing fix suggestion based on risk reasons.

    Matches the highest-priority fix from _DEV_FIXES.

    Args:
        risk_reasons: The tool's risk_reasons list.

    Returns:
        Fix suggestion string, or empty string if no match.
    """
    for reason in reversed(risk_reasons):
        for pattern, fix in _DEV_FIXES:
            if pattern in reason:
                return fix
    return ""


def _capabilities_label(tool_perm: ToolPermission) -> str:
    """Build a compact capabilities string from data access info."""
    parts: list[str] = []
    for access in tool_perm.data_access:
        verb = "read" if access.read and not access.write else ""
        if access.write:
            verb = "write" if not access.read else "read,write"
        if tool_perm.is_destructive:
            verb += ",del" if verb else "del"
        if verb:
            parts.append(verb)
        else:
            parts.append(access.type.value)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for p in parts:
        if p not in seen:
            unique.append(p)
            seen.add(p)
    return ",".join(unique) if unique else "unknown"


def _display_width(text: str) -> int:
    """Compute the terminal display width of a string.

    Accounts for wide characters (CJK, emoji) that occupy 2 columns
    but have ``len()`` of 1.

    Args:
        text: The plain text string (no rich markup).

    Returns:
        The number of terminal columns the text occupies.
    """
    import unicodedata

    width = 0
    for ch in text:
        eaw = unicodedata.east_asian_width(ch)
        width += 2 if eaw in ("W", "F") else 1
    return width


def _risk_color(level: RiskLevel) -> str:
    """Return the hex color for a risk level."""
    return {
        RiskLevel.LOW: _CLR_LOW,
        RiskLevel.MEDIUM: _CLR_MEDIUM,
        RiskLevel.HIGH: _CLR_HIGH,
        RiskLevel.CRITICAL: _CLR_CRITICAL,
    }.get(level, "white")


def _print_colored_table(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],  # last element of each tuple is the color
    console: Console,
) -> None:
    """Print a table where each row's borders and text share the row's color.

    Rich's Table doesn't support per-row border colors, so this renders
    manually with box-drawing characters. Each row tuple should contain
    N cell values followed by the color string as the last element.

    Args:
        headers: Column header labels (N columns).
        rows: List of (col1, col2, ..., colN, color) tuples.
        console: Rich console for output.
    """
    n_cols = len(headers)

    # Compute column widths using display width (handles wide emoji)
    widths: list[int] = [_display_width(h) for h in headers]
    for row in rows:
        for i in range(n_cols):
            widths[i] = max(widths[i], _display_width(row[i]))

    # Add padding (1 space each side)
    padded = [w + 2 for w in widths]

    def _hline(left: str, mid: str, right: str, fill: str, clr: str) -> str:
        """Build a horizontal border line with the given color."""
        parts = [f"[{clr}]{left}[/{clr}]"]
        for i, pw in enumerate(padded):
            parts.append(f"[{clr}]{fill * pw}[/{clr}]")
            if i < n_cols - 1:
                parts.append(f"[{clr}]{mid}[/{clr}]")
        parts.append(f"[{clr}]{right}[/{clr}]")
        return "".join(parts)

    def _row_line(cells: tuple[str, ...], clr: str) -> str:
        """Build a data row with colored borders and text."""
        parts = [f"[{clr}]\u2502[/{clr}]"]
        for i, cell in enumerate(cells):
            pad_right = widths[i] - _display_width(cell)
            parts.append(f"[{clr}] {cell}{' ' * pad_right} [/{clr}]")
            if i < n_cols - 1:
                parts.append(f"[{clr}]\u2502[/{clr}]")
        parts.append(f"[{clr}]\u2502[/{clr}]")
        return "".join(parts)

    # Top border (dim)
    console.print(_hline("\u250c", "\u252c", "\u2510", "\u2500", _CLR_DIM))
    # Header row (dim)
    console.print(_row_line(headers, _CLR_DIM))
    # Header separator (dim)
    console.print(_hline("\u251c", "\u253c", "\u2524", "\u2500", _CLR_DIM))
    # Data rows (each in its own color)
    for row in rows:
        cells = row[:n_cols]
        clr = row[n_cols]  # color is the last element
        console.print(_row_line(cells, clr))
    # Bottom border (dim)
    console.print(_hline("\u2514", "\u2534", "\u2518", "\u2500", _CLR_DIM))
    console.print()


def _print_unified_table(scan: ScanResult, console: Console) -> None:
    """Print a single unified table with all tools across all servers.

    Matches the website layout: entire row colored by risk level,
    including border characters. Uses manual box-drawing since Rich's
    Table doesn't support per-row border colors.
    """
    # Collect rows: (source, tool_label, risk_label, why, color)
    rows: list[tuple[str, str, str, str, str]] = []
    for server_map in scan.servers:
        source = _source_badge(server_map)
        for tool_perm in server_map.tools:
            caps = _capabilities_label(tool_perm)
            tool_label = f"{tool_perm.tool.name}  {caps}"
            emoji, _ = _RISK_BADGES[tool_perm.risk_level]
            risk_label = f"{emoji} {tool_perm.risk_level.value}"
            why = _risk_reason_summary(tool_perm)
            rows.append((source, tool_label, risk_label, why, _risk_color(tool_perm.risk_level)))

    if not rows:
        return

    _print_colored_table(
        headers=("Source", "Tool/Skill", "Risk", "Why"),
        rows=rows,
        console=console,
    )


# ---------------------------------------------------------------------------
# Chain analysis
# ---------------------------------------------------------------------------


def _skill_parent(name: str) -> str:
    """Return the parent skill name (strip capability suffix)."""
    return name.rsplit(":", 1)[0] if ":" in name else name


def _print_chain_analysis(
    chains: list[ChainDetection],
    console: Console,
) -> None:
    """Print the skill chain analysis section, grouped by parent skills.

    When capabilities produce many individual chains between the same two
    parent skills, they are collapsed into a single summary line:
        ⚠ bankr → coding-agent  (48 chains)
          Network responses could trigger code execution

    Args:
        chains: Detected skill chains.
        console: Rich console.
    """
    # Group chains by (parent_source, parent_target, description)
    from collections import defaultdict

    groups: dict[tuple[str, str, str], list[ChainDetection]] = defaultdict(list)
    for chain in chains:
        key = (
            _skill_parent(chain.source_server),
            _skill_parent(chain.target_server),
            chain.description,
        )
        groups[key].append(chain)

    # Sort: CRITICAL groups first, then by source name
    sorted_keys = sorted(
        groups.keys(),
        key=lambda k: (
            0 if any(c.risk == ChainRisk.CRITICAL for c in groups[k]) else 1,
            k[0],
            k[1],
        ),
    )

    for src, tgt, desc in sorted_keys:
        group = groups[(src, tgt, desc)]
        risk_clr = _CLR_CRITICAL if any(c.risk == ChainRisk.CRITICAL for c in group) else _CLR_HIGH
        count = len(group)
        if count > 1:
            console.print(
                f"\u26a0 {src} \u2192 {tgt}  ({count} chains)",
                style=risk_clr,
            )
        else:
            console.print(
                f"\u26a0 {group[0].label}",
                style=risk_clr,
            )
        console.print(f"  {desc}", style=_CLR_DIM)
        console.print()


# ---------------------------------------------------------------------------
# Risk footer (compact summary)
# ---------------------------------------------------------------------------


def _print_risk_footer(
    scan: ScanResult,
    chains: list[ChainDetection] | None,
    console: Console,
) -> None:
    """Print a compact risk summary footer matching the website.

    Format: 3 critical · 4 high · 1 medium · 1 low
            → Run `agentward configure` to generate policies
    """
    counts: dict[RiskLevel, int] = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.LOW: 0,
    }
    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            counts[tool_perm.risk_level] += 1

    # Build count line with risk-appropriate colors
    count_parts: list[str] = []
    level_colors = {
        RiskLevel.CRITICAL: _CLR_CRITICAL,
        RiskLevel.HIGH: _CLR_HIGH,
        RiskLevel.MEDIUM: _CLR_MEDIUM,
        RiskLevel.LOW: _CLR_LOW,
    }
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        if counts[level] > 0:
            clr = level_colors[level]
            count_parts.append(f"[{clr}]{counts[level]} {level.value.lower()}[/{clr}]")
    if chains:
        count_parts.append(f"[{_CLR_HIGH}]{len(chains)} chain(s)[/{_CLR_HIGH}]")

    summary = " \u00b7 ".join(count_parts)
    console.print(summary)
    console.print(
        f"[{_CLR_GREEN}]\u2192[/{_CLR_GREEN}] Run "
        f"[bold {_CLR_GREEN}]agentward configure[/bold {_CLR_GREEN}] to generate policies"
    )
    console.print()


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------


def _group_recommendations(
    recommendations: list[Recommendation],
) -> list[tuple[list[Recommendation], str]]:
    """Group recommendations with the same severity and message pattern.

    Capabilities of the same parent skill (e.g. coding-agent:pty_mode_required,
    coding-agent:claude_code) that produce the same recommendation type are
    collapsed into a single group.

    Returns:
        List of (group, display_target) tuples.
    """
    from collections import OrderedDict

    # Key: (severity, message-template) where template replaces tool name with parent
    groups: OrderedDict[tuple[str, str, str], list[Recommendation]] = OrderedDict()

    for rec in recommendations:
        # Normalize message: strip the tool-specific name to find the pattern
        # E.g. "Tool 'coding-agent:foo' can execute shell commands..." →
        #      "can execute shell commands..."
        msg = rec.message
        # Extract a message fingerprint by removing the tool-specific part
        # The message always starts with "Tool 'X'" or "Server 'X'"
        fingerprint = msg
        for prefix in ("Tool '", "Server '"):
            if msg.startswith(prefix):
                end = msg.index("'", len(prefix))
                fingerprint = msg[end + 2:]  # skip "' "
                break

        # Group by parent skill of the target
        target = rec.target
        if "/" in target:
            _, tool_part = target.rsplit("/", 1)
        else:
            tool_part = target
        parent = tool_part.rsplit(":", 1)[0] if ":" in tool_part else tool_part

        key = (rec.severity.value, parent, fingerprint)
        groups.setdefault(key, []).append(rec)

    result: list[tuple[list[Recommendation], str]] = []
    for (_sev, parent, _fp), group in groups.items():
        if len(group) == 1:
            display_target = group[0].target
        else:
            # Use parent name + count
            display_target = f"{group[0].target.rsplit('/', 1)[0]}/{parent} ({len(group)} tools)"
        result.append((group, display_target))

    return result


def _print_recommendations(
    recommendations: list[Recommendation],
    scan: ScanResult,
    console: Console,
) -> None:
    """Print recommendations section with risk explanations.

    Groups similar recommendations (e.g. all coding-agent capabilities with
    shell access) into a single entry to reduce noise.

    Args:
        recommendations: Generated recommendations.
        scan: The scan result (used to look up tool/server context for explanations).
        console: Rich console.
    """
    console.print("[bold]Recommendations[/bold]\n")

    # Build lookup: "server_name/tool_name" and "server_name" → (ToolPermission, ServerPermissionMap)
    tool_lookup: dict[str, tuple[ToolPermission, ServerPermissionMap]] = {}
    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            key = f"{server_map.server.name}/{tool_perm.tool.name}"
            tool_lookup[key] = (tool_perm, server_map)
            tool_lookup[tool_perm.tool.name] = (tool_perm, server_map)

    panels_shown = 0
    max_panels = 2  # limit attack scenario panels to reduce visual clutter
    grouped = _group_recommendations(recommendations)

    for i, (group, display_target) in enumerate(grouped, 1):
        rep = group[0]  # representative recommendation
        severity_style = _severity_style(rep.severity)
        console.print(
            f"  {i}. [{severity_style}]{rep.severity.value}[/{severity_style}] "
            f"[{_CLR_DIM}]({display_target})[/{_CLR_DIM}]"
        )
        console.print(f"     {rep.message}")
        if rep.suggested_policy:
            # Merge suggested policies for grouped recs
            if len(group) > 1 and "require_approval:" in rep.suggested_policy:
                # Combine all tool names under one require_approval block
                tool_names = []
                for r in group:
                    target = r.target
                    tool_name = target.rsplit("/", 1)[-1] if "/" in target else target
                    tool_names.append(tool_name)
                merged = "require_approval:\n" + "\n".join(
                    f"  - {name}" for name in tool_names
                )
                console.print(f"     [{_CLR_DIM}]Suggested policy:[/{_CLR_DIM}]")
                for line in merged.split("\n"):
                    console.print(f"       [{_CLR_GREEN}]{line}[/{_CLR_GREEN}]")
            else:
                console.print(f"     [{_CLR_DIM}]Suggested policy:[/{_CLR_DIM}]")
                for line in rep.suggested_policy.split("\n"):
                    console.print(f"       [{_CLR_GREEN}]{line}[/{_CLR_GREEN}]")

        # Show attack scenario panel for the first few CRITICAL recommendations
        if panels_shown < max_panels and rep.severity == RecommendationSeverity.CRITICAL:
            explanation = _find_explanation(rep.target, tool_lookup)
            if explanation is not None:
                _print_explanation_panel(explanation, console)
                panels_shown += 1

        console.print()


def _find_explanation(
    target: str,
    tool_lookup: dict[str, tuple[ToolPermission, ServerPermissionMap]],
) -> RiskExplanation | None:
    """Find a risk explanation for a recommendation target.

    Tries to match the target string to a tool in the lookup.
    Target formats: "server_name/tool_name", "server_name", or tool name.

    Args:
        target: The recommendation target string.
        tool_lookup: Mapping of target keys to (tool, server) pairs.

    Returns:
        A RiskExplanation, or None if no match or tool is low risk.
    """
    if target in tool_lookup:
        tool_perm, server_map = tool_lookup[target]
        return explain_risk(tool_perm, server_map)

    # Try matching by the part after "/" or the whole string
    if "/" in target:
        _, tool_name = target.rsplit("/", 1)
        if tool_name in tool_lookup:
            tool_perm, server_map = tool_lookup[tool_name]
            return explain_risk(tool_perm, server_map)

    return None


def _print_explanation_panel(
    explanation: RiskExplanation, console: Console
) -> None:
    """Render a risk explanation as a rich Panel.

    Args:
        explanation: The attack scenario explanation.
        console: Rich console.
    """
    lines = [
        f"[bold]{explanation.scenario}[/bold]",
        "",
        f"[italic]Example:[/italic] {explanation.example}",
        "",
        f"[{_CLR_CRITICAL}]Impact:[/{_CLR_CRITICAL}] {explanation.impact}",
        f"[{_CLR_GREEN}]Fix:[/{_CLR_GREEN}] {explanation.mitigation}",
    ]
    content = "\n".join(lines)
    # Constrain panel width so it doesn't span the full terminal
    panel_width = min(console.width - 10, 100)
    panel = Panel(
        content,
        title="Attack Scenario",
        title_align="left",
        border_style=_CLR_HIGH,
        padding=(0, 1),
        width=panel_width,
        expand=False,
    )
    # Use Padding to indent the panel under the recommendation text
    console.print(Padding(panel, (0, 0, 0, 5)))


# ---------------------------------------------------------------------------
# Shared style helpers
# ---------------------------------------------------------------------------


def _severity_style(severity: RecommendationSeverity) -> str:
    """Map recommendation severity to rich style."""
    return {
        RecommendationSeverity.INFO: _CLR_CYAN,
        RecommendationSeverity.WARNING: _CLR_HIGH,
        RecommendationSeverity.CRITICAL: f"bold {_CLR_CRITICAL}",
    }.get(severity, "white")
