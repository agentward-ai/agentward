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
    console.print()

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
    # Collect rows: (source, tool_label, risk_label, color)
    rows: list[tuple[str, str, str, str]] = []
    for server_map in scan.servers:
        source = _source_badge(server_map)
        for tool_perm in server_map.tools:
            caps = _capabilities_label(tool_perm)
            tool_label = f"{tool_perm.tool.name}  {caps}"
            emoji, _ = _RISK_BADGES[tool_perm.risk_level]
            risk_label = f"{emoji} {tool_perm.risk_level.value}"
            rows.append((source, tool_label, risk_label, _risk_color(tool_perm.risk_level)))

    if not rows:
        return

    _print_colored_table(
        headers=("Source", "Tool/Skill", "Risk"),
        rows=rows,
        console=console,
    )


# ---------------------------------------------------------------------------
# Chain analysis
# ---------------------------------------------------------------------------


def _print_chain_analysis(
    chains: list[ChainDetection],
    console: Console,
) -> None:
    """Print the skill chain analysis section.

    Matches the website format:
        ⚠ Skill chain detected: email-mgr → web-browser
          Email content could leak via browsing

    Args:
        chains: Detected skill chains.
        console: Rich console.
    """
    for chain in chains:
        risk_clr = _CLR_CRITICAL if chain.risk == ChainRisk.CRITICAL else _CLR_HIGH
        console.print(
            f"\u26a0 Skill chain detected: {chain.label}",
            style=risk_clr,
        )
        console.print(f"  {chain.description}", style=_CLR_DIM)
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


def _print_recommendations(
    recommendations: list[Recommendation],
    scan: ScanResult,
    console: Console,
) -> None:
    """Print recommendations section with risk explanations.

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

    for i, rec in enumerate(recommendations, 1):
        severity_style = _severity_style(rec.severity)
        console.print(
            f"  {i}. [{severity_style}]{rec.severity.value}[/{severity_style}] "
            f"[{_CLR_DIM}]({rec.target})[/{_CLR_DIM}]"
        )
        console.print(f"     {rec.message}")
        if rec.suggested_policy:
            console.print(f"     [{_CLR_DIM}]Suggested policy:[/{_CLR_DIM}]")
            for line in rec.suggested_policy.split("\n"):
                console.print(f"       [{_CLR_GREEN}]{line}[/{_CLR_GREEN}]")

        # Show attack scenario for CRITICAL and WARNING recommendations
        if rec.severity in (RecommendationSeverity.CRITICAL, RecommendationSeverity.WARNING):
            explanation = _find_explanation(rec.target, tool_lookup)
            if explanation is not None:
                _print_explanation_panel(explanation, console)

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
    panel = Panel(
        content,
        title="Attack Scenario",
        title_align="left",
        border_style=_CLR_HIGH,
        padding=(0, 1),
    )
    console.print(f"     ", end="")  # indent to align with recommendation
    console.print(panel)


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
