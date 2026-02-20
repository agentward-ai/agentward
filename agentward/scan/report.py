"""Rich CLI output for scan results.

Renders permission maps, risk trees, and recommendations as beautiful
terminal output using the rich library.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from agentward.scan.permissions import (
    DataAccess,
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


def print_scan_report(
    scan: ScanResult,
    recommendations: list[Recommendation],
    console: Console,
) -> None:
    """Render the full scan report to the console.

    Args:
        scan: The complete scan result.
        recommendations: Generated recommendations.
        console: Rich console to print to (should be stderr).
    """
    # Header
    console.print()
    console.print(
        Panel.fit(
            "[bold white]AgentWard Scan Report[/bold white]",
            border_style="blue",
        )
    )

    # Config sources
    if scan.config_sources:
        console.print(f"\n[dim]Config sources:[/dim]")
        for source in scan.config_sources:
            console.print(f"  [dim]{source}[/dim]")

    # Count totals
    total_servers = len(scan.servers)
    total_tools = sum(len(s.tools) for s in scan.servers)
    console.print(
        f"\n[bold]Found {total_servers} server(s) with {total_tools} tool(s)[/bold]\n"
    )

    # Per-server permission tables
    for server_map in scan.servers:
        _print_server_table(server_map, console)

    # Risk summary tree
    if total_tools > 0:
        _print_risk_tree(scan, console)

    # Recommendations (with risk explanations)
    if recommendations:
        _print_recommendations(recommendations, scan, console)

    # Footer — overall risk with summary + mitigation
    console.print()
    overall = _overall_risk(scan)
    footer = _risk_summary(scan, overall, recommendations)
    console.print(Panel(footer, border_style=_risk_border(overall)))
    console.print()


def print_scan_json(scan: ScanResult, console: Console) -> None:
    """Print the scan result as JSON for piping.

    Args:
        scan: The complete scan result.
        console: Rich console to print to.
    """
    data = json.loads(scan.model_dump_json())
    console.print_json(json.dumps(data, indent=2))


def _print_server_table(
    server_map: ServerPermissionMap, console: Console
) -> None:
    """Print a permission table for a single server."""
    server = server_map.server
    risk_style = _risk_style(server_map.overall_risk)

    # Server header
    title = f"{server.name}"
    subtitle_parts: list[str] = []
    if server.transport.value == "python":
        subtitle_parts.append(str(server.source_file))
        framework = server.client.replace("python:", "")
        subtitle_parts.append(f"framework: {framework}")
    elif server.transport.value == "openclaw":
        subtitle_parts.append(str(server.source_file))
        source_type = server.client.replace("openclaw:", "")
        subtitle_parts.append(f"source: {source_type}")
    else:
        if server.transport.value != "stdio":
            subtitle_parts.append(f"transport: {server.transport.value}")
        if server.command:
            cmd_display = " ".join([server.command, *server.args[:3]])
            if len(server.args) > 3:
                cmd_display += " ..."
            subtitle_parts.append(cmd_display)
        elif server.url:
            subtitle_parts.append(server.url)
        subtitle_parts.append(f"client: {server.client}")

    subtitle = " | ".join(subtitle_parts)

    if server_map.warning:
        console.print(f"  [yellow]⚠ {server_map.warning}[/yellow]")

    if not server_map.tools:
        console.print(
            f"  [dim]No tools discovered for {server.name} "
            f"({server_map.enumeration_method})[/dim]\n"
        )
        return

    # Build table
    table = Table(
        title=title,
        caption=f"[dim]{subtitle}[/dim]",
        title_style="bold",
        show_header=True,
        header_style="bold",
        border_style="dim",
        padding=(0, 1),
    )

    table.add_column("Tool", style="bold", min_width=20)
    table.add_column("Access", min_width=10)
    table.add_column("Risk", min_width=8, justify="center")
    table.add_column("Notes", min_width=30)

    for tool_perm in server_map.tools:
        tool_name = tool_perm.tool.name

        # Access icons
        access_str = _access_icons(tool_perm.data_access)

        # Risk badge
        risk_text = Text(
            tool_perm.risk_level.value,
            style=_risk_style(tool_perm.risk_level),
        )

        # Notes: first risk reason
        notes = tool_perm.risk_reasons[0] if tool_perm.risk_reasons else ""

        # Add R/W indicators
        rw_parts: list[str] = []
        if tool_perm.is_read_only:
            rw_parts.append("R")
        else:
            rw_parts.append("RW")
        if tool_perm.is_destructive:
            rw_parts.append("D")
        rw_str = "/".join(rw_parts)
        tool_display = f"{tool_name} [{rw_str}]"

        table.add_row(tool_display, access_str, risk_text, notes)

    console.print(table)
    console.print()


def _print_risk_tree(scan: ScanResult, console: Console) -> None:
    """Print a risk summary tree grouping tools by risk level."""
    tree = Tree("[bold]Risk Summary[/bold]")

    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        tools_at_level: list[tuple[str, str]] = []

        for server_map in scan.servers:
            for tool_perm in server_map.tools:
                if tool_perm.risk_level == level:
                    tools_at_level.append(
                        (server_map.server.name, tool_perm.tool.name)
                    )

        if tools_at_level:
            style = _risk_style(level)
            branch = tree.add(f"[{style}]{level.value}[/{style}] ({len(tools_at_level)})")
            for server_name, tool_name in tools_at_level:
                branch.add(f"[dim]{server_name}/[/dim]{tool_name}")

    console.print(tree)
    console.print()


def _print_recommendations(
    recommendations: list[Recommendation],
    scan: ScanResult,
    console: Console,
) -> None:
    """Print recommendations section with risk explanations.

    For CRITICAL and WARNING severity recommendations, renders an
    attack scenario panel explaining the risk in plain language.

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
            # Also store by tool name alone for simpler targets
            tool_lookup[tool_perm.tool.name] = (tool_perm, server_map)

    for i, rec in enumerate(recommendations, 1):
        severity_style = _severity_style(rec.severity)
        console.print(
            f"  {i}. [{severity_style}]{rec.severity.value}[/{severity_style}] "
            f"[dim]({rec.target})[/dim]"
        )
        console.print(f"     {rec.message}")
        if rec.suggested_policy:
            console.print(f"     [dim]Suggested policy:[/dim]")
            for line in rec.suggested_policy.split("\n"):
                console.print(f"       [green]{line}[/green]")

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
        f"[red]Impact:[/red] {explanation.impact}",
        f"[green]Fix:[/green] {explanation.mitigation}",
    ]
    content = "\n".join(lines)
    panel = Panel(
        content,
        title="Attack Scenario",
        title_align="left",
        border_style="yellow",
        padding=(0, 1),
    )
    console.print(f"     ", end="")  # indent to align with recommendation
    console.print(panel)


def _access_icons(accesses: list[DataAccess]) -> str:
    """Map data access list to emoji indicators."""
    icons: list[str] = []
    seen: set[DataAccessType] = set()
    for access in accesses:
        if access.type not in seen:
            icon = _ACCESS_ICONS.get(access.type, "\u2753")
            icons.append(icon)
            seen.add(access.type)
    return " ".join(icons) if icons else "\u2753"


def _risk_style(level: RiskLevel) -> str:
    """Map risk level to rich style string."""
    return {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "bold red",
    }.get(level, "white")


def _risk_border(level: RiskLevel) -> str:
    """Map risk level to panel border style."""
    return {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.CRITICAL: "red",
    }.get(level, "white")


def _severity_style(severity: RecommendationSeverity) -> str:
    """Map recommendation severity to rich style."""
    return {
        RecommendationSeverity.INFO: "blue",
        RecommendationSeverity.WARNING: "yellow",
        RecommendationSeverity.CRITICAL: "bold red",
    }.get(severity, "white")


def _overall_risk(scan: ScanResult) -> RiskLevel:
    """Compute the overall risk from a scan result."""
    if not scan.servers:
        return RiskLevel.LOW

    risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    highest = RiskLevel.LOW
    for server in scan.servers:
        if risk_order.index(server.overall_risk) > risk_order.index(highest):
            highest = server.overall_risk
    return highest


def _risk_summary(
    scan: ScanResult,
    overall: RiskLevel,
    recommendations: list[Recommendation],
) -> str:
    """Generate a rich-markup summary with drivers, mitigation, and config.

    Args:
        scan: The complete scan result.
        overall: The computed overall risk level.
        recommendations: Generated recommendations (for YAML snippets).

    Returns:
        A rich-markup string for rendering in a Panel.
    """
    if not scan.servers:
        return "[dim]No tools found.[/dim]"

    style = _risk_style(overall)

    # Count tools by risk level
    counts: dict[RiskLevel, int] = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.LOW: 0,
    }

    # Collect driver data: (label, reason, ToolPermission, ServerPermissionMap)
    drivers: list[tuple[str, str, ToolPermission, ServerPermissionMap]] = []
    seen_tools: set[str] = set()

    for server_map in scan.servers:
        source = _format_source(server_map.server.client)
        for tool_perm in server_map.tools:
            counts[tool_perm.risk_level] += 1
            if tool_perm.risk_level == overall and tool_perm.risk_reasons:
                tool_key = f"{server_map.server.name}/{tool_perm.tool.name}"
                if tool_key not in seen_tools:
                    label = f"{source} {tool_perm.tool.name}"
                    drivers.append((label, tool_perm.risk_reasons[0], tool_perm, server_map))
                    seen_tools.add(tool_key)

    # Build recommendation lookup: target → suggested_policy
    rec_lookup: dict[str, str] = {}
    for rec in recommendations:
        if rec.suggested_policy:
            rec_lookup[rec.target] = rec.suggested_policy

    # Header line
    lines: list[str] = [f"[{style}]Overall Risk: {overall.value}[/{style}]", ""]

    # Count summary
    count_parts: list[str] = []
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        if counts[level] > 0:
            count_parts.append(f"{counts[level]} {level.value}")
    lines.append("[dim]" + " \u00b7 ".join(count_parts) + "[/dim]")

    # Driver entries (up to 3)
    for label, reason, tool_perm, server_map in drivers[:3]:
        lines.append("")
        lines.append(f'Driven by: "{label}", "{reason}"')

        # Mitigation: the config snippet that fixes this
        tool_name = tool_perm.tool.name
        server_name = server_map.server.name
        yaml_snippet = (
            rec_lookup.get(f"{server_name}/{tool_name}")
            or rec_lookup.get(tool_name)
        )
        if yaml_snippet:
            lines.append(
                "  [green]Mitigation:[/green] "
                "Run [bold]agentward configure[/bold] to generate a policy with:"
            )
            for yaml_line in yaml_snippet.strip().split("\n"):
                lines.append(f"    [green]{yaml_line}[/green]")

    return "\n".join(lines)


def _format_source(client: str) -> str:
    """Format a client string into a human-readable source label.

    Extracts the source name from client identifiers like
    ``"claude_desktop"``, ``"cursor"``, ``"openclaw:windsurf bundled"``,
    ``"python:openai"``.

    Args:
        client: The server client identifier.

    Returns:
        A short parenthesized label, e.g. ``"(cursor)"``, ``"(clawdbot)"``.
    """
    # openclaw:xxx → clawdbot
    if client.startswith("openclaw"):
        return "(clawdbot)"
    # python:framework → framework
    if client.startswith("python:"):
        framework = client.split(":", 1)[1]
        return f"({framework})"
    # Known MCP clients
    _CLIENT_LABELS: dict[str, str] = {
        "claude_desktop": "claude desktop",
        "claude_code": "claude code",
        "cursor": "cursor",
        "windsurf": "windsurf",
        "vscode": "vscode",
    }
    label = _CLIENT_LABELS.get(client, client)
    return f"({label})"
