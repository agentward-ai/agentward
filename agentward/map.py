"""Permission graph visualization.

Builds an intermediate graph representation from scan results and policy,
then renders it as rich terminal output, Mermaid diagrams, or JSON.

Two modes:
  - Scan-only: shows servers, tools, data access types, risk levels, chains
  - Policy overlay: adds ALLOW/BLOCK/APPROVE markers per tool and chain status

Color palette (matches agentward.ai):
  - Neon green (#00ff88): LOW risk, ALLOW, success
  - Cyan (#5eead4): info, sources
  - Yellow (#ffcc00): MEDIUM risk
  - Orange (#ff6b35): HIGH risk
  - Hot pink (#ff3366): CRITICAL risk, BLOCK
  - Dim (#555555): borders, secondary text
"""

from __future__ import annotations

import json as _json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from rich.console import Console

from agentward.policy.engine import PolicyEngine
from agentward.policy.schema import PolicyDecision
from agentward.scan.chains import ChainDetection, ChainRisk
from agentward.scan.permissions import (
    DataAccessType,
    RiskLevel,
    ScanResult,
    ServerPermissionMap,
    ToolPermission,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ToolNode:
    """A tool in the permission graph."""

    name: str
    risk_level: RiskLevel
    access_types: list[DataAccessType]
    is_read_only: bool
    is_destructive: bool
    policy_decision: PolicyDecision | None = None


@dataclass
class ServerNode:
    """A server/skill in the permission graph."""

    name: str
    overall_risk: RiskLevel
    tools: list[ToolNode] = field(default_factory=list)
    transport: str = ""
    client: str = ""


@dataclass
class ChainEdge:
    """A detected chain between servers, with optional policy status."""

    source: str
    target: str
    risk: ChainRisk
    description: str
    is_blocked_by_policy: bool = False
    blocking_rule: str | None = None


@dataclass
class MapData:
    """Complete graph data for rendering."""

    servers: list[ServerNode] = field(default_factory=list)
    chains: list[ChainEdge] = field(default_factory=list)
    has_policy: bool = False
    total_tools: int = 0
    tools_blocked: int = 0
    tools_approved: int = 0
    chains_blocked: int = 0
    chains_unprotected: int = 0


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------


def build_map_data(
    scan: ScanResult,
    chains: list[ChainDetection],
    policy_engine: PolicyEngine | None = None,
) -> MapData:
    """Build the intermediate graph representation from scan results.

    Iterates over scan.servers and chains to build ServerNode/ToolNode/ChainEdge
    structures. When a policy_engine is provided, evaluates each tool and each
    chain to populate policy_decision and is_blocked_by_policy fields.

    Args:
        scan: Complete scan result from the scan pipeline.
        chains: Detected skill chains.
        policy_engine: Optional policy engine for overlay evaluation.

    Returns:
        A MapData with all graph nodes and edges populated.
    """
    servers: list[ServerNode] = []
    total_tools = 0
    tools_blocked = 0
    tools_approved = 0

    for server_map in scan.servers:
        tool_nodes: list[ToolNode] = []

        for tool_perm in server_map.tools:
            access_types = list({a.type for a in tool_perm.data_access})

            decision: PolicyDecision | None = None
            if policy_engine is not None:
                result = policy_engine.evaluate(tool_perm.tool.name, {})
                decision = result.decision
                if decision == PolicyDecision.BLOCK:
                    tools_blocked += 1
                elif decision == PolicyDecision.APPROVE:
                    tools_approved += 1

            tool_nodes.append(
                ToolNode(
                    name=tool_perm.tool.name,
                    risk_level=tool_perm.risk_level,
                    access_types=access_types,
                    is_read_only=tool_perm.is_read_only,
                    is_destructive=tool_perm.is_destructive,
                    policy_decision=decision,
                )
            )
            total_tools += 1

        servers.append(
            ServerNode(
                name=server_map.server.name,
                overall_risk=server_map.overall_risk,
                tools=tool_nodes,
                transport=server_map.server.transport.value,
                client=server_map.server.client,
            )
        )

    # Build chain edges
    chain_edges: list[ChainEdge] = []
    chains_blocked = 0
    chains_unprotected = 0

    for chain in chains:
        is_blocked = False
        blocking_rule: str | None = None

        if policy_engine is not None:
            chain_result = policy_engine.evaluate_chaining(
                chain.source_server, chain.target_server
            )
            if chain_result.decision == PolicyDecision.BLOCK:
                is_blocked = True
                # Extract the rule text from the reason
                blocking_rule = (
                    f"{chain.source_server} cannot trigger {chain.target_server}"
                )
                chains_blocked += 1
            else:
                chains_unprotected += 1

        chain_edges.append(
            ChainEdge(
                source=chain.source_server,
                target=chain.target_server,
                risk=chain.risk,
                description=chain.description,
                is_blocked_by_policy=is_blocked,
                blocking_rule=blocking_rule,
            )
        )

    return MapData(
        servers=servers,
        chains=chain_edges,
        has_policy=policy_engine is not None,
        total_tools=total_tools,
        tools_blocked=tools_blocked,
        tools_approved=tools_approved,
        chains_blocked=chains_blocked,
        chains_unprotected=chains_unprotected,
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


# ---------------------------------------------------------------------------
# Rich terminal rendering
# ---------------------------------------------------------------------------

# Data access type → display icon
_ACCESS_ICONS: dict[DataAccessType, str] = {
    DataAccessType.FILESYSTEM: "\U0001f4c1",  # 📁
    DataAccessType.NETWORK: "\U0001f310",  # 🌐
    DataAccessType.DATABASE: "\U0001f5c4",  # 🗄️
    DataAccessType.EMAIL: "\u2709\ufe0f",  # ✉️
    DataAccessType.MESSAGING: "\U0001f4ac",  # 💬
    DataAccessType.CREDENTIALS: "\U0001f511",  # 🔑
    DataAccessType.SHELL: "\U0001f4bb",  # 💻
    DataAccessType.CODE: "\U0001f4dd",  # 📝
    DataAccessType.BROWSER: "\U0001f30d",  # 🌍
    DataAccessType.UNKNOWN: "\u2753",  # ❓
}

# Risk level → (emoji badge, rich style)
_RISK_BADGES: dict[RiskLevel, tuple[str, str]] = {
    RiskLevel.CRITICAL: ("\U0001f534", f"bold {_CLR_CRITICAL}"),  # 🔴
    RiskLevel.HIGH: ("\u26a0", f"{_CLR_HIGH}"),                    # ⚠
    RiskLevel.MEDIUM: ("\u26a0", f"{_CLR_MEDIUM}"),                # ⚠
    RiskLevel.LOW: ("\u2713", f"{_CLR_LOW}"),                      # ✓
}


def _display_width(text: str) -> int:
    """Compute the terminal display width of a string.

    Accounts for wide characters (CJK, emoji) that occupy 2 columns.
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


def _access_icons(types: list[DataAccessType]) -> str:
    """Build access type icon string."""
    seen: set[DataAccessType] = set()
    icons: list[str] = []
    for t in types:
        if t not in seen:
            icons.append(_ACCESS_ICONS.get(t, "\u2753"))
            seen.add(t)
    return " ".join(icons) if icons else "\u2753"


def _policy_marker_plain(decision: PolicyDecision | None) -> str:
    """Render a policy decision as plain text (no rich markup).

    Used in row-colored tables where the entire row already has a color.
    """
    if decision is None:
        return ""
    if decision == PolicyDecision.ALLOW:
        return "  \u2713"
    if decision == PolicyDecision.BLOCK:
        return "  \u2717 BLOCKED"
    if decision == PolicyDecision.APPROVE:
        return "  \u26a0 APPROVE"
    if decision == PolicyDecision.LOG:
        return "  \u25cb LOG"
    return ""


def _source_badge(client: str) -> str:
    """Classify a client into a source badge: MCP, Skill, or SDK."""
    if client.startswith("openclaw"):
        return "Skill"
    if client.startswith("python:"):
        return "SDK"
    return "MCP"


def render_terminal(data: MapData, console: Console) -> None:
    """Render the permission graph as a hierarchical tree.

    Visually distinct from ``agentward scan`` (flat table). Shows servers as
    parent nodes with tools indented underneath, using tree-drawing characters.

    Sections:
      1. Permission tree — servers → tools with icons, risk, policy markers
      2. Skill chains — arrows with risk + policy status
      3. Summary footer — risk counts + protection stats (when policy loaded)

    Args:
        data: The intermediate graph representation.
        console: Rich console to print to (stderr).
    """
    console.print()

    # Section 1: Permission tree
    if data.servers:
        console.print(f"[bold {_CLR_CYAN}]Permission Graph[/bold {_CLR_CYAN}]")

        # Pre-compute column widths across ALL tools for consistent alignment
        max_name_w = 0
        max_icon_w = 0
        for server in data.servers:
            for tool in server.tools:
                max_name_w = max(max_name_w, len(tool.name))
                icons = _access_icons(tool.access_types)
                max_icon_w = max(max_icon_w, _display_width(icons))

        for s_idx, server in enumerate(data.servers):
            is_last_server = s_idx == len(data.servers) - 1
            srv_branch = "\u2514\u2500\u2500" if is_last_server else "\u251c\u2500\u2500"
            srv_cont = "    " if is_last_server else "\u2502   "

            # Server line: colored by overall risk
            srv_clr = _risk_color(server.overall_risk)
            source = _source_badge(server.client)
            emoji, _ = _RISK_BADGES[server.overall_risk]
            console.print(
                f"[{_CLR_DIM}]{srv_branch}[/{_CLR_DIM}] "
                f"[bold {srv_clr}]{server.name}[/bold {srv_clr}]  "
                f"[{srv_clr}]{emoji} {server.overall_risk.value}[/{srv_clr}]  "
                f"[{_CLR_DIM}]({source})[/{_CLR_DIM}]"
            )

            # Tool children — aligned columns
            for t_idx, tool in enumerate(server.tools):
                is_last_tool = t_idx == len(server.tools) - 1
                tool_branch = "\u2514\u2500\u2500" if is_last_tool else "\u251c\u2500\u2500"

                tool_clr = _risk_color(tool.risk_level)
                tool_emoji, _ = _RISK_BADGES[tool.risk_level]
                icons = _access_icons(tool.access_types)
                marker = _policy_marker_plain(tool.policy_decision)

                name_pad = " " * (max_name_w - len(tool.name))
                icon_pad = " " * (max_icon_w - _display_width(icons))

                console.print(
                    f"[{_CLR_DIM}]{srv_cont}{tool_branch}[/{_CLR_DIM}] "
                    f"[{tool_clr}]{tool.name}{name_pad}[/{tool_clr}]  "
                    f"{icons}{icon_pad}  "
                    f"[{tool_clr}]{tool_emoji} {tool.risk_level.value}[/{tool_clr}]"
                    f"[{tool_clr}]{marker}[/{tool_clr}]"
                )

        console.print()

    # Section 2: Chains (compact — one line per chain)
    if data.chains:
        for edge in data.chains:
            risk_clr = _CLR_CRITICAL if edge.risk == ChainRisk.CRITICAL else _CLR_HIGH

            if data.has_policy:
                if edge.is_blocked_by_policy:
                    status = f"  [{_CLR_CRITICAL}]\u2717 BLOCKED[/{_CLR_CRITICAL}]"
                else:
                    status = f"  [{_CLR_HIGH}]UNPROTECTED[/{_CLR_HIGH}]"
            else:
                status = ""

            console.print(
                f"[{risk_clr}]\u26a0 {edge.source} \u2192 {edge.target}[/{risk_clr}]"
                f"  [{_CLR_DIM}]{edge.description}[/{_CLR_DIM}]"
                f"{status}"
            )
        console.print()

    # Section 3: Compact summary footer
    risk_counts: dict[RiskLevel, int] = {
        RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0, RiskLevel.LOW: 0,
    }
    for server in data.servers:
        for tool in server.tools:
            risk_counts[tool.risk_level] += 1

    level_colors = {
        RiskLevel.CRITICAL: _CLR_CRITICAL, RiskLevel.HIGH: _CLR_HIGH,
        RiskLevel.MEDIUM: _CLR_MEDIUM, RiskLevel.LOW: _CLR_LOW,
    }
    count_parts: list[str] = []
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        if risk_counts[level] > 0:
            clr = level_colors[level]
            count_parts.append(
                f"[{clr}]{risk_counts[level]} {level.value.lower()}[/{clr}]"
            )
    if data.chains:
        count_parts.append(
            f"[{_CLR_HIGH}]{len(data.chains)} chain(s)[/{_CLR_HIGH}]"
        )
    if count_parts:
        console.print(" \u00b7 ".join(count_parts))

    # Protection stats (only with policy)
    if data.has_policy:
        tools_allowed = data.total_tools - data.tools_blocked - data.tools_approved
        prot_parts = [
            f"[{_CLR_GREEN}]{tools_allowed} allowed[/{_CLR_GREEN}]",
            f"[{_CLR_CRITICAL}]{data.tools_blocked} blocked[/{_CLR_CRITICAL}]",
            f"[{_CLR_HIGH}]{data.tools_approved} gated[/{_CLR_HIGH}]",
        ]
        console.print(" \u2502 ".join(prot_parts))

        if data.chains_unprotected > 0:
            console.print(
                f"[{_CLR_HIGH}]\u26a0[/{_CLR_HIGH}] "
                f"[{_CLR_HIGH}]{data.chains_unprotected} unprotected chain(s)[/{_CLR_HIGH}] "
                f"\u2014 run [bold {_CLR_GREEN}]agentward configure[/bold {_CLR_GREEN}] "
                f"to generate blocking rules"
            )
    else:
        console.print(
            f"[{_CLR_GREEN}]\u2192[/{_CLR_GREEN}] Run "
            f"[bold {_CLR_GREEN}]agentward configure[/bold {_CLR_GREEN}] to generate policies"
        )

    console.print()


# ---------------------------------------------------------------------------
# Mermaid diagram rendering
# ---------------------------------------------------------------------------


def _sanitize_id(name: str) -> str:
    """Convert a name to a valid Mermaid node ID.

    Replaces non-alphanumeric characters with underscores and ensures
    the ID starts with a letter.

    Args:
        name: The raw name (server name, tool name).

    Returns:
        A mermaid-safe identifier.
    """
    sanitized = ""
    for ch in name:
        if ch.isalnum() or ch == "_":
            sanitized += ch
        else:
            sanitized += "_"
    if sanitized and not sanitized[0].isalpha():
        sanitized = "n_" + sanitized
    return sanitized or "unnamed"


def _mermaid_access_icons(types: list[DataAccessType]) -> str:
    """Build a compact icon string for mermaid labels (no rich markup)."""
    seen: set[DataAccessType] = set()
    icons: list[str] = []
    for t in types:
        if t not in seen:
            icons.append(_ACCESS_ICONS.get(t, "?"))
            seen.add(t)
    return " ".join(icons) if icons else "?"


def render_mermaid(data: MapData) -> str:
    """Generate a Mermaid flowchart diagram from the graph data.

    Produces a complete Mermaid diagram with:
      - Subgraphs for each server
      - Nodes for each tool (styled by risk/policy)
      - Edges for each chain (styled by risk/blocked)

    Args:
        data: The intermediate graph representation.

    Returns:
        A string containing the Mermaid diagram definition.
    """
    lines: list[str] = ["flowchart LR"]

    # Track node → class assignments
    class_assignments: dict[str, str] = {}

    # Server subgraphs
    for server in data.servers:
        srv_id = f"srv_{_sanitize_id(server.name)}"
        lines.append(
            f'    subgraph {srv_id}["{server.name} [{server.overall_risk.value}]"]'
        )

        for tool in server.tools:
            tool_id = f"t_{_sanitize_id(server.name)}_{_sanitize_id(tool.name)}"
            icons = _mermaid_access_icons(tool.access_types)

            # Build label
            label_parts = [tool.name, f"{icons} {tool.risk_level.value}"]
            if data.has_policy and tool.policy_decision == PolicyDecision.BLOCK:
                label_parts.append("BLOCKED")
            elif data.has_policy and tool.policy_decision == PolicyDecision.APPROVE:
                label_parts.append("APPROVE")

            label = "<br/>".join(label_parts)
            lines.append(f'        {tool_id}["{label}"]')

            # Assign class based on policy decision or risk
            if data.has_policy and tool.policy_decision == PolicyDecision.BLOCK:
                class_assignments[tool_id] = "blocked"
            elif data.has_policy and tool.policy_decision == PolicyDecision.APPROVE:
                class_assignments[tool_id] = "approved"
            else:
                class_assignments[tool_id] = tool.risk_level.value.lower()

        lines.append("    end")

    # Chain edges (between subgraph IDs)
    if data.chains:
        lines.append("")
        for edge in data.chains:
            src_id = f"srv_{_sanitize_id(edge.source)}"
            tgt_id = f"srv_{_sanitize_id(edge.target)}"
            label = edge.risk.value
            if data.has_policy and edge.is_blocked_by_policy:
                label += " BLOCKED"
            lines.append(f'    {src_id} -->|"{label}"| {tgt_id}')

    # Class definitions
    lines.append("")
    lines.append("    classDef low fill:#22c55e20,stroke:#22c55e")
    lines.append("    classDef medium fill:#eab30820,stroke:#eab308")
    lines.append("    classDef high fill:#ef444420,stroke:#ef4444")
    lines.append(
        "    classDef critical fill:#dc262620,stroke:#dc2626,stroke-width:2px"
    )
    lines.append(
        "    classDef blocked fill:#ef444440,stroke:#ef4444,stroke-dasharray:5 5"
    )
    lines.append(
        "    classDef approved fill:#eab30840,stroke:#eab308,stroke-dasharray:5 5"
    )

    # Apply classes
    if class_assignments:
        lines.append("")
        for node_id, cls in class_assignments.items():
            lines.append(f"    class {node_id} {cls}")

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# JSON rendering
# ---------------------------------------------------------------------------


def _enum_value(obj: Any) -> Any:
    """Recursively convert enum values in a dict/list structure."""
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _enum_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_enum_value(item) for item in obj]
    return obj


def render_json(data: MapData) -> str:
    """Serialize the graph data to JSON.

    Args:
        data: The intermediate graph representation.

    Returns:
        A JSON string with servers, chains, and summary stats.
    """
    raw = asdict(data)
    cleaned = _enum_value(raw)
    return _json.dumps(cleaned, indent=2)
