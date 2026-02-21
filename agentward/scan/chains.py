"""Skill chain analyzer.

Detects potential tool-to-tool interaction paths that could be exploited
for prompt injection chains, data exfiltration, or privilege escalation.

A "chain" exists when one server's capabilities could feed into another
server's capabilities — e.g., an email server reading attacker-controlled
content that gets passed to a browser or shell server.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from agentward.scan.permissions import (
    DataAccessType,
    RiskLevel,
    ScanResult,
    ServerPermissionMap,
)


class ChainRisk(str, Enum):
    """Risk level for a detected skill chain."""

    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ChainDetection(BaseModel):
    """A detected skill chain between two servers."""

    source_server: str
    target_server: str
    risk: ChainRisk
    label: str  # short label, e.g. "email-mgr → web-browser"
    description: str  # e.g. "Email content could leak via browsing"
    attack_vector: str  # e.g. "Attacker sends email with malicious URL..."


# Known dangerous capability pairs: (source_type, target_type) → chain info
_CHAIN_PATTERNS: list[
    tuple[DataAccessType, DataAccessType, ChainRisk, str, str]
] = [
    (
        DataAccessType.EMAIL,
        DataAccessType.BROWSER,
        ChainRisk.HIGH,
        "Email content could leak via browsing",
        "Attacker embeds a malicious URL in an email. The email skill reads it, "
        "passes it to the browsing skill, which navigates to an attacker-controlled "
        "page containing prompt injection payloads.",
    ),
    (
        DataAccessType.EMAIL,
        DataAccessType.SHELL,
        ChainRisk.CRITICAL,
        "Email content could trigger code execution",
        "Attacker sends email with instructions that, when read by the email skill, "
        "chain to the shell skill to execute arbitrary commands.",
    ),
    (
        DataAccessType.BROWSER,
        DataAccessType.SHELL,
        ChainRisk.CRITICAL,
        "Web content could trigger code execution",
        "Attacker-controlled web page contains prompt injection that chains "
        "to the shell skill to execute arbitrary commands on the host.",
    ),
    (
        DataAccessType.BROWSER,
        DataAccessType.EMAIL,
        ChainRisk.HIGH,
        "Web content could trigger email actions",
        "Attacker-controlled web page contains prompt injection that chains "
        "to the email skill to send, forward, or exfiltrate emails.",
    ),
    (
        DataAccessType.MESSAGING,
        DataAccessType.SHELL,
        ChainRisk.CRITICAL,
        "Chat messages could trigger code execution",
        "Attacker sends a crafted message via Slack/Teams/etc. that chains "
        "to the shell skill to execute arbitrary commands.",
    ),
    (
        DataAccessType.MESSAGING,
        DataAccessType.BROWSER,
        ChainRisk.HIGH,
        "Chat messages could leak via browsing",
        "Attacker sends a crafted message containing a URL that chains "
        "to the browsing skill, navigating to an attacker-controlled page.",
    ),
    (
        DataAccessType.FILESYSTEM,
        DataAccessType.SHELL,
        ChainRisk.CRITICAL,
        "File content could trigger code execution",
        "Attacker plants a file with prompt injection content. The filesystem "
        "skill reads it, and the content chains to the shell skill.",
    ),
    (
        DataAccessType.DATABASE,
        DataAccessType.SHELL,
        ChainRisk.CRITICAL,
        "Database content could trigger code execution",
        "Attacker injects prompt injection into a database record. The database "
        "skill reads it, and the content chains to the shell skill.",
    ),
    (
        DataAccessType.NETWORK,
        DataAccessType.SHELL,
        ChainRisk.CRITICAL,
        "Network responses could trigger code execution",
        "Attacker-controlled API returns prompt injection in its response. "
        "The network skill processes it, and the content chains to the shell skill.",
    ),
]


def _build_capability_units(scan: ScanResult) -> list[tuple[str, set[DataAccessType]]]:
    """Build named capability units for chain detection.

    For most servers, each server is one unit with its aggregate capabilities.
    For servers with many tools that have distinct capability types (e.g.,
    OpenClaw skill collections), each tool becomes its own unit so chains
    show specific skill names instead of the generic server name.

    Args:
        scan: The complete scan result.

    Returns:
        A list of (name, capability_set) tuples.
    """
    units: list[tuple[str, set[DataAccessType]]] = []

    for server_map in scan.servers:
        # Count how many distinct DataAccessType categories this server has
        type_to_tools: dict[DataAccessType, list[str]] = {}
        for tool in server_map.tools:
            for access in tool.data_access:
                type_to_tools.setdefault(access.type, []).append(tool.tool.name)

        # If the server has multiple tools AND multiple distinct capability
        # types, emit per-tool units for granular chain labels.
        # This handles the OpenClaw case where 54 skills share one server.
        if len(server_map.tools) > 1 and len(type_to_tools) > 1:
            # Group by tool: each tool gets its own capability set
            for tool in server_map.tools:
                tool_types: set[DataAccessType] = set()
                for access in tool.data_access:
                    tool_types.add(access.type)
                if tool_types:
                    units.append((tool.tool.name, tool_types))
        else:
            # Single tool or homogeneous server — use server name
            all_types: set[DataAccessType] = set()
            for types in type_to_tools.values():
                for _ in types:
                    pass
            for tool in server_map.tools:
                for access in tool.data_access:
                    all_types.add(access.type)
            units.append((server_map.server.name, all_types))

    return units


def detect_chains(scan: ScanResult) -> list[ChainDetection]:
    """Detect potential skill chains across all scanned servers.

    Examines all pairs of capability units and checks whether their combined
    capabilities create dangerous interaction paths.

    For servers with many heterogeneous tools (like OpenClaw skill collections),
    chains are reported at the individual tool/skill level for clarity.

    Args:
        scan: The complete scan result.

    Returns:
        A list of detected chains, ordered by risk (CRITICAL first).
    """
    chains: list[ChainDetection] = []
    units = _build_capability_units(scan)

    # Check all ordered pairs (A→B is different from B→A)
    seen: set[tuple[str, str, str]] = set()  # (source, target, description) dedup

    for i, (name_a, types_a) in enumerate(units):
        for j, (name_b, types_b) in enumerate(units):
            if i == j:
                continue

            for src_type, tgt_type, risk, description, attack_vector in _CHAIN_PATTERNS:
                if src_type in types_a and tgt_type in types_b:
                    key = (name_a, name_b, description)
                    if key not in seen:
                        seen.add(key)
                        chains.append(
                            ChainDetection(
                                source_server=name_a,
                                target_server=name_b,
                                risk=risk,
                                label=f"{name_a} \u2192 {name_b}",
                                description=description,
                                attack_vector=attack_vector,
                            )
                        )

    # Sort: CRITICAL first, then HIGH
    risk_order = {ChainRisk.CRITICAL: 0, ChainRisk.HIGH: 1}
    chains.sort(key=lambda c: risk_order[c.risk])

    return chains
