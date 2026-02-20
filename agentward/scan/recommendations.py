"""Use-case-aware recommendation engine.

Examines scan results and generates specific, actionable security
recommendations with suggested policy YAML snippets.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from agentward.scan.permissions import (
    DataAccessType,
    RiskLevel,
    ScanResult,
    ServerPermissionMap,
    ToolPermission,
)


class RecommendationSeverity(str, Enum):
    """Severity of a recommendation."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Recommendation(BaseModel):
    """A specific, actionable recommendation from the scan."""

    severity: RecommendationSeverity
    target: str  # which server/tool this applies to
    message: str
    suggested_policy: str | None = None  # YAML snippet


def generate_recommendations(scan: ScanResult) -> list[Recommendation]:
    """Generate recommendations based on scan results.

    Applies all recommendation rules across all servers and tools.

    Args:
        scan: The complete scan result.

    Returns:
        A list of recommendations ordered by severity (CRITICAL first).
    """
    recs: list[Recommendation] = []

    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            recs.extend(_check_write_without_read_only(server_map, tool_perm))
            recs.extend(_check_shell_execution(server_map, tool_perm))
            recs.extend(_check_destructive_without_approval(server_map, tool_perm))
            recs.extend(_check_no_annotations(server_map, tool_perm))

        recs.extend(_check_network_with_sensitive(server_map))
        recs.extend(_check_dynamic_tools(server_map))

    recs.extend(_check_cross_server_chaining(scan.servers))

    # Sort: CRITICAL first, then WARNING, then INFO
    severity_order = {
        RecommendationSeverity.CRITICAL: 0,
        RecommendationSeverity.WARNING: 1,
        RecommendationSeverity.INFO: 2,
    }
    recs.sort(key=lambda r: severity_order[r.severity])

    return recs


def _check_write_without_read_only(
    server: ServerPermissionMap, tool: ToolPermission
) -> list[Recommendation]:
    """Flag tools that have write access when read-only might suffice."""
    if tool.is_read_only or tool.is_destructive:
        return []  # Already read-only, or flagged separately as destructive

    # Only recommend if the tool has writes to filesystem, database, or email
    write_types = {
        a.type for a in tool.data_access
        if a.write and a.type in (
            DataAccessType.FILESYSTEM, DataAccessType.DATABASE,
            DataAccessType.EMAIL, DataAccessType.MESSAGING,
        )
    }
    if not write_types:
        return []

    type_names = ", ".join(t.value for t in write_types)
    server_name = server.server.name
    tool_name = tool.tool.name

    return [
        Recommendation(
            severity=RecommendationSeverity.WARNING,
            target=f"{server_name}/{tool_name}",
            message=(
                f"Tool '{tool_name}' has write access to {type_names}. "
                f"Set to read-only if you only need to read data."
            ),
            suggested_policy=(
                f"skills:\n"
                f"  {server_name}:\n"
                f"    {_resource_key(tool_name)}:\n"
                f"      read: true\n"
                f"      write: false"
            ),
        )
    ]


def _check_shell_execution(
    server: ServerPermissionMap, tool: ToolPermission
) -> list[Recommendation]:
    """Flag tools that can execute shell commands."""
    has_shell = any(a.type == DataAccessType.SHELL for a in tool.data_access)
    if not has_shell:
        return []

    return [
        Recommendation(
            severity=RecommendationSeverity.CRITICAL,
            target=f"{server.server.name}/{tool.tool.name}",
            message=(
                f"Tool '{tool.tool.name}' can execute shell commands. "
                f"This is CRITICAL risk — an attacker could run arbitrary code. "
                f"Consider blocking or requiring human approval."
            ),
            suggested_policy=(
                f"require_approval:\n"
                f"  - {tool.tool.name}"
            ),
        )
    ]


def _check_network_with_sensitive(
    server: ServerPermissionMap,
) -> list[Recommendation]:
    """Flag servers with both network access and credential/sensitive data tools."""
    has_network = False
    has_sensitive = False

    for tool in server.tools:
        for access in tool.data_access:
            if access.type == DataAccessType.NETWORK:
                has_network = True
            if access.type in (DataAccessType.CREDENTIALS, DataAccessType.EMAIL):
                has_sensitive = True

    if not (has_network and has_sensitive):
        return []

    return [
        Recommendation(
            severity=RecommendationSeverity.CRITICAL,
            target=server.server.name,
            message=(
                f"Server '{server.server.name}' has tools with both network access "
                f"and access to sensitive data (credentials/email). "
                f"This creates a data exfiltration risk. Consider blocking outbound network."
            ),
            suggested_policy=(
                f"skills:\n"
                f"  {server.server.name}:\n"
                f"    network:\n"
                f"      outbound: false"
            ),
        )
    ]


def _check_destructive_without_approval(
    server: ServerPermissionMap, tool: ToolPermission
) -> list[Recommendation]:
    """Flag destructive tools not in require_approval."""
    if not tool.is_destructive:
        return []

    return [
        Recommendation(
            severity=RecommendationSeverity.WARNING,
            target=f"{server.server.name}/{tool.tool.name}",
            message=(
                f"Tool '{tool.tool.name}' is destructive (can delete/modify data irreversibly). "
                f"Consider requiring human approval before execution."
            ),
            suggested_policy=(
                f"require_approval:\n"
                f"  - {tool.tool.name}"
            ),
        )
    ]


def _check_cross_server_chaining(
    servers: list[ServerPermissionMap],
) -> list[Recommendation]:
    """Detect potential skill chaining risks across servers.

    Looks for dangerous combinations:
      - Email read + browser access (email links → prompt injection)
      - Any data read + shell execution (data → code execution)
    """
    recs: list[Recommendation] = []

    # Collect per-server capability sets
    server_caps: list[tuple[str, set[DataAccessType], bool]] = []
    for s in servers:
        types: set[DataAccessType] = set()
        has_shell = False
        for tool in s.tools:
            for access in tool.data_access:
                types.add(access.type)
            if any(a.type == DataAccessType.SHELL for a in tool.data_access):
                has_shell = True
        server_caps.append((s.server.name, types, has_shell))

    # Check pairs
    for i, (name_a, types_a, shell_a) in enumerate(server_caps):
        for name_b, types_b, shell_b in server_caps[i + 1:]:
            # Email + browser = chaining risk
            if (
                DataAccessType.EMAIL in types_a
                and DataAccessType.BROWSER in types_b
            ) or (
                DataAccessType.EMAIL in types_b
                and DataAccessType.BROWSER in types_a
            ):
                email_server = name_a if DataAccessType.EMAIL in types_a else name_b
                browser_server = name_a if DataAccessType.BROWSER in types_a else name_b
                recs.append(
                    Recommendation(
                        severity=RecommendationSeverity.WARNING,
                        target=f"{email_server} → {browser_server}",
                        message=(
                            f"Email server '{email_server}' + browser server '{browser_server}': "
                            f"email content could chain to the browser via URLs, "
                            f"enabling prompt injection attacks. Consider blocking this chain."
                        ),
                        suggested_policy=(
                            f"skill_chaining:\n"
                            f"  - {email_server} cannot trigger {browser_server}"
                        ),
                    )
                )

            # Any data + shell = code execution risk
            if shell_b and not shell_a:
                recs.append(
                    Recommendation(
                        severity=RecommendationSeverity.CRITICAL,
                        target=f"{name_a} → {name_b}",
                        message=(
                            f"Server '{name_a}' can read data that could chain to "
                            f"shell execution in '{name_b}'. This is a prompt injection "
                            f"→ code execution path. Consider blocking this chain."
                        ),
                        suggested_policy=(
                            f"skill_chaining:\n"
                            f"  - {name_a} cannot trigger {name_b}"
                        ),
                    )
                )
            elif shell_a and not shell_b:
                recs.append(
                    Recommendation(
                        severity=RecommendationSeverity.CRITICAL,
                        target=f"{name_b} → {name_a}",
                        message=(
                            f"Server '{name_b}' can read data that could chain to "
                            f"shell execution in '{name_a}'. This is a prompt injection "
                            f"→ code execution path. Consider blocking this chain."
                        ),
                        suggested_policy=(
                            f"skill_chaining:\n"
                            f"  - {name_b} cannot trigger {name_a}"
                        ),
                    )
                )

    return recs


def _check_dynamic_tools(
    server: ServerPermissionMap,
) -> list[Recommendation]:
    """Flag servers that support dynamic tool loading."""
    if server.capabilities is None:
        return []
    if not server.capabilities.tools_list_changed:
        return []

    return [
        Recommendation(
            severity=RecommendationSeverity.WARNING,
            target=server.server.name,
            message=(
                f"Server '{server.server.name}' supports dynamic tool loading "
                f"(listChanged: true). New tools could appear at runtime. "
                f"Monitor closely and re-scan periodically."
            ),
        )
    ]


def _check_no_annotations(
    server: ServerPermissionMap, tool: ToolPermission
) -> list[Recommendation]:
    """Flag tools with no annotations — risk assessment is heuristic only."""
    if tool.tool.annotations is not None:
        return []

    # Only flag if the tool has non-trivial risk
    if tool.risk_level in (RiskLevel.LOW,):
        return []

    return [
        Recommendation(
            severity=RecommendationSeverity.INFO,
            target=f"{server.server.name}/{tool.tool.name}",
            message=(
                f"Tool '{tool.tool.name}' has no MCP annotations. "
                f"Risk assessment is based on name/schema heuristics only."
            ),
        )
    ]


def _resource_key(tool_name: str) -> str:
    """Extract a resource key from a tool name for policy YAML snippets.

    E.g., "gmail_send" → "gmail", "read_file" → "file"
    """
    for sep in ("_", "-", "."):
        if sep in tool_name:
            parts = tool_name.split(sep)
            # Return the longest non-verb part
            from agentward.scan.permissions import _READ_VERBS, _WRITE_VERBS, _DELETE_VERBS, _EXECUTE_VERBS

            all_verbs = _READ_VERBS | _WRITE_VERBS | _DELETE_VERBS | _EXECUTE_VERBS
            for part in parts:
                if part.lower() not in all_verbs:
                    return part
            return parts[0]
    return tool_name
