"""Use-case-aware recommendation engine.

Examines scan results and generates specific, actionable security
recommendations with suggested policy YAML snippets.
"""

from __future__ import annotations

import re
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
            recs.extend(_check_session_history_exposure(server_map, tool_perm))
            recs.extend(_check_ssrf_risk(server_map, tool_perm))
            recs.extend(_check_read_only_hint_amplifier(server_map, tool_perm))

        recs.extend(_check_network_with_sensitive(server_map))
        recs.extend(_check_dynamic_tools(server_map))
        recs.extend(_check_write_reconfigure_chain(server_map))

    recs.extend(_check_cross_server_chaining(scan.servers))

    # Deduplicate by (severity, target) — same server pair can trigger
    # multiple rules but the user only needs one recommendation per pair
    seen: set[tuple[str, str]] = set()
    unique_recs: list[Recommendation] = []
    for rec in recs:
        key = (rec.severity.value, rec.target)
        if key not in seen:
            seen.add(key)
            unique_recs.append(rec)
    recs = unique_recs

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

    # Check pairs (skip self-referencing — same server name can appear
    # multiple times when e.g. OpenClaw groups all skills under one server)
    for i, (name_a, types_a, shell_a) in enumerate(server_caps):
        for name_b, types_b, shell_b in server_caps[i + 1:]:
            if name_a == name_b:
                continue
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


# ---------------------------------------------------------------------------
# Session / call-history exposure — Issue #406 gap 1
# ---------------------------------------------------------------------------

# Keywords that indicate a tool exposes prior session tool-call history.
_SESSION_HISTORY_KEYWORDS: frozenset[str] = frozenset({
    "recent", "history", "prior", "tool_calls", "call_log", "session_log",
    "call_history", "recent_calls", "get_history", "prior_calls",
    "conversation_log", "invocation_log", "audit_log",
})

# Substring patterns checked against the full (lowercased) tool name and description.
_SESSION_HISTORY_SUBSTRINGS: tuple[str, ...] = (
    "tool_call", "toolcall", "recent_tool", "prior_call", "session_log",
    "call_history", "get_recent", "last_n_call", "invocation",
    "conversation_log",
)


def _check_session_history_exposure(
    server: ServerPermissionMap, tool: ToolPermission
) -> list[Recommendation]:
    """Flag tools that expose session or tool-call history.

    Such tools let an attacker enumerate every previous tool invocation,
    reconstruct user activity, and discover targets for follow-on attacks.
    When combined with ``readOnlyHint: true``, many MCP clients auto-approve
    the call silently, making the exposure completely invisible to the user.
    """
    name_lower = tool.tool.name.lower()
    desc_lower = (tool.tool.description or "").lower()

    # Check name parts (word-boundary split) against the keyword set
    name_parts = set(re.split(r"[_\-\.]", name_lower))
    hit_in_name = bool(name_parts & _SESSION_HISTORY_KEYWORDS)

    # Check full name / description for substring patterns
    hit_in_substr = any(sub in name_lower or sub in desc_lower for sub in _SESSION_HISTORY_SUBSTRINGS)

    if not (hit_in_name or hit_in_substr):
        return []

    # Escalate to CRITICAL when readOnlyHint=true — auto-approval means the
    # exfiltration is invisible; HIGH otherwise.
    read_only_amplified = (
        tool.tool.annotations is not None
        and tool.tool.annotations.read_only_hint is True
    )
    severity = (
        RecommendationSeverity.CRITICAL if read_only_amplified else RecommendationSeverity.WARNING
    )
    amplifier_note = (
        " readOnlyHint=true causes many MCP clients to auto-approve this tool "
        "without user confirmation, enabling completely silent history enumeration."
        if read_only_amplified else ""
    )

    return [
        Recommendation(
            severity=severity,
            target=f"{server.server.name}/{tool.tool.name}",
            message=(
                f"Tool '{tool.tool.name}' exposes session or tool-call history. "
                f"An attacker can enumerate previous invocations, reconstruct user "
                f"activity, and identify sensitive targets for follow-on attacks."
                f"{amplifier_note}"
            ),
            suggested_policy=f"require_approval:\n  - {tool.tool.name}",
        )
    ]


# ---------------------------------------------------------------------------
# SSRF via URL-accepting parameters — Issue #406 gap 2
# ---------------------------------------------------------------------------

# Parameter names (lowercased, exact or substring) that signal URL input.
_URL_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "uri", "endpoint", "target_url", "fetch_url", "source_url",
    "webhook_url", "base_url", "callback_url", "redirect_url",
    "request_url", "remote_url", "href", "location",
})

# Substrings: if a parameter name contains any of these, it may accept a URL.
_URL_PARAM_SUBSTRINGS: tuple[str, ...] = ("url", "uri", "endpoint")

# Keywords in a parameter's *description* that imply URL input.
_URL_DESC_SIGNALS: tuple[str, ...] = (
    "http://", "https://", "url", "endpoint", "web address", "remote address",
    "network address",
)

# Phrases in a parameter's description that suggest an allowlist is enforced.
_ALLOWLIST_PHRASES: tuple[str, ...] = (
    "allowlist", "allowlisted", "allow-list",
    "whitelist", "whitelisted", "white-list",
    "restricted to", "only from", "must match", "approved domain",
    "approved host", "must be https://",
)


def _check_ssrf_risk(
    server: ServerPermissionMap, tool: ToolPermission
) -> list[Recommendation]:
    """Flag tools whose input schema accepts arbitrary URLs without an allowlist.

    An unconstrained URL parameter lets an attacker route requests to internal
    services (SSRF), cloud metadata endpoints, or other unexposed infrastructure.
    Checks both string URL parameters and boolean ``isUrl``-style flags that
    enable URL-fetching on another parameter.
    """
    schema = tool.tool.input_schema
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return []

    flagged_params: list[str] = []

    for prop_name, prop_schema in properties.items():
        prop_lower = prop_name.lower()
        prop_desc = ""
        if isinstance(prop_schema, dict):
            prop_desc = (prop_schema.get("description") or "").lower()
        prop_type = prop_schema.get("type", "") if isinstance(prop_schema, dict) else ""

        # Detect URL-accepting parameters:
        # 1. Exact match against known URL param names
        # 2. Name contains a URL-related substring
        # 3. Boolean "isUrl"-style flag (e.g. isUrl, is_url)
        # 4. Description explicitly mentions URL/endpoint
        is_url_param = (
            prop_lower in _URL_PARAM_NAMES
            or any(sub in prop_lower for sub in _URL_PARAM_SUBSTRINGS)
            or (
                prop_type == "boolean"
                and any(sub in prop_lower for sub in ("url", "uri"))
            )
            or any(sig in prop_desc for sig in _URL_DESC_SIGNALS)
        )
        if not is_url_param:
            continue

        # Skip if the description signals an allowlist is enforced.
        if any(phrase in prop_desc for phrase in _ALLOWLIST_PHRASES):
            continue

        flagged_params.append(prop_name)

    if not flagged_params:
        return []

    params_str = ", ".join(f"'{p}'" for p in flagged_params)
    return [
        Recommendation(
            severity=RecommendationSeverity.WARNING,
            target=f"{server.server.name}/{tool.tool.name}",
            message=(
                f"Tool '{tool.tool.name}' accepts URL parameter(s) ({params_str}) "
                f"with no allowlist constraint. An attacker can direct requests to "
                f"internal services, cloud metadata endpoints (169.254.169.254), or "
                f"other unexposed infrastructure (SSRF risk)."
            ),
            suggested_policy=(
                f"skills:\n"
                f"  {server.server.name}:\n"
                f"    network:\n"
                f"      outbound: false"
            ),
        )
    ]


# ---------------------------------------------------------------------------
# readOnlyHint=true as silent-exfil amplifier — Issue #406 gap 3
# ---------------------------------------------------------------------------

# Risk levels ordered from lowest to highest (used for index comparison).
_RISK_ORDER: list[RiskLevel] = [
    RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL
]


def _check_read_only_hint_amplifier(
    server: ServerPermissionMap, tool: ToolPermission
) -> list[Recommendation]:
    """Flag HIGH/CRITICAL risk tools that carry readOnlyHint=true.

    ``readOnlyHint: true`` is an MCP protocol annotation that many clients
    interpret as a license to auto-approve the call without asking the user.
    When a tool with genuinely high-risk capability — credentials access,
    network exfiltration surface, REPL injection, config mutation — carries
    this flag, an attacker can exploit it completely silently.

    This check escalates the effective severity by one level: a tool that
    would normally require a WARNING becomes CRITICAL because the approval
    gate has been removed.
    """
    if tool.tool.annotations is None or tool.tool.annotations.read_only_hint is not True:
        return []

    if _RISK_ORDER.index(tool.risk_level) < _RISK_ORDER.index(RiskLevel.HIGH):
        return []  # Only warn for genuinely high-risk tools

    return [
        Recommendation(
            severity=RecommendationSeverity.CRITICAL,
            target=f"{server.server.name}/{tool.tool.name}",
            message=(
                f"Tool '{tool.tool.name}' is rated {tool.risk_level.value} risk "
                f"but carries readOnlyHint=true. Many MCP clients auto-approve "
                f"read-only tools without user confirmation, removing the approval "
                f"gate from a high-risk operation and enabling silent exfiltration. "
                f"Add explicit approval or block this tool."
            ),
            suggested_policy=f"require_approval:\n  - {tool.tool.name}",
        )
    ]


# ---------------------------------------------------------------------------
# Write-then-reconfigure persistence chain — Issue #406 gap 5
# (per-server check — cross-tool on the same server)
# ---------------------------------------------------------------------------

# Regex patterns on tool names that indicate runtime config modification.
_CONFIG_WRITE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bset[_\-.]*(config|shell|interpreter|setting|preference)\b", re.IGNORECASE),
    re.compile(r"\b(update|modify|change|configure)[_\-.]*"
               r"(config|shell|interpreter|setting|preference)\b", re.IGNORECASE),
    re.compile(r"\bset[_\-.]config[_\-.]value\b", re.IGNORECASE),
]

# Phrases in a tool description that confirm shell/interpreter path manipulation.
_CONFIG_DESC_SIGNALS: tuple[str, ...] = (
    "default shell", "shell path", "interpreter path", "config value",
    "defaultshell", "shellpath", "interpreterpath",
    "sets the shell", "set the shell", "shell used",
)


def _check_write_reconfigure_chain(
    server: ServerPermissionMap,
) -> list[Recommendation]:
    """Detect write-then-reconfigure persistence attack paths.

    Flags servers where one tool can write arbitrary files AND another can
    mutate runtime configuration (e.g. defaultShell, shell_path).  An attacker
    can write a malicious binary then reconfigure the shell to point to it,
    achieving persistent code execution across restarts.

    This check complements the cross-server chain rule in chains.py by
    surfacing the pattern at the intra-server level with a concrete policy fix.
    """
    # Collect tools with filesystem write capability
    file_write_tools = [
        t for t in server.tools
        if any(a.type == DataAccessType.FILESYSTEM and a.write for a in t.data_access)
    ]
    if not file_write_tools:
        return []

    # Collect tools that can mutate runtime configuration
    config_write_tools: list[str] = []
    for t in server.tools:
        name_lower = t.tool.name.lower()
        desc_lower = (t.tool.description or "").lower()

        has_runtime_config_access = any(
            a.type == DataAccessType.RUNTIME_CONFIG for a in t.data_access
        )
        name_match = any(p.search(name_lower) for p in _CONFIG_WRITE_PATTERNS)
        desc_match = any(sig in desc_lower for sig in _CONFIG_DESC_SIGNALS)

        if has_runtime_config_access or name_match or desc_match:
            config_write_tools.append(t.tool.name)

    if not config_write_tools:
        return []

    file_names = ", ".join(f"'{t.tool.name}'" for t in file_write_tools[:3])
    cfg_names = ", ".join(f"'{n}'" for n in config_write_tools[:3])

    return [
        Recommendation(
            severity=RecommendationSeverity.CRITICAL,
            target=server.server.name,
            message=(
                f"Server '{server.server.name}' combines arbitrary file write "
                f"({file_names}) with runtime config modification ({cfg_names}). "
                f"An attacker can write a malicious executable then reconfigure the "
                f"default shell or interpreter to point to it, achieving persistent "
                f"compromise that survives process restarts."
            ),
            suggested_policy=(
                f"require_approval:\n"
                f"  - {config_write_tools[0]}\n"
                f"  - {file_write_tools[0].tool.name}"
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
