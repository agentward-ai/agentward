"""Tests for the recommendation engine — new detection rules (Issue #406).

Covers:
  1. Session history exposure detection
  2. SSRF via URL-accepting parameters
  3. readOnlyHint=true as silent-exfil amplifier
  4. Write-then-reconfigure persistence chain (per-server)

Also verifies that known-safe server profiles do NOT trigger false positives.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentward.scan.chains import detect_chains
from agentward.scan.config import ServerConfig, TransportType
from agentward.scan.enumerator import ToolAnnotations, ToolInfo
from agentward.scan.permissions import (
    DataAccess,
    DataAccessType,
    RiskLevel,
    ScanResult,
    ServerPermissionMap,
    ToolPermission,
    analyze_tool,
)
from agentward.scan.recommendations import (
    Recommendation,
    RecommendationSeverity,
    generate_recommendations,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _server_config(name: str = "test-server") -> ServerConfig:
    return ServerConfig(
        name=name,
        transport=TransportType.STDIO,
        command="test",
        source_file=Path("/tmp/test.json"),
        client="test",
    )


def _make_tool_info(
    name: str,
    description: str | None = None,
    schema_props: dict[str, Any] | None = None,
    annotations: ToolAnnotations | None = None,
) -> ToolInfo:
    schema: dict[str, Any] = {}
    if schema_props:
        schema = {"type": "object", "properties": schema_props}
    return ToolInfo(
        name=name,
        description=description,
        input_schema=schema,
        annotations=annotations,
    )


def _tool_perm(
    name: str,
    description: str | None = None,
    schema_props: dict[str, Any] | None = None,
    annotations: ToolAnnotations | None = None,
    risk: RiskLevel = RiskLevel.LOW,
    access: list[DataAccess] | None = None,
    is_destructive: bool = False,
    is_read_only: bool = True,
) -> ToolPermission:
    return ToolPermission(
        tool=_make_tool_info(name, description, schema_props, annotations),
        data_access=access or [],
        risk_level=risk,
        risk_reasons=["test"],
        is_destructive=is_destructive,
        is_read_only=is_read_only,
    )


def _access(
    typ: DataAccessType,
    read: bool = True,
    write: bool = False,
) -> DataAccess:
    return DataAccess(type=typ, read=read, write=write, reason="test")


def _server_map(
    name: str,
    tools: list[ToolPermission],
    overall_risk: RiskLevel = RiskLevel.LOW,
) -> ServerPermissionMap:
    return ServerPermissionMap(
        server=_server_config(name),
        enumeration_method="live",
        tools=tools,
        overall_risk=overall_risk,
    )


def _scan(*servers: ServerPermissionMap) -> ScanResult:
    return ScanResult(
        servers=list(servers),
        config_sources=[],
        scan_timestamp="2026-04-16T00:00:00Z",
    )


def _recs(server: ServerPermissionMap) -> list[Recommendation]:
    return generate_recommendations(_scan(server))


# ---------------------------------------------------------------------------
# 1.  Session history exposure
# ---------------------------------------------------------------------------


class TestSessionHistoryExposure:
    """Verifies that session/call-history tools are flagged correctly."""

    def test_get_recent_tool_calls_flagged(self) -> None:
        """Desktop Commander's primary session history tool must be caught."""
        tool = _tool_perm("get_recent_tool_calls", description="Returns the N most recent tool calls")
        srv = _server_map("desktop-commander", [tool])
        recs = _recs(srv)

        targets = [r.target for r in recs]
        assert "desktop-commander/get_recent_tool_calls" in targets

    def test_get_recent_tool_calls_severity_is_warning(self) -> None:
        tool = _tool_perm("get_recent_tool_calls")
        srv = _server_map("dc", [tool])
        recs = _recs(srv)

        history_recs = [r for r in recs if "get_recent_tool_calls" in r.target]
        assert history_recs, "Expected at least one recommendation for the history tool"
        assert any(r.severity == RecommendationSeverity.WARNING for r in history_recs)

    def test_read_only_hint_escalates_to_critical(self) -> None:
        """readOnlyHint=true on a history tool must escalate to CRITICAL."""
        tool = _tool_perm(
            "get_recent_tool_calls",
            annotations=ToolAnnotations(read_only_hint=True),
        )
        srv = _server_map("dc", [tool])
        recs = _recs(srv)

        history_recs = [r for r in recs if "get_recent_tool_calls" in r.target]
        assert any(r.severity == RecommendationSeverity.CRITICAL for r in history_recs)

    def test_conversation_log_flagged(self) -> None:
        tool = _tool_perm("get_conversation_log")
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        assert any("conversation_log" in r.target for r in recs)

    def test_prior_calls_flagged(self) -> None:
        tool = _tool_perm("list_prior_calls")
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        assert any("prior_calls" in r.target for r in recs)

    def test_call_history_flagged(self) -> None:
        tool = _tool_perm("fetch_call_history")
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        assert any("call_history" in r.target for r in recs)

    def test_description_hit_flagged(self) -> None:
        """A tool whose description mentions tool call history must be flagged."""
        tool = _tool_perm(
            "diagnostics",
            description="Returns recent tool invocations from the session log",
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        assert any("diagnostics" in r.target for r in recs)

    def test_read_file_not_flagged(self) -> None:
        """An unrelated filesystem tool must not be flagged for session history."""
        tool = _tool_perm("read_file", description="Read a file from disk")
        srv = _server_map("fs", [tool])
        recs = _recs(srv)
        hist_recs = [r for r in recs if "recent" in r.message.lower() or "history" in r.message.lower()]
        # 'read_file' must not produce a session-history recommendation
        assert not any("read_file" in r.target for r in hist_recs)

    def test_suggested_policy_requires_approval(self) -> None:
        tool = _tool_perm("get_recent_tool_calls")
        srv = _server_map("dc", [tool])
        recs = _recs(srv)
        history_recs = [r for r in recs if "get_recent_tool_calls" in r.target
                        and r.suggested_policy]
        assert history_recs
        assert "require_approval" in history_recs[0].suggested_policy


# ---------------------------------------------------------------------------
# 2.  SSRF via URL-accepting parameters
# ---------------------------------------------------------------------------


class TestSsrfRisk:
    """Verifies SSRF detection on tools with unconstrained URL parameters."""

    def test_url_parameter_flagged(self) -> None:
        """A tool with an unconstrained 'url' parameter must be flagged."""
        tool = _tool_perm(
            "fetch_page",
            schema_props={"url": {"type": "string", "description": "Target URL"}},
        )
        srv = _server_map("fetcher", [tool])
        recs = _recs(srv)
        assert any("fetch_page" in r.target for r in recs)

    def test_read_file_is_url_parameter_flagged(self) -> None:
        """Desktop Commander's read_file with isUrl must be flagged for SSRF."""
        tool = _tool_perm(
            "read_file",
            schema_props={
                "path": {"type": "string"},
                "isUrl": {"type": "boolean", "description": "If true, treat path as URL"},
            },
        )
        srv = _server_map("desktop-commander", [tool])
        recs = _recs(srv)
        assert any("read_file" in r.target for r in recs), (
            "read_file with isUrl parameter must trigger SSRF recommendation"
        )

    def test_endpoint_parameter_flagged(self) -> None:
        tool = _tool_perm(
            "call_api",
            schema_props={"endpoint": {"type": "string"}},
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        assert any("call_api" in r.target for r in recs)

    def test_target_url_parameter_flagged(self) -> None:
        tool = _tool_perm(
            "proxy_request",
            schema_props={"target_url": {"type": "string"}},
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        assert any("proxy_request" in r.target for r in recs)

    def test_url_with_allowlist_not_flagged(self) -> None:
        """URL parameter with explicit allowlist in description must not be flagged."""
        tool = _tool_perm(
            "fetch_page",
            schema_props={
                "url": {
                    "type": "string",
                    "description": "URL to fetch — must be from an allowlisted domain",
                }
            },
        )
        srv = _server_map("fetcher", [tool])
        recs = _recs(srv)
        ssrf_recs = [r for r in recs if "fetch_page" in r.target and "SSRF" in r.message]
        assert not ssrf_recs, "URL param with allowlist description must not trigger SSRF"

    def test_url_with_whitelist_not_flagged(self) -> None:
        tool = _tool_perm(
            "fetch_page",
            schema_props={
                "url": {
                    "type": "string",
                    "description": "Must be whitelisted. Only approved domains.",
                }
            },
        )
        srv = _server_map("fetcher", [tool])
        recs = _recs(srv)
        ssrf_recs = [r for r in recs if "fetch_page" in r.target and "SSRF" in r.message]
        assert not ssrf_recs

    def test_path_parameter_without_url_semantics_not_flagged(self) -> None:
        """A plain 'path' property with no URL semantics must not trigger SSRF."""
        tool = _tool_perm(
            "read_file",
            schema_props={"path": {"type": "string", "description": "Local file path"}},
        )
        srv = _server_map("fs", [tool])
        recs = _recs(srv)
        ssrf_recs = [r for r in recs if "read_file" in r.target and "SSRF" in r.message]
        assert not ssrf_recs

    def test_ssrf_recommendation_mentions_internal_services(self) -> None:
        """SSRF recommendation message must mention internal services / SSRF."""
        tool = _tool_perm(
            "fetch_page",
            schema_props={"url": {"type": "string"}},
        )
        srv = _server_map("fetcher", [tool])
        recs = _recs(srv)
        ssrf_recs = [r for r in recs if "fetch_page" in r.target]
        assert ssrf_recs
        assert "SSRF" in ssrf_recs[0].message or "internal" in ssrf_recs[0].message.lower()


# ---------------------------------------------------------------------------
# 3.  readOnlyHint=true as silent-exfil amplifier
# ---------------------------------------------------------------------------


class TestReadOnlyHintAmplifier:
    """Verifies that HIGH/CRITICAL-risk tools with readOnlyHint=true are flagged."""

    def test_credentials_tool_with_read_only_hint_flagged(self) -> None:
        """A credentials-access tool that claims readOnlyHint=true must be CRITICAL."""
        tool = _tool_perm(
            "get_api_key",
            annotations=ToolAnnotations(read_only_hint=True),
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.CREDENTIALS)],
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        amp_recs = [r for r in recs if "get_api_key" in r.target
                    and r.severity == RecommendationSeverity.CRITICAL]
        assert amp_recs, "HIGH-risk tool with readOnlyHint=true must produce CRITICAL rec"

    def test_critical_risk_tool_with_read_only_hint_flagged(self) -> None:
        tool = _tool_perm(
            "read_credentials_store",
            annotations=ToolAnnotations(read_only_hint=True),
            risk=RiskLevel.CRITICAL,
            access=[
                _access(DataAccessType.CREDENTIALS),
                _access(DataAccessType.NETWORK),
            ],
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        amp_recs = [r for r in recs if "read_credentials_store" in r.target
                    and r.severity == RecommendationSeverity.CRITICAL]
        assert amp_recs

    def test_low_risk_tool_with_read_only_hint_not_flagged(self) -> None:
        """A LOW-risk tool with readOnlyHint=true must NOT produce an amplifier rec."""
        tool = _tool_perm(
            "list_todos",
            annotations=ToolAnnotations(read_only_hint=True),
            risk=RiskLevel.LOW,
            access=[_access(DataAccessType.FILESYSTEM)],
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        # No CRITICAL recommendation for this tool
        critical_recs = [r for r in recs if "list_todos" in r.target
                         and r.severity == RecommendationSeverity.CRITICAL]
        assert not critical_recs

    def test_medium_risk_tool_with_read_only_hint_not_flagged(self) -> None:
        """A MEDIUM-risk tool with readOnlyHint=true must NOT produce an amplifier rec."""
        tool = _tool_perm(
            "list_messages",
            annotations=ToolAnnotations(read_only_hint=True),
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.MESSAGING)],
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        critical_recs = [r for r in recs if "list_messages" in r.target
                         and r.severity == RecommendationSeverity.CRITICAL
                         and "readOnlyHint" in r.message]
        assert not critical_recs

    def test_amplifier_message_mentions_auto_approval(self) -> None:
        """Amplifier recommendation message must explain the auto-approval risk."""
        tool = _tool_perm(
            "get_secrets",
            annotations=ToolAnnotations(read_only_hint=True),
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.CREDENTIALS)],
        )
        srv = _server_map("srv", [tool])
        recs = _recs(srv)
        amp_recs = [r for r in recs if "get_secrets" in r.target
                    and "readOnlyHint" in r.message]
        assert amp_recs
        msg = amp_recs[0].message.lower()
        assert "auto-approv" in msg or "auto approv" in msg or "without user confirmation" in msg


# ---------------------------------------------------------------------------
# 4.  Write-then-reconfigure persistence chain
# ---------------------------------------------------------------------------


class TestWriteReconfigureChain:
    """Verifies persistence chain detection on servers with write + config tools."""

    def _write_file_perm(self) -> ToolPermission:
        return _tool_perm(
            "write_file",
            description="Write content to a file path",
            access=[_access(DataAccessType.FILESYSTEM, read=False, write=True)],
            is_read_only=False,
        )

    def _set_config_perm(self, name: str = "set_config_value") -> ToolPermission:
        return ToolPermission(
            tool=_make_tool_info(
                name,
                description="Set a configuration value (e.g. defaultShell)",
                schema_props={
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
            ),
            data_access=[_access(DataAccessType.RUNTIME_CONFIG, read=False, write=True)],
            risk_level=RiskLevel.HIGH,
            risk_reasons=["runtime config write"],
            is_destructive=False,
            is_read_only=False,
        )

    def test_desktop_commander_pattern_flagged(self) -> None:
        """write_file + set_config_value on same server must produce CRITICAL rec."""
        srv = _server_map(
            "desktop-commander",
            [self._write_file_perm(), self._set_config_perm()],
            RiskLevel.HIGH,
        )
        recs = _recs(srv)
        persist_recs = [r for r in recs if r.severity == RecommendationSeverity.CRITICAL
                        and r.target == "desktop-commander"]
        assert persist_recs, (
            "write_file + set_config_value on same server must produce CRITICAL "
            "persistence recommendation"
        )

    def test_persistence_message_mentions_shell_and_file(self) -> None:
        srv = _server_map(
            "dc",
            [self._write_file_perm(), self._set_config_perm()],
            RiskLevel.HIGH,
        )
        recs = _recs(srv)
        persist_recs = [r for r in recs if r.severity == RecommendationSeverity.CRITICAL
                        and r.target == "dc"]
        assert persist_recs
        msg = persist_recs[0].message.lower()
        assert "shell" in msg or "interpreter" in msg or "config" in msg
        assert "file" in msg or "write" in msg or "filesystem" in msg

    def test_no_config_tool_no_persistence_rec(self) -> None:
        """Server with only write_file but no config tool must not be flagged."""
        srv = _server_map(
            "plain-fs",
            [self._write_file_perm()],
        )
        recs = _recs(srv)
        persist_recs = [r for r in recs if r.severity == RecommendationSeverity.CRITICAL
                        and r.target == "plain-fs"
                        and ("shell" in r.message.lower() or "config" in r.message.lower())]
        assert not persist_recs

    def test_read_only_fs_tool_no_persistence_rec(self) -> None:
        """Server with read-only filesystem + config tool must not be flagged."""
        read_only_fs = _tool_perm(
            "read_file",
            access=[_access(DataAccessType.FILESYSTEM, read=True, write=False)],
            is_read_only=True,
        )
        srv = _server_map("srv", [read_only_fs, self._set_config_perm()])
        recs = _recs(srv)
        persist_recs = [r for r in recs if r.severity == RecommendationSeverity.CRITICAL
                        and r.target == "srv"
                        and "config" in r.message.lower() and "file" in r.message.lower()]
        assert not persist_recs

    def test_set_shell_config_description_detected(self) -> None:
        """Config tool detected via description ('default shell') even without RUNTIME_CONFIG type."""
        shell_config = _tool_perm(
            "configure_runtime",
            description="Sets the default shell used for process execution",
            access=[],
            is_read_only=False,
        )
        srv = _server_map("srv", [self._write_file_perm(), shell_config])
        recs = _recs(srv)
        persist_recs = [r for r in recs if r.severity == RecommendationSeverity.CRITICAL
                        and r.target == "srv"]
        assert persist_recs

    def test_suggested_policy_targets_config_tool(self) -> None:
        srv = _server_map(
            "dc",
            [self._write_file_perm(), self._set_config_perm()],
            RiskLevel.HIGH,
        )
        recs = _recs(srv)
        persist_recs = [r for r in recs if r.severity == RecommendationSeverity.CRITICAL
                        and r.target == "dc" and r.suggested_policy]
        assert persist_recs
        assert "require_approval" in persist_recs[0].suggested_policy


# ---------------------------------------------------------------------------
# 5.  False-positive guard — known-safe server profiles
# ---------------------------------------------------------------------------


class TestNoFalsePositivesOnBenignServers:
    """Verifies that the new rules do not fire on benign, well-known MCP servers."""

    def _github_server(self) -> ServerPermissionMap:
        """Simulated GitHub MCP server: code, network, some write."""
        tools = [
            _tool_perm("list_repos", risk=RiskLevel.LOW,
                       access=[_access(DataAccessType.CODE)], is_read_only=True),
            _tool_perm("get_file_contents", risk=RiskLevel.LOW,
                       access=[_access(DataAccessType.CODE),
                                _access(DataAccessType.FILESYSTEM)],
                       is_read_only=True),
            _tool_perm("create_issue", risk=RiskLevel.MEDIUM,
                       access=[_access(DataAccessType.CODE, write=True)],
                       is_read_only=False),
            _tool_perm("push_files", risk=RiskLevel.MEDIUM,
                       access=[_access(DataAccessType.CODE, write=True),
                                _access(DataAccessType.FILESYSTEM, write=True)],
                       is_read_only=False),
        ]
        return _server_map("github", tools, RiskLevel.MEDIUM)

    def _filesystem_reader_server(self) -> ServerPermissionMap:
        """Simulated read-only filesystem MCP server."""
        tools = [
            _tool_perm("read_file", risk=RiskLevel.LOW,
                       access=[_access(DataAccessType.FILESYSTEM)],
                       is_read_only=True),
            _tool_perm("list_directory", risk=RiskLevel.LOW,
                       access=[_access(DataAccessType.FILESYSTEM)],
                       is_read_only=True),
            _tool_perm("search_files", risk=RiskLevel.LOW,
                       access=[_access(DataAccessType.FILESYSTEM)],
                       is_read_only=True),
        ]
        return _server_map("filesystem", tools, RiskLevel.LOW)

    def _slack_server(self) -> ServerPermissionMap:
        """Simulated Slack messaging MCP server."""
        tools = [
            _tool_perm("list_channels", risk=RiskLevel.LOW,
                       access=[_access(DataAccessType.MESSAGING)],
                       is_read_only=True),
            _tool_perm("read_messages", risk=RiskLevel.MEDIUM,
                       access=[_access(DataAccessType.MESSAGING)],
                       is_read_only=True),
            _tool_perm("post_message", risk=RiskLevel.MEDIUM,
                       access=[_access(DataAccessType.MESSAGING, write=True)],
                       is_read_only=False),
        ]
        return _server_map("slack", tools, RiskLevel.MEDIUM)

    def _no_session_history_false_positive(self, server: ServerPermissionMap) -> None:
        recs = generate_recommendations(_scan(server))
        session_recs = [
            r for r in recs
            if "session" in r.message.lower() or
               "tool call" in r.message.lower() or
               "call history" in r.message.lower() or
               "invocation" in r.message.lower()
        ]
        assert not session_recs, (
            f"Server '{server.server.name}' produced spurious session-history "
            f"recommendations: {[r.message for r in session_recs]}"
        )

    def _no_ssrf_false_positive(self, server: ServerPermissionMap) -> None:
        recs = generate_recommendations(_scan(server))
        ssrf_recs = [r for r in recs if "SSRF" in r.message]
        assert not ssrf_recs, (
            f"Server '{server.server.name}' produced spurious SSRF "
            f"recommendations: {[r.message for r in ssrf_recs]}"
        )

    def _no_persistence_false_positive(self, server: ServerPermissionMap) -> None:
        recs = generate_recommendations(_scan(server))
        persist_recs = [
            r for r in recs
            if r.severity == RecommendationSeverity.CRITICAL
            and "config" in r.message.lower()
            and "file" in r.message.lower()
        ]
        assert not persist_recs, (
            f"Server '{server.server.name}' produced spurious persistence "
            f"recommendations: {[r.message for r in persist_recs]}"
        )

    def test_github_server_no_session_history(self) -> None:
        self._no_session_history_false_positive(self._github_server())

    def test_github_server_no_ssrf(self) -> None:
        self._no_ssrf_false_positive(self._github_server())

    def test_github_server_no_persistence(self) -> None:
        self._no_persistence_false_positive(self._github_server())

    def test_filesystem_reader_no_session_history(self) -> None:
        self._no_session_history_false_positive(self._filesystem_reader_server())

    def test_filesystem_reader_no_ssrf(self) -> None:
        self._no_ssrf_false_positive(self._filesystem_reader_server())

    def test_filesystem_reader_no_persistence(self) -> None:
        self._no_persistence_false_positive(self._filesystem_reader_server())

    def test_slack_server_no_session_history(self) -> None:
        self._no_session_history_false_positive(self._slack_server())

    def test_slack_server_no_ssrf(self) -> None:
        self._no_ssrf_false_positive(self._slack_server())

    def test_slack_server_no_persistence(self) -> None:
        self._no_persistence_false_positive(self._slack_server())


# ---------------------------------------------------------------------------
# 6.  End-to-end: Desktop Commander schema fixtures
# ---------------------------------------------------------------------------


class TestDesktopCommanderIssue406:
    """Regression tests: each finding from DesktopCommanderMCP issue #406 must
    be detected by the appropriate rule.

    These tests use realistic ToolPermission objects that reflect what the
    actual Desktop Commander MCP server exposes.
    """

    def _dc_server(self, tools: list[ToolPermission]) -> ServerPermissionMap:
        return _server_map("desktop-commander", tools, RiskLevel.CRITICAL)

    def test_finding_session_history_tool_flagged(self) -> None:
        """Issue #406 finding: get_recent_tool_calls exposes call history."""
        tool = _tool_perm(
            "get_recent_tool_calls",
            description="Returns the N most recent tool calls made in this session",
            annotations=ToolAnnotations(read_only_hint=True),
        )
        srv = self._dc_server([tool])
        recs = _recs(srv)
        hist_recs = [r for r in recs if "get_recent_tool_calls" in r.target]
        assert hist_recs, "get_recent_tool_calls must be flagged"
        # readOnlyHint=true → must escalate to CRITICAL
        assert any(r.severity == RecommendationSeverity.CRITICAL for r in hist_recs)

    def test_finding_read_file_isurl_ssrf(self) -> None:
        """Issue #406 finding: read_file with isUrl parameter has SSRF risk."""
        tool = _tool_perm(
            "read_file",
            description="Read file contents; if isUrl is true, fetch from URL",
            schema_props={
                "path": {"type": "string"},
                "isUrl": {
                    "type": "boolean",
                    "description": "If true, treats path as a URL and fetches it",
                },
            },
        )
        srv = self._dc_server([tool])
        recs = _recs(srv)
        ssrf_recs = [r for r in recs if "read_file" in r.target]
        assert ssrf_recs, "read_file with isUrl must be flagged for SSRF"

    def test_finding_write_plus_set_config_persistence(self) -> None:
        """Issue #406 finding: write_file + set_config_value enables persistence."""
        write_file = _tool_perm(
            "write_file",
            description="Write arbitrary content to any file path",
            access=[_access(DataAccessType.FILESYSTEM, read=False, write=True)],
            is_read_only=False,
        )
        set_config = ToolPermission(
            tool=_make_tool_info(
                "set_config_value",
                description="Set a configuration key/value pair (e.g. defaultShell)",
                schema_props={
                    "key": {"type": "string", "description": "Config key like defaultShell"},
                    "value": {"type": "string"},
                },
            ),
            data_access=[_access(DataAccessType.RUNTIME_CONFIG, read=False, write=True)],
            risk_level=RiskLevel.HIGH,
            risk_reasons=["runtime config write"],
            is_destructive=False,
            is_read_only=False,
        )
        srv = self._dc_server([write_file, set_config])
        recs = _recs(srv)
        persist_recs = [r for r in recs if r.severity == RecommendationSeverity.CRITICAL
                        and r.target == "desktop-commander"
                        and ("config" in r.message.lower() or "shell" in r.message.lower())]
        assert persist_recs, "write_file + set_config_value must produce persistence CRITICAL rec"
