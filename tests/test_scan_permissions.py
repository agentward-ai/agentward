"""Tests for permission map builder and risk rating engine."""

import pytest

from agentward.scan.enumerator import (
    EnumerationResult,
    ServerCapabilities,
    ToolAnnotations,
    ToolInfo,
)
from agentward.scan.config import ServerConfig, TransportType
from agentward.scan.permissions import (
    DataAccessType,
    RiskLevel,
    analyze_tool,
    build_permission_map,
    compute_risk,
)
from pathlib import Path


def _make_server(name: str = "test-server") -> ServerConfig:
    """Create a minimal ServerConfig for testing."""
    return ServerConfig(
        name=name,
        transport=TransportType.STDIO,
        command="test",
        source_file=Path("/test/config.json"),
        client="test",
    )


def _make_tool(
    name: str,
    description: str | None = None,
    schema_props: dict | None = None,
    annotations: ToolAnnotations | None = None,
) -> ToolInfo:
    """Create a ToolInfo for testing."""
    schema = {}
    if schema_props:
        schema = {"type": "object", "properties": schema_props}
    return ToolInfo(
        name=name,
        description=description,
        input_schema=schema,
        annotations=annotations,
    )


class TestToolNameAnalysis:
    """Tests for risk classification from tool names."""

    def test_read_file_is_low(self) -> None:
        tool = _make_tool("read_file")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.LOW
        assert perm.is_read_only is True

    def test_write_file_is_medium(self) -> None:
        tool = _make_tool("write_file")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.MEDIUM
        assert perm.is_read_only is False

    def test_delete_file_is_high(self) -> None:
        tool = _make_tool("delete_file")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.HIGH
        assert perm.is_destructive is True

    def test_run_shell_is_critical(self) -> None:
        tool = _make_tool("run_shell")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.CRITICAL

    def test_execute_command_is_critical(self) -> None:
        tool = _make_tool("execute_command")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.CRITICAL

    def test_list_directory_is_low(self) -> None:
        tool = _make_tool("list_directory")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.LOW

    def test_search_files_is_low(self) -> None:
        tool = _make_tool("search_files")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.LOW
        assert perm.is_read_only is True

    def test_create_issue_is_medium(self) -> None:
        tool = _make_tool("create_issue")
        perm = analyze_tool(tool)
        assert perm.risk_level == RiskLevel.MEDIUM
        assert perm.is_read_only is False

    def test_slack_post_message_is_medium(self) -> None:
        tool = _make_tool("slack_post_message")
        perm = analyze_tool(tool)
        # post is a write verb, messaging is detected
        assert perm.is_read_only is False


class TestDataAccessFromSchema:
    """Tests for data access detection from inputSchema properties."""

    def test_path_property_detects_filesystem(self) -> None:
        tool = _make_tool("my_tool", schema_props={"path": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.FILESYSTEM in access_types

    def test_url_property_detects_network(self) -> None:
        tool = _make_tool("my_tool", schema_props={"url": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.NETWORK in access_types

    def test_sql_property_detects_database(self) -> None:
        tool = _make_tool("my_tool", schema_props={"sql": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.DATABASE in access_types

    def test_token_property_detects_credentials(self) -> None:
        tool = _make_tool("my_tool", schema_props={"token": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.CREDENTIALS in access_types

    def test_command_property_detects_shell(self) -> None:
        tool = _make_tool("my_tool", schema_props={"command": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.SHELL in access_types

    def test_channel_id_detects_messaging(self) -> None:
        tool = _make_tool("my_tool", schema_props={"channel_id": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.MESSAGING in access_types

    def test_empty_schema_gives_unknown(self) -> None:
        tool = _make_tool("some_unknown_tool")
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.UNKNOWN in access_types


class TestAnnotationOverrides:
    """Tests for annotation overriding heuristic analysis."""

    def test_read_only_annotation_overrides_write_name(self) -> None:
        tool = _make_tool(
            "write_file",
            annotations=ToolAnnotations(read_only_hint=True),
        )
        perm = analyze_tool(tool)
        assert perm.is_read_only is True
        assert perm.is_destructive is False
        # Risk should be lower than without annotation
        assert perm.risk_level == RiskLevel.LOW

    def test_destructive_annotation_bumps_risk(self) -> None:
        tool = _make_tool(
            "update_record",
            annotations=ToolAnnotations(destructive_hint=True),
        )
        perm = analyze_tool(tool)
        assert perm.is_destructive is True
        assert perm.risk_level.value in ("HIGH", "CRITICAL")

    def test_no_annotations_uses_heuristics(self) -> None:
        tool = _make_tool("read_file")
        perm = analyze_tool(tool)
        assert perm.is_read_only is True
        assert perm.risk_level == RiskLevel.LOW


class TestComputeRisk:
    """Tests for the risk computation function."""

    def test_shell_is_critical(self) -> None:
        from agentward.scan.permissions import DataAccess

        accesses = [DataAccess(type=DataAccessType.SHELL, write=True, reason="test")]
        risk, reasons = compute_risk("exec_cmd", accesses, None, False)
        assert risk == RiskLevel.CRITICAL
        assert any("shell" in r.lower() for r in reasons)

    def test_network_plus_credentials_is_critical(self) -> None:
        from agentward.scan.permissions import DataAccess

        accesses = [
            DataAccess(type=DataAccessType.NETWORK, read=True, reason="test"),
            DataAccess(type=DataAccessType.CREDENTIALS, read=True, reason="test"),
        ]
        risk, reasons = compute_risk("fetch_with_token", accesses, None, False)
        assert risk == RiskLevel.CRITICAL
        assert any("exfiltration" in r.lower() for r in reasons)

    def test_read_only_is_low(self) -> None:
        from agentward.scan.permissions import DataAccess

        accesses = [DataAccess(type=DataAccessType.FILESYSTEM, read=True, write=False, reason="test")]
        risk, reasons = compute_risk("read_file", accesses, None, False)
        assert risk == RiskLevel.LOW

    def test_annotation_read_only_lowers_risk(self) -> None:
        from agentward.scan.permissions import DataAccess

        accesses = [DataAccess(type=DataAccessType.FILESYSTEM, read=True, write=False, reason="test")]
        annotations = ToolAnnotations(read_only_hint=True)
        risk, reasons = compute_risk("some_tool", accesses, annotations, False)
        assert risk == RiskLevel.LOW
        assert any("read-only" in r.lower() for r in reasons)


class TestBuildPermissionMap:
    """Tests for the full permission map builder."""

    def test_single_server_single_tool(self) -> None:
        server = _make_server()
        tool = _make_tool("read_file", schema_props={"path": {"type": "string"}})
        result = EnumerationResult(
            server=server,
            tools=[tool],
            capabilities=None,
            enumeration_method="live_stdio",
        )
        scan = build_permission_map([result])
        assert len(scan.servers) == 1
        assert len(scan.servers[0].tools) == 1
        assert scan.servers[0].tools[0].risk_level == RiskLevel.LOW

    def test_overall_risk_is_max(self) -> None:
        server = _make_server()
        tools = [
            _make_tool("read_file"),
            _make_tool("run_shell"),
        ]
        result = EnumerationResult(
            server=server,
            tools=tools,
            capabilities=None,
            enumeration_method="live_stdio",
        )
        scan = build_permission_map([result])
        assert scan.servers[0].overall_risk == RiskLevel.CRITICAL

    def test_failed_enumeration_has_warning(self) -> None:
        server = _make_server()
        result = EnumerationResult(
            server=server,
            tools=[],
            capabilities=None,
            enumeration_method="static_inference",
            error="Command not found: test",
        )
        scan = build_permission_map([result])
        assert scan.servers[0].warning is not None

    def test_empty_results(self) -> None:
        scan = build_permission_map([])
        assert len(scan.servers) == 0


class TestToolNameSplitting:
    """Tests for various tool name formats."""

    def test_underscore_separated(self) -> None:
        perm = analyze_tool(_make_tool("read_text_file"))
        assert perm.is_read_only is True
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.FILESYSTEM in access_types

    def test_hyphen_separated(self) -> None:
        perm = analyze_tool(_make_tool("delete-record"))
        assert perm.is_destructive is True

    def test_camel_case(self) -> None:
        perm = analyze_tool(_make_tool("readFile"))
        assert perm.is_read_only is True

    def test_dot_separated(self) -> None:
        perm = analyze_tool(_make_tool("fs.read"))
        assert perm.is_read_only is True


class TestSchemaWordBoundaryMatching:
    """Tests for word-boundary matching in schema property analysis.

    Substring matching like 'file' in 'profile' produces false positives.
    Word-boundary matching prevents this.
    """

    def test_file_does_not_match_profile(self) -> None:
        """'profile' should NOT trigger filesystem detection."""
        tool = _make_tool("update_profile", schema_props={"profile": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.FILESYSTEM not in access_types

    def test_file_matches_file_path(self) -> None:
        """'file_path' should still trigger filesystem detection."""
        tool = _make_tool("upload_tool", schema_props={"file_path": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.FILESYSTEM in access_types

    def test_host_does_not_match_ghost(self) -> None:
        """'ghost' should NOT trigger network detection."""
        tool = _make_tool("ghost_tool", schema_props={"ghost": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.NETWORK not in access_types

    def test_host_matches_host_name(self) -> None:
        """'host_name' should trigger network detection."""
        tool = _make_tool("connect_tool", schema_props={"host_name": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.NETWORK in access_types

    def test_exact_match_still_works(self) -> None:
        """Exact property name matches should still work."""
        tool = _make_tool("my_tool", schema_props={"file": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.FILESYSTEM in access_types
