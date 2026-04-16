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


# ---------------------------------------------------------------------------
# Issue #406 gap 4 — PROCESS_STDIN detection (REPL chain source)
# ---------------------------------------------------------------------------


class TestProcessStdinDetection:
    """Tests for PROCESS_STDIN DataAccessType classification."""

    def test_stdin_schema_property_detected(self) -> None:
        """Tool with 'stdin' schema property must get PROCESS_STDIN classification."""
        tool = _make_tool(
            "interact_with_process",
            description="Send input to a running process via its stdin",
            schema_props={
                "pid": {"type": "number"},
                "stdin": {"type": "string"},
            },
        )
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.PROCESS_STDIN in access_types, (
            "Tool with 'stdin' schema property must be classified as PROCESS_STDIN"
        )

    def test_interact_in_name_detected(self) -> None:
        """Tool named 'interact_with_process' must get PROCESS_STDIN via name."""
        tool = _make_tool("interact_with_process")
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.PROCESS_STDIN in access_types

    def test_interact_is_execute_verb(self) -> None:
        """'interact' must be treated as an execute-class verb (not read-only)."""
        tool = _make_tool("interact_with_process")
        perm = analyze_tool(tool)
        assert perm.is_read_only is False

    def test_process_stdin_risk_is_high(self) -> None:
        """PROCESS_STDIN access must produce at least HIGH risk."""
        tool = _make_tool(
            "interact_with_process",
            schema_props={"stdin": {"type": "string"}, "pid": {"type": "number"}},
        )
        perm = analyze_tool(tool)
        risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert risk_order.index(perm.risk_level.value) >= risk_order.index("HIGH"), (
            f"PROCESS_STDIN tool must be at least HIGH risk, got {perm.risk_level}"
        )

    def test_process_stdin_risk_reason_mentions_repl(self) -> None:
        from agentward.scan.permissions import DataAccess, compute_risk

        accesses = [DataAccess(type=DataAccessType.PROCESS_STDIN, read=False, write=True, reason="test")]
        risk, reasons = compute_risk("interact_with_process", accesses, None, False)
        assert risk.value in ("HIGH", "CRITICAL")
        combined = " ".join(reasons).lower()
        assert "stdin" in combined or "repl" in combined or "process" in combined

    def test_get_process_status_no_false_positive(self) -> None:
        """get_process_status with only 'pid' must NOT be classified as PROCESS_STDIN.

        'pid' alone is too ambiguous — it's used in status-read tools too.
        Only 'stdin' as a schema property should trigger PROCESS_STDIN.
        """
        tool = _make_tool(
            "get_process_status",
            schema_props={"pid": {"type": "number"}},
        )
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.PROCESS_STDIN not in access_types, (
            "get_process_status with only 'pid' must not be classified as PROCESS_STDIN"
        )

    def test_list_processes_no_false_positive(self) -> None:
        """list_processes with no stdin property must not get PROCESS_STDIN."""
        tool = _make_tool(
            "list_processes",
            schema_props={"filter": {"type": "string"}},
        )
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.PROCESS_STDIN not in access_types


# ---------------------------------------------------------------------------
# Issue #406 gap 5 — RUNTIME_CONFIG detection (persistence chain source)
# ---------------------------------------------------------------------------


class TestRuntimeConfigDetection:
    """Tests for RUNTIME_CONFIG DataAccessType classification."""

    def test_set_config_value_detected(self) -> None:
        """Desktop Commander's set_config_value must get RUNTIME_CONFIG classification."""
        tool = _make_tool(
            "set_config_value",
            description="Set a configuration key/value pair (e.g. defaultShell)",
            schema_props={
                "key": {"type": "string"},
                "value": {"type": "string"},
            },
        )
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.RUNTIME_CONFIG in access_types, (
            "set_config_value must be classified as RUNTIME_CONFIG"
        )

    def test_runtime_config_is_write(self) -> None:
        """RUNTIME_CONFIG access on set_config_value must be a write operation."""
        tool = _make_tool("set_config_value")
        perm = analyze_tool(tool)
        config_accesses = [a for a in perm.data_access if a.type == DataAccessType.RUNTIME_CONFIG]
        assert config_accesses
        assert any(a.write for a in config_accesses)

    def test_update_config_detected(self) -> None:
        tool = _make_tool("update_config", schema_props={"key": {"type": "string"}})
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.RUNTIME_CONFIG in access_types

    def test_default_shell_schema_property_detected(self) -> None:
        """Tool with 'default_shell' schema property must get RUNTIME_CONFIG."""
        tool = _make_tool(
            "configure_runtime",
            schema_props={"default_shell": {"type": "string"}},
        )
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.RUNTIME_CONFIG in access_types

    def test_runtime_config_risk_is_high(self) -> None:
        """RUNTIME_CONFIG write must produce at least HIGH risk."""
        tool = _make_tool("set_config_value")
        perm = analyze_tool(tool)
        risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert risk_order.index(perm.risk_level.value) >= risk_order.index("HIGH"), (
            f"set_config_value must be at least HIGH risk, got {perm.risk_level}"
        )

    def test_get_config_no_false_positive(self) -> None:
        """get_config (read verb) must NOT be classified as RUNTIME_CONFIG."""
        tool = _make_tool(
            "get_config",
            schema_props={"key": {"type": "string"}},
        )
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.RUNTIME_CONFIG not in access_types, (
            "get_config (read verb) must not be classified as RUNTIME_CONFIG"
        )

    def test_list_settings_no_false_positive(self) -> None:
        """list_settings (read verb) must NOT be classified as RUNTIME_CONFIG."""
        tool = _make_tool("list_settings")
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.RUNTIME_CONFIG not in access_types

    def test_show_config_no_false_positive(self) -> None:
        """show_config (read verb) must NOT be classified as RUNTIME_CONFIG."""
        tool = _make_tool("show_config")
        perm = analyze_tool(tool)
        access_types = {a.type for a in perm.data_access}
        assert DataAccessType.RUNTIME_CONFIG not in access_types


# ---------------------------------------------------------------------------
# Issue #406 gap 3 — readOnlyHint amplifier in compute_risk
# ---------------------------------------------------------------------------


class TestReadOnlyHintAmplifier:
    """Tests for readOnlyHint=true as silent-exfil amplifier signal in compute_risk."""

    def test_high_risk_tool_with_read_only_hint_gets_amplifier_reason(self) -> None:
        """compute_risk must add amplifier reason when readOnlyHint=true on HIGH+ tool."""
        from agentward.scan.permissions import DataAccess, compute_risk

        accesses = [
            DataAccess(type=DataAccessType.CREDENTIALS, read=True, write=False, reason="test"),
        ]
        annotations = ToolAnnotations(read_only_hint=True)
        risk, reasons = compute_risk("get_token", accesses, annotations, False)
        assert risk.value in ("HIGH", "CRITICAL")
        combined = " ".join(reasons).lower()
        assert "auto" in combined or "silent" in combined or "amplifier" in combined, (
            f"Expected amplifier reason in compute_risk output, got: {reasons}"
        )

    def test_low_risk_tool_with_read_only_hint_no_amplifier(self) -> None:
        """compute_risk must NOT add amplifier reason for LOW risk tools."""
        from agentward.scan.permissions import DataAccess, compute_risk

        accesses = [
            DataAccess(type=DataAccessType.FILESYSTEM, read=True, write=False, reason="test"),
        ]
        annotations = ToolAnnotations(read_only_hint=True)
        risk, reasons = compute_risk("read_file", accesses, annotations, False)
        assert risk == RiskLevel.LOW
        combined = " ".join(reasons).lower()
        assert "amplifier" not in combined
