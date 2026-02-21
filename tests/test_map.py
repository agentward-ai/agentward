"""Tests for the agentward map visualization module."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from agentward.map import (
    ChainEdge,
    MapData,
    ServerNode,
    ToolNode,
    build_map_data,
    render_json,
    render_mermaid,
    render_terminal,
    _sanitize_id,
)
from agentward.policy.engine import PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    ChainingRule,
    PolicyDecision,
    ResourcePermissions,
)
from agentward.scan.chains import ChainDetection, ChainRisk
from agentward.scan.config import ServerConfig, TransportType
from agentward.scan.enumerator import ToolInfo
from agentward.scan.permissions import (
    DataAccess,
    DataAccessType,
    RiskLevel,
    ScanResult,
    ServerPermissionMap,
    ToolPermission,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _tool(name: str, access_type: DataAccessType = DataAccessType.UNKNOWN,
          risk: RiskLevel = RiskLevel.LOW, read_only: bool = True,
          destructive: bool = False) -> ToolPermission:
    """Create a minimal ToolPermission for testing."""
    accesses = [DataAccess(type=access_type, read=True, write=not read_only,
                           reason="test")]
    return ToolPermission(
        tool=ToolInfo(name=name),
        data_access=accesses,
        risk_level=risk,
        risk_reasons=["test reason"],
        is_destructive=destructive,
        is_read_only=read_only,
    )


def _server(name: str, tools: list[ToolPermission],
            risk: RiskLevel = RiskLevel.LOW,
            client: str = "cursor") -> ServerPermissionMap:
    """Create a minimal ServerPermissionMap for testing."""
    return ServerPermissionMap(
        server=ServerConfig(
            name=name,
            transport=TransportType.STDIO,
            source_file=Path("/test/config.json"),
            client=client,
        ),
        enumeration_method="test",
        tools=tools,
        overall_risk=risk,
    )


def _scan(servers: list[ServerPermissionMap]) -> ScanResult:
    """Create a minimal ScanResult for testing."""
    return ScanResult(servers=servers)


def _chain(source: str, target: str,
           risk: ChainRisk = ChainRisk.HIGH) -> ChainDetection:
    """Create a minimal ChainDetection for testing."""
    return ChainDetection(
        source_server=source,
        target_server=target,
        risk=risk,
        label=f"{source} \u2192 {target}",
        description="Test chain description",
        attack_vector="Test attack vector",
    )


def _make_resource(**actions: bool) -> ResourcePermissions:
    """Create a ResourcePermissions bypassing the model_validator."""
    return ResourcePermissions.model_construct(
        denied=False,
        actions=dict(actions),
        filters={},
    )


def _policy_with_rules() -> AgentWardPolicy:
    """Create a test policy with specific rules."""
    return AgentWardPolicy(
        version="1.0",
        skills={
            "email-server": {
                "gmail": _make_resource(read=True, send=False),
            },
            "shell-server": {
                "shell": _make_resource(execute=False),
            },
        },
        skill_chaining=[
            ChainingRule(
                source_skill="email-server",
                target_skill="shell-server",
            ),
        ],
        require_approval=["run_command"],
    )


# ---------------------------------------------------------------------------
# TestBuildMapData
# ---------------------------------------------------------------------------


class TestBuildMapData:
    """Tests for build_map_data graph construction."""

    def test_no_policy_decisions_none(self) -> None:
        """Without policy engine, all policy_decision fields are None."""
        scan = _scan([
            _server("srv", [
                _tool("read_file", DataAccessType.FILESYSTEM),
                _tool("send_email", DataAccessType.EMAIL),
            ]),
        ])
        data = build_map_data(scan, [], policy_engine=None)

        assert not data.has_policy
        assert data.total_tools == 2
        for server in data.servers:
            for tool in server.tools:
                assert tool.policy_decision is None

    def test_with_policy_overlay(self) -> None:
        """With policy engine, tools get correct policy decisions."""
        scan = _scan([
            _server("email-server", [
                _tool("gmail_read", DataAccessType.EMAIL),
                _tool("gmail_send", DataAccessType.EMAIL),
            ]),
        ])
        policy = _policy_with_rules()
        engine = PolicyEngine(policy)

        data = build_map_data(scan, [], policy_engine=engine)

        assert data.has_policy
        tools_by_name = {t.name: t for s in data.servers for t in s.tools}
        assert tools_by_name["gmail_read"].policy_decision == PolicyDecision.ALLOW
        assert tools_by_name["gmail_send"].policy_decision == PolicyDecision.BLOCK

    def test_approval_counted(self) -> None:
        """Tools in require_approval get APPROVE decision."""
        scan = _scan([
            _server("shell-server", [
                _tool("run_command", DataAccessType.SHELL),
            ]),
        ])
        policy = _policy_with_rules()
        engine = PolicyEngine(policy)

        data = build_map_data(scan, [], policy_engine=engine)
        assert data.tools_approved == 1

    def test_chain_blocked_by_policy(self) -> None:
        """Chain edge gets is_blocked_by_policy when policy blocks it."""
        scan = _scan([
            _server("email-server", [_tool("gmail_read", DataAccessType.EMAIL)]),
            _server("shell-server", [_tool("run_cmd", DataAccessType.SHELL)]),
        ])
        chains = [_chain("email-server", "shell-server", ChainRisk.CRITICAL)]
        policy = _policy_with_rules()
        engine = PolicyEngine(policy)

        data = build_map_data(scan, chains, policy_engine=engine)

        assert len(data.chains) == 1
        assert data.chains[0].is_blocked_by_policy is True
        assert data.chains_blocked == 1

    def test_chain_unprotected(self) -> None:
        """Chain without matching policy rule is unprotected."""
        scan = _scan([
            _server("web-server", [_tool("browse", DataAccessType.BROWSER)]),
            _server("fs-server", [_tool("read_file", DataAccessType.FILESYSTEM)]),
        ])
        chains = [_chain("web-server", "fs-server")]
        policy = _policy_with_rules()
        engine = PolicyEngine(policy)

        data = build_map_data(scan, chains, policy_engine=engine)

        assert len(data.chains) == 1
        assert data.chains[0].is_blocked_by_policy is False
        assert data.chains_unprotected == 1

    def test_summary_stats(self) -> None:
        """Summary stats are computed correctly."""
        scan = _scan([
            _server("email-server", [
                _tool("gmail_read", DataAccessType.EMAIL),
                _tool("gmail_send", DataAccessType.EMAIL),
            ]),
            _server("shell-server", [
                _tool("run_command", DataAccessType.SHELL),
            ]),
        ])
        chains = [_chain("email-server", "shell-server")]
        policy = _policy_with_rules()
        engine = PolicyEngine(policy)

        data = build_map_data(scan, chains, policy_engine=engine)

        assert data.total_tools == 3
        assert data.tools_blocked == 1  # gmail_send
        assert data.tools_approved == 1  # run_command
        assert data.chains_blocked == 1

    def test_server_metadata_preserved(self) -> None:
        """Server transport and client metadata are preserved."""
        scan = _scan([
            _server("test-srv", [_tool("tool1")], client="claude_desktop"),
        ])
        data = build_map_data(scan, [])

        assert data.servers[0].name == "test-srv"
        assert data.servers[0].client == "claude_desktop"
        assert data.servers[0].transport == "stdio"


# ---------------------------------------------------------------------------
# TestRenderMermaid
# ---------------------------------------------------------------------------


class TestRenderMermaid:
    """Tests for Mermaid diagram generation."""

    def test_produces_valid_flowchart(self) -> None:
        """Output starts with 'flowchart' and has subgraph per server."""
        data = MapData(
            servers=[
                ServerNode(
                    name="email-server",
                    overall_risk=RiskLevel.HIGH,
                    tools=[ToolNode("gmail_read", RiskLevel.LOW, [DataAccessType.EMAIL],
                                    True, False)],
                ),
                ServerNode(
                    name="shell-server",
                    overall_risk=RiskLevel.CRITICAL,
                    tools=[ToolNode("run_cmd", RiskLevel.CRITICAL, [DataAccessType.SHELL],
                                    False, True)],
                ),
            ],
        )
        output = render_mermaid(data)

        assert output.startswith("flowchart LR")
        assert "subgraph srv_email_server" in output
        assert "subgraph srv_shell_server" in output
        assert "gmail_read" in output
        assert "run_cmd" in output

    def test_policy_classes_applied(self) -> None:
        """Blocked tools get 'blocked' class, approved get 'approved'."""
        data = MapData(
            servers=[
                ServerNode(
                    name="srv",
                    overall_risk=RiskLevel.HIGH,
                    tools=[
                        ToolNode("tool_a", RiskLevel.LOW, [DataAccessType.EMAIL],
                                 True, False, PolicyDecision.BLOCK),
                        ToolNode("tool_b", RiskLevel.MEDIUM, [DataAccessType.SHELL],
                                 False, False, PolicyDecision.APPROVE),
                        ToolNode("tool_c", RiskLevel.LOW, [DataAccessType.FILESYSTEM],
                                 True, False, PolicyDecision.ALLOW),
                    ],
                ),
            ],
            has_policy=True,
        )
        output = render_mermaid(data)

        assert "class t_srv_tool_a blocked" in output
        assert "class t_srv_tool_b approved" in output
        assert "class t_srv_tool_c low" in output

    def test_chain_edges_present(self) -> None:
        """Chain edges are rendered between subgraph IDs."""
        data = MapData(
            servers=[
                ServerNode("email-srv", RiskLevel.HIGH, []),
                ServerNode("shell-srv", RiskLevel.CRITICAL, []),
            ],
            chains=[
                ChainEdge("email-srv", "shell-srv", ChainRisk.CRITICAL,
                           "test chain"),
            ],
        )
        output = render_mermaid(data)

        assert "srv_email_srv" in output
        assert "srv_shell_srv" in output
        assert "CRITICAL" in output

    def test_blocked_chain_labeled(self) -> None:
        """Blocked chains show 'BLOCKED' in edge label."""
        data = MapData(
            servers=[],
            chains=[
                ChainEdge("a", "b", ChainRisk.HIGH, "desc",
                           is_blocked_by_policy=True),
            ],
            has_policy=True,
        )
        output = render_mermaid(data)
        assert "BLOCKED" in output

    def test_class_defs_present(self) -> None:
        """Class definitions for risk levels are always present."""
        data = MapData(servers=[], chains=[])
        output = render_mermaid(data)

        assert "classDef low" in output
        assert "classDef medium" in output
        assert "classDef high" in output
        assert "classDef critical" in output
        assert "classDef blocked" in output
        assert "classDef approved" in output


# ---------------------------------------------------------------------------
# TestSanitizeId
# ---------------------------------------------------------------------------


class TestSanitizeId:
    """Tests for Mermaid ID sanitization."""

    def test_alphanumeric_unchanged(self) -> None:
        assert _sanitize_id("server1") == "server1"

    def test_hyphens_replaced(self) -> None:
        assert _sanitize_id("email-server") == "email_server"

    def test_dots_replaced(self) -> None:
        assert _sanitize_id("com.example.server") == "com_example_server"

    def test_starts_with_number(self) -> None:
        result = _sanitize_id("123server")
        assert result[0].isalpha()

    def test_empty_string(self) -> None:
        assert _sanitize_id("") == "unnamed"

    def test_special_chars(self) -> None:
        result = _sanitize_id("@server/name")
        # @ → _, / → _, and _ doesn't start with alpha so n_ prefix added
        assert result == "n__server_name"


# ---------------------------------------------------------------------------
# TestRenderTerminal
# ---------------------------------------------------------------------------


class TestRenderTerminal:
    """Tests for rich terminal rendering (smoke tests)."""

    def _capture_console(self) -> tuple[Console, StringIO]:
        """Create a console that captures output to a string."""
        buf = StringIO()
        console = Console(file=buf, force_terminal=True, width=120)
        return console, buf

    def test_smoke_no_policy(self) -> None:
        """Render without policy does not raise."""
        data = MapData(
            servers=[
                ServerNode(
                    name="test-server",
                    overall_risk=RiskLevel.LOW,
                    tools=[
                        ToolNode("read_file", RiskLevel.LOW, [DataAccessType.FILESYSTEM],
                                 True, False),
                    ],
                ),
            ],
            total_tools=1,
        )
        console, buf = self._capture_console()
        render_terminal(data, console)
        output = buf.getvalue()
        # Tree header present
        assert "Permission Graph" in output
        # Server name appears in tree
        assert "test-server" in output
        assert "read_file" in output
        assert "low" in output.lower()

    def test_smoke_with_policy(self) -> None:
        """Render with policy overlay does not raise."""
        data = MapData(
            servers=[
                ServerNode(
                    name="email-server",
                    overall_risk=RiskLevel.HIGH,
                    tools=[
                        ToolNode("gmail_read", RiskLevel.LOW, [DataAccessType.EMAIL],
                                 True, False, PolicyDecision.ALLOW),
                        ToolNode("gmail_send", RiskLevel.HIGH, [DataAccessType.EMAIL],
                                 False, False, PolicyDecision.BLOCK),
                    ],
                ),
            ],
            chains=[
                ChainEdge("email-server", "shell-server", ChainRisk.CRITICAL,
                           "test desc", is_blocked_by_policy=True,
                           blocking_rule="email-server cannot trigger shell-server"),
            ],
            has_policy=True,
            total_tools=2,
            tools_blocked=1,
            tools_approved=0,
            chains_blocked=1,
            chains_unprotected=0,
        )
        console, buf = self._capture_console()
        render_terminal(data, console)
        output = buf.getvalue()
        assert "gmail_read" in output
        assert "gmail_send" in output
        assert "allowed" in output.lower()
        assert "blocked" in output.lower()

    def test_policy_markers_in_output(self) -> None:
        """BLOCKED and APPROVE markers appear in output."""
        data = MapData(
            servers=[
                ServerNode(
                    name="srv",
                    overall_risk=RiskLevel.HIGH,
                    tools=[
                        ToolNode("blocked_tool", RiskLevel.HIGH, [DataAccessType.SHELL],
                                 False, False, PolicyDecision.BLOCK),
                        ToolNode("gated_tool", RiskLevel.MEDIUM, [DataAccessType.EMAIL],
                                 False, False, PolicyDecision.APPROVE),
                    ],
                ),
            ],
            has_policy=True,
            total_tools=2,
            tools_blocked=1,
            tools_approved=1,
        )
        console, buf = self._capture_console()
        render_terminal(data, console)
        output = buf.getvalue()
        assert "BLOCKED" in output
        assert "APPROVE" in output

    def test_unprotected_chain_warning(self) -> None:
        """Unprotected chains show warning in protection summary."""
        data = MapData(
            servers=[],
            chains=[
                ChainEdge("a", "b", ChainRisk.HIGH, "desc"),
            ],
            has_policy=True,
            total_tools=0,
            chains_unprotected=1,
        )
        console, buf = self._capture_console()
        render_terminal(data, console)
        output = buf.getvalue()
        assert "unprotected" in output.lower()

    def test_empty_data(self) -> None:
        """Render with no servers or chains does not raise."""
        data = MapData()
        console, buf = self._capture_console()
        render_terminal(data, console)
        # Just verify it doesn't crash


# ---------------------------------------------------------------------------
# TestRenderJson
# ---------------------------------------------------------------------------


class TestRenderJson:
    """Tests for JSON output."""

    def test_round_trip(self) -> None:
        """JSON output parses back with json.loads."""
        data = MapData(
            servers=[
                ServerNode(
                    name="srv",
                    overall_risk=RiskLevel.LOW,
                    tools=[ToolNode("tool1", RiskLevel.LOW, [DataAccessType.FILESYSTEM],
                                    True, False)],
                ),
            ],
            total_tools=1,
        )
        output = render_json(data)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_structure(self) -> None:
        """JSON has expected top-level keys."""
        data = MapData(
            servers=[
                ServerNode("srv", RiskLevel.LOW, []),
            ],
            chains=[
                ChainEdge("a", "b", ChainRisk.HIGH, "desc"),
            ],
            has_policy=True,
            total_tools=0,
        )
        output = render_json(data)
        parsed = json.loads(output)

        assert "servers" in parsed
        assert "chains" in parsed
        assert "has_policy" in parsed
        assert "total_tools" in parsed
        assert parsed["has_policy"] is True

    def test_enum_values_serialized(self) -> None:
        """Enum values are serialized as strings, not objects."""
        data = MapData(
            servers=[
                ServerNode(
                    name="srv",
                    overall_risk=RiskLevel.CRITICAL,
                    tools=[ToolNode("t", RiskLevel.HIGH, [DataAccessType.SHELL],
                                    False, True, PolicyDecision.BLOCK)],
                ),
            ],
            has_policy=True,
        )
        output = render_json(data)
        parsed = json.loads(output)

        server = parsed["servers"][0]
        assert server["overall_risk"] == "CRITICAL"
        tool = server["tools"][0]
        assert tool["risk_level"] == "HIGH"
        assert tool["access_types"] == ["shell"]
        assert tool["policy_decision"] == "BLOCK"

    def test_chain_in_json(self) -> None:
        """Chains are properly serialized."""
        data = MapData(
            chains=[
                ChainEdge("src", "tgt", ChainRisk.CRITICAL, "desc",
                           is_blocked_by_policy=True, blocking_rule="rule text"),
            ],
        )
        output = render_json(data)
        parsed = json.loads(output)

        chain = parsed["chains"][0]
        assert chain["source"] == "src"
        assert chain["target"] == "tgt"
        assert chain["risk"] == "CRITICAL"
        assert chain["is_blocked_by_policy"] is True
        assert chain["blocking_rule"] == "rule text"


# ---------------------------------------------------------------------------
# Integration: build_map_data with fixture policy files
# ---------------------------------------------------------------------------


class TestBuildMapDataWithFixtures:
    """Integration tests using the test fixture policy files."""

    def test_full_policy_fixture(self) -> None:
        """Build map data with the full_policy.yaml fixture."""
        from agentward.policy.loader import load_policy

        policy = load_policy(_FIXTURE_DIR / "full_policy.yaml")
        engine = PolicyEngine(policy)

        scan = _scan([
            _server("email-manager", [
                _tool("gmail_read", DataAccessType.EMAIL),
                _tool("gmail_send", DataAccessType.EMAIL),
                _tool("gmail_delete", DataAccessType.EMAIL),
            ]),
            _server("web-researcher", [
                _tool("browser_navigate", DataAccessType.BROWSER),
            ]),
        ])
        chains = [_chain("email-manager", "web-researcher", ChainRisk.HIGH)]

        data = build_map_data(scan, chains, policy_engine=engine)

        assert data.has_policy
        assert data.total_tools == 4

        # gmail_read: allowed, gmail_send: blocked, gmail_delete: blocked
        tools = {t.name: t for s in data.servers for t in s.tools}
        assert tools["gmail_read"].policy_decision == PolicyDecision.ALLOW
        assert tools["gmail_send"].policy_decision == PolicyDecision.BLOCK

        # Chain email-manager → web-researcher should be blocked
        assert data.chains[0].is_blocked_by_policy is True
