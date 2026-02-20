"""Tests for the policy generator module."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentward.configure.generator import (
    generate_policy,
    serialize_policy,
    write_policy,
    _infer_resource_key,
    _policy_to_dict,
)
from agentward.policy.loader import load_policy
from agentward.policy.schema import AgentWardPolicy, ChainingRule, ResourcePermissions
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
# Helpers
# ---------------------------------------------------------------------------


def _tool(name: str) -> ToolInfo:
    return ToolInfo(name=name, description=f"Tool: {name}", input_schema={})


def _perm(
    name: str,
    risk: RiskLevel = RiskLevel.LOW,
    access: list[DataAccess] | None = None,
    destructive: bool = False,
    read_only: bool = True,
) -> ToolPermission:
    return ToolPermission(
        tool=_tool(name),
        data_access=access or [],
        risk_level=risk,
        risk_reasons=["test"],
        is_destructive=destructive,
        is_read_only=read_only,
    )


def _access(
    typ: DataAccessType,
    read: bool = True,
    write: bool = False,
) -> DataAccess:
    return DataAccess(type=typ, read=read, write=write, reason="test")


def _server(
    name: str,
    tools: list[ToolPermission],
    risk: RiskLevel = RiskLevel.LOW,
) -> ServerPermissionMap:
    return ServerPermissionMap(
        server=ServerConfig(
            name=name,
            transport=TransportType.STDIO,
            command="test",
            client="test",
            source_file=Path("/tmp/test.json"),
        ),
        enumeration_method="live",
        tools=tools,
        overall_risk=risk,
    )


def _scan(*servers: ServerPermissionMap) -> ScanResult:
    return ScanResult(
        servers=list(servers),
        config_sources=[],
        scan_timestamp="2026-02-18T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# Tests: require_approval rules
# ---------------------------------------------------------------------------


class TestRequireApproval:
    def test_critical_risk_tool_requires_approval(self) -> None:
        tool = _perm("dangerous_tool", risk=RiskLevel.CRITICAL)
        scan = _scan(_server("s", [tool], RiskLevel.CRITICAL))
        policy = generate_policy(scan)
        assert "dangerous_tool" in policy.require_approval

    def test_shell_tool_requires_approval(self) -> None:
        tool = _perm(
            "run_command",
            risk=RiskLevel.CRITICAL,
            access=[_access(DataAccessType.SHELL, write=True)],
        )
        scan = _scan(_server("s", [tool], RiskLevel.CRITICAL))
        policy = generate_policy(scan)
        assert "run_command" in policy.require_approval

    def test_destructive_tool_requires_approval(self) -> None:
        tool = _perm("delete_file", risk=RiskLevel.HIGH, destructive=True)
        scan = _scan(_server("s", [tool], RiskLevel.HIGH))
        policy = generate_policy(scan)
        assert "delete_file" in policy.require_approval

    def test_low_risk_read_only_no_approval(self) -> None:
        tool = _perm("read_file", risk=RiskLevel.LOW, read_only=True)
        scan = _scan(_server("s", [tool]))
        policy = generate_policy(scan)
        assert "read_file" not in policy.require_approval

    def test_require_approval_deduplicates(self) -> None:
        """A tool that is both CRITICAL and destructive should appear once."""
        tool = _perm(
            "nuke",
            risk=RiskLevel.CRITICAL,
            access=[_access(DataAccessType.SHELL, write=True)],
            destructive=True,
        )
        scan = _scan(_server("s", [tool], RiskLevel.CRITICAL))
        policy = generate_policy(scan)
        assert policy.require_approval.count("nuke") == 1


# ---------------------------------------------------------------------------
# Tests: Skill resource restrictions
# ---------------------------------------------------------------------------


class TestSkillRestrictions:
    def test_email_write_restricted_to_read_only(self) -> None:
        tool = _perm(
            "gmail_send",
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.EMAIL, write=True)],
            read_only=False,
        )
        scan = _scan(_server("email-server", [tool], RiskLevel.HIGH))
        policy = generate_policy(scan)
        assert "email-server" in policy.skills
        # Should have a resource with read: true, send: false
        resources = policy.skills["email-server"]
        assert len(resources) > 0
        resource = next(iter(resources.values()))
        assert resource.actions.get("read") is True
        assert resource.actions.get("send") is False

    def test_messaging_write_restricted(self) -> None:
        tool = _perm(
            "slack_post",
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.MESSAGING, write=True)],
            read_only=False,
        )
        scan = _scan(_server("msg-server", [tool], RiskLevel.HIGH))
        policy = generate_policy(scan)
        assert "msg-server" in policy.skills
        resources = policy.skills["msg-server"]
        resource = next(iter(resources.values()))
        assert resource.actions.get("read") is True
        assert resource.actions.get("send") is False

    def test_filesystem_write_restricted_to_read_only(self) -> None:
        tool = _perm(
            "write_file",
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.FILESYSTEM, write=True)],
            read_only=False,
        )
        scan = _scan(_server("fs-server", [tool], RiskLevel.MEDIUM))
        policy = generate_policy(scan)
        assert "fs-server" in policy.skills
        resources = policy.skills["fs-server"]
        resource = next(iter(resources.values()))
        assert resource.actions.get("read") is True
        assert resource.actions.get("write") is False

    def test_read_only_tool_no_restriction(self) -> None:
        tool = _perm(
            "read_email",
            risk=RiskLevel.LOW,
            access=[_access(DataAccessType.EMAIL, read=True, write=False)],
            read_only=True,
        )
        scan = _scan(_server("email-server", [tool]))
        policy = generate_policy(scan)
        # Read-only email should NOT generate skill restrictions
        assert "email-server" not in policy.skills


# ---------------------------------------------------------------------------
# Tests: Network + credentials → outbound block
# ---------------------------------------------------------------------------


class TestNetworkCredentials:
    def test_network_plus_credentials_blocks_outbound(self) -> None:
        tools = [
            _perm(
                "fetch_url",
                risk=RiskLevel.HIGH,
                access=[_access(DataAccessType.NETWORK)],
            ),
            _perm(
                "get_secret",
                risk=RiskLevel.HIGH,
                access=[_access(DataAccessType.CREDENTIALS)],
            ),
        ]
        scan = _scan(_server("risky-server", tools, RiskLevel.HIGH))
        policy = generate_policy(scan)
        assert "risky-server" in policy.skills
        assert "network" in policy.skills["risky-server"]
        network_perms = policy.skills["risky-server"]["network"]
        assert network_perms.actions.get("outbound") is False

    def test_network_without_credentials_no_block(self) -> None:
        tool = _perm(
            "fetch_url",
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.NETWORK)],
        )
        scan = _scan(_server("net-server", [tool], RiskLevel.MEDIUM))
        policy = generate_policy(scan)
        # Should not have network outbound block
        if "net-server" in policy.skills:
            assert "network" not in policy.skills["net-server"]


# ---------------------------------------------------------------------------
# Tests: Cross-server chaining rules
# ---------------------------------------------------------------------------


class TestChainingRules:
    def test_email_plus_browser_generates_chaining_rule(self) -> None:
        email_server = _server(
            "email-srv",
            [_perm("read_email", access=[_access(DataAccessType.EMAIL)])],
        )
        browser_server = _server(
            "browser-srv",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        scan = _scan(email_server, browser_server)
        policy = generate_policy(scan)
        assert len(policy.skill_chaining) > 0
        sources = {r.source_skill for r in policy.skill_chaining}
        targets = {r.target_skill for r in policy.skill_chaining}
        assert "email-srv" in sources
        assert "browser-srv" in targets

    def test_data_plus_shell_generates_chaining_rule(self) -> None:
        data_server = _server(
            "data-srv",
            [_perm("read_db", access=[_access(DataAccessType.DATABASE)])],
        )
        shell_server = _server(
            "shell-srv",
            [_perm(
                "run_cmd",
                risk=RiskLevel.CRITICAL,
                access=[_access(DataAccessType.SHELL, write=True)],
            )],
            RiskLevel.CRITICAL,
        )
        scan = _scan(data_server, shell_server)
        policy = generate_policy(scan)
        assert len(policy.skill_chaining) > 0
        # data → shell chaining should be blocked
        rule_pairs = {(r.source_skill, r.target_skill) for r in policy.skill_chaining}
        assert ("data-srv", "shell-srv") in rule_pairs

    def test_no_chaining_for_single_server(self) -> None:
        scan = _scan(_server("only", [_perm("tool")]))
        policy = generate_policy(scan)
        assert len(policy.skill_chaining) == 0


# ---------------------------------------------------------------------------
# Tests: Policy structure and serialization
# ---------------------------------------------------------------------------


class TestPolicyStructure:
    def test_generated_policy_has_version(self) -> None:
        scan = _scan(_server("s", [_perm("t")]))
        policy = generate_policy(scan)
        assert policy.version == "1.0"

    def test_empty_scan_generates_minimal_policy(self) -> None:
        scan = _scan()
        policy = generate_policy(scan)
        assert policy.version == "1.0"
        assert policy.skills == {}
        assert policy.require_approval == []
        assert policy.skill_chaining == []

    def test_generated_policy_validates_as_agentward_policy(self) -> None:
        """The generated policy must be a valid AgentWardPolicy model."""
        tools = [
            _perm(
                "shell_exec",
                risk=RiskLevel.CRITICAL,
                access=[_access(DataAccessType.SHELL, write=True)],
                destructive=True,
            ),
            _perm(
                "gmail_send",
                risk=RiskLevel.HIGH,
                access=[_access(DataAccessType.EMAIL, write=True)],
                read_only=False,
            ),
        ]
        scan = _scan(_server("my-server", tools, RiskLevel.CRITICAL))
        policy = generate_policy(scan)

        # This should not raise
        assert isinstance(policy, AgentWardPolicy)
        assert policy.version
        assert len(policy.require_approval) > 0

    def test_serialized_yaml_is_parseable(self) -> None:
        tool = _perm(
            "delete_records",
            risk=RiskLevel.HIGH,
            destructive=True,
        )
        scan = _scan(_server("db-server", [tool], RiskLevel.HIGH))
        policy = generate_policy(scan)
        yaml_str = serialize_policy(policy)

        # Must be valid YAML
        parsed = yaml.safe_load(yaml_str)
        assert parsed["version"] == "1.0"
        assert "require_approval" in parsed

    def test_serialized_yaml_loads_as_policy(self, tmp_path: Path) -> None:
        """Generated YAML must round-trip through load_policy()."""
        tools = [
            _perm(
                "shell_runner",
                risk=RiskLevel.CRITICAL,
                access=[_access(DataAccessType.SHELL, write=True)],
            ),
            _perm(
                "gmail_draft",
                risk=RiskLevel.HIGH,
                access=[_access(DataAccessType.EMAIL, write=True)],
                read_only=False,
            ),
        ]
        email_server = _server("email-mgr", tools[:1], RiskLevel.CRITICAL)
        browser_server = _server(
            "browser-srv",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        scan = _scan(
            _server("my-server", tools, RiskLevel.CRITICAL),
            email_server,
            browser_server,
        )
        policy = generate_policy(scan)

        # Write to file
        out_path = tmp_path / "agentward.yaml"
        write_policy(policy, out_path)

        # Must load back without errors
        loaded = load_policy(out_path)
        assert loaded.version == "1.0"


# ---------------------------------------------------------------------------
# Tests: write_policy
# ---------------------------------------------------------------------------


class TestWritePolicy:
    def test_write_policy_creates_file(self, tmp_path: Path) -> None:
        scan = _scan(_server("s", [_perm("t")]))
        policy = generate_policy(scan)
        out = tmp_path / "test.yaml"
        write_policy(policy, out)
        assert out.exists()
        content = out.read_text()
        assert "version" in content
        assert "AgentWard Policy" in content  # header comment


# ---------------------------------------------------------------------------
# Tests: _infer_resource_key
# ---------------------------------------------------------------------------


class TestInferResourceKey:
    def test_extracts_service_name_from_tool(self) -> None:
        assert _infer_resource_key("gmail_send", "email") == "gmail"

    def test_skips_verb_parts(self) -> None:
        assert _infer_resource_key("send_email", "email") == "email"

    def test_fallback_to_default(self) -> None:
        assert _infer_resource_key("x", "fallback") == "fallback"

    def test_handles_hyphen_separator(self) -> None:
        assert _infer_resource_key("slack-post", "messaging") == "slack"

    def test_handles_dot_separator(self) -> None:
        assert _infer_resource_key("db.query", "database") == "db"


# ---------------------------------------------------------------------------
# Tests: _policy_to_dict
# ---------------------------------------------------------------------------


class TestPolicyToDict:
    def test_empty_policy_only_has_version(self) -> None:
        policy = AgentWardPolicy(version="1.0")
        d = _policy_to_dict(policy)
        assert d == {"version": "1.0"}

    def test_chaining_rules_as_strings(self) -> None:
        policy = AgentWardPolicy(
            version="1.0",
            skill_chaining=[
                ChainingRule(source_skill="a", target_skill="b"),
            ],
        )
        d = _policy_to_dict(policy)
        assert d["skill_chaining"] == ["a cannot trigger b"]

    def test_denied_resource_serialized(self) -> None:
        policy = AgentWardPolicy(
            version="1.0",
            skills={
                "server": {
                    "resource": ResourcePermissions(denied=True),
                },
            },
        )
        d = _policy_to_dict(policy)
        assert d["skills"]["server"]["resource"] == {"denied": True}
