"""Tests for the EU AI Act (Reg. 2024/1689) compliance framework."""

from __future__ import annotations

from pathlib import Path

from agentward.comply.controls import (
    ComplianceRating,
    ControlSeverity,
    apply_fixes,
    evaluate_compliance,
)
from agentward.comply.frameworks import available_frameworks, get_framework
from agentward.comply.frameworks.eu_ai_act import EU_AI_ACT_CONTROLS
from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalRule,
    AuditConfig,
    DefaultAction,
    ResourcePermissions,
    SensitiveContentConfig,
    SkillMetadata,
    SubcontractorEntry,
)
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
    return ToolInfo(name=name, description=name, input_schema={})


def _access(typ: DataAccessType, *, read: bool = True, write: bool = False) -> DataAccess:
    return DataAccess(type=typ, read=read, write=write, reason="t")


def _perm(name: str, accesses: list[DataAccess] | None = None) -> ToolPermission:
    return ToolPermission(
        tool=_tool(name),
        data_access=accesses or [],
        risk_level=RiskLevel.LOW,
        risk_reasons=["t"],
        is_destructive=False,
        is_read_only=True,
    )


def _server(name: str, tools: list[ToolPermission]) -> ServerPermissionMap:
    return ServerPermissionMap(
        server=ServerConfig(
            name=name, transport=TransportType.STDIO, command="t",
            client="t", source_file=Path("/tmp/t.json"),
        ),
        enumeration_method="live", tools=tools, overall_risk=RiskLevel.LOW,
    )


def _scan(*servers: ServerPermissionMap) -> ScanResult:
    return ScanResult(
        servers=list(servers), config_sources=[],
        scan_timestamp="2026-04-25T00:00:00Z",
    )


def _bare(**kwargs: object) -> AgentWardPolicy:
    fields: dict[str, object] = {"version": "1.0"}
    fields.update(kwargs)
    return AgentWardPolicy(**fields)


def _ids(report) -> list[str]:
    return [f.control_id for f in report.findings]


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_registered(self) -> None:
        assert "eu_ai_act" in available_frameworks()

    def test_get_returns_seven_controls(self) -> None:
        controls = get_framework("eu_ai_act")
        assert controls is EU_AI_ACT_CONTROLS
        assert len(controls) == 8

    def test_case_insensitive_lookup(self) -> None:
        assert get_framework("EU_AI_ACT") == EU_AI_ACT_CONTROLS
        assert get_framework("Eu_Ai_Act") == EU_AI_ACT_CONTROLS

    def test_control_ids_unique(self) -> None:
        ids = [c.control_id for c in EU_AI_ACT_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_control_ids_namespaced(self) -> None:
        for c in EU_AI_ACT_CONTROLS:
            assert c.control_id.startswith("eu-ai-act.")

    def test_severity_distribution(self) -> None:
        required = [c for c in EU_AI_ACT_CONTROLS if c.severity == ControlSeverity.REQUIRED]
        recommended = [c for c in EU_AI_ACT_CONTROLS if c.severity == ControlSeverity.RECOMMENDED]
        assert len(required) >= 4
        assert len(recommended) >= 2


# ---------------------------------------------------------------------------
# Art. 9 — Risk Management
# ---------------------------------------------------------------------------


class TestArt9RiskManagement:
    def test_default_allow_fails(self) -> None:
        policy = _bare(default_action=DefaultAction.ALLOW)
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art9-risk-management" in _ids(report)

    def test_default_block_passes(self) -> None:
        policy = _bare(default_action=DefaultAction.BLOCK)
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art9-risk-management" not in _ids(report)


# ---------------------------------------------------------------------------
# Art. 12 — Record-keeping
# ---------------------------------------------------------------------------


class TestArt12RecordKeeping:
    def test_default_path_passes(self) -> None:
        policy = _bare()  # syslog_path None == default JSONL-with-.syslog
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art12-record-keeping" not in _ids(report)

    def test_explicit_path_passes(self) -> None:
        policy = _bare(audit=AuditConfig(syslog_path="/var/log/agentward.syslog"))
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art12-record-keeping" not in _ids(report)

    def test_empty_string_path_fails(self) -> None:
        policy = _bare(audit=AuditConfig(syslog_path=""))
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art12-record-keeping" in _ids(report)


class TestArt12Detection:
    def test_disabled_fails(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(enabled=False))
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art12-detection" in _ids(report)

    def test_enabled_passes(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(
            enabled=True, patterns=["api_key"],
        ))
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art12-detection" not in _ids(report)


# ---------------------------------------------------------------------------
# Art. 13 — Transparency
# ---------------------------------------------------------------------------


class TestArt13Transparency:
    def test_registry_disabled_fails(self) -> None:
        policy = _bare(registry_check=False)
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art13-transparency" in _ids(report)

    def test_registry_enabled_passes(self) -> None:
        # registry_check defaults to True, so the bare policy passes
        policy = _bare()
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art13-transparency" not in _ids(report)


# ---------------------------------------------------------------------------
# Art. 14 — Human Oversight
# ---------------------------------------------------------------------------


class TestArt14WriteOversight:
    def test_write_capable_skill_fails(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        finds = [f for f in report.findings
                 if f.control_id == "eu-ai-act.art14-human-oversight-write"]
        assert len(finds) == 1
        assert finds[0].skill == "filesystem"

    def test_read_only_skill_passes(self) -> None:
        scan = _scan(_server("github", [
            _perm("read_repo", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art14-human-oversight-write" not in _ids(report)

    def test_write_with_approval_passes(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare(require_approval=[ApprovalRule(tool_name="filesystem")])
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art14-human-oversight-write" not in _ids(report)


class TestArt14NetworkOversight:
    def test_network_unrestricted_fails(self) -> None:
        scan = _scan(_server("api-bridge", [
            _perm("call", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        finds = [f for f in report.findings
                 if f.control_id == "eu-ai-act.art14-human-oversight-network"]
        assert len(finds) == 1
        assert finds[0].skill == "api-bridge"

    def test_network_with_block_passes(self) -> None:
        scan = _scan(_server("api-bridge", [
            _perm("call", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare(skills={
            "api-bridge": {
                "network": ResourcePermissions.model_construct(
                    denied=False, actions={"outbound": False}, filters={},
                ),
            },
        })
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art14-human-oversight-network" not in _ids(report)


# ---------------------------------------------------------------------------
# Art. 15 — Cybersecurity / baseline
# ---------------------------------------------------------------------------


class TestArt15Cybersecurity:
    def test_baseline_off_fails(self) -> None:
        policy = _bare(baseline_check=False)
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art15-cybersecurity" in _ids(report)

    def test_baseline_on_passes(self) -> None:
        policy = _bare(baseline_check=True)
        report = evaluate_compliance(policy, None, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art15-cybersecurity" not in _ids(report)


# ---------------------------------------------------------------------------
# Art. 25 — Provider chain & accountable owner
# ---------------------------------------------------------------------------


class TestArt25ProviderChain:
    def test_missing_metadata_fires(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        finds = [f for f in report.findings
                 if f.control_id == "eu-ai-act.art25-provider-chain"]
        assert len(finds) == 1
        assert finds[0].skill == "filesystem"
        assert finds[0].severity == ControlSeverity.RECOMMENDED
        # No auto-fix — operator must supply these facts
        assert finds[0].fix is None

    def test_owner_only_still_fires(self) -> None:
        scan = _scan(_server("filesystem", [_perm("read_file")]))
        policy = _bare(skill_metadata={
            "filesystem": SkillMetadata(owner="team@example.com"),
        })
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        ids = _ids(report)
        assert "eu-ai-act.art25-provider-chain" in ids

    def test_chain_only_still_fires(self) -> None:
        scan = _scan(_server("filesystem", [_perm("read_file")]))
        policy = _bare(skill_metadata={
            "filesystem": SkillMetadata(
                subcontractor_chain=[SubcontractorEntry(vendor="X", role="y")],
            ),
        })
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art25-provider-chain" in _ids(report)

    def test_owner_and_chain_passes(self) -> None:
        scan = _scan(_server("filesystem", [_perm("read_file")]))
        policy = _bare(skill_metadata={
            "filesystem": SkillMetadata(
                owner="team@example.com",
                subcontractor_chain=[SubcontractorEntry(vendor="X", role="y")],
            ),
        })
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert "eu-ai-act.art25-provider-chain" not in _ids(report)


# ---------------------------------------------------------------------------
# Auto-fix round trip
# ---------------------------------------------------------------------------


class TestAutoFix:
    def test_round_trip_resolves_required(self) -> None:
        scan = _scan(
            _server("filesystem", [
                _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
            ]),
            _server("api-bridge", [
                _perm("call", [_access(DataAccessType.NETWORK)]),
            ]),
        )
        policy = _bare()
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        fixed = apply_fixes(policy, report.findings)
        re_report = evaluate_compliance(fixed, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        required_remaining = [
            f for f in re_report.findings
            if f.severity == ControlSeverity.REQUIRED
        ]
        assert required_remaining == []


# ---------------------------------------------------------------------------
# Compliant baseline — every control passes
# ---------------------------------------------------------------------------


def _compliant_policy(skill: str = "filesystem") -> AgentWardPolicy:
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        baseline_check=True,
        registry_check=True,
        sensitive_content=SensitiveContentConfig(
            enabled=True, patterns=["api_key", "credit_card"],
        ),
        skills={
            skill: {
                skill: ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False, "delete": False},
                    filters={},
                ),
                "network": ResourcePermissions.model_construct(
                    denied=False, actions={"outbound": False}, filters={},
                ),
            },
        },
        require_approval=[ApprovalRule(tool_name=skill)],
        skill_metadata={
            skill: SkillMetadata(
                owner="platform-team@example.com",
                subcontractor_chain=[
                    SubcontractorEntry(vendor="Example Vendor", role="hosting"),
                ],
            ),
        },
    )


class TestCompliantBaseline:
    def test_all_required_pass(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [
                _access(DataAccessType.NETWORK),
                _access(DataAccessType.FILESYSTEM, write=True),
            ]),
        ]))
        policy = _compliant_policy()
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        required = [f for f in report.findings
                    if f.severity == ControlSeverity.REQUIRED]
        assert required == []

    def test_compliant_skill_rating_green(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [
                _access(DataAccessType.NETWORK),
                _access(DataAccessType.FILESYSTEM, write=True),
            ]),
        ]))
        policy = _compliant_policy()
        report = evaluate_compliance(policy, scan, EU_AI_ACT_CONTROLS, "eu_ai_act")
        assert report.skill_ratings.get("filesystem") == ComplianceRating.GREEN
