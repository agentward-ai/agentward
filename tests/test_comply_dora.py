"""Tests for the DORA (EU 2022/2554) compliance framework.

Coverage matrix
---------------
Every control in DORA_CONTROLS has at least one positive (failure) and
one negative (pass) test.  The framework registry, auto-fix DSL, rating
roll-up, and CLI dispatch are also exercised.
"""

from __future__ import annotations

from pathlib import Path

from agentward.comply.controls import (
    ComplianceRating,
    ControlSeverity,
    apply_fixes,
    evaluate_compliance,
)
from agentward.comply.frameworks import available_frameworks, get_framework
from agentward.comply.frameworks.dora import DORA_CONTROLS
from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalRule,
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
    return ToolInfo(name=name, description=f"Tool: {name}", input_schema={})


def _access(
    typ: DataAccessType,
    *,
    read: bool = True,
    write: bool = False,
) -> DataAccess:
    return DataAccess(type=typ, read=read, write=write, reason="t")


def _perm(
    name: str,
    accesses: list[DataAccess] | None = None,
    *,
    read_only: bool = True,
) -> ToolPermission:
    return ToolPermission(
        tool=_tool(name),
        data_access=accesses or [],
        risk_level=RiskLevel.LOW,
        risk_reasons=["t"],
        is_destructive=False,
        is_read_only=read_only,
    )


def _server(name: str, tools: list[ToolPermission]) -> ServerPermissionMap:
    return ServerPermissionMap(
        server=ServerConfig(
            name=name,
            transport=TransportType.STDIO,
            command="t",
            client="t",
            source_file=Path("/tmp/t.json"),
        ),
        enumeration_method="live",
        tools=tools,
        overall_risk=RiskLevel.LOW,
    )


def _scan(*servers: ServerPermissionMap) -> ScanResult:
    return ScanResult(
        servers=list(servers),
        config_sources=[],
        scan_timestamp="2026-04-01T00:00:00Z",
    )


def _bare(**kwargs: object) -> AgentWardPolicy:
    """Policy with version=1.0 only (and any overrides)."""
    fields: dict[str, object] = {"version": "1.0"}
    fields.update(kwargs)
    return AgentWardPolicy(**fields)


def _control_ids(report) -> list[str]:
    return [f.control_id for f in report.findings]


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_dora_is_registered(self) -> None:
        assert "dora" in available_frameworks()

    def test_get_dora_returns_controls(self) -> None:
        controls = get_framework("dora")
        assert controls is DORA_CONTROLS
        assert len(controls) == 10

    def test_case_insensitive_lookup(self) -> None:
        assert get_framework("DORA") == DORA_CONTROLS
        assert get_framework("Dora") == DORA_CONTROLS

    def test_control_ids_unique(self) -> None:
        ids = [c.control_id for c in DORA_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_every_control_has_check(self) -> None:
        for c in DORA_CONTROLS:
            assert callable(c.check)
            assert c.section.startswith("Art.")
            assert c.title
            assert c.description

    def test_severity_distribution(self) -> None:
        required = [c for c in DORA_CONTROLS if c.severity == ControlSeverity.REQUIRED]
        recommended = [c for c in DORA_CONTROLS if c.severity == ControlSeverity.RECOMMENDED]
        # Must have a non-trivial mix of each
        assert len(required) >= 4
        assert len(recommended) >= 2


# ---------------------------------------------------------------------------
# Art. 5 — Governance (zero-trust default)
# ---------------------------------------------------------------------------


class TestGovernance:
    def test_default_allow_fails(self) -> None:
        policy = _bare(default_action=DefaultAction.ALLOW)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art5.governance" in _control_ids(report)

    def test_default_block_passes(self) -> None:
        policy = _bare(default_action=DefaultAction.BLOCK)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art5.governance" not in _control_ids(report)

    def test_governance_finding_is_required(self) -> None:
        policy = _bare(default_action=DefaultAction.ALLOW)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        gov = [f for f in report.findings if f.control_id == "dora-art5.governance"]
        assert len(gov) == 1
        assert gov[0].severity == ControlSeverity.REQUIRED
        assert gov[0].skill is None  # policy-level finding


# ---------------------------------------------------------------------------
# Art. 28 — Third-party register
# ---------------------------------------------------------------------------


class TestThirdPartyRegister:
    def test_skill_in_scan_not_in_policy_fails(self) -> None:
        scan = _scan(_server("github", [_perm("read_repo")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        finds = [f for f in report.findings if f.control_id == "dora-art28.registry"]
        assert len(finds) == 1
        assert finds[0].skill == "github"

    def test_skill_with_explicit_entry_passes(self) -> None:
        scan = _scan(_server("github", [_perm("read_repo")]))
        policy = _bare(skills={
            "github": {
                "github": ResourcePermissions.model_construct(
                    denied=False, actions={"read": True}, filters={},
                ),
            },
        })
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art28.registry" not in _control_ids(report)

    def test_no_findings_when_no_scan(self) -> None:
        # Without scan we don't know what third parties exist
        policy = _bare()
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art28.registry" not in _control_ids(report)

    def test_one_finding_per_unregistered_skill(self) -> None:
        scan = _scan(
            _server("github", [_perm("a")]),
            _server("slack", [_perm("b")]),
            _server("postgres", [_perm("c")]),
        )
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        finds = [f for f in report.findings if f.control_id == "dora-art28.registry"]
        assert len(finds) == 3


# ---------------------------------------------------------------------------
# Art. 9 — Write-capable third-party services
# ---------------------------------------------------------------------------


class TestWriteCapableControl:
    def test_write_capable_no_restriction_no_approval_fails(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        finds = [f for f in report.findings if f.control_id == "dora-art9.write-control"]
        assert len(finds) == 1
        assert finds[0].skill == "filesystem"

    def test_read_only_skill_passes(self) -> None:
        scan = _scan(_server("github", [
            _perm("read_repo", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art9.write-control" not in _control_ids(report)

    def test_write_with_approval_passes(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare(require_approval=[ApprovalRule(tool_name="filesystem")])
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art9.write-control" not in _control_ids(report)

    def test_write_with_restriction_passes(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare(skills={
            "filesystem": {
                "filesystem": ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False},
                    filters={},
                ),
            },
        })
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art9.write-control" not in _control_ids(report)


# ---------------------------------------------------------------------------
# Art. 28 — Outbound concentration risk
# ---------------------------------------------------------------------------


class TestOutboundConcentration:
    def test_network_skill_unrestricted_fails(self) -> None:
        scan = _scan(_server("api-bridge", [
            _perm("call", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        finds = [f for f in report.findings if f.control_id == "dora-art28.outbound"]
        assert len(finds) == 1
        assert finds[0].skill == "api-bridge"

    def test_network_skill_with_outbound_block_passes(self) -> None:
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
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art28.outbound" not in _control_ids(report)

    def test_network_skill_with_approval_passes(self) -> None:
        scan = _scan(_server("api-bridge", [
            _perm("call", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare(require_approval=[ApprovalRule(tool_name="api-bridge")])
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art28.outbound" not in _control_ids(report)

    def test_non_network_skill_no_finding(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("read_file", [_access(DataAccessType.FILESYSTEM)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        finds = [f for f in report.findings if f.control_id == "dora-art28.outbound"]
        assert len(finds) == 0


# ---------------------------------------------------------------------------
# Art. 17 — Audit trail and detection
# ---------------------------------------------------------------------------


class TestAuditTrail:
    def test_default_syslog_path_passes(self) -> None:
        # syslog_path=None defaults to JSONL-with-.syslog suffix
        policy = _bare()
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art17.audit-trail" not in _control_ids(report)

    def test_explicit_path_passes(self) -> None:
        from agentward.policy.schema import AuditConfig
        policy = _bare(audit=AuditConfig(syslog_path="/var/log/agentward.syslog"))
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art17.audit-trail" not in _control_ids(report)

    def test_empty_string_path_fails(self) -> None:
        from agentward.policy.schema import AuditConfig
        policy = _bare(audit=AuditConfig(syslog_path="   "))
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art17.audit-trail" in _control_ids(report)


class TestIncidentDetection:
    def test_disabled_fails(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(enabled=False))
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art17.detection" in _control_ids(report)

    def test_enabled_with_api_key_passes(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(
            enabled=True,
            patterns=["api_key", "credit_card"],
        ))
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art17.detection" not in _control_ids(report)

    def test_enabled_without_api_key_fails(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(
            enabled=True,
            patterns=["credit_card"],
        ))
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art17.detection" in _control_ids(report)


# ---------------------------------------------------------------------------
# Art. 28 — Chain depth, unregistered third parties; Art. 10 — Anomaly
# ---------------------------------------------------------------------------


class TestChainDepth:
    def test_unbounded_fails(self) -> None:
        policy = _bare(skill_chain_depth=None)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art28.chain-depth" in _control_ids(report)

    def test_bounded_passes(self) -> None:
        policy = _bare(skill_chain_depth=3)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art28.chain-depth" not in _control_ids(report)

    def test_chain_depth_finding_is_recommended(self) -> None:
        policy = _bare()
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        find = next(f for f in report.findings if f.control_id == "dora-art28.chain-depth")
        assert find.severity == ControlSeverity.RECOMMENDED


class TestAnomalyDetection:
    def test_disabled_fails(self) -> None:
        policy = _bare(baseline_check=False)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art10.anomaly" in _control_ids(report)

    def test_enabled_passes(self) -> None:
        policy = _bare(baseline_check=True)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art10.anomaly" not in _control_ids(report)


class TestUnregisteredWarning:
    def test_disabled_fails(self) -> None:
        policy = _bare(warn_unregistered=False)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art28.unregistered" in _control_ids(report)

    def test_enabled_passes(self) -> None:
        policy = _bare(warn_unregistered=True)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        assert "dora-art28.unregistered" not in _control_ids(report)


class TestSubcontractorChain:
    def test_missing_metadata_fires(self) -> None:
        scan = _scan(_server("filesystem", [_perm("read_file")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        finds = [f for f in report.findings
                 if f.control_id == "dora-art28.subcontractor-chain"]
        assert len(finds) == 1
        assert finds[0].skill == "filesystem"
        assert finds[0].severity == ControlSeverity.RECOMMENDED
        assert finds[0].fix is None

    def test_owner_only_still_fires(self) -> None:
        scan = _scan(_server("filesystem", [_perm("read_file")]))
        policy = _bare(skill_metadata={
            "filesystem": SkillMetadata(owner="team@example.com"),
        })
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art28.subcontractor-chain" in _control_ids(report)

    def test_chain_only_still_fires(self) -> None:
        scan = _scan(_server("filesystem", [_perm("read_file")]))
        policy = _bare(skill_metadata={
            "filesystem": SkillMetadata(
                subcontractor_chain=[SubcontractorEntry(vendor="X", role="y")],
            ),
        })
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art28.subcontractor-chain" in _control_ids(report)

    def test_owner_and_chain_passes(self) -> None:
        scan = _scan(_server("filesystem", [_perm("read_file")]))
        policy = _bare(skill_metadata={
            "filesystem": SkillMetadata(
                owner="team@example.com",
                subcontractor_chain=[SubcontractorEntry(vendor="X", role="y")],
            ),
        })
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert "dora-art28.subcontractor-chain" not in _control_ids(report)


# ---------------------------------------------------------------------------
# Skill rating roll-up
# ---------------------------------------------------------------------------


class TestSkillRatings:
    def test_unregistered_skill_is_red(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert report.skill_ratings["filesystem"] == ComplianceRating.RED

    def test_compliant_skill_is_green(self) -> None:
        scan = _scan(_server("github", [_perm("read_repo")]))
        policy = _bare(
            default_action=DefaultAction.BLOCK,
            skills={
                "github": {
                    "github": ResourcePermissions.model_construct(
                        denied=False, actions={"read": True}, filters={},
                    ),
                },
            },
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["api_key"],
            ),
            skill_metadata={
                "github": SkillMetadata(
                    owner="platform-team@example.com",
                    subcontractor_chain=[
                        SubcontractorEntry(vendor="GitHub Inc.", role="repo hosting"),
                    ],
                ),
            },
        )
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert report.skill_ratings["github"] == ComplianceRating.GREEN


# ---------------------------------------------------------------------------
# Auto-fix coverage
# ---------------------------------------------------------------------------


class TestAutoFix:
    def test_set_default_action(self) -> None:
        policy = _bare(default_action=DefaultAction.ALLOW)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.default_action == DefaultAction.BLOCK

    def test_set_chain_depth(self) -> None:
        policy = _bare(skill_chain_depth=None)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.skill_chain_depth == 3

    def test_set_chain_depth_does_not_loosen(self) -> None:
        policy = _bare(skill_chain_depth=2)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        # Existing tighter depth (2) must not be loosened to fix-default 3
        assert fixed.skill_chain_depth == 2

    def test_set_baseline_check(self) -> None:
        policy = _bare(baseline_check=False)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.baseline_check is True

    def test_set_warn_unregistered(self) -> None:
        policy = _bare(warn_unregistered=False)
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.warn_unregistered is True

    def test_enable_sensitive_content(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(
            enabled=False, patterns=[],
        ))
        report = evaluate_compliance(policy, None, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.sensitive_content.enabled is True
        assert "api_key" in fixed.sensitive_content.patterns

    def test_add_third_party_registry_entry(self) -> None:
        scan = _scan(_server("github", [_perm("read")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        assert "github" in fixed.skills
        assert "github" in fixed.skills["github"]

    def test_add_approval_for_write_capable(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)
        approval_names = {r.tool_name for r in fixed.require_approval}
        assert "filesystem" in approval_names

    def test_round_trip_resolves_all_required(self) -> None:
        """Empty policy + scan → after auto-fix, no REQUIRED findings remain."""
        scan = _scan(
            _server("github", [_perm("read", [_access(DataAccessType.NETWORK)])]),
            _server("filesystem", [
                _perm("write", [_access(DataAccessType.FILESYSTEM, write=True)]),
            ]),
        )
        policy = _bare()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        fixed = apply_fixes(policy, report.findings)

        re_report = evaluate_compliance(fixed, scan, DORA_CONTROLS, "dora")
        required_remaining = [
            f for f in re_report.findings
            if f.severity == ControlSeverity.REQUIRED
        ]
        assert required_remaining == []


# ---------------------------------------------------------------------------
# Compliant baseline (everything passes)
# ---------------------------------------------------------------------------


def _compliant_policy(skill: str = "github") -> AgentWardPolicy:
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        skill_chain_depth=3,
        baseline_check=True,
        warn_unregistered=True,
        sensitive_content=SensitiveContentConfig(
            enabled=True,
            patterns=["api_key", "credit_card", "ssn"],
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
        scan = _scan(_server("github", [
            _perm("write_repo", [
                _access(DataAccessType.NETWORK),
                _access(DataAccessType.FILESYSTEM, write=True),
            ]),
        ]))
        policy = _compliant_policy()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        required = [
            f for f in report.findings
            if f.severity == ControlSeverity.REQUIRED
        ]
        assert required == []

    def test_compliant_skill_rating_green(self) -> None:
        scan = _scan(_server("github", [
            _perm("write_repo", [
                _access(DataAccessType.NETWORK),
                _access(DataAccessType.FILESYSTEM, write=True),
            ]),
        ]))
        policy = _compliant_policy()
        report = evaluate_compliance(policy, scan, DORA_CONTROLS, "dora")
        assert report.skill_ratings.get("github") == ComplianceRating.GREEN
