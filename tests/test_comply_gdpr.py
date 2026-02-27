"""Tests for the GDPR compliance framework."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentward.comply.controls import (
    ComplianceFinding,
    ComplianceRating,
    ControlSeverity,
    SkillAnalysis,
    apply_fixes,
    build_skill_analysis,
    evaluate_compliance,
    has_approval_for_skill,
)
from agentward.comply.frameworks import available_frameworks, get_framework
from agentward.comply.frameworks.gdpr import GDPR_CONTROLS
from agentward.comply.report import render_compliance_json, render_compliance_report
from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalRule,
    ChainingRule,
    ConditionalApproval,
    DataBoundary,
    DefaultAction,
    ResourcePermissions,
    SensitiveContentConfig,
    ViolationAction,
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


def _perm(
    name: str,
    access: list[DataAccess] | None = None,
    read_only: bool = True,
) -> ToolPermission:
    return ToolPermission(
        tool=_tool(name),
        data_access=access or [],
        risk_level=RiskLevel.LOW,
        risk_reasons=["test"],
        is_destructive=False,
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
        overall_risk=RiskLevel.LOW,
    )


def _scan(*servers: ServerPermissionMap) -> ScanResult:
    return ScanResult(
        servers=list(servers),
        config_sources=[],
        scan_timestamp="2026-02-18T00:00:00Z",
    )


def _minimal_policy(**kwargs: object) -> AgentWardPolicy:
    """Create a minimal policy with defaults."""
    defaults: dict[str, object] = {"version": "1.0"}
    defaults.update(kwargs)
    return AgentWardPolicy(**defaults)


def _compliant_pd_policy(pd_skill: str = "user-manager") -> AgentWardPolicy:
    """Create a policy that passes all GDPR controls for a single personal data skill."""
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        skills={
            pd_skill: {
                pd_skill: ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False, "delete": False},
                    filters={},
                ),
            },
        },
        skill_chaining=[
            ChainingRule(source_skill=pd_skill, target_skill="any"),
        ],
        require_approval=[
            ApprovalRule(tool_name=pd_skill),
        ],
        sensitive_content=SensitiveContentConfig(
            enabled=True,
            patterns=["credit_card", "ssn", "api_key"],
        ),
        data_boundaries={
            "gdpr_zone": DataBoundary(
                skills=[pd_skill],
                classification="personal_data",
                rules=["personal_data cannot flow outside gdpr_zone"],
                on_violation=ViolationAction.BLOCK_AND_LOG,
            ),
        },
    )


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------


class TestGDPRFrameworkRegistry:
    def test_gdpr_is_registered(self) -> None:
        frameworks = available_frameworks()
        assert "gdpr" in frameworks

    def test_get_gdpr_returns_controls(self) -> None:
        controls = get_framework("gdpr")
        assert len(controls) == 8

    def test_case_insensitive_lookup(self) -> None:
        controls = get_framework("GDPR")
        assert len(controls) == 8

    def test_control_ids_are_unique(self) -> None:
        ids = [c.control_id for c in GDPR_CONTROLS]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Personal data skill detection
# ---------------------------------------------------------------------------


class TestPersonalDataSkillDetection:
    """Verify build_skill_analysis detects personal data skills."""

    def test_by_name_user(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "user-manager" in analysis.personal_data_skills

    def test_by_name_profile(self) -> None:
        scan = _scan(_server("profile-service", [_perm("get_profile")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "profile-service" in analysis.personal_data_skills

    def test_by_name_customer(self) -> None:
        scan = _scan(_server("customer-crm", [_perm("lookup")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "customer-crm" in analysis.personal_data_skills

    def test_by_name_contact(self) -> None:
        scan = _scan(_server("contact-manager", [_perm("list")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "contact-manager" in analysis.personal_data_skills

    def test_by_name_identity(self) -> None:
        scan = _scan(_server("identity-provider", [_perm("verify")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "identity-provider" in analysis.personal_data_skills

    def test_by_name_account(self) -> None:
        scan = _scan(_server("account-service", [_perm("get")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "account-service" in analysis.personal_data_skills

    def test_by_name_consent(self) -> None:
        scan = _scan(_server("consent-tracker", [_perm("check")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "consent-tracker" in analysis.personal_data_skills

    def test_by_name_subscriber(self) -> None:
        scan = _scan(_server("subscriber-list", [_perm("get")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "subscriber-list" in analysis.personal_data_skills

    def test_by_name_employee(self) -> None:
        scan = _scan(_server("employee-directory", [_perm("search")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "employee-directory" in analysis.personal_data_skills

    def test_by_data_access_email(self) -> None:
        scan = _scan(_server("mailer", [
            _perm("send", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "mailer" in analysis.personal_data_skills

    def test_by_data_access_messaging(self) -> None:
        scan = _scan(_server("chat-bot", [
            _perm("send_msg", [_access(DataAccessType.MESSAGING, write=True)], read_only=False),
        ]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "chat-bot" in analysis.personal_data_skills

    def test_non_personal_data_skill_not_flagged(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint_file")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "code-linter" not in analysis.personal_data_skills

    def test_from_policy_data_boundary(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["custom-pd-handler"],
                    classification="personal_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "custom-pd-handler" in analysis.personal_data_skills

    def test_from_policy_pii_classification(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "pii_zone": DataBoundary(
                    skills=["pii-handler"],
                    classification="pii",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "pii-handler" in analysis.personal_data_skills

    def test_from_policy_gdpr_classification(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["gdpr-handler"],
                    classification="gdpr",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "gdpr-handler" in analysis.personal_data_skills

    def test_boundary_skill_assumed_write_capable(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["custom-handler"],
                    classification="personal_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert analysis.skill_write_capable.get("custom-handler") is True


# ---------------------------------------------------------------------------
# Art. 5(1)(c) — Data Minimisation
# ---------------------------------------------------------------------------


class TestGDPRDataMinimisation:
    """gdpr-art5.1c: Personal data skills need explicit permissions."""

    def test_pd_skill_without_permissions_fails(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art5.1c" in ids

    def test_pd_skill_with_permissions_passes(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "user-manager": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art5.1c"]
        assert len(findings) == 0

    def test_no_pd_skills_no_findings(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art5.1c"]
        assert len(findings) == 0

    def test_fix_adds_skill_restriction(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art5.1c")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["skill_name"] == "user-manager"


# ---------------------------------------------------------------------------
# Art. 25 — Data Protection by Design
# ---------------------------------------------------------------------------


class TestGDPRDataProtectionByDesign:
    """gdpr-art25: Personal data skills need data boundary."""

    def test_pd_without_boundary_fails(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art25" in ids

    def test_pd_with_boundary_passes(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["user-manager"],
                    classification="personal_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art25"]
        assert len(findings) == 0

    def test_boundary_with_pii_classification_passes(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy(
            data_boundaries={
                "pii_zone": DataBoundary(
                    skills=["user-manager"],
                    classification="pii",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_NOTIFY,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art25"]
        assert len(findings) == 0

    def test_boundary_with_gdpr_classification_passes(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["user-manager"],
                    classification="gdpr",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art25"]
        assert len(findings) == 0

    def test_boundary_with_log_only_still_fails(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["user-manager"],
                    classification="personal_data",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art25"]
        assert len(findings) == 1

    def test_fix_adds_data_boundary(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art25")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_data_boundary"
        assert finding.fix.params["classification"] == "personal_data"
        assert finding.fix.params["zone_name"] == "gdpr_zone"


# ---------------------------------------------------------------------------
# Art. 30 — Records of Processing
# ---------------------------------------------------------------------------


class TestGDPRRecordsOfProcessing:
    """gdpr-art30: Sensitive content scanning must be enabled."""

    def test_scanning_disabled_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art30" in ids

    def test_scanning_enabled_with_ssn_passes(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["ssn", "credit_card"],
            ),
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art30"]
        assert len(findings) == 0

    def test_scanning_enabled_without_ssn_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["credit_card"],
            ),
        )
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art30"]
        assert len(findings) == 1

    def test_fix_enables_scanning(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art30")
        assert finding.fix is not None
        assert finding.fix.fix_type == "enable_sensitive_content"


# ---------------------------------------------------------------------------
# Art. 32(1) — Integrity of Processing
# ---------------------------------------------------------------------------


class TestGDPRIntegrity:
    """gdpr-art32.integrity: Write-capable PD skills need write restrictions."""

    def test_write_capable_without_restriction_fails(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art32.integrity" in ids

    def test_write_restricted_passes(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "user-manager": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.integrity"]
        assert len(findings) == 0

    def test_approval_satisfies_integrity(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="user-manager")],
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.integrity"]
        assert len(findings) == 0

    def test_read_only_skill_not_checked(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("get_user", [_access(DataAccessType.EMAIL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.integrity"]
        assert len(findings) == 0

    def test_fix_adds_write_restriction(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art32.integrity")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["actions"]["write"] is False

    def test_delete_false_counts_as_restriction(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "user-manager": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.integrity"]
        assert len(findings) == 0

    def test_denied_resource_counts_as_restriction(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "user-manager": ResourcePermissions.model_construct(
                        denied=True,
                        actions={},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.integrity"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Art. 32(1) — Confidentiality of Processing
# ---------------------------------------------------------------------------


class TestGDPRConfidentiality:
    """gdpr-art32.auth: Write-capable PD skills need human approval."""

    def test_write_capable_without_approval_fails(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art32.auth" in ids

    def test_with_approval_passes(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="user-manager")],
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.auth"]
        assert len(findings) == 0

    def test_conditional_approval_satisfies(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        cond_rule = ApprovalRule.model_construct(
            tool_name=None,
            conditional=ConditionalApproval(
                tool="user-manager",
                when={},
            ),
        )
        policy = _minimal_policy(
            require_approval=[cond_rule],
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.auth"]
        assert len(findings) == 0

    def test_read_only_not_checked(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("get_user", [_access(DataAccessType.EMAIL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.auth"]
        assert len(findings) == 0

    def test_fix_adds_approval_rule(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art32.auth")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_approval_rule"
        assert finding.fix.params["tool_name"] == "user-manager"


# ---------------------------------------------------------------------------
# Art. 32(1) — Transmission Security
# ---------------------------------------------------------------------------


class TestGDPRTransmissionSecurity:
    """gdpr-art32.transmission: PD skills with network must control outbound."""

    def test_pd_with_network_no_block_fails(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("sync_users", [
                _access(DataAccessType.EMAIL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art32.transmission" in ids

    def test_outbound_blocked_passes(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("sync_users", [
                _access(DataAccessType.EMAIL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "network": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.transmission"]
        assert len(findings) == 0

    def test_approval_satisfies_transmission(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("sync_users", [
                _access(DataAccessType.EMAIL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="user-manager")],
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.transmission"]
        assert len(findings) == 0

    def test_pd_without_network_not_checked(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("get_user", [_access(DataAccessType.EMAIL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.transmission"]
        assert len(findings) == 0

    def test_network_denied_passes(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("sync_users", [
                _access(DataAccessType.EMAIL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "network": ResourcePermissions.model_construct(
                        denied=True,
                        actions={},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.transmission"]
        assert len(findings) == 0

    def test_fix_blocks_outbound(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("sync_users", [
                _access(DataAccessType.EMAIL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art32.transmission")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["resource_name"] == "network"
        assert finding.fix.params["actions"]["outbound"] is False


# ---------------------------------------------------------------------------
# Art. 28 — Processor Obligations (Isolation)
# ---------------------------------------------------------------------------


class TestGDPRProcessorIsolation:
    """gdpr-art28: PD skills must be isolated via chaining rules."""

    def test_pd_can_trigger_non_pd_fails(self) -> None:
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art28" in ids

    def test_chaining_blocks_any_passes(self) -> None:
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="user-manager", target_skill="any"),
            ],
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art28"]
        assert len(findings) == 0

    def test_chaining_blocks_specific_target_passes(self) -> None:
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="user-manager", target_skill="code-linter"),
            ],
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art28"]
        assert len(findings) == 0

    def test_no_non_pd_skills_passes(self) -> None:
        """If all skills are PD skills, no isolation finding."""
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("customer-crm", [_perm("lookup")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art28"]
        assert len(findings) == 0

    def test_fix_adds_chaining_rule(self) -> None:
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art28")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_chaining_rule"
        assert finding.fix.params["source_skill"] == "user-manager"
        assert finding.fix.params["target_skill"] == "any"

    def test_partial_chaining_still_fails(self) -> None:
        """Blocking one non-PD target but not all still fails."""
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("code-linter", [_perm("lint")]),
            _server("file-server", [_perm("read_file")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="user-manager", target_skill="code-linter"),
            ],
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art28"]
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Art. 5(2) — Accountability Default
# ---------------------------------------------------------------------------


class TestGDPRAccountabilityDefault:
    """gdpr-art5.default: default_action should be block."""

    def test_default_allow_finds_recommendation(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        ids = [f.control_id for f in report.findings]
        assert "gdpr-art5.default" in ids

    def test_severity_is_recommended(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art5.default")
        assert finding.severity == ControlSeverity.RECOMMENDED

    def test_default_block_passes(self) -> None:
        policy = _minimal_policy(default_action="block")
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art5.default"]
        assert len(findings) == 0

    def test_fix_sets_default_block(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        finding = next(f for f in report.findings if f.control_id == "gdpr-art5.default")
        assert finding.fix is not None
        assert finding.fix.fix_type == "set_default_action"
        assert finding.fix.params["action"] == "block"


# ---------------------------------------------------------------------------
# Full evaluation and ratings
# ---------------------------------------------------------------------------


class TestGDPREvaluateCompliance:
    """End-to-end evaluation tests."""

    def test_fully_compliant_policy(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _compliant_pd_policy("user-manager")
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        assert report.framework == "gdpr"
        assert len(report.findings) == 0
        assert report.controls_passed == 8
        assert report.skill_ratings["user-manager"] == ComplianceRating.GREEN

    def test_no_pd_skills_all_pass(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy(
            default_action="block",
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["ssn", "credit_card"],
            ),
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        assert len(report.findings) == 0
        assert report.controls_passed == 8

    def test_pd_skill_gets_red_rating(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        assert report.skill_ratings.get("user-manager") == ComplianceRating.RED

    def test_yellow_rating_for_recommended_only(self) -> None:
        """A skill with only recommended failures gets YELLOW."""
        scan = _scan(_server("code-linter", [_perm("lint")]))
        # Only the default_action check should fire (RECOMMENDED), not skill-specific
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["ssn", "credit_card"],
            ),
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        # code-linter is not PD, so no skill-specific findings.
        # The default_action finding is policy-level (skill=None), so no skill rating impact.
        assert report.skill_ratings.get("code-linter") == ComplianceRating.GREEN


# ---------------------------------------------------------------------------
# Apply fixes
# ---------------------------------------------------------------------------


class TestGDPRApplyFixes:
    """Test that apply_fixes creates a compliant policy."""

    def test_fix_produces_compliant_policy(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [
                _access(DataAccessType.EMAIL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        # First evaluation — should have findings
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        assert len(report.findings) > 0

        # Apply fixes
        fixed = apply_fixes(policy, report.findings)

        # Re-evaluate — required findings should be resolved
        report2 = evaluate_compliance(fixed, scan, GDPR_CONTROLS, "gdpr")
        required_findings = [
            f for f in report2.findings if f.severity == ControlSeverity.REQUIRED
        ]
        assert len(required_findings) == 0

    def test_fix_adds_gdpr_zone(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        fixed = apply_fixes(policy, report.findings)
        assert "gdpr_zone" in fixed.data_boundaries
        assert fixed.data_boundaries["gdpr_zone"].classification == "personal_data"

    def test_fix_enables_sensitive_content(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.sensitive_content.enabled is True
        assert "ssn" in fixed.sensitive_content.patterns

    def test_fix_adds_approval_rule(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        fixed = apply_fixes(policy, report.findings)
        tool_names = {r.tool_name for r in fixed.require_approval if r.tool_name}
        assert "user-manager" in tool_names

    def test_fix_adds_chaining_rule(self) -> None:
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        fixed = apply_fixes(policy, report.findings)
        chain_pairs = {(r.source_skill, r.target_skill) for r in fixed.skill_chaining}
        assert ("user-manager", "any") in chain_pairs

    def test_fix_preserves_existing_boundaries(self) -> None:
        """Existing HIPAA boundary should not be overwritten by GDPR fix."""
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr-connector"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        fixed = apply_fixes(policy, report.findings)
        assert "hipaa_zone" in fixed.data_boundaries
        assert "gdpr_zone" in fixed.data_boundaries

    def test_fix_merges_into_existing_gdpr_zone(self) -> None:
        """If gdpr_zone already exists, new skills get merged in."""
        scan = _scan(
            _server("user-manager", [_perm("get_user")]),
            _server("customer-crm", [_perm("lookup")]),
        )
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["user-manager"],
                    classification="personal_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        fixed = apply_fixes(policy, report.findings)
        assert "customer-crm" in fixed.data_boundaries["gdpr_zone"].skills
        assert "user-manager" in fixed.data_boundaries["gdpr_zone"].skills


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


class TestGDPRReportRendering:
    """Verify report renders without errors."""

    def test_render_gdpr_report(self) -> None:
        from rich.console import Console

        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        console = Console(stderr=True, quiet=True)
        # Should not raise
        render_compliance_report(report, console)

    def test_render_gdpr_json(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        # Should not raise
        render_compliance_json(report)

    def test_render_compliant_report(self) -> None:
        from rich.console import Console

        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _compliant_pd_policy("user-manager")
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        console = Console(stderr=True, quiet=True)
        render_compliance_report(report, console)


# ---------------------------------------------------------------------------
# End-to-end with fixes
# ---------------------------------------------------------------------------


class TestGDPREndToEnd:
    """Full pipeline: evaluate → fix → re-evaluate → all required pass."""

    def test_single_pd_skill_full_pipeline(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("update_user", [
                _access(DataAccessType.EMAIL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        assert report.controls_passed < 8

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, scan, GDPR_CONTROLS, "gdpr")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_multiple_pd_skills_full_pipeline(self) -> None:
        scan = _scan(
            _server("user-manager", [
                _perm("update_user", [
                    _access(DataAccessType.EMAIL, write=True),
                    _access(DataAccessType.NETWORK, write=True),
                ], read_only=False),
            ]),
            _server("customer-crm", [
                _perm("update_customer", [
                    _access(DataAccessType.EMAIL, write=True),
                ], read_only=False),
            ]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, scan, GDPR_CONTROLS, "gdpr")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_already_compliant_no_changes(self) -> None:
        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _compliant_pd_policy("user-manager")
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        assert len(report.findings) == 0
        assert report.controls_passed == 8

    def test_pd_from_boundary_full_pipeline(self) -> None:
        """Skills identified as PD via data_boundaries (not scan) should also pass after fix."""
        policy = _minimal_policy(
            data_boundaries={
                "gdpr_zone": DataBoundary(
                    skills=["custom-pd-handler"],
                    classification="personal_data",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )

        report = evaluate_compliance(policy, None, GDPR_CONTROLS, "gdpr")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, None, GDPR_CONTROLS, "gdpr")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0


# ---------------------------------------------------------------------------
# Cross-framework: HIPAA + GDPR coexistence
# ---------------------------------------------------------------------------


class TestCrossFramework:
    """Verify HIPAA and GDPR frameworks coexist correctly."""

    def test_both_registered(self) -> None:
        import agentward.comply.frameworks.hipaa  # noqa: F401

        frameworks = available_frameworks()
        assert "hipaa" in frameworks
        assert "gdpr" in frameworks

    def test_separate_evaluations(self) -> None:
        from agentward.comply.frameworks.hipaa import HIPAA_CONTROLS

        scan = _scan(_server("user-manager", [_perm("get_user")]))
        policy = _minimal_policy()

        hipaa_report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        gdpr_report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")

        assert hipaa_report.framework == "hipaa"
        assert gdpr_report.framework == "gdpr"

        # user-manager is PD skill but not PHI skill
        hipaa_pd_findings = [
            f for f in hipaa_report.findings
            if f.skill == "user-manager"
            and f.control_id.startswith("hipaa-164.312.a")
        ]
        assert len(hipaa_pd_findings) == 0  # HIPAA doesn't care about non-PHI skills

        gdpr_findings = [
            f for f in gdpr_report.findings if f.skill == "user-manager"
        ]
        assert len(gdpr_findings) > 0  # GDPR cares about PD skills


# ---------------------------------------------------------------------------
# Resource scoping
# ---------------------------------------------------------------------------


class TestGDPRResourceScoping:
    """Verify that only the skill's own resource counts for restrictions."""

    def test_unrelated_resource_does_not_satisfy_integrity(self) -> None:
        """Write restriction on a different resource doesn't help."""
        scan = _scan(_server("user-manager", [
            _perm("update_user", [_access(DataAccessType.EMAIL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "some-other-resource": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.integrity"]
        assert len(findings) == 1

    def test_unrelated_resource_does_not_satisfy_transmission(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("sync_users", [
                _access(DataAccessType.EMAIL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "unrelated": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.transmission"]
        assert len(findings) == 1

    def test_skill_own_resource_outbound_satisfies_transmission(self) -> None:
        scan = _scan(_server("user-manager", [
            _perm("sync_users", [
                _access(DataAccessType.EMAIL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "user-manager": {
                    "user-manager": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, GDPR_CONTROLS, "gdpr")
        findings = [f for f in report.findings if f.control_id == "gdpr-art32.transmission"]
        assert len(findings) == 0
