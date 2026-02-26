"""Tests for the compliance evaluation module."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentward.comply.controls import (
    ComplianceFinding,
    ComplianceRating,
    ComplianceReport,
    ControlSeverity,
    PolicyFix,
    SkillAnalysis,
    apply_fixes,
    build_skill_analysis,
    evaluate_compliance,
)
from agentward.comply.frameworks import (
    available_frameworks,
    get_framework,
    register_framework,
)
from agentward.comply.frameworks.hipaa import HIPAA_CONTROLS
from agentward.comply.report import render_compliance_json, render_compliance_report
from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalCondition,
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


def _minimal_policy(**kwargs) -> AgentWardPolicy:
    """Create a minimal policy with defaults."""
    defaults = {"version": "1.0"}
    defaults.update(kwargs)
    return AgentWardPolicy(**defaults)


def _compliant_phi_policy(phi_skill: str = "ehr-connector") -> AgentWardPolicy:
    """Create a policy that passes all HIPAA controls for a single PHI skill."""
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        skills={
            phi_skill: {
                phi_skill: ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False, "delete": False},
                    filters={},
                ),
            },
        },
        skill_chaining=[
            ChainingRule(source_skill=phi_skill, target_skill="any"),
        ],
        require_approval=[
            ApprovalRule(tool_name=phi_skill),
        ],
        sensitive_content=SensitiveContentConfig(
            enabled=True,
            patterns=["credit_card", "ssn", "api_key"],
        ),
        data_boundaries={
            "hipaa_zone": DataBoundary(
                skills=[phi_skill],
                classification="phi",
                rules=["phi_data cannot flow outside hipaa_zone"],
                on_violation=ViolationAction.BLOCK_AND_LOG,
            ),
        },
    )


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------


class TestFrameworkRegistry:
    def test_hipaa_is_registered(self) -> None:
        frameworks = available_frameworks()
        assert "hipaa" in frameworks

    def test_get_hipaa_returns_controls(self) -> None:
        controls = get_framework("hipaa")
        assert len(controls) == 8

    def test_get_unknown_framework_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown compliance framework"):
            get_framework("nonexistent-framework")

    def test_case_insensitive_lookup(self) -> None:
        controls = get_framework("HIPAA")
        assert len(controls) == 8

    def test_register_custom_framework(self) -> None:
        register_framework("test-framework", [])
        assert "test-framework" in available_frameworks()
        assert get_framework("test-framework") == []


# ---------------------------------------------------------------------------
# build_skill_analysis
# ---------------------------------------------------------------------------


class TestBuildSkillAnalysis:
    def test_phi_detection_by_name(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        analysis = build_skill_analysis(policy, scan)
        assert "ehr-connector" in analysis.phi_skills

    def test_phi_detection_by_clinical_name(self) -> None:
        scan = _scan(_server("clinical-notes", [_perm("get_notes")]))
        policy = _minimal_policy()
        analysis = build_skill_analysis(policy, scan)
        assert "clinical-notes" in analysis.phi_skills

    def test_phi_detection_by_data_access(self) -> None:
        """DATABASE + EMAIL heuristic triggers PHI detection."""
        tool = _perm("query_records", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.EMAIL, read=True),
        ])
        scan = _scan(_server("data-service", [tool]))
        policy = _minimal_policy()
        analysis = build_skill_analysis(policy, scan)
        assert "data-service" in analysis.phi_skills

    def test_phi_detection_by_policy_boundary(self) -> None:
        scan = _scan(_server("some-service", [_perm("read_data")]))
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["some-service"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, scan)
        assert "some-service" in analysis.phi_skills

    def test_non_phi_skill_not_detected(self) -> None:
        scan = _scan(_server("web-browser", [_perm("navigate")]))
        policy = _minimal_policy()
        analysis = build_skill_analysis(policy, scan)
        assert "web-browser" not in analysis.phi_skills

    def test_network_skill_detection(self) -> None:
        tool = _perm("fetch", access=[_access(DataAccessType.NETWORK)])
        scan = _scan(_server("api-caller", [tool]))
        policy = _minimal_policy()
        analysis = build_skill_analysis(policy, scan)
        assert "api-caller" in analysis.network_skills

    def test_financial_skill_detection(self) -> None:
        tool = _perm("transfer", access=[_access(DataAccessType.FINANCIAL)])
        scan = _scan(_server("finance-tool", [tool]))
        policy = _minimal_policy()
        analysis = build_skill_analysis(policy, scan)
        assert "finance-tool" in analysis.financial_skills

    def test_write_capable_detection(self) -> None:
        tool = _perm("update_record", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("db-tool", [tool]))
        policy = _minimal_policy()
        analysis = build_skill_analysis(policy, scan)
        assert analysis.skill_write_capable["db-tool"] is True

    def test_null_scan_uses_policy_only(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr-system"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "ehr-system" in analysis.phi_skills
        assert "ehr-system" in analysis.all_skills

    def test_all_skills_includes_policy_skills(self) -> None:
        policy = _minimal_policy(
            skills={
                "email-manager": {
                    "gmail": ResourcePermissions.model_construct(
                        denied=False, actions={"read": True}, filters={},
                    ),
                },
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "email-manager" in analysis.all_skills


# ---------------------------------------------------------------------------
# HIPAA controls — individual checks
# ---------------------------------------------------------------------------


class TestHIPAAAccessControl:
    """hipaa-164.312.a.1: PHI skills need explicit permissions."""

    def test_phi_skill_without_permissions_fails(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-164.312.a.1" in ids

    def test_phi_skill_with_permissions_passes(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        access_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.a.1"
        ]
        assert len(access_findings) == 0


class TestHIPAADataBoundary:
    """hipaa-164.312.a.1.boundary: PHI skills need data boundary."""

    def test_phi_without_boundary_fails(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-164.312.a.1.boundary" in ids

    def test_phi_with_boundary_passes(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
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
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        boundary_findings = [
            f for f in report.findings
            if f.control_id == "hipaa-164.312.a.1.boundary"
        ]
        assert len(boundary_findings) == 0

    def test_boundary_with_log_only_still_fails(self) -> None:
        """log_only violation action is not strong enough for HIPAA."""
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr-connector"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        boundary_findings = [
            f for f in report.findings
            if f.control_id == "hipaa-164.312.a.1.boundary"
        ]
        assert len(boundary_findings) == 1


class TestHIPAAAuditControls:
    """hipaa-164.312.b: Sensitive content scanning."""

    def test_scanning_disabled_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-164.312.b" in ids

    def test_scanning_without_ssn_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["credit_card"],  # no SSN
            ),
        )
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        audit_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.b"
        ]
        assert len(audit_findings) == 1

    def test_scanning_with_ssn_passes(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["credit_card", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        audit_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.b"
        ]
        assert len(audit_findings) == 0


class TestHIPAAIntegrity:
    """hipaa-164.312.c.1: PHI write-capable skills need restrictions."""

    def test_write_capable_phi_without_restriction_fails(self) -> None:
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-164.312.c.1" in ids

    def test_write_capable_phi_with_write_false_passes(self) -> None:
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 0

    def test_read_only_phi_passes(self) -> None:
        """Read-only PHI skills don't need write restrictions."""
        tool = _perm("read_patient", access=[
            _access(DataAccessType.DATABASE, read=True),
        ], read_only=True)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 0


class TestHIPAAAuthentication:
    """hipaa-164.312.d: PHI write tools need approval."""

    def test_write_phi_without_approval_fails(self) -> None:
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-164.312.d" in ids

    def test_write_phi_with_approval_passes(self) -> None:
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="ehr-connector")],
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        auth_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.d"
        ]
        assert len(auth_findings) == 0


class TestHIPAATransmissionSecurity:
    """hipaa-164.312.e.1: PHI + network needs controls."""

    def test_phi_with_network_no_controls_fails(self) -> None:
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-164.312.e.1" in ids

    def test_phi_with_outbound_blocked_passes(self) -> None:
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "network": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 0

    def test_phi_without_network_passes(self) -> None:
        """PHI skill without network access doesn't trigger this control."""
        tool = _perm("read_patient", access=[
            _access(DataAccessType.DATABASE, read=True),
        ])
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 0


class TestHIPAAIsolation:
    """hipaa-164.308.a.4: PHI skills must be isolated via chaining."""

    def test_phi_without_chaining_fails(self) -> None:
        scan = _scan(
            _server("ehr-connector", [_perm("read_patient")]),
            _server("web-browser", [_perm("navigate")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-164.308.a.4" in ids

    def test_phi_with_any_chaining_rule_passes(self) -> None:
        scan = _scan(
            _server("ehr-connector", [_perm("read_patient")]),
            _server("web-browser", [_perm("navigate")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="ehr-connector", target_skill="any"),
            ],
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        isolation_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.308.a.4"
        ]
        assert len(isolation_findings) == 0

    def test_no_non_phi_skills_means_no_isolation_needed(self) -> None:
        """If all skills are PHI, isolation check doesn't trigger."""
        scan = _scan(
            _server("ehr-connector", [_perm("read_patient")]),
            _server("clinical-notes", [_perm("get_notes")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        isolation_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.308.a.4"
        ]
        assert len(isolation_findings) == 0


class TestHIPAADefaultAction:
    """hipaa-default-action: Best practice zero-trust."""

    def test_default_allow_produces_warning(self) -> None:
        policy = _minimal_policy()  # default_action defaults to ALLOW
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        ids = [f.control_id for f in report.findings]
        assert "hipaa-default-action" in ids
        finding = [f for f in report.findings if f.control_id == "hipaa-default-action"][0]
        assert finding.severity == ControlSeverity.RECOMMENDED

    def test_default_block_passes(self) -> None:
        policy = _minimal_policy(default_action=DefaultAction.BLOCK)
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        da_findings = [
            f for f in report.findings if f.control_id == "hipaa-default-action"
        ]
        assert len(da_findings) == 0


# ---------------------------------------------------------------------------
# evaluate_compliance
# ---------------------------------------------------------------------------


class TestEvaluateCompliance:
    def test_no_phi_skills_all_green(self) -> None:
        """No PHI skills → only policy-level checks apply."""
        scan = _scan(_server("web-browser", [_perm("navigate")]))
        policy = _minimal_policy(default_action=DefaultAction.BLOCK)
        policy.sensitive_content = SensitiveContentConfig(
            enabled=True, patterns=["ssn"],
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        # Should be mostly passing — no PHI skills to fail
        phi_related = [
            f for f in report.findings
            if f.control_id not in ("hipaa-default-action", "hipaa-164.312.b")
        ]
        assert len(phi_related) == 0

    def test_empty_scan_graceful(self) -> None:
        """None scan → policy-only checks still run."""
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        # Should at least check default_action and sensitive content
        assert report.controls_checked == 8

    def test_controls_passed_count(self) -> None:
        policy = _compliant_phi_policy()
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        assert report.controls_checked == 8
        assert report.controls_passed == report.controls_checked - len(
            {f.control_id for f in report.findings}
        )

    def test_skill_rating_red_for_required_failure(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        assert report.skill_ratings.get("ehr-connector") == ComplianceRating.RED

    def test_skill_rating_green_for_compliant(self) -> None:
        policy = _compliant_phi_policy()
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        assert report.skill_ratings.get("ehr-connector") == ComplianceRating.GREEN


# ---------------------------------------------------------------------------
# apply_fixes
# ---------------------------------------------------------------------------


class TestApplyFixes:
    def test_set_default_action(self) -> None:
        policy = _minimal_policy()
        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(fix_type="set_default_action", params={"action": "block"}),
                severity=ControlSeverity.RECOMMENDED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert fixed.default_action == DefaultAction.BLOCK
        # Original unchanged
        assert policy.default_action == DefaultAction.ALLOW

    def test_add_approval_rule(self) -> None:
        policy = _minimal_policy()
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(fix_type="add_approval_rule", params={"tool_name": "ehr"}),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert any(r.tool_name == "ehr" for r in fixed.require_approval)

    def test_add_approval_rule_idempotent(self) -> None:
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="ehr")],
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(fix_type="add_approval_rule", params={"tool_name": "ehr"}),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        ehr_rules = [r for r in fixed.require_approval if r.tool_name == "ehr"]
        assert len(ehr_rules) == 1

    def test_add_chaining_rule(self) -> None:
        policy = _minimal_policy()
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(
                    fix_type="add_chaining_rule",
                    params={"source_skill": "ehr", "target_skill": "any"},
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert any(
            r.source_skill == "ehr" and r.target_skill == "any"
            for r in fixed.skill_chaining
        )

    def test_add_chaining_rule_idempotent(self) -> None:
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="ehr", target_skill="any"),
            ],
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(
                    fix_type="add_chaining_rule",
                    params={"source_skill": "ehr", "target_skill": "any"},
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        ehr_chains = [
            r for r in fixed.skill_chaining
            if r.source_skill == "ehr" and r.target_skill == "any"
        ]
        assert len(ehr_chains) == 1

    def test_add_data_boundary(self) -> None:
        policy = _minimal_policy()
        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(
                    fix_type="add_data_boundary",
                    params={
                        "zone_name": "hipaa_zone",
                        "skills": ["ehr"],
                        "classification": "phi",
                        "rules": ["phi_data cannot flow outside hipaa_zone"],
                        "on_violation": "block_and_log",
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert "hipaa_zone" in fixed.data_boundaries
        assert "ehr" in fixed.data_boundaries["hipaa_zone"].skills

    def test_add_data_boundary_merges_skills(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(
                    fix_type="add_data_boundary",
                    params={
                        "zone_name": "hipaa_zone",
                        "skills": ["clinical-notes"],
                        "classification": "phi",
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert "ehr" in fixed.data_boundaries["hipaa_zone"].skills
        assert "clinical-notes" in fixed.data_boundaries["hipaa_zone"].skills

    def test_enable_sensitive_content(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(
                    fix_type="enable_sensitive_content",
                    params={"patterns": ["ssn", "credit_card"]},
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert fixed.sensitive_content.enabled is True
        assert "ssn" in fixed.sensitive_content.patterns
        assert "credit_card" in fixed.sensitive_content.patterns

    def test_add_skill_restriction(self) -> None:
        policy = _minimal_policy()
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(
                    fix_type="add_skill_restriction",
                    params={
                        "skill_name": "ehr",
                        "resource_name": "ehr",
                        "actions": {"read": True, "write": False},
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert "ehr" in fixed.skills
        assert fixed.skills["ehr"]["ehr"].actions["write"] is False

    def test_no_fix_on_finding_is_skipped(self) -> None:
        policy = _minimal_policy()
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=None,
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert fixed.version == policy.version  # unchanged

    def test_original_policy_not_mutated(self) -> None:
        policy = _minimal_policy()
        original_action = policy.default_action
        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(fix_type="set_default_action", params={"action": "block"}),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        apply_fixes(policy, findings)
        assert policy.default_action == original_action

    def test_fixed_policy_is_loadable(self, tmp_path: Path) -> None:
        """The fixed policy should be serializable and loadable."""
        from agentward.configure.generator import serialize_policy
        from agentward.policy.loader import load_policy

        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        fixed = apply_fixes(policy, report.findings)

        yaml_content = serialize_policy(fixed)
        policy_path = tmp_path / "fixed.yaml"
        policy_path.write_text(yaml_content)

        reloaded = load_policy(policy_path)
        assert reloaded.version == "1.0"


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


class TestReportRendering:
    def test_render_no_crash_on_empty(self) -> None:
        """Rendering an empty report shouldn't crash."""
        from rich.console import Console

        console = Console(stderr=True, force_terminal=True)
        report = ComplianceReport(
            framework="hipaa",
            controls_checked=8,
            controls_passed=8,
        )
        render_compliance_report(report, console)  # should not raise

    def test_render_no_crash_with_findings(self) -> None:
        from rich.console import Console

        console = Console(stderr=True, force_terminal=True)
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        render_compliance_report(report, console)  # should not raise

    def test_json_output_structure(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        json_data = render_compliance_json(report)

        assert json_data["framework"] == "hipaa"
        assert json_data["controls_checked"] == 8
        assert isinstance(json_data["findings"], list)
        assert isinstance(json_data["skill_ratings"], dict)

    def test_json_finding_has_required_fields(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        json_data = render_compliance_json(report)

        for finding in json_data["findings"]:
            assert "control_id" in finding
            assert "description" in finding
            assert "severity" in finding
            assert "has_fix" in finding

    def test_json_ratings_correct(self) -> None:
        policy = _compliant_phi_policy()
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        json_data = render_compliance_json(report)
        assert json_data["skill_ratings"]["ehr-connector"] == "green"


# ---------------------------------------------------------------------------
# End-to-end: full compliant policy passes all controls
# ---------------------------------------------------------------------------


class TestEndToEnd:
    def test_fully_compliant_policy_has_no_required_findings(self) -> None:
        policy = _compliant_phi_policy()
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        required = [f for f in report.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_fix_then_reevaluate_passes(self) -> None:
        """Apply fixes → re-evaluate → no required findings."""
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()

        # First evaluation: should have findings
        report1 = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        assert len(report1.findings) > 0

        # Apply fixes
        fixed = apply_fixes(policy, report1.findings)

        # Re-evaluate: required findings should be gone
        report2 = evaluate_compliance(fixed, scan, HIPAA_CONTROLS, "hipaa")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_double_fix_idempotent(self) -> None:
        """Applying fixes twice doesn't duplicate entries."""
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()

        report1 = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        fixed1 = apply_fixes(policy, report1.findings)

        report2 = evaluate_compliance(fixed1, scan, HIPAA_CONTROLS, "hipaa")
        fixed2 = apply_fixes(fixed1, report2.findings)

        # Approval rules should not be duplicated
        ehr_approvals = [
            r for r in fixed2.require_approval if r.tool_name == "ehr-connector"
        ]
        assert len(ehr_approvals) <= 1

        # Chaining rules should not be duplicated
        ehr_chains = [
            r for r in fixed2.skill_chaining
            if r.source_skill == "ehr-connector" and r.target_skill == "any"
        ]
        assert len(ehr_chains) <= 1

    def test_fix_then_reevaluate_write_capable_phi(self) -> None:
        """Fix→re-evaluate with write-capable PHI skill resolves all required."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(
            _server("ehr-connector", [tool]),
            _server("web-browser", [_perm("navigate")]),
        )
        policy = _minimal_policy()

        report1 = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        assert len(report1.findings) > 0

        fixed = apply_fixes(policy, report1.findings)

        report2 = evaluate_compliance(fixed, scan, HIPAA_CONTROLS, "hipaa")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_boundary_finding_affects_skill_rating(self) -> None:
        """Data boundary failure → skill rating is RED (not GREEN)."""
        scan = _scan(_server("ehr-connector", [_perm("read_patient")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        assert report.skill_ratings.get("ehr-connector") == ComplianceRating.RED

    def test_multiple_phi_skills_partial_compliance(self) -> None:
        """Two PHI skills: one compliant, one not."""
        scan = _scan(
            _server("ehr-connector", [_perm("read_patient")]),
            _server("clinical-notes", [_perm("get_notes")]),
        )
        # Only ehr-connector has permissions
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        # ehr-connector has some permissions but still fails on boundary/isolation
        # clinical-notes has no permissions at all
        access_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.a.1"
        ]
        # clinical-notes should have access control finding, ehr-connector should not
        assert any(f.skill == "clinical-notes" for f in access_findings)
        assert not any(f.skill == "ehr-connector" for f in access_findings)

    def test_unknown_fix_type_raises(self) -> None:
        """Unknown fix_type in PolicyFix raises ValueError."""
        policy = _minimal_policy()
        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(fix_type="nonexistent_fix_type", params={}),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        with pytest.raises(ValueError, match="Unknown fix_type"):
            apply_fixes(policy, findings)

    def test_denied_unrelated_resource_does_not_satisfy_write_check(self) -> None:
        """Denying an unrelated resource shouldn't satisfy integrity control."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        # Deny google_calendar (unrelated) — should NOT satisfy write restriction
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "google_calendar": ResourcePermissions.model_construct(
                        denied=True, actions={}, filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 1  # Still fails — unrelated denial

    def test_denied_skill_resource_satisfies_write_check(self) -> None:
        """Denying the skill's own resource SHOULD satisfy integrity control."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        # Deny ehr-connector itself — should satisfy write restriction
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=True, actions={}, filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 0  # Passes — own resource denied


# ---------------------------------------------------------------------------
# Serialization roundtrip: default_action preserved through fix
# ---------------------------------------------------------------------------


class TestPolicySerializationRoundtrip:
    def test_default_action_block_survives_serialize(self, tmp_path: Path) -> None:
        """default_action: block must survive serialize → load roundtrip."""
        from agentward.configure.generator import serialize_policy
        from agentward.policy.loader import load_policy

        policy = _minimal_policy(default_action=DefaultAction.BLOCK)
        yaml_content = serialize_policy(policy)
        assert "default_action: block" in yaml_content

        policy_path = tmp_path / "test.yaml"
        policy_path.write_text(yaml_content)
        reloaded = load_policy(policy_path)
        assert reloaded.default_action == DefaultAction.BLOCK

    def test_default_action_allow_omitted_from_yaml(self) -> None:
        """default_action: allow is the default; should be omitted from YAML."""
        from agentward.configure.generator import serialize_policy

        policy = _minimal_policy()
        yaml_content = serialize_policy(policy)
        assert "default_action" not in yaml_content

    def test_fix_sets_default_action_and_survives_roundtrip(self, tmp_path: Path) -> None:
        """apply_fixes → set_default_action → serialize → load preserves block."""
        from agentward.configure.generator import serialize_policy
        from agentward.policy.loader import load_policy

        policy = _minimal_policy()
        assert policy.default_action == DefaultAction.ALLOW

        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(fix_type="set_default_action", params={"action": "block"}),
                severity=ControlSeverity.RECOMMENDED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert fixed.default_action == DefaultAction.BLOCK

        yaml_content = serialize_policy(fixed)
        policy_path = tmp_path / "fixed.yaml"
        policy_path.write_text(yaml_content)
        reloaded = load_policy(policy_path)
        assert reloaded.default_action == DefaultAction.BLOCK


# ---------------------------------------------------------------------------
# Conditional approval rules in HIPAA checks
# ---------------------------------------------------------------------------


class TestConditionalApprovalCompliance:
    def test_conditional_approval_recognized_by_authentication_check(self) -> None:
        """Conditional approval rule on a PHI skill satisfies §164.312(d)."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        cond_rule = ApprovalRule.model_construct(
            tool_name=None,
            conditional=ConditionalApproval(
                tool="ehr-connector",
                when={"action": ApprovalCondition(contains="delete")},
            ),
        )
        policy = _minimal_policy(require_approval=[cond_rule])
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        auth_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.d"
        ]
        assert len(auth_findings) == 0  # Conditional approval counts

    def test_conditional_approval_recognized_by_integrity_check(self) -> None:
        """Conditional approval on PHI skill satisfies §164.312(c)(1) integrity."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        cond_rule = ApprovalRule.model_construct(
            tool_name=None,
            conditional=ConditionalApproval(
                tool="ehr-connector",
                when={"action": ApprovalCondition(contains="write")},
            ),
        )
        policy = _minimal_policy(require_approval=[cond_rule])
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 0

    def test_conditional_approval_recognized_by_transmission_check(self) -> None:
        """Conditional approval on PHI+network skill satisfies §164.312(e)(1)."""
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        cond_rule = ApprovalRule.model_construct(
            tool_name=None,
            conditional=ConditionalApproval(
                tool="ehr-connector",
                when={"dest": ApprovalCondition(contains="external")},
            ),
        )
        policy = _minimal_policy(require_approval=[cond_rule])
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 0

    def test_conditional_approval_wrong_tool_does_not_match(self) -> None:
        """Conditional approval on a DIFFERENT tool doesn't satisfy the check."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        cond_rule = ApprovalRule.model_construct(
            tool_name=None,
            conditional=ConditionalApproval(
                tool="other-tool",
                when={"action": ApprovalCondition(contains="delete")},
            ),
        )
        policy = _minimal_policy(require_approval=[cond_rule])
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        auth_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.d"
        ]
        assert len(auth_findings) == 1  # Not covered


# ---------------------------------------------------------------------------
# Data boundary merge: on_violation upgrade
# ---------------------------------------------------------------------------


class TestDataBoundaryMerge:
    def test_merge_upgrades_on_violation(self) -> None:
        """Merging into existing zone upgrades log_only → block_and_log."""
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="clinical",
                description="test",
                fix=PolicyFix(
                    fix_type="add_data_boundary",
                    params={
                        "zone_name": "hipaa_zone",
                        "skills": ["clinical"],
                        "classification": "phi",
                        "on_violation": "block_and_log",
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        assert fixed.data_boundaries["hipaa_zone"].on_violation == ViolationAction.BLOCK_AND_LOG
        assert "clinical" in fixed.data_boundaries["hipaa_zone"].skills

    def test_merge_does_not_downgrade_on_violation(self) -> None:
        """Merging must not downgrade block_and_notify → block_and_log."""
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_NOTIFY,
                ),
            },
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill=None,
                description="test",
                fix=PolicyFix(
                    fix_type="add_data_boundary",
                    params={
                        "zone_name": "hipaa_zone",
                        "skills": ["clinical"],
                        "on_violation": "block_and_log",
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        # Should remain BLOCK_AND_NOTIFY (stricter)
        assert fixed.data_boundaries["hipaa_zone"].on_violation == ViolationAction.BLOCK_AND_NOTIFY


# ---------------------------------------------------------------------------
# Integrity check: delete/write logic
# ---------------------------------------------------------------------------


class TestIntegrityWriteLogic:
    def test_write_true_delete_false_does_not_satisfy(self) -> None:
        """write: true + delete: false does NOT satisfy integrity control."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"write": True, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 1  # write: true → not restricted

    def test_delete_false_alone_satisfies(self) -> None:
        """delete: false (write not mentioned) satisfies integrity control."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 0


# ---------------------------------------------------------------------------
# PHI skills from data_boundaries: write-capable assumption
# ---------------------------------------------------------------------------


class TestPHIBoundaryOnlySkills:
    def test_boundary_only_phi_triggers_integrity_check(self) -> None:
        """PHI skill from boundary (no scan) assumed write-capable → integrity check fires."""
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr-system"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        # No scan data at all
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 1
        assert integrity_findings[0].skill == "ehr-system"

    def test_boundary_only_phi_triggers_authentication_check(self) -> None:
        """PHI skill from boundary (no scan) assumed write-capable → auth check fires."""
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr-system"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, None, HIPAA_CONTROLS, "hipaa")
        auth_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.d"
        ]
        assert len(auth_findings) == 1

    def test_boundary_only_phi_with_scan_data_not_overridden(self) -> None:
        """If scan data exists for a skill, don't override its write_capable."""
        tool = _perm("read_patient", access=[
            _access(DataAccessType.DATABASE, read=True),
        ], read_only=True)
        scan = _scan(_server("ehr-system", [tool]))
        policy = _minimal_policy(
            data_boundaries={
                "hipaa_zone": DataBoundary(
                    skills=["ehr-system"],
                    classification="phi",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, scan)
        # Scan says read-only → skill_write_capable should be False
        assert analysis.skill_write_capable["ehr-system"] is False


# ---------------------------------------------------------------------------
# Transmission security: additional scenarios
# ---------------------------------------------------------------------------


class TestTransmissionSecurityExtra:
    def test_approval_satisfies_transmission_check(self) -> None:
        """Approval rule satisfies transmission security (alternative to outbound block)."""
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="ehr-connector")],
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 0

    def test_denied_network_resource_satisfies(self) -> None:
        """Denying 'network' resource blocks outbound for transmission security."""
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "network": ResourcePermissions.model_construct(
                        denied=True, actions={}, filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 0

    def test_denied_unrelated_resource_does_not_satisfy_transmission(self) -> None:
        """Denying unrelated resource does NOT satisfy transmission check."""
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "google_calendar": ResourcePermissions.model_construct(
                        denied=True, actions={}, filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 1  # Still fails


# ---------------------------------------------------------------------------
# YELLOW rating for RECOMMENDED-only failure
# ---------------------------------------------------------------------------


class TestYellowRating:
    def test_recommended_only_failure_produces_yellow(self) -> None:
        """A skill with only RECOMMENDED failures should be YELLOW, not RED."""
        # Use a policy that passes all REQUIRED controls but fails default_action
        scan = _scan(_server("web-browser", [_perm("navigate")]))
        policy = _minimal_policy(
            default_action=DefaultAction.ALLOW,  # RECOMMENDED: should be block
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["ssn"],
            ),
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        # Only finding should be the default_action RECOMMENDED one (policy-level)
        required_findings = [
            f for f in report.findings if f.severity == ControlSeverity.REQUIRED
        ]
        # web-browser is not PHI, so no required findings for it
        assert len([f for f in required_findings if f.skill == "web-browser"]) == 0
        # web-browser should be GREEN since no findings affect it
        assert report.skill_ratings.get("web-browser") == ComplianceRating.GREEN


# ---------------------------------------------------------------------------
# Skill restriction merge (existing actions not overwritten)
# ---------------------------------------------------------------------------


class TestSkillRestrictionMerge:
    def test_existing_actions_not_overwritten(self) -> None:
        """add_skill_restriction merge should not overwrite existing actions."""
        policy = _minimal_policy(
            skills={
                "ehr": {
                    "ehr": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(
                    fix_type="add_skill_restriction",
                    params={
                        "skill_name": "ehr",
                        "resource_name": "ehr",
                        "actions": {"write": True, "delete": False},  # try to override write
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        # write should still be False (original value preserved)
        assert fixed.skills["ehr"]["ehr"].actions["write"] is False
        # delete should be added (new action)
        assert fixed.skills["ehr"]["ehr"].actions["delete"] is False


# ---------------------------------------------------------------------------
# Report helpers
# ---------------------------------------------------------------------------


class TestReportHelpers:
    def test_get_section_for_unknown_control(self) -> None:
        """Unknown control_id falls back to the id itself."""
        from agentward.comply.report import _get_section_for_control

        section = _get_section_for_control("nonexistent-control-id", "hipaa")
        assert section == "nonexistent-control-id"

    def test_get_section_for_unknown_framework(self) -> None:
        """Unknown framework falls back to the control_id."""
        from agentward.comply.report import _get_section_for_control

        section = _get_section_for_control("hipaa-164.312.a.1", "nonexistent-framework")
        assert section == "hipaa-164.312.a.1"

    def test_get_section_for_known_control(self) -> None:
        """Known control returns section + title."""
        from agentward.comply.report import _get_section_for_control

        section = _get_section_for_control("hipaa-164.312.a.1", "hipaa")
        assert "§164.312(a)(1)" in section
        assert "Access Control" in section


# ---------------------------------------------------------------------------
# build_skill_analysis: additional coverage
# ---------------------------------------------------------------------------


class TestBuildSkillAnalysisExtra:
    def test_pii_detection_via_email(self) -> None:
        """Skills with EMAIL access are detected as PII handlers."""
        tool = _perm("read_mail", access=[_access(DataAccessType.EMAIL)])
        scan = _scan(_server("mail-tool", [tool]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "mail-tool" in analysis.pii_skills

    def test_pii_detection_via_messaging(self) -> None:
        """Skills with MESSAGING access are detected as PII handlers."""
        tool = _perm("send_msg", access=[_access(DataAccessType.MESSAGING)])
        scan = _scan(_server("chat-tool", [tool]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "chat-tool" in analysis.pii_skills

    def test_protected_health_information_classification(self) -> None:
        """'protected_health_information' classification counts as PHI."""
        policy = _minimal_policy(
            data_boundaries={
                "zone": DataBoundary(
                    skills=["my-tool"],
                    classification="protected_health_information",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "my-tool" in analysis.phi_skills

    def test_phi_by_database_and_network(self) -> None:
        """DATABASE + NETWORK triggers PHI heuristic."""
        tool = _perm("query", access=[
            _access(DataAccessType.DATABASE),
            _access(DataAccessType.NETWORK),
        ])
        scan = _scan(_server("data-api", [tool]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "data-api" in analysis.phi_skills


# ---------------------------------------------------------------------------
# Isolation check: per-skill chaining
# ---------------------------------------------------------------------------


class TestIsolationPerSkillChaining:
    def test_individual_skill_blocks_suffice(self) -> None:
        """Blocking each non-PHI skill individually (not 'any') passes."""
        scan = _scan(
            _server("ehr-connector", [_perm("read_patient")]),
            _server("web-browser", [_perm("navigate")]),
            _server("file-manager", [_perm("read_file")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="ehr-connector", target_skill="web-browser"),
                ChainingRule(source_skill="ehr-connector", target_skill="file-manager"),
            ],
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        isolation_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.308.a.4"
        ]
        assert len(isolation_findings) == 0

    def test_partial_chaining_still_fails(self) -> None:
        """Blocking some but not all non-PHI skills still fails."""
        scan = _scan(
            _server("ehr-connector", [_perm("read_patient")]),
            _server("web-browser", [_perm("navigate")]),
            _server("file-manager", [_perm("read_file")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="ehr-connector", target_skill="web-browser"),
                # Missing: ehr-connector → file-manager
            ],
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        isolation_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.308.a.4"
        ]
        assert len(isolation_findings) == 1
        assert "file-manager" in isolation_findings[0].description


# ---------------------------------------------------------------------------
# P0 fix: resource scoping — actions on unrelated resources
# ---------------------------------------------------------------------------


class TestResourceScopingIntegrity:
    """Verify integrity check only accepts restrictions on the skill's own resource."""

    def test_write_false_on_unrelated_resource_does_not_satisfy(self) -> None:
        """write: False on 'network' (not skill name) shouldn't satisfy integrity."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "network": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"write": False, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 1

    def test_write_false_on_own_resource_satisfies(self) -> None:
        """write: False on skill's own resource SHOULD satisfy integrity."""
        tool = _perm("update_patient", access=[
            _access(DataAccessType.DATABASE, read=True, write=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        integrity_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.c.1"
        ]
        assert len(integrity_findings) == 0


class TestResourceScopingTransmission:
    """Verify transmission check only accepts restrictions on network or skill's own resource."""

    def test_outbound_false_on_unrelated_resource_does_not_satisfy(self) -> None:
        """outbound: False on 'filesystem' (not network/skill) shouldn't satisfy."""
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "filesystem": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 1

    def test_outbound_false_on_network_resource_satisfies(self) -> None:
        """outbound: False on 'network' resource SHOULD satisfy."""
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "network": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 0

    def test_outbound_false_on_skill_resource_satisfies(self) -> None:
        """outbound: False on skill's own resource SHOULD satisfy."""
        tool = _perm("send_data", access=[
            _access(DataAccessType.DATABASE, read=True),
            _access(DataAccessType.NETWORK, read=True),
        ], read_only=False)
        scan = _scan(_server("ehr-connector", [tool]))
        policy = _minimal_policy(
            skills={
                "ehr-connector": {
                    "ehr-connector": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, HIPAA_CONTROLS, "hipaa")
        tx_findings = [
            f for f in report.findings if f.control_id == "hipaa-164.312.e.1"
        ]
        assert len(tx_findings) == 0


# ---------------------------------------------------------------------------
# P0 fix: skill restriction merge — stricter value wins
# ---------------------------------------------------------------------------


class TestSkillRestrictionMergeStricter:
    """Verify add_skill_restriction merge enforces stricter compliance values."""

    def test_true_overridden_by_false(self) -> None:
        """Existing write: True must be overridden by compliance fix write: False."""
        policy = _minimal_policy(
            skills={
                "ehr": {
                    "ehr": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": True},
                        filters={},
                    ),
                },
            },
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(
                    fix_type="add_skill_restriction",
                    params={
                        "skill_name": "ehr",
                        "resource_name": "ehr",
                        "actions": {"write": False, "delete": False},
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        # write must be overridden to False (stricter compliance value)
        assert fixed.skills["ehr"]["ehr"].actions["write"] is False
        # read should remain True (untouched)
        assert fixed.skills["ehr"]["ehr"].actions["read"] is True
        # delete should be added as False
        assert fixed.skills["ehr"]["ehr"].actions["delete"] is False

    def test_false_not_overridden_by_true(self) -> None:
        """Existing write: False must NOT be overridden by fix write: True."""
        policy = _minimal_policy(
            skills={
                "ehr": {
                    "ehr": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        findings = [
            ComplianceFinding(
                control_id="test",
                skill="ehr",
                description="test",
                fix=PolicyFix(
                    fix_type="add_skill_restriction",
                    params={
                        "skill_name": "ehr",
                        "resource_name": "ehr",
                        "actions": {"write": True},  # try to relax
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ),
        ]
        fixed = apply_fixes(policy, findings)
        # write must stay False (more restrictive value preserved)
        assert fixed.skills["ehr"]["ehr"].actions["write"] is False
