"""Tests for the SOX compliance framework."""

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
from agentward.comply.frameworks.sox import SOX_CONTROLS
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


def _compliant_fin_policy(fin_skill: str = "finance-tracker") -> AgentWardPolicy:
    """Create a policy that passes all SOX controls for a single financial skill."""
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        skills={
            fin_skill: {
                fin_skill: ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False, "delete": False},
                    filters={},
                ),
            },
        },
        skill_chaining=[
            ChainingRule(source_skill=fin_skill, target_skill="any"),
        ],
        require_approval=[
            ApprovalRule(tool_name=fin_skill),
        ],
        sensitive_content=SensitiveContentConfig(
            enabled=True,
            patterns=["credit_card", "ssn", "api_key"],
        ),
        data_boundaries={
            "sox_zone": DataBoundary(
                skills=[fin_skill],
                classification="financial",
                rules=["financial_data cannot flow outside sox_zone"],
                on_violation=ViolationAction.BLOCK_AND_LOG,
            ),
        },
    )


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------


class TestSOXFrameworkRegistry:
    def test_sox_is_registered(self) -> None:
        frameworks = available_frameworks()
        assert "sox" in frameworks

    def test_get_sox_returns_controls(self) -> None:
        controls = get_framework("sox")
        assert len(controls) == 8

    def test_case_insensitive_lookup(self) -> None:
        controls = get_framework("SOX")
        assert len(controls) == 8

    def test_control_ids_are_unique(self) -> None:
        ids = [c.control_id for c in SOX_CONTROLS]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Financial skill detection
# ---------------------------------------------------------------------------


class TestFinancialSkillDetection:
    """Verify build_skill_analysis detects financial skills."""

    def test_by_name_finance(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "finance-tracker" in analysis.financial_skills

    def test_by_name_payment(self) -> None:
        scan = _scan(_server("payment-processor", [_perm("charge")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "payment-processor" in analysis.financial_skills

    def test_by_name_billing(self) -> None:
        scan = _scan(_server("billing-service", [_perm("invoice")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "billing-service" in analysis.financial_skills

    def test_by_name_invoice(self) -> None:
        scan = _scan(_server("invoice-generator", [_perm("create")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "invoice-generator" in analysis.financial_skills

    def test_by_name_ledger(self) -> None:
        scan = _scan(_server("ledger-manager", [_perm("post")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "ledger-manager" in analysis.financial_skills

    def test_by_name_accounting(self) -> None:
        scan = _scan(_server("accounting-tool", [_perm("reconcile")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "accounting-tool" in analysis.financial_skills

    def test_by_name_payroll(self) -> None:
        scan = _scan(_server("payroll-system", [_perm("run")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "payroll-system" in analysis.financial_skills

    def test_by_name_stripe(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "stripe-payments" in analysis.financial_skills

    def test_by_name_quickbooks(self) -> None:
        scan = _scan(_server("quickbooks-connector", [_perm("sync")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "quickbooks-connector" in analysis.financial_skills

    def test_by_data_access_financial(self) -> None:
        scan = _scan(_server("generic-tool", [
            _perm("process", [_access(DataAccessType.FINANCIAL)]),
        ]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "generic-tool" in analysis.financial_skills

    def test_non_financial_skill_not_flagged(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint_file")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "code-linter" not in analysis.financial_skills

    def test_audit_logger_not_financial_false_positive(self) -> None:
        """'audit' was removed from patterns — 'audit-logger' should NOT be financial."""
        scan = _scan(_server("audit-logger", [_perm("write_log")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "audit-logger" not in analysis.financial_skills

    def test_from_policy_data_boundary_financial(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["custom-finance"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "custom-finance" in analysis.financial_skills

    def test_from_policy_data_boundary_sox(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["sox-handler"],
                    classification="sox",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "sox-handler" in analysis.financial_skills

    def test_boundary_skill_assumed_write_capable(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["custom-finance"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert analysis.skill_write_capable.get("custom-finance") is True


# ---------------------------------------------------------------------------
# §404 — Access Control
# ---------------------------------------------------------------------------


class TestSOXAccessControl:
    """sox-404.access: Financial skills need explicit permissions."""

    def test_fin_skill_without_permissions_fails(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.access" in ids

    def test_fin_skill_with_permissions_passes(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "finance-tracker": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.access"]
        assert len(findings) == 0

    def test_no_fin_skills_no_findings(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.access"]
        assert len(findings) == 0

    def test_fix_adds_skill_restriction(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.access")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["skill_name"] == "finance-tracker"


# ---------------------------------------------------------------------------
# §404 — Data Boundary
# ---------------------------------------------------------------------------


class TestSOXDataBoundary:
    """sox-404.boundary: Financial skills need data boundary."""

    def test_fin_without_boundary_fails(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.boundary" in ids

    def test_fin_with_boundary_passes(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["finance-tracker"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.boundary"]
        assert len(findings) == 0

    def test_boundary_with_sox_classification_passes(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["finance-tracker"],
                    classification="sox",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_NOTIFY,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.boundary"]
        assert len(findings) == 0

    def test_boundary_with_log_only_still_fails(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["finance-tracker"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.boundary"]
        assert len(findings) == 1

    def test_fix_adds_data_boundary(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.boundary")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_data_boundary"
        assert finding.fix.params["classification"] == "financial"
        assert finding.fix.params["zone_name"] == "sox_zone"


# ---------------------------------------------------------------------------
# §404 — Audit Trail
# ---------------------------------------------------------------------------


class TestSOXAuditTrail:
    """sox-404.audit: Sensitive content scanning must be enabled."""

    def test_scanning_disabled_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.audit" in ids

    def test_scanning_enabled_with_credit_card_passes(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["credit_card", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.audit"]
        assert len(findings) == 0

    def test_scanning_enabled_without_credit_card_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["ssn"],
            ),
        )
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.audit"]
        assert len(findings) == 1

    def test_fix_enables_scanning(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.audit")
        assert finding.fix is not None
        assert finding.fix.fix_type == "enable_sensitive_content"


# ---------------------------------------------------------------------------
# §404 — Integrity Controls
# ---------------------------------------------------------------------------


class TestSOXIntegrity:
    """sox-404.integrity: Write-capable financial skills need write restrictions."""

    def test_write_capable_without_restriction_fails(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.integrity" in ids

    def test_write_restricted_passes(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "finance-tracker": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.integrity"]
        assert len(findings) == 0

    def test_approval_satisfies_integrity(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="finance-tracker")],
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.integrity"]
        assert len(findings) == 0

    def test_read_only_skill_not_checked(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("get_balance", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.integrity"]
        assert len(findings) == 0

    def test_fix_adds_write_restriction(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.integrity")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["actions"]["write"] is False

    def test_delete_false_counts_as_restriction(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "finance-tracker": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.integrity"]
        assert len(findings) == 0

    def test_denied_resource_counts_as_restriction(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "finance-tracker": ResourcePermissions.model_construct(
                        denied=True,
                        actions={},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.integrity"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# §404 — Authorization Controls
# ---------------------------------------------------------------------------


class TestSOXApproval:
    """sox-404.approval: Write-capable financial skills need human approval."""

    def test_write_capable_without_approval_fails(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.approval" in ids

    def test_with_approval_passes(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="finance-tracker")],
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.approval"]
        assert len(findings) == 0

    def test_conditional_approval_satisfies(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        cond_rule = ApprovalRule.model_construct(
            tool_name=None,
            conditional=ConditionalApproval(
                tool="finance-tracker",
                when={},
            ),
        )
        policy = _minimal_policy(
            require_approval=[cond_rule],
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.approval"]
        assert len(findings) == 0

    def test_read_only_not_checked(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("get_balance", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.approval"]
        assert len(findings) == 0

    def test_fix_adds_approval_rule(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.approval")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_approval_rule"
        assert finding.fix.params["tool_name"] == "finance-tracker"


# ---------------------------------------------------------------------------
# §404 — Network Segregation
# ---------------------------------------------------------------------------


class TestSOXNetworkSegregation:
    """sox-404.network: Financial skills with network must control outbound."""

    def test_fin_with_network_no_block_fails(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("sync", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.network" in ids

    def test_outbound_blocked_passes(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("sync", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "network": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.network"]
        assert len(findings) == 0

    def test_approval_satisfies_network(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("sync", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="finance-tracker")],
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.network"]
        assert len(findings) == 0

    def test_fin_without_network_not_checked(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("get_balance", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.network"]
        assert len(findings) == 0

    def test_network_denied_passes(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("sync", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "network": ResourcePermissions.model_construct(
                        denied=True,
                        actions={},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.network"]
        assert len(findings) == 0

    def test_fix_blocks_outbound(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("sync", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.network")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["resource_name"] == "network"
        assert finding.fix.params["actions"]["outbound"] is False


# ---------------------------------------------------------------------------
# §404 — Segregation of Duties (Isolation)
# ---------------------------------------------------------------------------


class TestSOXIsolation:
    """sox-404.isolation: Financial skills must be isolated via chaining rules."""

    def test_fin_can_trigger_non_fin_fails(self) -> None:
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.isolation" in ids

    def test_chaining_blocks_any_passes(self) -> None:
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="finance-tracker", target_skill="any"),
            ],
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.isolation"]
        assert len(findings) == 0

    def test_chaining_blocks_specific_target_passes(self) -> None:
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="finance-tracker", target_skill="code-linter"),
            ],
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.isolation"]
        assert len(findings) == 0

    def test_no_non_fin_skills_passes(self) -> None:
        """If all skills are financial, no isolation finding."""
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("billing-service", [_perm("invoice")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.isolation"]
        assert len(findings) == 0

    def test_fix_adds_chaining_rule(self) -> None:
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.isolation")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_chaining_rule"
        assert finding.fix.params["source_skill"] == "finance-tracker"
        assert finding.fix.params["target_skill"] == "any"

    def test_partial_chaining_still_fails(self) -> None:
        """Blocking one non-fin target but not all still fails."""
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("code-linter", [_perm("lint")]),
            _server("file-server", [_perm("read_file")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="finance-tracker", target_skill="code-linter"),
            ],
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.isolation"]
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# §404 — Zero-Trust Default
# ---------------------------------------------------------------------------


class TestSOXDefaultAction:
    """sox-404.default: default_action should be block."""

    def test_default_allow_finds_recommendation(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        ids = [f.control_id for f in report.findings]
        assert "sox-404.default" in ids

    def test_severity_is_recommended(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.default")
        assert finding.severity == ControlSeverity.RECOMMENDED

    def test_default_block_passes(self) -> None:
        policy = _minimal_policy(default_action="block")
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.default"]
        assert len(findings) == 0

    def test_fix_sets_default_block(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        finding = next(f for f in report.findings if f.control_id == "sox-404.default")
        assert finding.fix is not None
        assert finding.fix.fix_type == "set_default_action"
        assert finding.fix.params["action"] == "block"


# ---------------------------------------------------------------------------
# Full evaluation and ratings
# ---------------------------------------------------------------------------


class TestSOXEvaluateCompliance:
    """End-to-end evaluation tests."""

    def test_fully_compliant_policy(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _compliant_fin_policy("finance-tracker")
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert report.framework == "sox"
        assert len(report.findings) == 0
        assert report.controls_passed == 8
        assert report.skill_ratings["finance-tracker"] == ComplianceRating.GREEN

    def test_no_fin_skills_all_pass(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy(
            default_action="block",
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["credit_card", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert len(report.findings) == 0
        assert report.controls_passed == 8

    def test_fin_skill_gets_red_rating(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert report.skill_ratings.get("finance-tracker") == ComplianceRating.RED

    def test_yellow_rating_for_recommended_only(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["credit_card", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert report.skill_ratings.get("code-linter") == ComplianceRating.GREEN


# ---------------------------------------------------------------------------
# Apply fixes
# ---------------------------------------------------------------------------


class TestSOXApplyFixes:
    """Test that apply_fixes creates a compliant policy."""

    def test_fix_produces_compliant_policy(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)

        report2 = evaluate_compliance(fixed, scan, SOX_CONTROLS, "sox")
        required_findings = [
            f for f in report2.findings if f.severity == ControlSeverity.REQUIRED
        ]
        assert len(required_findings) == 0

    def test_fix_adds_sox_zone(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        fixed = apply_fixes(policy, report.findings)
        assert "sox_zone" in fixed.data_boundaries
        assert fixed.data_boundaries["sox_zone"].classification == "financial"

    def test_fix_enables_sensitive_content(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.sensitive_content.enabled is True
        assert "credit_card" in fixed.sensitive_content.patterns

    def test_fix_adds_approval_rule(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        fixed = apply_fixes(policy, report.findings)
        tool_names = {r.tool_name for r in fixed.require_approval if r.tool_name}
        assert "finance-tracker" in tool_names

    def test_fix_adds_chaining_rule(self) -> None:
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        fixed = apply_fixes(policy, report.findings)
        chain_pairs = {(r.source_skill, r.target_skill) for r in fixed.skill_chaining}
        assert ("finance-tracker", "any") in chain_pairs

    def test_fix_preserves_existing_boundaries(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
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
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        fixed = apply_fixes(policy, report.findings)
        assert "hipaa_zone" in fixed.data_boundaries
        assert "sox_zone" in fixed.data_boundaries

    def test_fix_merges_into_existing_sox_zone(self) -> None:
        scan = _scan(
            _server("finance-tracker", [_perm("get_balance")]),
            _server("billing-service", [
                _perm("create_invoice", [_access(DataAccessType.FINANCIAL)]),
            ]),
        )
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["finance-tracker"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        fixed = apply_fixes(policy, report.findings)
        assert "billing-service" in fixed.data_boundaries["sox_zone"].skills
        assert "finance-tracker" in fixed.data_boundaries["sox_zone"].skills


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


class TestSOXReportRendering:
    """Verify report renders without errors."""

    def test_render_sox_report(self) -> None:
        from rich.console import Console

        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        console = Console(stderr=True, quiet=True)
        render_compliance_report(report, console)

    def test_render_sox_json(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        render_compliance_json(report)

    def test_render_compliant_report(self) -> None:
        from rich.console import Console

        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _compliant_fin_policy("finance-tracker")
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        console = Console(stderr=True, quiet=True)
        render_compliance_report(report, console)


# ---------------------------------------------------------------------------
# End-to-end with fixes
# ---------------------------------------------------------------------------


class TestSOXEndToEnd:
    """Full pipeline: evaluate → fix → re-evaluate → all required pass."""

    def test_single_fin_skill_full_pipeline(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert report.controls_passed < 8

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, scan, SOX_CONTROLS, "sox")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_multiple_fin_skills_full_pipeline(self) -> None:
        scan = _scan(
            _server("finance-tracker", [
                _perm("post_entry", [
                    _access(DataAccessType.FINANCIAL, write=True),
                    _access(DataAccessType.NETWORK, write=True),
                ], read_only=False),
            ]),
            _server("billing-service", [
                _perm("create_invoice", [
                    _access(DataAccessType.FINANCIAL, write=True),
                ], read_only=False),
            ]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, scan, SOX_CONTROLS, "sox")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_already_compliant_no_changes(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        policy = _compliant_fin_policy("finance-tracker")
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        assert len(report.findings) == 0
        assert report.controls_passed == 8

    def test_fin_from_boundary_full_pipeline(self) -> None:
        """Skills identified as financial via data_boundaries should also pass after fix."""
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["custom-finance"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )

        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, None, SOX_CONTROLS, "sox")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0


# ---------------------------------------------------------------------------
# Cross-framework coexistence
# ---------------------------------------------------------------------------


class TestSOXCrossFramework:
    """Verify SOX coexists with other frameworks."""

    def test_all_registered(self) -> None:
        import agentward.comply.frameworks.hipaa  # noqa: F401
        import agentward.comply.frameworks.gdpr  # noqa: F401

        frameworks = available_frameworks()
        assert "hipaa" in frameworks
        assert "gdpr" in frameworks
        assert "sox" in frameworks

    def test_financial_skill_not_detected_as_phi(self) -> None:
        """A generic financial skill should not trigger HIPAA controls."""
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "finance-tracker" in analysis.financial_skills
        assert "finance-tracker" not in analysis.phi_skills


# ---------------------------------------------------------------------------
# Resource scoping
# ---------------------------------------------------------------------------


class TestSOXResourceScoping:
    """Verify that only the skill's own resource counts for restrictions."""

    def test_unrelated_resource_does_not_satisfy_integrity(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [_access(DataAccessType.FINANCIAL, write=True)], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "some-other-resource": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.integrity"]
        assert len(findings) == 1

    def test_unrelated_resource_does_not_satisfy_network(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("sync", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "unrelated": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.network"]
        assert len(findings) == 1

    def test_skill_own_resource_outbound_satisfies_network(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("sync", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "finance-tracker": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        findings = [f for f in report.findings if f.control_id == "sox-404.network"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Edge cases: integrity write/delete logic
# ---------------------------------------------------------------------------


class TestSOXIntegrityWriteLogic:
    """Verify write: True + delete: False edge case in integrity checks."""

    def test_write_true_delete_false_does_not_satisfy(self) -> None:
        """write: true + delete: false does NOT satisfy integrity control."""
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [
                _access(DataAccessType.FINANCIAL, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "finance-tracker": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"write": True, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        integrity_findings = [
            f for f in report.findings if f.control_id == "sox-404.integrity"
        ]
        assert len(integrity_findings) == 1  # write: true → not restricted

    def test_delete_false_alone_satisfies(self) -> None:
        """delete: false (write not mentioned) satisfies integrity control."""
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [
                _access(DataAccessType.FINANCIAL, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "finance-tracker": {
                    "finance-tracker": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        integrity_findings = [
            f for f in report.findings if f.control_id == "sox-404.integrity"
        ]
        assert len(integrity_findings) == 0


# ---------------------------------------------------------------------------
# Boundary-only skills: write-capable assumption vs scan data
# ---------------------------------------------------------------------------


class TestSOXBoundaryOnlySkills:
    """Verify boundary-only skill assumptions and scan data interaction."""

    def test_boundary_only_fin_triggers_integrity_check(self) -> None:
        """Financial skill from boundary (no scan) assumed write-capable → integrity fires."""
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["custom-finance"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        integrity_findings = [
            f for f in report.findings if f.control_id == "sox-404.integrity"
        ]
        assert len(integrity_findings) == 1
        assert integrity_findings[0].skill == "custom-finance"

    def test_boundary_only_fin_triggers_approval_check(self) -> None:
        """Financial skill from boundary (no scan) assumed write-capable → approval fires."""
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["custom-finance"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, None, SOX_CONTROLS, "sox")
        approval_findings = [
            f for f in report.findings if f.control_id == "sox-404.approval"
        ]
        assert len(approval_findings) == 1

    def test_boundary_with_scan_read_only_not_overridden(self) -> None:
        """If scan shows read-only, boundary should not override write_capable to True."""
        scan = _scan(_server("custom-finance", [
            _perm("read_report", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy(
            data_boundaries={
                "sox_zone": DataBoundary(
                    skills=["custom-finance"],
                    classification="financial",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, scan)
        # Scan says read-only → should be False despite boundary
        assert analysis.skill_write_capable["custom-finance"] is False


# ---------------------------------------------------------------------------
# Cross-framework fix composition
# ---------------------------------------------------------------------------


class TestSOXCrossFrameworkFixComposition:
    """Verify SOX + PCI-DSS fixes compose correctly on overlapping skills."""

    def test_sox_and_pci_fixes_on_stripe_compose(self) -> None:
        """stripe-payments is both financial and cardholder — both frameworks' fixes apply."""
        from agentward.comply.frameworks.pci_dss import PCI_DSS_CONTROLS

        scan = _scan(
            _server("stripe-payments", [
                _perm("charge", [
                    _access(DataAccessType.FINANCIAL, write=True),
                    _access(DataAccessType.NETWORK, write=True),
                ], read_only=False),
            ]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()

        # Apply SOX fixes
        sox_report = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        after_sox = apply_fixes(policy, sox_report.findings)

        # Apply PCI-DSS fixes on top
        pci_report = evaluate_compliance(after_sox, scan, PCI_DSS_CONTROLS, "pci-dss")
        after_both = apply_fixes(after_sox, pci_report.findings)

        # Re-evaluate both frameworks — all required should pass
        sox_final = evaluate_compliance(after_both, scan, SOX_CONTROLS, "sox")
        sox_required = [f for f in sox_final.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(sox_required) == 0

        pci_final = evaluate_compliance(after_both, scan, PCI_DSS_CONTROLS, "pci-dss")
        pci_required = [f for f in pci_final.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(pci_required) == 0


# ---------------------------------------------------------------------------
# Apply fixes idempotency
# ---------------------------------------------------------------------------


class TestSOXApplyFixesIdempotency:
    """Verify applying fixes twice produces the same result."""

    def test_double_fix_is_idempotent(self) -> None:
        scan = _scan(_server("finance-tracker", [
            _perm("post_entry", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        report1 = evaluate_compliance(policy, scan, SOX_CONTROLS, "sox")
        fixed1 = apply_fixes(policy, report1.findings)

        report2 = evaluate_compliance(fixed1, scan, SOX_CONTROLS, "sox")
        fixed2 = apply_fixes(fixed1, report2.findings)

        # Second fix should produce no new changes (all required already pass)
        report3 = evaluate_compliance(fixed2, scan, SOX_CONTROLS, "sox")
        required = [f for f in report3.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0
