"""Tests for the PCI-DSS compliance framework."""

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
from agentward.comply.frameworks.pci_dss import PCI_DSS_CONTROLS
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


def _compliant_cd_policy(cd_skill: str = "stripe-payments") -> AgentWardPolicy:
    """Create a policy that passes all PCI-DSS controls for a single cardholder data skill."""
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        skills={
            cd_skill: {
                cd_skill: ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False, "delete": False},
                    filters={},
                ),
            },
        },
        skill_chaining=[
            ChainingRule(source_skill=cd_skill, target_skill="any"),
        ],
        require_approval=[
            ApprovalRule(tool_name=cd_skill),
        ],
        sensitive_content=SensitiveContentConfig(
            enabled=True,
            patterns=["credit_card", "cvv", "ssn", "api_key"],
        ),
        data_boundaries={
            "pci_zone": DataBoundary(
                skills=[cd_skill],
                classification="cardholder_data",
                rules=["cardholder_data cannot flow outside pci_zone"],
                on_violation=ViolationAction.BLOCK_AND_LOG,
            ),
        },
    )


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------


class TestPCIDSSFrameworkRegistry:
    def test_pci_dss_is_registered(self) -> None:
        frameworks = available_frameworks()
        assert "pci-dss" in frameworks

    def test_get_pci_dss_returns_controls(self) -> None:
        controls = get_framework("pci-dss")
        assert len(controls) == 8

    def test_case_insensitive_lookup(self) -> None:
        controls = get_framework("PCI-DSS")
        assert len(controls) == 8

    def test_control_ids_are_unique(self) -> None:
        ids = [c.control_id for c in PCI_DSS_CONTROLS]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Cardholder data skill detection
# ---------------------------------------------------------------------------


class TestCardholderSkillDetection:
    """Verify build_skill_analysis detects cardholder data skills."""

    def test_by_name_payment(self) -> None:
        scan = _scan(_server("payment-gateway", [_perm("charge")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "payment-gateway" in analysis.cardholder_data_skills

    def test_by_name_checkout(self) -> None:
        scan = _scan(_server("checkout-service", [_perm("process")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "checkout-service" in analysis.cardholder_data_skills

    def test_by_name_stripe(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "stripe-payments" in analysis.cardholder_data_skills

    def test_by_name_braintree(self) -> None:
        scan = _scan(_server("braintree-connector", [_perm("pay")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "braintree-connector" in analysis.cardholder_data_skills

    def test_by_name_square(self) -> None:
        scan = _scan(_server("square-pos", [_perm("charge")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "square-pos" in analysis.cardholder_data_skills

    def test_by_name_cardholder(self) -> None:
        scan = _scan(_server("cardholder-vault", [_perm("store")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "cardholder-vault" in analysis.cardholder_data_skills

    def test_by_name_tokenize(self) -> None:
        scan = _scan(_server("tokenize-service", [_perm("token")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "tokenize-service" in analysis.cardholder_data_skills

    def test_by_name_merchant(self) -> None:
        scan = _scan(_server("merchant-portal", [_perm("view")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "merchant-portal" in analysis.cardholder_data_skills

    def test_by_name_pci(self) -> None:
        scan = _scan(_server("pci-processor", [_perm("process")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "pci-processor" in analysis.cardholder_data_skills

    def test_by_data_access_financial_and_network(self) -> None:
        """FINANCIAL + NETWORK pattern = payment processing."""
        scan = _scan(_server("generic-tool", [
            _perm("process", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "generic-tool" in analysis.cardholder_data_skills

    def test_financial_without_network_not_cardholder(self) -> None:
        """FINANCIAL alone (no NETWORK) does NOT trigger cardholder detection."""
        scan = _scan(_server("ledger-only", [
            _perm("post", [_access(DataAccessType.FINANCIAL)]),
        ]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "ledger-only" not in analysis.cardholder_data_skills

    def test_non_cardholder_skill_not_flagged(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint_file")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "code-linter" not in analysis.cardholder_data_skills

    def test_flashcard_app_not_cardholder_false_positive(self) -> None:
        """'card' was removed from patterns — 'flashcard-app' should NOT be cardholder."""
        scan = _scan(_server("flashcard-app", [_perm("create_card")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "flashcard-app" not in analysis.cardholder_data_skills

    def test_postcard_sender_not_cardholder_false_positive(self) -> None:
        """'card' was removed — 'postcard-sender' should NOT be cardholder."""
        scan = _scan(_server("postcard-sender", [_perm("send")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "postcard-sender" not in analysis.cardholder_data_skills

    def test_from_policy_data_boundary_cardholder(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["custom-card-handler"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "custom-card-handler" in analysis.cardholder_data_skills

    def test_from_policy_data_boundary_pci(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["pci-handler"],
                    classification="pci",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "pci-handler" in analysis.cardholder_data_skills

    def test_from_policy_data_boundary_pci_dss(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["pci-dss-handler"],
                    classification="pci_dss",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert "pci-dss-handler" in analysis.cardholder_data_skills

    def test_boundary_skill_assumed_write_capable(self) -> None:
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["custom-card-handler"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, None)
        assert analysis.skill_write_capable.get("custom-card-handler") is True


# ---------------------------------------------------------------------------
# Req. 7 — Restrict Access
# ---------------------------------------------------------------------------


class TestPCIDSSRestrictAccess:
    """pci-req7: Cardholder data skills need explicit permissions."""

    def test_cd_skill_without_permissions_fails(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req7" in ids

    def test_cd_skill_with_permissions_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "stripe-payments": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7"]
        assert len(findings) == 0

    def test_no_cd_skills_no_findings(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7"]
        assert len(findings) == 0

    def test_fix_adds_skill_restriction(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req7")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["skill_name"] == "stripe-payments"


# ---------------------------------------------------------------------------
# Req. 7 — Cardholder Data Environment (Data Boundary)
# ---------------------------------------------------------------------------


class TestPCIDSSDataBoundary:
    """pci-req7.boundary: Cardholder skills need data boundary."""

    def test_cd_without_boundary_fails(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req7.boundary" in ids

    def test_cd_with_boundary_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["stripe-payments"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.boundary"]
        assert len(findings) == 0

    def test_boundary_with_pci_classification_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["stripe-payments"],
                    classification="pci",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_NOTIFY,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.boundary"]
        assert len(findings) == 0

    def test_boundary_with_pci_dss_classification_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["stripe-payments"],
                    classification="pci_dss",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.boundary"]
        assert len(findings) == 0

    def test_boundary_with_log_only_still_fails(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["stripe-payments"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.boundary"]
        assert len(findings) == 1

    def test_fix_adds_data_boundary(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req7.boundary")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_data_boundary"
        assert finding.fix.params["classification"] == "cardholder_data"
        assert finding.fix.params["zone_name"] == "pci_zone"


# ---------------------------------------------------------------------------
# Req. 10 — Log and Monitor
# ---------------------------------------------------------------------------


class TestPCIDSSLogAndMonitor:
    """pci-req10: Sensitive content scanning with credit_card + cvv."""

    def test_scanning_disabled_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req10" in ids

    def test_scanning_enabled_with_both_patterns_passes(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["credit_card", "cvv", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req10"]
        assert len(findings) == 0

    def test_scanning_enabled_without_credit_card_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["cvv", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req10"]
        assert len(findings) == 1

    def test_scanning_enabled_without_cvv_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["credit_card", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req10"]
        assert len(findings) == 1

    def test_scanning_without_both_fails(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["ssn"],
            ),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req10"]
        assert len(findings) == 1
        # Should mention both missing patterns
        assert "credit_card" in findings[0].description
        assert "cvv" in findings[0].description

    def test_fix_enables_scanning(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req10")
        assert finding.fix is not None
        assert finding.fix.fix_type == "enable_sensitive_content"
        assert "credit_card" in finding.fix.params["patterns"]
        assert "cvv" in finding.fix.params["patterns"]

    def test_fix_adds_missing_patterns_only(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True,
                patterns=["credit_card"],
            ),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req10")
        assert finding.fix is not None
        # Should only add what's missing
        assert "cvv" in finding.fix.params["patterns"]


# ---------------------------------------------------------------------------
# Req. 3 — Protect Stored Data
# ---------------------------------------------------------------------------


class TestPCIDSSProtectStoredData:
    """pci-req3: Write-capable cardholder skills need write restrictions."""

    def test_write_capable_without_restriction_fails(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req3" in ids

    def test_write_restricted_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "stripe-payments": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req3"]
        assert len(findings) == 0

    def test_approval_satisfies(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="stripe-payments")],
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req3"]
        assert len(findings) == 0

    def test_read_only_skill_not_checked(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("list_charges", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req3"]
        assert len(findings) == 0

    def test_fix_adds_write_restriction(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req3")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["actions"]["write"] is False

    def test_denied_resource_counts_as_restriction(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "stripe-payments": ResourcePermissions.model_construct(
                        denied=True,
                        actions={},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req3"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Req. 8 — Identify and Authenticate
# ---------------------------------------------------------------------------


class TestPCIDSSAuthenticate:
    """pci-req8: Write-capable cardholder skills need human approval."""

    def test_write_capable_without_approval_fails(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req8" in ids

    def test_with_approval_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="stripe-payments")],
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req8"]
        assert len(findings) == 0

    def test_conditional_approval_satisfies(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        cond_rule = ApprovalRule.model_construct(
            tool_name=None,
            conditional=ConditionalApproval(
                tool="stripe-payments",
                when={},
            ),
        )
        policy = _minimal_policy(
            require_approval=[cond_rule],
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req8"]
        assert len(findings) == 0

    def test_read_only_not_checked(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("list_charges", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req8"]
        assert len(findings) == 0

    def test_fix_adds_approval_rule(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req8")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_approval_rule"
        assert finding.fix.params["tool_name"] == "stripe-payments"


# ---------------------------------------------------------------------------
# Req. 1 — Network Segmentation
# ---------------------------------------------------------------------------


class TestPCIDSSNetworkSegmentation:
    """pci-req1: Cardholder skills with network must control outbound."""

    def test_cd_with_network_no_block_fails(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req1" in ids

    def test_outbound_blocked_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "network": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req1"]
        assert len(findings) == 0

    def test_approval_satisfies_network(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            require_approval=[ApprovalRule(tool_name="stripe-payments")],
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req1"]
        assert len(findings) == 0

    def test_cd_without_network_not_checked(self) -> None:
        """Cardholder skill without NETWORK data type: network control doesn't apply."""
        scan = _scan(_server("cardholder-vault", [
            _perm("store", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req1"]
        assert len(findings) == 0

    def test_network_denied_passes(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "network": ResourcePermissions.model_construct(
                        denied=True,
                        actions={},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req1"]
        assert len(findings) == 0

    def test_fix_blocks_outbound(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req1")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_skill_restriction"
        assert finding.fix.params["resource_name"] == "network"
        assert finding.fix.params["actions"]["outbound"] is False


# ---------------------------------------------------------------------------
# Req. 7 — Least Privilege Isolation
# ---------------------------------------------------------------------------


class TestPCIDSSIsolation:
    """pci-req7.isolation: Cardholder skills must be isolated via chaining rules."""

    def test_cd_can_trigger_non_cd_fails(self) -> None:
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req7.isolation" in ids

    def test_chaining_blocks_any_passes(self) -> None:
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="stripe-payments", target_skill="any"),
            ],
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.isolation"]
        assert len(findings) == 0

    def test_chaining_blocks_specific_target_passes(self) -> None:
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="stripe-payments", target_skill="code-linter"),
            ],
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.isolation"]
        assert len(findings) == 0

    def test_no_non_cd_skills_passes(self) -> None:
        """If all skills are cardholder skills, no isolation finding."""
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("checkout-service", [_perm("process")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.isolation"]
        assert len(findings) == 0

    def test_fix_adds_chaining_rule(self) -> None:
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req7.isolation")
        assert finding.fix is not None
        assert finding.fix.fix_type == "add_chaining_rule"
        assert finding.fix.params["source_skill"] == "stripe-payments"
        assert finding.fix.params["target_skill"] == "any"

    def test_partial_chaining_still_fails(self) -> None:
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("code-linter", [_perm("lint")]),
            _server("file-server", [_perm("read_file")]),
        )
        policy = _minimal_policy(
            skill_chaining=[
                ChainingRule(source_skill="stripe-payments", target_skill="code-linter"),
            ],
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req7.isolation"]
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Req. 6 — Secure Default
# ---------------------------------------------------------------------------


class TestPCIDSSDefaultAction:
    """pci-req6.default: default_action should be block."""

    def test_default_allow_finds_recommendation(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        ids = [f.control_id for f in report.findings]
        assert "pci-req6.default" in ids

    def test_severity_is_recommended(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req6.default")
        assert finding.severity == ControlSeverity.RECOMMENDED

    def test_default_block_passes(self) -> None:
        policy = _minimal_policy(default_action="block")
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req6.default"]
        assert len(findings) == 0

    def test_fix_sets_default_block(self) -> None:
        policy = _minimal_policy()
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        finding = next(f for f in report.findings if f.control_id == "pci-req6.default")
        assert finding.fix is not None
        assert finding.fix.fix_type == "set_default_action"
        assert finding.fix.params["action"] == "block"


# ---------------------------------------------------------------------------
# Full evaluation and ratings
# ---------------------------------------------------------------------------


class TestPCIDSSEvaluateCompliance:
    """End-to-end evaluation tests."""

    def test_fully_compliant_policy(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _compliant_cd_policy("stripe-payments")
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert report.framework == "pci-dss"
        assert len(report.findings) == 0
        assert report.controls_passed == 8
        assert report.skill_ratings["stripe-payments"] == ComplianceRating.GREEN

    def test_no_cd_skills_all_pass(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy(
            default_action="block",
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["credit_card", "cvv", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert len(report.findings) == 0
        assert report.controls_passed == 8

    def test_cd_skill_gets_red_rating(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert report.skill_ratings.get("stripe-payments") == ComplianceRating.RED

    def test_yellow_rating_for_recommended_only(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(
                enabled=True, patterns=["credit_card", "cvv", "ssn"],
            ),
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert report.skill_ratings.get("code-linter") == ComplianceRating.GREEN


# ---------------------------------------------------------------------------
# Apply fixes
# ---------------------------------------------------------------------------


class TestPCIDSSApplyFixes:
    """Test that apply_fixes creates a compliant policy."""

    def test_fix_produces_compliant_policy(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)

        report2 = evaluate_compliance(fixed, scan, PCI_DSS_CONTROLS, "pci-dss")
        required_findings = [
            f for f in report2.findings if f.severity == ControlSeverity.REQUIRED
        ]
        assert len(required_findings) == 0

    def test_fix_adds_pci_zone(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        fixed = apply_fixes(policy, report.findings)
        assert "pci_zone" in fixed.data_boundaries
        assert fixed.data_boundaries["pci_zone"].classification == "cardholder_data"

    def test_fix_enables_sensitive_content_with_cvv(self) -> None:
        policy = _minimal_policy(
            sensitive_content=SensitiveContentConfig(enabled=False, patterns=[]),
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.sensitive_content.enabled is True
        assert "credit_card" in fixed.sensitive_content.patterns
        assert "cvv" in fixed.sensitive_content.patterns

    def test_fix_adds_approval_rule(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        fixed = apply_fixes(policy, report.findings)
        tool_names = {r.tool_name for r in fixed.require_approval if r.tool_name}
        assert "stripe-payments" in tool_names

    def test_fix_adds_chaining_rule(self) -> None:
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        fixed = apply_fixes(policy, report.findings)
        chain_pairs = {(r.source_skill, r.target_skill) for r in fixed.skill_chaining}
        assert ("stripe-payments", "any") in chain_pairs

    def test_fix_preserves_existing_boundaries(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
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
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        fixed = apply_fixes(policy, report.findings)
        assert "hipaa_zone" in fixed.data_boundaries
        assert "pci_zone" in fixed.data_boundaries

    def test_fix_merges_into_existing_pci_zone(self) -> None:
        scan = _scan(
            _server("stripe-payments", [_perm("charge")]),
            _server("checkout-service", [_perm("process")]),
        )
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["stripe-payments"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        fixed = apply_fixes(policy, report.findings)
        assert "checkout-service" in fixed.data_boundaries["pci_zone"].skills
        assert "stripe-payments" in fixed.data_boundaries["pci_zone"].skills


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


class TestPCIDSSReportRendering:
    """Verify report renders without errors."""

    def test_render_pci_report(self) -> None:
        from rich.console import Console

        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        console = Console(stderr=True, quiet=True)
        render_compliance_report(report, console)

    def test_render_pci_json(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _minimal_policy()
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        render_compliance_json(report)

    def test_render_compliant_report(self) -> None:
        from rich.console import Console

        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _compliant_cd_policy("stripe-payments")
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        console = Console(stderr=True, quiet=True)
        render_compliance_report(report, console)


# ---------------------------------------------------------------------------
# End-to-end with fixes
# ---------------------------------------------------------------------------


class TestPCIDSSEndToEnd:
    """Full pipeline: evaluate → fix → re-evaluate → all required pass."""

    def test_single_cd_skill_full_pipeline(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert report.controls_passed < 8

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, scan, PCI_DSS_CONTROLS, "pci-dss")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_multiple_cd_skills_full_pipeline(self) -> None:
        scan = _scan(
            _server("stripe-payments", [
                _perm("charge", [
                    _access(DataAccessType.FINANCIAL, write=True),
                    _access(DataAccessType.NETWORK, write=True),
                ], read_only=False),
            ]),
            _server("checkout-service", [
                _perm("process", [
                    _access(DataAccessType.FINANCIAL, write=True),
                    _access(DataAccessType.NETWORK, write=True),
                ], read_only=False),
            ]),
            _server("code-linter", [_perm("lint")]),
        )
        policy = _minimal_policy()

        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, scan, PCI_DSS_CONTROLS, "pci-dss")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0

    def test_already_compliant_no_changes(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        policy = _compliant_cd_policy("stripe-payments")
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        assert len(report.findings) == 0
        assert report.controls_passed == 8

    def test_cd_from_boundary_full_pipeline(self) -> None:
        """Skills identified as cardholder via data_boundaries should also pass after fix."""
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["custom-card-handler"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.LOG_ONLY,
                ),
            },
        )

        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        assert len(report.findings) > 0

        fixed = apply_fixes(policy, report.findings)
        report2 = evaluate_compliance(fixed, None, PCI_DSS_CONTROLS, "pci-dss")
        required = [f for f in report2.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0


# ---------------------------------------------------------------------------
# Cross-framework coexistence
# ---------------------------------------------------------------------------


class TestPCIDSSCrossFramework:
    """Verify PCI-DSS coexists with other frameworks."""

    def test_all_registered(self) -> None:
        import agentward.comply.frameworks.hipaa  # noqa: F401
        import agentward.comply.frameworks.gdpr  # noqa: F401
        import agentward.comply.frameworks.sox  # noqa: F401

        frameworks = available_frameworks()
        assert "hipaa" in frameworks
        assert "gdpr" in frameworks
        assert "sox" in frameworks
        assert "pci-dss" in frameworks

    def test_stripe_detected_as_both_financial_and_cardholder(self) -> None:
        """stripe-payments should be in both financial_skills and cardholder_data_skills."""
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "stripe-payments" in analysis.financial_skills
        assert "stripe-payments" in analysis.cardholder_data_skills

    def test_cardholder_skill_not_detected_as_phi(self) -> None:
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        analysis = build_skill_analysis(_minimal_policy(), scan)
        assert "stripe-payments" not in analysis.phi_skills


# ---------------------------------------------------------------------------
# Resource scoping
# ---------------------------------------------------------------------------


class TestPCIDSSResourceScoping:
    """Verify that only the skill's own resource counts for restrictions."""

    def test_unrelated_resource_does_not_satisfy_stored_data(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "some-other-resource": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"write": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req3"]
        assert len(findings) == 1

    def test_unrelated_resource_does_not_satisfy_network(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "unrelated": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req1"]
        assert len(findings) == 1

    def test_skill_own_resource_outbound_satisfies_network(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "stripe-payments": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"outbound": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        findings = [f for f in report.findings if f.control_id == "pci-req1"]
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Edge cases: integrity write/delete logic
# ---------------------------------------------------------------------------


class TestPCIDSSIntegrityWriteLogic:
    """Verify write: True + delete: False edge case in stored data checks."""

    def test_write_true_delete_false_does_not_satisfy(self) -> None:
        """write: true + delete: false does NOT satisfy stored data control."""
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "stripe-payments": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"write": True, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        stored_data_findings = [
            f for f in report.findings if f.control_id == "pci-req3"
        ]
        assert len(stored_data_findings) == 1  # write: true → not restricted

    def test_delete_false_alone_satisfies(self) -> None:
        """delete: false (write not mentioned) satisfies stored data control."""
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy(
            skills={
                "stripe-payments": {
                    "stripe-payments": ResourcePermissions.model_construct(
                        denied=False,
                        actions={"read": True, "delete": False},
                        filters={},
                    ),
                },
            },
        )
        report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        stored_data_findings = [
            f for f in report.findings if f.control_id == "pci-req3"
        ]
        assert len(stored_data_findings) == 0


# ---------------------------------------------------------------------------
# Boundary-only skills: write-capable assumption vs scan data
# ---------------------------------------------------------------------------


class TestPCIDSSBoundaryOnlySkills:
    """Verify boundary-only skill assumptions and scan data interaction."""

    def test_boundary_only_cd_triggers_stored_data_check(self) -> None:
        """Cardholder skill from boundary (no scan) assumed write-capable → stored data fires."""
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["custom-card-handler"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        stored_findings = [
            f for f in report.findings if f.control_id == "pci-req3"
        ]
        assert len(stored_findings) == 1
        assert stored_findings[0].skill == "custom-card-handler"

    def test_boundary_only_cd_triggers_auth_check(self) -> None:
        """Cardholder skill from boundary (no scan) assumed write-capable → auth fires."""
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["custom-card-handler"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        report = evaluate_compliance(policy, None, PCI_DSS_CONTROLS, "pci-dss")
        auth_findings = [
            f for f in report.findings if f.control_id == "pci-req8"
        ]
        assert len(auth_findings) == 1

    def test_boundary_with_scan_read_only_not_overridden(self) -> None:
        """If scan shows read-only, boundary should not override write_capable to True."""
        scan = _scan(_server("custom-card-handler", [
            _perm("list_cards", [_access(DataAccessType.FINANCIAL)]),
        ]))
        policy = _minimal_policy(
            data_boundaries={
                "pci_zone": DataBoundary(
                    skills=["custom-card-handler"],
                    classification="cardholder_data",
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        analysis = build_skill_analysis(policy, scan)
        # Scan says read-only → should be False despite boundary
        assert analysis.skill_write_capable["custom-card-handler"] is False


# ---------------------------------------------------------------------------
# Cross-framework fix composition
# ---------------------------------------------------------------------------


class TestPCIDSSCrossFrameworkFixComposition:
    """Verify PCI-DSS + SOX fixes compose correctly on overlapping skills."""

    def test_pci_and_sox_fixes_on_stripe_compose(self) -> None:
        """stripe-payments is both cardholder and financial — both frameworks' fixes apply."""
        from agentward.comply.frameworks.sox import SOX_CONTROLS

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

        # Apply PCI-DSS fixes
        pci_report = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        after_pci = apply_fixes(policy, pci_report.findings)

        # Apply SOX fixes on top
        sox_report = evaluate_compliance(after_pci, scan, SOX_CONTROLS, "sox")
        after_both = apply_fixes(after_pci, sox_report.findings)

        # Re-evaluate both — all required should pass
        pci_final = evaluate_compliance(after_both, scan, PCI_DSS_CONTROLS, "pci-dss")
        pci_required = [f for f in pci_final.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(pci_required) == 0

        sox_final = evaluate_compliance(after_both, scan, SOX_CONTROLS, "sox")
        sox_required = [f for f in sox_final.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(sox_required) == 0


# ---------------------------------------------------------------------------
# Apply fixes idempotency
# ---------------------------------------------------------------------------


class TestPCIDSSApplyFixesIdempotency:
    """Verify applying fixes twice produces the same result."""

    def test_double_fix_is_idempotent(self) -> None:
        scan = _scan(_server("stripe-payments", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL, write=True),
                _access(DataAccessType.NETWORK, write=True),
            ], read_only=False),
        ]))
        policy = _minimal_policy()

        report1 = evaluate_compliance(policy, scan, PCI_DSS_CONTROLS, "pci-dss")
        fixed1 = apply_fixes(policy, report1.findings)

        report2 = evaluate_compliance(fixed1, scan, PCI_DSS_CONTROLS, "pci-dss")
        fixed2 = apply_fixes(fixed1, report2.findings)

        # Second fix should produce no new changes (all required already pass)
        report3 = evaluate_compliance(fixed2, scan, PCI_DSS_CONTROLS, "pci-dss")
        required = [f for f in report3.findings if f.severity == ControlSeverity.REQUIRED]
        assert len(required) == 0
