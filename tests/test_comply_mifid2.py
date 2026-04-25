"""Tests for the MiFID II / RTS 6 compliance framework.

Coverage matrix
---------------
Every control in MIFID2_CONTROLS has at least one positive (failure)
and one negative (pass) test, plus dedicated coverage of the
trading-skill detection helper.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentward.comply.controls import (
    ComplianceRating,
    ControlSeverity,
    apply_fixes,
    evaluate_compliance,
)
from agentward.comply.frameworks import available_frameworks, get_framework
from agentward.comply.frameworks.mifid2 import (
    MIFID2_CONTROLS,
    _get_trading_skills,
)
from agentward.comply.controls import build_skill_analysis
from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalRule,
    ChainingRule,
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
    fields: dict[str, object] = {"version": "1.0"}
    fields.update(kwargs)
    return AgentWardPolicy(**fields)


def _control_ids(report) -> list[str]:
    return [f.control_id for f in report.findings]


# ---------------------------------------------------------------------------
# Framework registry
# ---------------------------------------------------------------------------


class TestRegistry:
    def test_mifid2_is_registered(self) -> None:
        assert "mifid2" in available_frameworks()

    def test_get_returns_controls(self) -> None:
        controls = get_framework("mifid2")
        assert controls is MIFID2_CONTROLS
        assert len(controls) == 10

    def test_case_insensitive_lookup(self) -> None:
        assert get_framework("MIFID2") == MIFID2_CONTROLS
        assert get_framework("MiFID2") == MIFID2_CONTROLS

    def test_control_ids_unique(self) -> None:
        ids = [c.control_id for c in MIFID2_CONTROLS]
        assert len(ids) == len(set(ids))

    def test_control_ids_are_namespaced(self) -> None:
        for c in MIFID2_CONTROLS:
            assert c.control_id.startswith("mifid2-")

    def test_severity_distribution(self) -> None:
        required = [c for c in MIFID2_CONTROLS if c.severity == ControlSeverity.REQUIRED]
        recommended = [c for c in MIFID2_CONTROLS if c.severity == ControlSeverity.RECOMMENDED]
        assert len(required) >= 6
        assert len(recommended) >= 2


# ---------------------------------------------------------------------------
# Trading-skill detection
# ---------------------------------------------------------------------------


class TestTradingSkillDetection:
    """Verify _get_trading_skills covers all three detection paths."""

    def test_via_financial_skills_set(self) -> None:
        # 'stripe-payments' matches existing _FINANCIAL_NAME_PATTERNS
        scan = _scan(_server("stripe-payments", [_perm("charge")]))
        analysis = build_skill_analysis(_bare(), scan)
        assert "stripe-payments" in _get_trading_skills(_bare(), analysis)

    def test_via_trading_token_pattern(self) -> None:
        # Tokenized whole-word matches
        for name in [
            "trading-engine",
            "broker-api",
            "venue-router",
            "execution-service",
            "blotter-service",
            "rfq-handler",
            "exchange-feed",
            "darkpool-router",
            "oms-bridge",
            "liquidity-monitor",
        ]:
            scan = _scan(_server(name, [_perm("op")]))
            analysis = build_skill_analysis(_bare(), scan)
            trading = _get_trading_skills(_bare(), analysis)
            assert name in trading, f"expected {name} to be detected as trading"

    def test_via_phrase_pattern(self) -> None:
        # Multi-word phrase matches via substring
        for name in [
            "smart-order-routing",
            "market-data-feed",
            "market-maker-bot",
            "matching-engine",
            "order-management-system",
            "dark-pool-bridge",
        ]:
            scan = _scan(_server(name, [_perm("op")]))
            analysis = build_skill_analysis(_bare(), scan)
            trading = _get_trading_skills(_bare(), analysis)
            assert name in trading, f"expected {name} to be detected as trading"

    def test_via_fix_protocol_prefix(self) -> None:
        # `fix-` prefix — FIX protocol gateways
        for name in [
            "fix-gateway",
            "fix-engine",
            "fix-acceptor",
            "fix-initiator",
        ]:
            scan = _scan(_server(name, [_perm("op")]))
            analysis = build_skill_analysis(_bare(), scan)
            trading = _get_trading_skills(_bare(), analysis)
            assert name in trading, f"expected {name} to be detected as trading"

    def test_unrelated_name_not_detected(self) -> None:
        for name in ["calendar", "weather-service", "code-linter", "logger"]:
            scan = _scan(_server(name, [_perm("op")]))
            analysis = build_skill_analysis(_bare(), scan)
            assert name not in _get_trading_skills(_bare(), analysis)

    def test_via_explicit_boundary_classification(self) -> None:
        for label in ["trading", "mifid", "mifid2", "rts6"]:
            policy = _bare(data_boundaries={
                "z": DataBoundary(
                    skills=["custom-svc"],
                    classification=label,
                    rules=[],
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            })
            analysis = build_skill_analysis(policy, None)
            assert "custom-svc" in _get_trading_skills(policy, analysis)

    def test_fix_prefix_does_not_match_embedded_fix(self) -> None:
        # `fix-` is anchored to the start; must not match `bug-fix-tool`
        for name in ["bug-fix-tool", "auto-fix-helper", "quick-fix-utility"]:
            scan = _scan(_server(name, [_perm("op")]))
            analysis = build_skill_analysis(_bare(), scan)
            assert name not in _get_trading_skills(_bare(), analysis), (
                f"false positive: {name} should not be detected as trading"
            )

    def test_underscore_separator_tokenized(self) -> None:
        # Names with underscore separators tokenize the same way
        scan = _scan(_server("trading_engine", [_perm("op")]))
        analysis = build_skill_analysis(_bare(), scan)
        assert "trading_engine" in _get_trading_skills(_bare(), analysis)


# ---------------------------------------------------------------------------
# RTS 6 Art. 1 — Governance
# ---------------------------------------------------------------------------


class TestGovernance:
    def test_default_allow_fails(self) -> None:
        policy = _bare(default_action=DefaultAction.ALLOW)
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.governance" in _control_ids(report)

    def test_default_block_passes(self) -> None:
        policy = _bare(default_action=DefaultAction.BLOCK)
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.governance" not in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 12 — Trading-skill access control
# ---------------------------------------------------------------------------


class TestTradingAccessControl:
    def test_trading_skill_without_entry_fails(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        finds = [f for f in report.findings if f.control_id == "mifid2-rts6.access"]
        assert len(finds) == 1
        assert finds[0].skill == "trading-engine"

    def test_non_trading_skill_no_finding(self) -> None:
        scan = _scan(_server("calendar", [_perm("create")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.access" not in _control_ids(report)

    def test_trading_skill_with_entry_passes(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(skills={
            "trading-engine": {
                "trading-engine": ResourcePermissions.model_construct(
                    denied=False, actions={"read": True, "write": False}, filters={},
                ),
            },
        })
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.access" not in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 13 — Pre-trade controls
# ---------------------------------------------------------------------------


class TestPreTradeControls:
    def test_write_capable_trading_without_approval_fails(self) -> None:
        scan = _scan(_server("oms-bridge", [
            _perm("submit_order", [
                _access(DataAccessType.NETWORK, write=True),
            ]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        finds = [f for f in report.findings if f.control_id == "mifid2-rts6.pre-trade"]
        assert len(finds) == 1
        assert finds[0].skill == "oms-bridge"

    def test_write_capable_trading_with_approval_passes(self) -> None:
        scan = _scan(_server("oms-bridge", [
            _perm("submit_order", [
                _access(DataAccessType.NETWORK, write=True),
            ]),
        ]))
        policy = _bare(require_approval=[ApprovalRule(tool_name="oms-bridge")])
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.pre-trade" not in _control_ids(report)

    def test_read_only_trading_no_finding(self) -> None:
        scan = _scan(_server("market-data-feed", [
            _perm("subscribe", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.pre-trade" not in _control_ids(report)

    def test_non_trading_skill_no_finding(self) -> None:
        scan = _scan(_server("filesystem", [
            _perm("write_file", [_access(DataAccessType.FILESYSTEM, write=True)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.pre-trade" not in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 13 — Outbound order routing
# ---------------------------------------------------------------------------


class TestOutboundRouting:
    def test_network_trading_without_outbound_block_fails(self) -> None:
        scan = _scan(_server("venue-router", [
            _perm("route", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.outbound" in _control_ids(report)

    def test_with_outbound_block_passes(self) -> None:
        scan = _scan(_server("venue-router", [
            _perm("route", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare(skills={
            "venue-router": {
                "network": ResourcePermissions.model_construct(
                    denied=False, actions={"outbound": False}, filters={},
                ),
            },
        })
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.outbound" not in _control_ids(report)

    def test_with_approval_passes(self) -> None:
        scan = _scan(_server("venue-router", [
            _perm("route", [_access(DataAccessType.NETWORK)]),
        ]))
        policy = _bare(require_approval=[ApprovalRule(tool_name="venue-router")])
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.outbound" not in _control_ids(report)

    def test_non_network_trading_skill_no_finding(self) -> None:
        scan = _scan(_server("blotter-service", [
            _perm("read", [_access(DataAccessType.FILESYSTEM)]),
        ]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.outbound" not in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 18 — Boundary
# ---------------------------------------------------------------------------


class TestBoundary:
    def test_trading_without_boundary_fails(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        finds = [f for f in report.findings if f.control_id == "mifid2-rts6.boundary"]
        assert len(finds) == 1

    def test_trading_with_blocking_boundary_passes(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(data_boundaries={
            "z": DataBoundary(
                skills=["trading-engine"],
                classification="trading",
                rules=["x"],
                on_violation=ViolationAction.BLOCK_AND_LOG,
            ),
        })
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.boundary" not in _control_ids(report)

    def test_log_only_boundary_still_fails(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(data_boundaries={
            "z": DataBoundary(
                skills=["trading-engine"],
                classification="trading",
                rules=["x"],
                on_violation=ViolationAction.LOG_ONLY,
            ),
        })
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.boundary" in _control_ids(report)

    def test_non_trading_classification_does_not_cover(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(data_boundaries={
            "z": DataBoundary(
                skills=["trading-engine"],
                classification="phi",  # wrong label
                rules=["x"],
                on_violation=ViolationAction.BLOCK_AND_LOG,
            ),
        })
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.boundary" in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 16 — Segregation
# ---------------------------------------------------------------------------


class TestSegregation:
    def test_trading_with_open_chain_fails(self) -> None:
        scan = _scan(
            _server("trading-engine", [_perm("place")]),
            _server("logger", [_perm("write")]),
        )
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        finds = [f for f in report.findings if f.control_id == "mifid2-rts6.segregation"]
        assert any(f.skill == "trading-engine" for f in finds)

    def test_trading_with_block_any_passes(self) -> None:
        scan = _scan(
            _server("trading-engine", [_perm("place")]),
            _server("logger", [_perm("write")]),
        )
        policy = _bare(skill_chaining=[
            ChainingRule(source_skill="trading-engine", target_skill="any"),
        ])
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        finds = [f for f in report.findings if f.control_id == "mifid2-rts6.segregation"]
        assert all(f.skill != "trading-engine" for f in finds)

    def test_no_non_trading_skills_no_finding(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.segregation" not in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 28 — Record-keeping audit
# ---------------------------------------------------------------------------


class TestAudit:
    def test_default_passes(self) -> None:
        policy = _bare()
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.audit" not in _control_ids(report)

    def test_explicit_path_passes(self) -> None:
        from agentward.policy.schema import AuditConfig
        policy = _bare(audit=AuditConfig(syslog_path="/var/log/agentward.syslog"))
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.audit" not in _control_ids(report)

    def test_empty_path_fails(self) -> None:
        from agentward.policy.schema import AuditConfig
        policy = _bare(audit=AuditConfig(syslog_path=""))
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.audit" in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 1 — Credential leak detection
# ---------------------------------------------------------------------------


class TestCredentialDetection:
    def test_disabled_fails(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(enabled=False))
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.credential-detection" in _control_ids(report)

    def test_enabled_with_api_key_passes(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(
            enabled=True, patterns=["api_key"],
        ))
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.credential-detection" not in _control_ids(report)

    def test_enabled_without_api_key_fails(self) -> None:
        policy = _bare(sensitive_content=SensitiveContentConfig(
            enabled=True, patterns=["credit_card"],
        ))
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.credential-detection" in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 16 — Chain depth (only fires when trading skills exist)
# ---------------------------------------------------------------------------


class TestChainDepth:
    def test_no_trading_skills_no_finding(self) -> None:
        # No trading skills → chain-depth control is silent
        policy = _bare(skill_chain_depth=None)
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.chain-depth" not in _control_ids(report)

    def test_trading_skills_unbounded_fails(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(skill_chain_depth=None)
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.chain-depth" in _control_ids(report)

    def test_trading_skills_bounded_passes(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(skill_chain_depth=3)
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.chain-depth" not in _control_ids(report)


# ---------------------------------------------------------------------------
# RTS 6 Art. 14 — Real-time monitoring
# ---------------------------------------------------------------------------


class TestMonitoring:
    def test_no_trading_skills_no_finding(self) -> None:
        policy = _bare(baseline_check=False)
        report = evaluate_compliance(policy, None, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.monitoring" not in _control_ids(report)

    def test_trading_skills_baseline_off_fails(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(baseline_check=False)
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.monitoring" in _control_ids(report)

    def test_trading_skills_baseline_on_passes(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(baseline_check=True)
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert "mifid2-rts6.monitoring" not in _control_ids(report)


# ---------------------------------------------------------------------------
# Auto-fix coverage
# ---------------------------------------------------------------------------


class TestAutoFix:
    def test_round_trip_resolves_all_required(self) -> None:
        """Empty policy + trading scan → after fix, no REQUIRED findings remain."""
        scan = _scan(
            _server("trading-engine", [
                _perm("submit", [
                    _access(DataAccessType.NETWORK, write=True),
                ]),
            ]),
            _server("market-data-feed", [
                _perm("subscribe", [_access(DataAccessType.NETWORK)]),
            ]),
        )
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        fixed = apply_fixes(policy, report.findings)
        re_report = evaluate_compliance(fixed, scan, MIFID2_CONTROLS, "mifid2")
        required = [
            f for f in re_report.findings
            if f.severity == ControlSeverity.REQUIRED
        ]
        assert required == [], f"Remaining: {required}"

    def test_chain_depth_set_to_three(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(skill_chain_depth=None)
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.skill_chain_depth == 3

    def test_baseline_check_enabled(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare(baseline_check=False)
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        fixed = apply_fixes(policy, report.findings)
        assert fixed.baseline_check is True

    def test_boundary_classification_is_trading(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        policy = _bare()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        fixed = apply_fixes(policy, report.findings)
        assert "mifid2_zone" in fixed.data_boundaries
        boundary = fixed.data_boundaries["mifid2_zone"]
        assert "trading-engine" in boundary.skills
        assert boundary.classification == "trading"


# ---------------------------------------------------------------------------
# End-to-end compliant baseline
# ---------------------------------------------------------------------------


def _compliant_trading_policy() -> AgentWardPolicy:
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        skill_chain_depth=3,
        baseline_check=True,
        sensitive_content=SensitiveContentConfig(
            enabled=True, patterns=["api_key", "credit_card"],
        ),
        skills={
            "trading-engine": {
                "trading-engine": ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False, "delete": False},
                    filters={},
                ),
                "network": ResourcePermissions.model_construct(
                    denied=False, actions={"outbound": False}, filters={},
                ),
            },
        },
        require_approval=[ApprovalRule(tool_name="trading-engine")],
        skill_chaining=[
            ChainingRule(source_skill="trading-engine", target_skill="any"),
        ],
        data_boundaries={
            "mifid2_zone": DataBoundary(
                skills=["trading-engine"],
                classification="trading",
                rules=["trading_data cannot flow outside mifid2_zone"],
                on_violation=ViolationAction.BLOCK_AND_LOG,
            ),
        },
    )


class TestCompliantBaseline:
    def test_all_required_pass(self) -> None:
        scan = _scan(_server("trading-engine", [
            _perm("submit", [
                _access(DataAccessType.NETWORK, write=True),
            ]),
        ]))
        policy = _compliant_trading_policy()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        required = [
            f for f in report.findings
            if f.severity == ControlSeverity.REQUIRED
        ]
        assert required == []

    def test_compliant_skill_rating_green(self) -> None:
        scan = _scan(_server("trading-engine", [
            _perm("submit", [
                _access(DataAccessType.NETWORK, write=True),
            ]),
        ]))
        policy = _compliant_trading_policy()
        report = evaluate_compliance(policy, scan, MIFID2_CONTROLS, "mifid2")
        assert report.skill_ratings.get("trading-engine") == ComplianceRating.GREEN
