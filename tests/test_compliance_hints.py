"""Tests for the compliance-framework suggester used by ``agentward scan``."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

from agentward.scan.compliance_hints import (
    FrameworkSuggestion,
    suggest_frameworks,
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


# ---------------------------------------------------------------------------
# Empty / non-regulated case
# ---------------------------------------------------------------------------


class TestEmptyAndNonRegulated:
    def test_empty_scan_returns_no_suggestions(self) -> None:
        scan = _scan()
        assert suggest_frameworks(scan) == []

    def test_pure_dev_skills_no_suggestions(self) -> None:
        scan = _scan(
            _server("code-linter", [_perm("lint")]),
            _server("calendar", [_perm("create_event")]),
        )
        # Two servers with no NETWORK access and no regulated patterns
        # → no framework suggestions.
        assert suggest_frameworks(scan) == []


# ---------------------------------------------------------------------------
# Per-framework triggers
# ---------------------------------------------------------------------------


class TestHIPAATrigger:
    def test_phi_skill_triggers_hipaa(self) -> None:
        scan = _scan(_server("ehr-connector", [_perm("read_chart")]))
        suggestions = suggest_frameworks(scan)
        ids = {s.framework for s in suggestions}
        assert "hipaa" in ids

    def test_hipaa_carries_triggering_skill(self) -> None:
        scan = _scan(_server("clinical-notes", [_perm("read")]))
        suggestion = next(s for s in suggest_frameworks(scan) if s.framework == "hipaa")
        assert "clinical-notes" in suggestion.triggering_skills
        assert suggestion.command == "agentward comply --framework hipaa"

    def test_no_phi_no_hipaa(self) -> None:
        scan = _scan(_server("code-linter", [_perm("lint")]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "hipaa" not in ids


class TestMiFID2Trigger:
    def test_trading_skill_triggers_mifid2(self) -> None:
        scan = _scan(_server("trading-engine", [
            _perm("place", [_access(DataAccessType.NETWORK)]),
        ]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "mifid2" in ids

    def test_fix_gateway_triggers_mifid2(self) -> None:
        scan = _scan(_server("fix-gateway", [_perm("send")]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "mifid2" in ids

    def test_unrelated_skill_no_mifid2(self) -> None:
        scan = _scan(_server("calendar", [_perm("create")]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "mifid2" not in ids

    def test_bug_fix_tool_does_not_trigger_mifid2(self) -> None:
        scan = _scan(_server("bug-fix-tool", [_perm("op")]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "mifid2" not in ids


class TestPCIDSSTrigger:
    def test_payment_skill_triggers_pci(self) -> None:
        scan = _scan(_server("stripe-checkout", [
            _perm("charge", [
                _access(DataAccessType.FINANCIAL),
                _access(DataAccessType.NETWORK),
            ]),
        ]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "pci_dss" in ids


class TestGDPRTrigger:
    def test_email_skill_triggers_gdpr(self) -> None:
        scan = _scan(_server("gmail", [
            _perm("read_inbox", [_access(DataAccessType.EMAIL)]),
        ]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "gdpr" in ids

    def test_messaging_skill_triggers_gdpr(self) -> None:
        scan = _scan(_server("slack", [
            _perm("read", [_access(DataAccessType.MESSAGING)]),
        ]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "gdpr" in ids


class TestSOXTrigger:
    def test_financial_skill_triggers_sox(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "sox" in ids


class TestDORATrigger:
    def test_financial_skill_triggers_dora(self) -> None:
        scan = _scan(_server("finance-tracker", [_perm("get_balance")]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "dora" in ids

    def test_trading_skill_triggers_dora(self) -> None:
        scan = _scan(_server("trading-engine", [_perm("place")]))
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "dora" in ids

    def test_three_network_servers_triggers_dora(self) -> None:
        # Broad-scope DORA trigger: substantive third-party ICT estate
        scan = _scan(
            _server("svc-a", [_perm("op", [_access(DataAccessType.NETWORK)])]),
            _server("svc-b", [_perm("op", [_access(DataAccessType.NETWORK)])]),
            _server("svc-c", [_perm("op", [_access(DataAccessType.NETWORK)])]),
        )
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "dora" in ids

    def test_two_network_servers_does_not_trigger_dora(self) -> None:
        # Two network servers is not yet the broad-scope trigger
        scan = _scan(
            _server("svc-a", [_perm("op", [_access(DataAccessType.NETWORK)])]),
            _server("svc-b", [_perm("op", [_access(DataAccessType.NETWORK)])]),
        )
        ids = {s.framework for s in suggest_frameworks(scan)}
        assert "dora" not in ids

    def test_dora_reason_distinguishes_trigger_type(self) -> None:
        # Financial trigger emits a different reason from broad-ict trigger
        fin_scan = _scan(_server("finance-tracker", [_perm("op")]))
        broad_scan = _scan(
            _server("svc-a", [_perm("op", [_access(DataAccessType.NETWORK)])]),
            _server("svc-b", [_perm("op", [_access(DataAccessType.NETWORK)])]),
            _server("svc-c", [_perm("op", [_access(DataAccessType.NETWORK)])]),
        )
        fin_dora = next(s for s in suggest_frameworks(fin_scan) if s.framework == "dora")
        broad_dora = next(s for s in suggest_frameworks(broad_scan) if s.framework == "dora")
        assert "financial/trading" in fin_dora.reason
        assert "third-party" in broad_dora.reason


# ---------------------------------------------------------------------------
# Ordering and serialization
# ---------------------------------------------------------------------------


class TestOrdering:
    def test_canonical_order(self) -> None:
        # Trigger HIPAA + GDPR + SOX + DORA simultaneously and check ordering.
        scan = _scan(
            _server("ehr-connector", [_perm("read")]),  # → HIPAA
            _server("crm-bridge", [_perm("read", [_access(DataAccessType.EMAIL)])]),  # → GDPR
            _server("finance-tracker", [_perm("op")]),  # → SOX + DORA
        )
        suggestions = suggest_frameworks(scan)
        order = [s.framework for s in suggestions]
        # Expected order subset based on canonical priority:
        # hipaa < gdpr < sox < dora  (mifid2 + pci_dss not triggered)
        assert order.index("hipaa") < order.index("gdpr")
        assert order.index("gdpr") < order.index("sox")
        assert order.index("sox") < order.index("dora")


class TestSerialization:
    def test_to_dict_roundtrip(self) -> None:
        suggestion = FrameworkSuggestion(
            framework="hipaa",
            display_name="HIPAA",
            reason="reason",
            triggering_skills=("ehr",),
            command="agentward comply --framework hipaa",
        )
        data = suggestion.to_dict()
        # Must be JSON-serializable
        encoded = json.dumps(data)
        decoded = json.loads(encoded)
        assert decoded["framework"] == "hipaa"
        assert decoded["triggering_skills"] == ["ehr"]
        assert decoded["display_name"] == "HIPAA"


# ---------------------------------------------------------------------------
# Integration with print_scan_json — suggestions appear in JSON output
# ---------------------------------------------------------------------------


class TestJSONIntegration:
    def test_json_output_includes_suggestions(self) -> None:
        from agentward.scan.report import print_scan_json

        scan = _scan(_server("trading-engine", [_perm("place")]))
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, color_system=None)
        print_scan_json(scan, console)

        data = json.loads(buf.getvalue())
        assert "compliance_suggestions" in data
        ids = {s["framework"] for s in data["compliance_suggestions"]}
        assert "mifid2" in ids
        assert "dora" in ids

    def test_json_output_empty_when_nothing_relevant(self) -> None:
        from agentward.scan.report import print_scan_json

        scan = _scan(_server("calendar", [_perm("create")]))
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, color_system=None)
        print_scan_json(scan, console)

        data = json.loads(buf.getvalue())
        assert data["compliance_suggestions"] == []


# ---------------------------------------------------------------------------
# Integration with markdown report
# ---------------------------------------------------------------------------


class TestMarkdownIntegration:
    def test_markdown_includes_compliance_section_when_triggered(self) -> None:
        from agentward.scan.report import generate_scan_markdown

        scan = _scan(_server("trading-engine", [_perm("place")]))
        md = generate_scan_markdown(scan, recommendations=[])
        assert "## Compliance Frameworks Worth Evaluating" in md
        assert "MiFID II" in md
        assert "agentward comply --framework mifid2" in md

    def test_markdown_omits_compliance_section_when_silent(self) -> None:
        from agentward.scan.report import generate_scan_markdown

        scan = _scan(_server("calendar", [_perm("create")]))
        md = generate_scan_markdown(scan, recommendations=[])
        assert "## Compliance Frameworks Worth Evaluating" not in md
