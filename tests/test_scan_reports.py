"""Tests for HTML and SARIF scan report generators.

Covers:
  - HTML report generation (structure, score badge, tables)
  - SARIF report generation (schema compliance, rule IDs, results)
  - Edge cases (empty scans, no recommendations)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentward.scan.chains import ChainDetection, ChainRisk
from agentward.scan.html_report import generate_scan_html, _compute_score
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
from agentward.scan.recommendations import Recommendation, RecommendationSeverity
from agentward.scan.sarif_report import generate_sarif


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_scan(tools: list[tuple[str, RiskLevel, list[DataAccessType]]]) -> ScanResult:
    """Build a ScanResult with the given tools on a single server."""
    tool_perms = []
    for name, risk, access_types in tools:
        tool_perms.append(
            ToolPermission(
                tool=ToolInfo(
                    name=name,
                    description=f"Test tool {name}",
                    input_schema={},
                ),
                risk_level=risk,
                risk_reasons=[f"Test reason for {name}"],
                data_access=[DataAccess(type=at, reason="test") for at in access_types],
            )
        )

    server = ServerPermissionMap(
        server=ServerConfig(
            name="test-server",
            command="test",
            transport=TransportType.STDIO,
            source_file=Path("/tmp/test-config.json"),
            client="test",
        ),
        enumeration_method="test",
        tools=tool_perms,
    )
    return ScanResult(servers=[server])


def _make_chain() -> ChainDetection:
    return ChainDetection(
        source_server="email-manager",
        target_server="web-browser",
        risk=ChainRisk.HIGH,
        label="email-manager → web-browser",
        description="Email content could leak via browsing",
        attack_vector="Attacker sends email with URL...",
    )


def _make_recommendation() -> Recommendation:
    return Recommendation(
        target="test-server/gmail_send",
        severity=RecommendationSeverity.WARNING,
        message="Consider blocking email send capability.",
        suggested_policy="require_approval:\n  - gmail_send",
    )


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


class TestHtmlReport:
    """Test HTML report generation."""

    def test_basic_html_structure(self) -> None:
        scan = _make_scan([
            ("gmail_read", RiskLevel.LOW, [DataAccessType.EMAIL]),
            ("shell_exec", RiskLevel.CRITICAL, [DataAccessType.SHELL]),
        ])
        html = generate_scan_html(scan, [])

        assert "<!DOCTYPE html>" in html
        assert "AgentWard Scan Report" in html
        assert "Permission Map" in html
        assert "gmail_read" in html
        assert "shell_exec" in html

    def test_score_badge_present(self) -> None:
        scan = _make_scan([
            ("test_tool", RiskLevel.LOW, [DataAccessType.FILESYSTEM]),
        ])
        html = generate_scan_html(scan, [])

        assert "Security Score" in html
        assert "<svg" in html

    def test_risk_colors_in_table(self) -> None:
        scan = _make_scan([
            ("crit_tool", RiskLevel.CRITICAL, [DataAccessType.SHELL]),
        ])
        html = generate_scan_html(scan, [])

        assert "#ff3366" in html  # CRITICAL color
        assert "CRITICAL" in html

    def test_chains_included(self) -> None:
        scan = _make_scan([("tool_a", RiskLevel.LOW, [])])
        chains = [_make_chain()]
        html = generate_scan_html(scan, [], chains=chains)

        assert "Skill Chains Detected" in html
        assert "email-manager" in html

    def test_recommendations_included(self) -> None:
        scan = _make_scan([("tool_a", RiskLevel.LOW, [])])
        recs = [_make_recommendation()]
        html = generate_scan_html(scan, recs)

        assert "Recommendations" in html
        assert "gmail_send" in html

    def test_empty_scan(self) -> None:
        scan = ScanResult(servers=[])
        html = generate_scan_html(scan, [])

        assert "<!DOCTYPE html>" in html
        assert "No tools found" in html

    def test_html_escaping(self) -> None:
        """Verify tool names with special chars are escaped."""
        scan = _make_scan([
            ("<script>alert(1)</script>", RiskLevel.HIGH, []),
        ])
        html = generate_scan_html(scan, [])

        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html


class TestComputeScore:
    """Test security score computation."""

    def test_perfect_score(self) -> None:
        counts = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 5,
        }
        assert _compute_score(counts, 0) == 100

    def test_critical_deduction(self) -> None:
        counts = {
            RiskLevel.CRITICAL: 2,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0,
        }
        assert _compute_score(counts, 0) == 60  # 100 - 2*20

    def test_mixed_deductions(self) -> None:
        counts = {
            RiskLevel.CRITICAL: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 10,
        }
        # 100 - 20 - 20 - 9 = 51
        assert _compute_score(counts, 0) == 51

    def test_chains_deduction(self) -> None:
        counts = {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0,
        }
        assert _compute_score(counts, 4) == 80  # 100 - 4*5

    def test_floor_at_zero(self) -> None:
        counts = {
            RiskLevel.CRITICAL: 10,
            RiskLevel.HIGH: 0,
            RiskLevel.MEDIUM: 0,
            RiskLevel.LOW: 0,
        }
        assert _compute_score(counts, 0) == 0


# ---------------------------------------------------------------------------
# SARIF report
# ---------------------------------------------------------------------------


class TestSarifReport:
    """Test SARIF report generation."""

    def test_basic_sarif_structure(self) -> None:
        scan = _make_scan([
            ("shell_exec", RiskLevel.HIGH, [DataAccessType.SHELL]),
        ])
        sarif_str = generate_sarif(scan, [])
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "AgentWard"

    def test_high_tool_produces_result(self) -> None:
        scan = _make_scan([
            ("shell_exec", RiskLevel.HIGH, [DataAccessType.SHELL]),
        ])
        sarif = json.loads(generate_sarif(scan, []))
        results = sarif["runs"][0]["results"]

        assert len(results) == 1
        assert "shell_exec" in results[0]["message"]["text"]
        assert results[0]["level"] == "warning"

    def test_critical_tool_is_error(self) -> None:
        scan = _make_scan([
            ("rm_rf", RiskLevel.CRITICAL, [DataAccessType.SHELL]),
        ])
        sarif = json.loads(generate_sarif(scan, []))
        results = sarif["runs"][0]["results"]

        assert results[0]["level"] == "error"

    def test_low_tool_excluded(self) -> None:
        scan = _make_scan([
            ("safe_tool", RiskLevel.LOW, [DataAccessType.FILESYSTEM]),
        ])
        sarif = json.loads(generate_sarif(scan, []))
        results = sarif["runs"][0]["results"]

        assert len(results) == 0

    def test_chains_in_sarif(self) -> None:
        scan = _make_scan([])
        chains = [_make_chain()]
        sarif = json.loads(generate_sarif(scan, [], chains=chains))
        results = sarif["runs"][0]["results"]

        chain_results = [r for r in results if "chain" in r["ruleId"]]
        assert len(chain_results) == 1
        assert "email-manager" in chain_results[0]["message"]["text"]

    def test_recommendations_in_sarif(self) -> None:
        scan = _make_scan([])
        recs = [_make_recommendation()]
        sarif = json.loads(generate_sarif(scan, recs))
        results = sarif["runs"][0]["results"]

        rec_results = [r for r in results if "recommendation" in r["ruleId"]]
        assert len(rec_results) == 1
        assert "blocking email send" in rec_results[0]["message"]["text"]
        # Target is used for artifact location, not message
        assert rec_results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "test-server/gmail_send"

    def test_rules_are_deduplicated(self) -> None:
        scan = _make_scan([
            ("tool_a", RiskLevel.HIGH, []),
            ("tool_b", RiskLevel.HIGH, []),
        ])
        sarif = json.loads(generate_sarif(scan, []))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]

        rule_ids = [r["id"] for r in rules]
        assert len(rule_ids) == len(set(rule_ids))  # No duplicates

    def test_empty_scan(self) -> None:
        scan = ScanResult(servers=[])
        sarif = json.loads(generate_sarif(scan, []))

        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
