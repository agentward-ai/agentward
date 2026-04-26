"""Tests for the Evidence Pack HTML exporter."""

from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from agentward.audit.integrity import AuditChain
from agentward.comply.controls import (
    ComplianceFinding,
    ComplianceRating,
    ComplianceReport,
    ControlSeverity,
    PolicyFix,
)
from agentward.policy.schema import (
    AgentWardPolicy,
    DefaultAction,
    ResourcePermissions,
    SkillMetadata,
    SubcontractorEntry,
)
from agentward.report import EvidencePack, build_evidence_pack
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


def _policy_with_metadata() -> AgentWardPolicy:
    return AgentWardPolicy(
        version="1.0",
        default_action=DefaultAction.BLOCK,
        skills={
            "github": {
                "github": ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": False},
                    filters={},
                ),
            },
        },
        skill_metadata={
            "github": SkillMetadata(
                owner="platform-team@example.com",
                subcontractor_chain=[
                    SubcontractorEntry(
                        vendor="GitHub Inc.",
                        role="repo hosting",
                        data_residency="US",
                        contract_status="standard-tos",
                    ),
                ],
            ),
        },
    )


def _scan_with_one_server() -> ScanResult:
    return ScanResult(
        servers=[
            ServerPermissionMap(
                server=ServerConfig(
                    name="github",
                    transport=TransportType.STDIO,
                    command="ghx",
                    client="cursor",
                    source_file=Path("/tmp/mcp.json"),
                ),
                enumeration_method="live",
                tools=[
                    ToolPermission(
                        tool=ToolInfo(name="search_repos", description="t", input_schema={}),
                        data_access=[
                            DataAccess(type=DataAccessType.NETWORK, read=True, write=False, reason="t"),
                        ],
                        risk_level=RiskLevel.LOW,
                        risk_reasons=["t"],
                        is_destructive=False,
                        is_read_only=True,
                    ),
                ],
                overall_risk=RiskLevel.LOW,
            ),
        ],
        config_sources=[],
        scan_timestamp="2026-04-25T00:00:00Z",
    )


def _report_with_findings() -> ComplianceReport:
    findings = [
        ComplianceFinding(
            control_id="dora-art5.governance",
            skill=None,
            description="default_action must be 'block'.",
            fix=PolicyFix(fix_type="set_default_action", params={"action": "block"}),
            severity=ControlSeverity.REQUIRED,
        ),
        ComplianceFinding(
            control_id="dora-art28.subcontractor-chain",
            skill="github",
            description="Missing subcontractor chain.",
            fix=None,
            severity=ControlSeverity.RECOMMENDED,
        ),
    ]
    return ComplianceReport(
        framework="dora",
        findings=findings,
        skill_ratings={"github": ComplianceRating.YELLOW},
    )


def _empty_report() -> ComplianceReport:
    return ComplianceReport(
        framework="dora",
        findings=[],
        skill_ratings={"github": ComplianceRating.GREEN},
    )


def _write_signed_log(path: Path, key: bytes, decisions: list[str]) -> None:
    chain = AuditChain(key=key)
    with path.open("w", encoding="utf-8") as f:
        for decision in decisions:
            entry: dict[str, Any] = {
                "event": "tool_call",
                "tool": "github",
                "decision": decision,
            }
            chain.sign(entry)
            f.write(json.dumps(entry) + "\n")


def _validates_as_html(s: str) -> bool:
    """A loose HTML well-formedness check — parser doesn't raise."""

    class V(HTMLParser):
        def __init__(self) -> None:
            super().__init__()
            self.errors: list[str] = []

        def error(self, message: str) -> None:  # type: ignore[override]
            self.errors.append(message)

    v = V()
    v.feed(s)
    return not v.errors


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class TestBuildEvidencePack:
    def test_minimal_pack(self, tmp_path: Path) -> None:
        policy = _policy_with_metadata()
        pack = build_evidence_pack(
            policy,
            policy_path=tmp_path / "agentward.yaml",
            reports={"dora": _empty_report()},
        )
        assert isinstance(pack, EvidencePack)
        assert pack.frameworks == ["dora"]
        assert pack.scan_result is None
        assert pack.audit_verification is None
        assert pack.policy is policy

    def test_with_scan_inventory(self, tmp_path: Path) -> None:
        scan = _scan_with_one_server()
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
            scan_result=scan,
        )
        assert pack.scan_result is scan
        assert "github" in pack.to_html()
        assert "search_repos" in pack.to_html()

    def test_audit_log_missing_path_does_not_crash(self, tmp_path: Path) -> None:
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
            audit_log_path=tmp_path / "missing.jsonl",
        )
        assert pack.audit_verification is not None
        assert pack.audit_verification.total_lines == 0

    def test_audit_log_signed_chain_verifies(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_signed_log(log, b"k1", ["ALLOW", "BLOCK", "APPROVE"])
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
            audit_log_path=log,
            hmac_key=b"k1",
        )
        assert pack.audit_verification is not None
        assert pack.audit_verification.total_lines == 3
        assert pack.audit_verification.signed_lines == 3
        assert pack.audit_verification.ok is True
        assert len(pack.audit_recent_entries) == 3

    def test_audit_log_tamper_detected(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_signed_log(log, b"k1", ["ALLOW", "BLOCK", "APPROVE"])
        # Rewrite line 2 without re-signing
        lines = log.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["decision"] = "ALLOW"
        lines[1] = json.dumps(entry)
        log.write_text("\n".join(lines) + "\n")

        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
            audit_log_path=log,
            hmac_key=b"k1",
        )
        assert pack.audit_verification is not None
        assert pack.audit_verification.ok is False
        assert pack.audit_verification.first_break == 2

    def test_recent_entry_limit(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_signed_log(log, b"k1", ["ALLOW"] * 10)
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
            audit_log_path=log,
            hmac_key=b"k1",
            recent_entry_limit=3,
        )
        assert len(pack.audit_recent_entries) == 3
        assert pack.audit_recent_count == 10


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


class TestHtmlRendering:
    def test_html_is_well_formed(self, tmp_path: Path) -> None:
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _report_with_findings()},
            scan_result=_scan_with_one_server(),
        )
        html = pack.to_html()
        assert _validates_as_html(html)
        assert html.startswith("<!DOCTYPE html>")
        assert "<title>" in html

    def test_html_contains_policy_owner(self, tmp_path: Path) -> None:
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
        )
        html = pack.to_html()
        assert "platform-team@example.com" in html
        assert "GitHub Inc." in html
        assert "repo hosting" in html

    def test_html_contains_findings(self, tmp_path: Path) -> None:
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _report_with_findings()},
        )
        html = pack.to_html()
        assert "dora-art5.governance" in html
        assert "dora-art28.subcontractor-chain" in html
        assert "REQUIRED" in html
        assert "RECOMMENDED" in html
        assert "auto-fix available" in html
        assert "manual fix required" in html

    def test_html_no_external_assets(self, tmp_path: Path) -> None:
        # Self-contained: no external script/link/img references.
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _report_with_findings()},
            scan_result=_scan_with_one_server(),
        )
        html = pack.to_html()
        assert "<script" not in html
        assert "src=" not in html
        # No external <link rel="stylesheet"> — we only inline CSS.
        assert 'rel="stylesheet"' not in html
        assert 'href="http' not in html
        assert 'src="http' not in html

    def test_html_escapes_user_input(self, tmp_path: Path) -> None:
        # Ensure HTML special characters from policy/scan are escaped
        # to avoid injection into the generated document.
        policy = AgentWardPolicy(
            version="1.0",
            default_action=DefaultAction.BLOCK,
            skills={"<script>alert(1)</script>": {}},
            skill_metadata={
                "<script>alert(1)</script>": SkillMetadata(
                    owner="<b>boss</b>",
                ),
            },
        )
        pack = build_evidence_pack(
            policy,
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
        )
        html = pack.to_html()
        # Raw <script> tags from policy must not appear unescaped.
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
        assert "<b>boss</b>" not in html
        assert "&lt;b&gt;boss&lt;/b&gt;" in html

    def test_audit_section_present_when_log_supplied(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        _write_signed_log(log, b"k1", ["ALLOW", "BLOCK"])
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
            audit_log_path=log,
            hmac_key=b"k1",
        )
        html = pack.to_html()
        assert "Audit Log Integrity" in html
        assert "All 2 signed entries verified" in html

    def test_audit_section_absent_message_when_no_log(self, tmp_path: Path) -> None:
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={"dora": _empty_report()},
        )
        html = pack.to_html()
        assert "Audit Log Integrity" in html
        assert "No audit log path supplied" in html

    def test_summary_cards_show_per_framework(self, tmp_path: Path) -> None:
        pack = build_evidence_pack(
            _policy_with_metadata(),
            policy_path=tmp_path / "p.yaml",
            reports={
                "dora": _report_with_findings(),
                "mifid2": _empty_report(),
            },
        )
        html = pack.to_html()
        assert "DORA" in html
        assert "MIFID2" in html
        assert "REQUIRED GAPS" in html  # dora has required findings
        assert "CLEAN" in html  # mifid2 has none


# ---------------------------------------------------------------------------
# CLI command end-to-end
# ---------------------------------------------------------------------------


class TestCliCommand:
    def test_report_command_runs(self, tmp_path: Path, monkeypatch) -> None:
        # Avoid scan auto-discovery; we only want policy-level output.
        from typer.testing import CliRunner

        from agentward.cli import app

        policy_path = tmp_path / "agentward.yaml"
        policy_path.write_text(
            "version: \"1.0\"\n"
            "default_action: block\n"
            "baseline_check: true\n"
            "sensitive_content:\n"
            "  enabled: true\n"
            "  patterns: [api_key]\n"
        )

        # Provide an empty target directory so scan finds nothing fast.
        scan_target = tmp_path / "empty"
        scan_target.mkdir()

        runner = CliRunner()
        out = tmp_path / "evidence.html"
        result = runner.invoke(
            app,
            [
                "report",
                "-o", str(out),
                "-p", str(policy_path),
                "--frameworks", "dora",
                str(scan_target),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "DORA" in html

    def test_report_command_unknown_framework_errors(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        policy_path = tmp_path / "agentward.yaml"
        policy_path.write_text("version: \"1.0\"\n")
        scan_target = tmp_path / "empty"
        scan_target.mkdir()

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "report",
                "-o", str(tmp_path / "x.html"),
                "-p", str(policy_path),
                "--frameworks", "nonexistent_framework",
                str(scan_target),
            ],
        )
        assert result.exit_code != 0
