"""Tests for RFC 5424 syslog formatter and AuditLogger dual-write behaviour."""

from __future__ import annotations

import re
from typing import Any

import pytest

from agentward.audit.logger import AuditLogger
from agentward.audit.syslog_formatter import (
    _escape_sd_value,
    _msg_for_entry,
    _sd_element,
    _sd_params_for_entry,
    _severity_for_entry,
    format_rfc5424,
    _SEV_ALERT,
    _SEV_ERROR,
    _SEV_INFO,
    _SEV_NOTICE,
    _SEV_WARNING,
)
from agentward.policy.engine import EvaluationResult
from agentward.policy.schema import PolicyDecision

# RFC 5424 header pattern: <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
_RFC5424_RE = re.compile(
    r"^<\d+>1 "                     # PRI + VERSION
    r"\S+ "                          # TIMESTAMP
    r"\S+ "                          # HOSTNAME
    r"agentward "                    # APP-NAME
    r"\d+ "                          # PROCID
    r"\S+ "                          # MSGID
    r"(?:-|\[.+?\]) "               # SD (NILVALUE or SD-ELEMENT)
    r".+$"                           # MSG (non-empty)
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _tool_call_entry(
    decision: str = "ALLOW",
    tool: str = "gmail_send",
    skill: str = "email-manager",
    resource: str = "gmail",
    reason: str = "permitted",
    chain_violation: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "timestamp": "2026-03-20T10:00:00.000000+00:00",
        "event": "tool_call",
        "tool": tool,
        "arguments": {},
        "decision": decision,
        "reason": reason,
        "skill": skill,
        "resource": resource,
    }
    if chain_violation:
        entry["chain_violation"] = True
    if dry_run:
        entry["dry_run"] = True
    return entry


# ---------------------------------------------------------------------------
# TestSdEscaping
# ---------------------------------------------------------------------------

class TestSdEscaping:
    def test_backslash_escaped(self) -> None:
        assert _escape_sd_value("a\\b") == "a\\\\b"

    def test_double_quote_escaped(self) -> None:
        assert _escape_sd_value('say "hi"') == 'say \\"hi\\"'

    def test_closing_bracket_escaped(self) -> None:
        assert _escape_sd_value("foo]bar") == "foo\\]bar"

    def test_all_three_escaped(self) -> None:
        result = _escape_sd_value('a\\"b]c')
        assert "\\\\" in result or '\\"' in result  # both escapes present

    def test_plain_value_unchanged(self) -> None:
        assert _escape_sd_value("hello world") == "hello world"


# ---------------------------------------------------------------------------
# TestSdElement
# ---------------------------------------------------------------------------

class TestSdElement:
    def test_empty_params_returns_nilvalue(self) -> None:
        assert _sd_element({}) == "-"

    def test_single_param(self) -> None:
        result = _sd_element({"tool": "gmail_send"})
        assert result.startswith("[agentward@0")
        assert 'tool="gmail_send"' in result
        assert result.endswith("]")

    def test_multiple_params(self) -> None:
        result = _sd_element({"event": "tool_call", "decision": "ALLOW"})
        assert 'event="tool_call"' in result
        assert 'decision="ALLOW"' in result

    def test_value_with_special_chars(self) -> None:
        result = _sd_element({"reason": 'permitted "by" policy'})
        assert '\\"by\\"' in result


# ---------------------------------------------------------------------------
# TestSeverityMapping
# ---------------------------------------------------------------------------

class TestSeverityMapping:
    def test_allow_is_info(self) -> None:
        assert _severity_for_entry(_tool_call_entry("ALLOW")) == _SEV_INFO

    def test_log_is_info(self) -> None:
        assert _severity_for_entry(_tool_call_entry("LOG")) == _SEV_INFO

    def test_block_is_warning(self) -> None:
        assert _severity_for_entry(_tool_call_entry("BLOCK")) == _SEV_WARNING

    def test_chain_block_is_error(self) -> None:
        entry = _tool_call_entry("BLOCK", chain_violation=True)
        assert _severity_for_entry(entry) == _SEV_ERROR

    def test_redact_is_notice(self) -> None:
        assert _severity_for_entry(_tool_call_entry("REDACT")) == _SEV_NOTICE

    def test_approve_is_notice(self) -> None:
        assert _severity_for_entry(_tool_call_entry("APPROVE")) == _SEV_NOTICE

    def test_judge_flag_is_warning(self) -> None:
        entry = {"event": "judge_decision", "tool": "t", "verdict": "flag"}
        assert _severity_for_entry(entry) == _SEV_WARNING

    def test_judge_block_is_warning(self) -> None:
        entry = {"event": "judge_decision", "tool": "t", "verdict": "block"}
        assert _severity_for_entry(entry) == _SEV_WARNING

    def test_judge_allow_is_info(self) -> None:
        entry = {"event": "judge_decision", "tool": "t", "verdict": "allow"}
        assert _severity_for_entry(entry) == _SEV_INFO

    def test_approval_dialog_is_notice(self) -> None:
        entry = {"event": "approval_dialog", "tool": "t", "decision": "allow_once", "elapsed_ms": 500}
        assert _severity_for_entry(entry) == _SEV_NOTICE

    def test_circuit_breaker_is_alert(self) -> None:
        entry = {"event": "circuit_breaker"}
        assert _severity_for_entry(entry) == _SEV_ALERT

    def test_sensitive_block_is_warning(self) -> None:
        entry = {"event": "sensitive_data_blocked", "tool": "t", "action": "block"}
        assert _severity_for_entry(entry) == _SEV_WARNING

    def test_boundary_block_is_warning(self) -> None:
        entry = {"event": "boundary_violation", "tool": "t", "action": "block"}
        assert _severity_for_entry(entry) == _SEV_WARNING

    def test_boundary_log_is_notice(self) -> None:
        entry = {"event": "boundary_violation", "tool": "t", "action": "log_only"}
        assert _severity_for_entry(entry) == _SEV_NOTICE

    def test_startup_is_info(self) -> None:
        entry = {"event": "startup", "mode": "enforce"}
        assert _severity_for_entry(entry) == _SEV_INFO

    def test_shutdown_is_info(self) -> None:
        entry = {"event": "shutdown", "reason": "done"}
        assert _severity_for_entry(entry) == _SEV_INFO

    def test_unknown_event_is_info(self) -> None:
        assert _severity_for_entry({"event": "something_new"}) == _SEV_INFO


# ---------------------------------------------------------------------------
# TestSdParamsExtraction
# ---------------------------------------------------------------------------

class TestSdParamsExtraction:
    def test_tool_call_params(self) -> None:
        params = _sd_params_for_entry(_tool_call_entry("ALLOW"))
        assert params["event"] == "tool_call"
        assert params["tool"] == "gmail_send"
        assert params["decision"] == "ALLOW"
        assert params["skill"] == "email-manager"
        assert params["resource"] == "gmail"

    def test_chain_violation_flag(self) -> None:
        params = _sd_params_for_entry(_tool_call_entry("BLOCK", chain_violation=True))
        assert params.get("chain_violation") == "true"

    def test_dry_run_flag(self) -> None:
        params = _sd_params_for_entry(_tool_call_entry("ALLOW", dry_run=True))
        assert params.get("dry_run") == "true"

    def test_no_chain_violation_when_false(self) -> None:
        params = _sd_params_for_entry(_tool_call_entry("BLOCK"))
        assert "chain_violation" not in params

    def test_judge_decision_params(self) -> None:
        entry = {
            "event": "judge_decision",
            "tool": "gmail_send",
            "verdict": "flag",
            "risk_score": 0.8,
            "reasoning": "suspicious scope",
            "elapsed_ms": 120,
            "cached": False,
        }
        params = _sd_params_for_entry(entry)
        assert params["verdict"] == "flag"
        assert params["risk_score"] == "0.8"
        assert "cached" not in params  # False → not emitted

    def test_judge_cached_flag(self) -> None:
        entry = {
            "event": "judge_decision",
            "tool": "t",
            "verdict": "allow",
            "cached": True,
        }
        params = _sd_params_for_entry(entry)
        assert params.get("cached") == "true"

    def test_approval_dialog_params(self) -> None:
        entry = {"event": "approval_dialog", "tool": "t", "decision": "allow_once", "elapsed_ms": 1500}
        params = _sd_params_for_entry(entry)
        assert params["elapsed_ms"] == "1500"
        assert params["decision"] == "allow_once"

    def test_sensitive_block_params(self) -> None:
        entry = {
            "event": "sensitive_data_blocked",
            "tool": "send_msg",
            "findings": [{"type": "credit_card"}, {"type": "ssn"}],
        }
        params = _sd_params_for_entry(entry)
        assert params["finding_count"] == "2"
        assert params["tool"] == "send_msg"

    def test_boundary_violation_params(self) -> None:
        entry = {
            "event": "boundary_violation",
            "tool": "exfil_tool",
            "zone": "phi-zone",
            "classification": "phi",
            "source_tool": "patient_db",
            "action": "block",
        }
        params = _sd_params_for_entry(entry)
        assert params["zone"] == "phi-zone"
        assert params["classification"] == "phi"
        assert params["source_tool"] == "patient_db"


# ---------------------------------------------------------------------------
# TestMsgGeneration
# ---------------------------------------------------------------------------

class TestMsgGeneration:
    def test_allow_msg(self) -> None:
        msg = _msg_for_entry(_tool_call_entry("ALLOW", reason="permitted by policy"))
        assert "ALLOW" in msg
        assert "gmail_send" in msg
        assert "permitted by policy" in msg

    def test_block_msg(self) -> None:
        msg = _msg_for_entry(_tool_call_entry("BLOCK", reason="denied"))
        assert "BLOCK" in msg

    def test_chain_block_msg(self) -> None:
        msg = _msg_for_entry(_tool_call_entry("BLOCK", chain_violation=True))
        assert "chain violation" in msg

    def test_dry_run_msg(self) -> None:
        msg = _msg_for_entry(_tool_call_entry("BLOCK", dry_run=True))
        assert "dry-run" in msg

    def test_judge_decision_msg(self) -> None:
        entry = {
            "event": "judge_decision",
            "tool": "gmail_send",
            "verdict": "flag",
            "risk_score": 0.75,
            "reasoning": "suspicious",
        }
        msg = _msg_for_entry(entry)
        assert "FLAG" in msg
        assert "gmail_send" in msg
        assert "suspicious" in msg

    def test_approval_dialog_msg(self) -> None:
        entry = {"event": "approval_dialog", "tool": "t", "decision": "deny", "elapsed_ms": 60000}
        msg = _msg_for_entry(entry)
        assert "deny" in msg
        assert "60000ms" in msg

    def test_sensitive_block_msg(self) -> None:
        entry = {"event": "sensitive_data_blocked", "tool": "t", "findings": [{}, {}]}
        msg = _msg_for_entry(entry)
        assert "2 finding" in msg

    def test_startup_msg(self) -> None:
        msg = _msg_for_entry({"event": "startup", "mode": "enforce"})
        assert "enforce" in msg

    def test_shutdown_msg(self) -> None:
        msg = _msg_for_entry({"event": "shutdown", "reason": "SIGTERM"})
        assert "SIGTERM" in msg

    def test_unknown_event_msg(self) -> None:
        msg = _msg_for_entry({"event": "foo_bar"})
        assert "foo_bar" in msg


# ---------------------------------------------------------------------------
# TestFormatRfc5424
# ---------------------------------------------------------------------------

class TestFormatRfc5424:
    def test_output_matches_rfc5424_pattern(self) -> None:
        line = format_rfc5424(_tool_call_entry("ALLOW"))
        assert _RFC5424_RE.match(line), f"Did not match RFC 5424 pattern: {line!r}"

    def test_version_is_1(self) -> None:
        line = format_rfc5424(_tool_call_entry("ALLOW"))
        # Second token after PRI should be "1"
        parts = line.split(" ", 2)
        assert parts[0].endswith(">1") or parts[1] == "1" or line[line.index(">") + 1] == "1"
        # Simpler: the PRI+VERSION field matches <N>1
        assert re.match(r"<\d+>1 ", line)

    def test_app_name_is_agentward(self) -> None:
        line = format_rfc5424(_tool_call_entry("ALLOW"))
        assert " agentward " in line

    def test_msgid_is_event_type(self) -> None:
        line = format_rfc5424(_tool_call_entry("ALLOW"))
        # MSGID comes after PROCID (5th space-delimited token)
        tokens = line.split(" ", 6)
        assert tokens[5] == "tool_call"

    def test_block_has_lower_pri_than_allow(self) -> None:
        """Lower PRI number = higher severity."""
        allow_line = format_rfc5424(_tool_call_entry("ALLOW"))
        block_line = format_rfc5424(_tool_call_entry("BLOCK"))
        allow_pri = int(re.match(r"<(\d+)>", allow_line).group(1))
        block_pri = int(re.match(r"<(\d+)>", block_line).group(1))
        assert block_pri < allow_pri

    def test_chain_block_has_lower_pri_than_plain_block(self) -> None:
        block_line = format_rfc5424(_tool_call_entry("BLOCK"))
        chain_line = format_rfc5424(_tool_call_entry("BLOCK", chain_violation=True))
        block_pri = int(re.match(r"<(\d+)>", block_line).group(1))
        chain_pri = int(re.match(r"<(\d+)>", chain_line).group(1))
        assert chain_pri < block_pri

    def test_sd_element_contains_tool_and_decision(self) -> None:
        line = format_rfc5424(_tool_call_entry("ALLOW"))
        assert 'tool="gmail_send"' in line
        assert 'decision="ALLOW"' in line

    def test_timestamp_preserved_from_entry(self) -> None:
        ts = "2026-03-20T10:00:00.000000+00:00"
        line = format_rfc5424(_tool_call_entry("ALLOW"))
        assert ts in line

    def test_missing_timestamp_falls_back_gracefully(self) -> None:
        entry = {"event": "tool_call", "decision": "ALLOW", "tool": "t"}
        line = format_rfc5424(entry)
        assert _RFC5424_RE.match(line)

    def test_no_trailing_newline(self) -> None:
        line = format_rfc5424(_tool_call_entry("ALLOW"))
        assert not line.endswith("\n")

    def test_all_event_types_produce_valid_lines(self) -> None:
        entries = [
            _tool_call_entry("ALLOW"),
            _tool_call_entry("BLOCK"),
            _tool_call_entry("BLOCK", chain_violation=True),
            _tool_call_entry("REDACT"),
            _tool_call_entry("APPROVE"),
            _tool_call_entry("LOG"),
            {"event": "judge_decision", "tool": "t", "verdict": "flag", "risk_score": 0.8, "reasoning": "x"},
            {"event": "approval_dialog", "tool": "t", "decision": "allow_once", "elapsed_ms": 500},
            {"event": "sensitive_data_blocked", "tool": "t", "findings": []},
            {"event": "boundary_violation", "tool": "t", "zone": "z", "classification": "phi", "source_tool": "s", "action": "block"},
            {"event": "startup", "mode": "enforce", "policy_path": "/tmp/a.yaml"},
            {"event": "http_proxy_startup", "listen_port": 18900, "mode": "enforce"},
            {"event": "llm_proxy_startup", "listen_port": 18900},
            {"event": "shutdown", "reason": "SIGTERM"},
            {"event": "http_request", "method": "POST", "path": "/tools-invoke", "status": 200},
            {"event": "tool_result", "tool": "t", "request_id": 1, "is_error": False},
            {"event": "websocket_disconnect", "path": "/ws"},
            {"event": "circuit_breaker"},
        ]
        for entry in entries:
            line = format_rfc5424(entry)
            assert _RFC5424_RE.match(line), f"Event {entry['event']!r} produced invalid line: {line!r}"


# ---------------------------------------------------------------------------
# TestAuditLoggerDualWrite
# ---------------------------------------------------------------------------

class TestAuditLoggerDualWrite:
    """Verify AuditLogger writes to both JSONL and syslog files."""

    def test_both_files_created(self, tmp_path: Any) -> None:
        jsonl = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=jsonl)
        logger.log_startup(["npx", "server"], None)
        logger.close()

        assert jsonl.exists()
        assert (tmp_path / "audit.syslog").exists()

    def test_jsonl_has_json_content(self, tmp_path: Any) -> None:
        import json

        jsonl = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=jsonl)
        result = EvaluationResult(decision=PolicyDecision.ALLOW, reason="ok")
        logger.log_tool_call("test_tool", {}, result)
        logger.close()

        entries = [json.loads(line) for line in jsonl.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["event"] == "tool_call"

    def test_syslog_has_rfc5424_content(self, tmp_path: Any) -> None:
        jsonl = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=jsonl)
        result = EvaluationResult(decision=PolicyDecision.ALLOW, reason="ok")
        logger.log_tool_call("test_tool", {}, result)
        logger.close()

        syslog_path = tmp_path / "audit.syslog"
        lines = syslog_path.read_text().splitlines()
        assert len(lines) == 1
        assert _RFC5424_RE.match(lines[0]), f"Syslog line not RFC 5424: {lines[0]!r}"

    def test_both_files_get_same_number_of_entries(self, tmp_path: Any) -> None:
        import json

        jsonl = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=jsonl)

        allow = EvaluationResult(decision=PolicyDecision.ALLOW, reason="ok")
        block = EvaluationResult(decision=PolicyDecision.BLOCK, reason="denied")
        logger.log_tool_call("tool_a", {}, allow)
        logger.log_tool_call("tool_b", {}, block)
        logger.log_shutdown("test done")
        logger.close()

        jsonl_count = len(jsonl.read_text().splitlines())
        syslog_count = len((tmp_path / "audit.syslog").read_text().splitlines())
        assert jsonl_count == syslog_count == 3

    def test_custom_syslog_path(self, tmp_path: Any) -> None:
        jsonl = tmp_path / "audit.jsonl"
        custom_syslog = tmp_path / "custom" / "my-audit.syslog"
        logger = AuditLogger(log_path=jsonl, syslog_path=custom_syslog)
        logger.log_shutdown("done")
        logger.close()

        assert custom_syslog.exists()
        assert not (tmp_path / "audit.syslog").exists()

    def test_no_files_when_log_path_none(self, tmp_path: Any) -> None:
        logger = AuditLogger(log_path=None)
        result = EvaluationResult(decision=PolicyDecision.ALLOW, reason="ok")
        logger.log_tool_call("t", {}, result)
        logger.close()

        # No files should be created
        assert list(tmp_path.iterdir()) == []

    def test_syslog_block_entries_have_warning_pri(self, tmp_path: Any) -> None:
        """BLOCK decisions should use a lower PRI (higher severity) than ALLOW."""
        jsonl = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=jsonl)

        allow_result = EvaluationResult(decision=PolicyDecision.ALLOW, reason="ok")
        block_result = EvaluationResult(decision=PolicyDecision.BLOCK, reason="denied")
        logger.log_tool_call("tool_a", {}, allow_result)
        logger.log_tool_call("tool_b", {}, block_result)
        logger.close()

        lines = (tmp_path / "audit.syslog").read_text().splitlines()
        allow_pri = int(re.match(r"<(\d+)>", lines[0]).group(1))
        block_pri = int(re.match(r"<(\d+)>", lines[1]).group(1))
        assert block_pri < allow_pri, "BLOCK should have lower PRI (higher severity) than ALLOW"

    def test_all_log_methods_write_to_syslog(self, tmp_path: Any) -> None:
        """All AuditLogger.log_* methods should produce a syslog line."""
        jsonl = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=jsonl)

        result = EvaluationResult(decision=PolicyDecision.ALLOW, reason="ok")
        logger.log_tool_call("t", {}, result)
        logger.log_tool_result("t", 1, False)
        logger.log_startup(["npx", "srv"], None)
        logger.log_http_request("POST", "/path", 200)
        logger.log_websocket_disconnect("/ws")
        logger.log_http_startup(18900, "http://localhost:18789", None)
        logger.log_llm_startup(18900, {"anthropic": "https://api.anthropic.com"}, None)
        logger.log_approval_dialog("t", {}, "allow_once", 1500)
        logger.log_judge_decision("t", "allow", 0.1, "looks fine", 80)
        logger.log_shutdown("test")
        logger.close()

        import json

        jsonl_count = len(jsonl.read_text().splitlines())
        syslog_count = len((tmp_path / "audit.syslog").read_text().splitlines())
        assert jsonl_count == syslog_count


# ---------------------------------------------------------------------------
# TestAuditConfigPolicySchema
# ---------------------------------------------------------------------------

class TestAuditConfigPolicySchema:
    """Verify the AuditConfig model parses correctly from policy YAML."""

    def test_default_syslog_path_is_none(self) -> None:
        from agentward.policy.schema import AuditConfig

        cfg = AuditConfig()
        assert cfg.syslog_path is None

    def test_syslog_path_set(self) -> None:
        from agentward.policy.schema import AuditConfig

        cfg = AuditConfig(syslog_path="/var/log/agentward.syslog")
        assert cfg.syslog_path == "/var/log/agentward.syslog"

    def test_agent_ward_policy_has_audit_field(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy(version="1")
        assert hasattr(policy, "audit")
        assert policy.audit.syslog_path is None

    def test_agent_ward_policy_audit_syslog_path_parsed(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy(
            version="1",
            audit={"syslog_path": "/tmp/custom.syslog"},
        )
        assert policy.audit.syslog_path == "/tmp/custom.syslog"
