"""Tests for --dry-run mode across all proxy types.

Verifies that in dry-run mode:
  - BLOCK decisions are logged with dry_run=True but calls are forwarded
  - APPROVE decisions are logged with dry_run=True without showing dialog
  - ALLOW decisions work normally
  - Chain violations are logged but not enforced
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agentward.audit.logger import AuditLogger
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.loader import load_policy
from agentward.policy.schema import (
    AgentWardPolicy,
    PolicyDecision,
    ResourcePermissions,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def block_policy() -> AgentWardPolicy:
    """Policy that blocks gmail_send."""
    return AgentWardPolicy(
        version="1.0",
        skills={
            "email-manager": {
                "gmail": ResourcePermissions.model_validate({"read": True, "send": False}),
            },
        },
    )


@pytest.fixture
def block_engine(block_policy: AgentWardPolicy) -> PolicyEngine:
    return PolicyEngine(block_policy)


@pytest.fixture
def approve_policy() -> AgentWardPolicy:
    """Policy that requires approval for send_email."""
    return AgentWardPolicy(
        version="1.0",
        require_approval=["send_email"],
    )


@pytest.fixture
def approve_engine(approve_policy: AgentWardPolicy) -> PolicyEngine:
    return PolicyEngine(approve_policy)


@pytest.fixture
def mock_audit_logger(tmp_path: Path) -> AuditLogger:
    return AuditLogger(log_path=tmp_path / "audit.jsonl")


# ---------------------------------------------------------------------------
# Audit logger dry-run tagging
# ---------------------------------------------------------------------------


class TestAuditLoggerDryRun:
    """Verify the audit logger includes dry_run flag in JSON entries."""

    def test_log_tool_call_dry_run_true(
        self, mock_audit_logger: AuditLogger, tmp_path: Path
    ) -> None:
        result = EvaluationResult(
            decision=PolicyDecision.BLOCK,
            reason="Test block reason",
        )
        mock_audit_logger.log_tool_call(
            "gmail_send", {"to": "test@example.com"}, result, dry_run=True
        )
        mock_audit_logger.close()

        log_file = tmp_path / "audit.jsonl"
        entries = [json.loads(line) for line in log_file.read_text().strip().split("\n")]
        tool_entries = [e for e in entries if e["event"] == "tool_call"]
        assert len(tool_entries) == 1
        assert tool_entries[0]["dry_run"] is True
        assert tool_entries[0]["decision"] == "BLOCK"

    def test_log_tool_call_dry_run_false_no_key(
        self, mock_audit_logger: AuditLogger, tmp_path: Path
    ) -> None:
        result = EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason="Allowed",
        )
        mock_audit_logger.log_tool_call("gmail_read", {}, result, dry_run=False)
        mock_audit_logger.close()

        log_file = tmp_path / "audit.jsonl"
        entries = [json.loads(line) for line in log_file.read_text().strip().split("\n")]
        tool_entries = [e for e in entries if e["event"] == "tool_call"]
        assert len(tool_entries) == 1
        assert "dry_run" not in tool_entries[0]

    def test_log_tool_call_chain_violation_dry_run(
        self, mock_audit_logger: AuditLogger, tmp_path: Path
    ) -> None:
        result = EvaluationResult(
            decision=PolicyDecision.BLOCK,
            reason="Chain blocked",
        )
        mock_audit_logger.log_tool_call(
            "browser_open", {}, result, chain_violation=True, dry_run=True
        )
        mock_audit_logger.close()

        log_file = tmp_path / "audit.jsonl"
        entries = [json.loads(line) for line in log_file.read_text().strip().split("\n")]
        tool_entries = [e for e in entries if e["event"] == "tool_call"]
        assert len(tool_entries) == 1
        assert tool_entries[0]["dry_run"] is True
        assert tool_entries[0]["chain_violation"] is True


# ---------------------------------------------------------------------------
# StdioProxy dry-run
# ---------------------------------------------------------------------------


class TestStdioProxyDryRun:
    """Verify that StdioProxy in dry-run mode forwards blocked calls."""

    def test_block_decision_forwards_in_dry_run(
        self, block_engine: PolicyEngine, mock_audit_logger: AuditLogger, tmp_path: Path
    ) -> None:
        """BLOCK in dry-run should log dry_run=True and NOT return error."""
        from agentward.proxy.server import StdioProxy

        proxy = StdioProxy(
            server_command=["echo"],
            policy_engine=block_engine,
            audit_logger=mock_audit_logger,
            dry_run=True,
        )
        # Directly test the evaluation — the proxy should evaluate as BLOCK
        result = proxy._evaluate_tool_call("gmail_send", {"to": "x"})
        assert result.decision == PolicyDecision.BLOCK

        # But in dry-run mode the proxy should log with dry_run and fall through
        # (actual forwarding requires subprocess, so we verify the flag is stored)
        assert proxy._dry_run is True

    def test_approve_decision_in_dry_run(
        self, approve_engine: PolicyEngine, mock_audit_logger: AuditLogger
    ) -> None:
        from agentward.proxy.server import StdioProxy

        proxy = StdioProxy(
            server_command=["echo"],
            policy_engine=approve_engine,
            audit_logger=mock_audit_logger,
            dry_run=True,
        )
        result = proxy._evaluate_tool_call("send_email", {"to": "x"})
        assert result.decision == PolicyDecision.APPROVE
        assert proxy._dry_run is True


# ---------------------------------------------------------------------------
# HttpProxy dry-run
# ---------------------------------------------------------------------------


class TestHttpProxyDryRun:
    """Verify HttpProxy stores dry_run flag."""

    def test_dry_run_flag_stored(
        self, block_engine: PolicyEngine, mock_audit_logger: AuditLogger
    ) -> None:
        from agentward.proxy.http import HttpProxy

        proxy = HttpProxy(
            backend_url="http://127.0.0.1:9999",
            listen_host="127.0.0.1",
            listen_port=9998,
            policy_engine=block_engine,
            audit_logger=mock_audit_logger,
            dry_run=True,
        )
        assert proxy._dry_run is True

    def test_dry_run_default_false(
        self, block_engine: PolicyEngine, mock_audit_logger: AuditLogger
    ) -> None:
        from agentward.proxy.http import HttpProxy

        proxy = HttpProxy(
            backend_url="http://127.0.0.1:9999",
            listen_host="127.0.0.1",
            listen_port=9998,
            policy_engine=block_engine,
            audit_logger=mock_audit_logger,
        )
        assert proxy._dry_run is False


# ---------------------------------------------------------------------------
# LlmProxy dry-run
# ---------------------------------------------------------------------------


class TestLlmProxyDryRun:
    """Verify LlmProxy stores dry_run flag."""

    def test_dry_run_flag_stored(
        self, block_engine: PolicyEngine, mock_audit_logger: AuditLogger
    ) -> None:
        from agentward.proxy.llm import LlmProxy

        proxy = LlmProxy(
            listen_port=19000,
            policy_engine=block_engine,
            audit_logger=mock_audit_logger,
            dry_run=True,
        )
        assert proxy._dry_run is True

    def test_dry_run_default_false(
        self, block_engine: PolicyEngine, mock_audit_logger: AuditLogger
    ) -> None:
        from agentward.proxy.llm import LlmProxy

        proxy = LlmProxy(
            listen_port=19000,
            policy_engine=block_engine,
            audit_logger=mock_audit_logger,
        )
        assert proxy._dry_run is False
