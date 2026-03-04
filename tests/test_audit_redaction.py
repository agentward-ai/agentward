"""Tests for audit log redaction (fix #5).

Verifies that sensitive data in tool arguments is redacted before
writing to the JSONL audit log.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agentward.audit.logger import AuditLogger, _redact_for_audit
from agentward.policy.engine import EvaluationResult
from agentward.policy.schema import PolicyDecision


class TestRedactForAudit:
    """Test the _redact_for_audit helper function."""

    def test_clean_arguments_unchanged(self) -> None:
        args = {"url": "https://example.com", "method": "GET"}
        result = _redact_for_audit(args)
        assert result == args

    def test_credit_card_redacted(self) -> None:
        args = {"text": "pay with 4111 1111 1111 1111"}
        result = _redact_for_audit(args)
        assert "4111 1111 1111 1111" not in result["text"]
        assert "REDACTED" in result["text"]

    def test_ssn_redacted(self) -> None:
        args = {"body": "ssn: 123-45-6789"}
        result = _redact_for_audit(args)
        assert "123-45-6789" not in result["body"]
        assert "REDACTED" in result["body"]

    def test_api_key_redacted(self) -> None:
        args = {"token": "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"}
        result = _redact_for_audit(args)
        assert "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" not in result["token"]
        assert "REDACTED" in result["token"]

    def test_nested_redaction(self) -> None:
        args = {"data": {"payment": {"card": "4111111111111111"}}}
        result = _redact_for_audit(args)
        assert "4111111111111111" not in str(result)
        assert "REDACTED" in str(result)

    def test_empty_arguments(self) -> None:
        assert _redact_for_audit({}) == {}

    def test_original_not_modified(self) -> None:
        args = {"text": "pay with 4111 1111 1111 1111"}
        _redact_for_audit(args)
        assert "4111 1111 1111 1111" in args["text"]  # original unchanged


class TestAuditLogRedaction:
    """Test that the AuditLogger writes redacted arguments to JSONL."""

    def test_log_tool_call_redacts_sensitive_data(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file)

        result = EvaluationResult(decision=PolicyDecision.ALLOW, reason="test")
        args = {"message": "card number is 4111111111111111", "to": "user@example.com"}
        logger.log_tool_call("send_message", args, result)
        logger.close()

        entries = [json.loads(line) for line in log_file.read_text().splitlines()]
        assert len(entries) == 1
        # Card number must NOT appear in audit log
        assert "4111111111111111" not in json.dumps(entries[0])
        assert "REDACTED" in json.dumps(entries[0])
        # Non-sensitive data preserved
        assert entries[0]["arguments"]["to"] == "user@example.com"

    def test_log_tool_call_clean_data_preserved(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file)

        result = EvaluationResult(decision=PolicyDecision.ALLOW, reason="test")
        args = {"url": "https://example.com", "method": "GET"}
        logger.log_tool_call("web_fetch", args, result)
        logger.close()

        entries = [json.loads(line) for line in log_file.read_text().splitlines()]
        assert entries[0]["arguments"] == args
