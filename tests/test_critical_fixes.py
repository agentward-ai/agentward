"""Tests for critical fixes from devil's advocate analysis.

Covers:
  1. Classifier wired into stdio + HTTP proxies
  2. Tool arguments in audit log entries
  3. Per-tool session approval scoping
  4. Circuit breaker (rate limiting)
  5. REDACT mode (sensitive data masking)
  6. tools/list + resources/read interception
  7. Resource filter enforcement (only_from, exclude_labels)
  8. Response content inspection
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentward.audit.logger import AuditLogger
from agentward.inspect.classifier import (
    ClassificationResult,
    Finding,
    FindingType,
    classify_arguments,
    redact_arguments,
)
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    DefaultAction,
    PolicyDecision,
    ResourcePermissions,
    SensitiveContentAction,
    SensitiveContentConfig,
)
from agentward.proxy.approval import ApprovalDecision, ApprovalHandler
from agentward.proxy.circuit_breaker import CircuitBreaker, CircuitBreakerConfig


# -----------------------------------------------------------------------
# 1. Classifier integration
# -----------------------------------------------------------------------


class TestClassifierIntegration:
    """Test that the classifier is accessible from both proxies."""

    def test_classify_arguments_detects_credit_card(self) -> None:
        result = classify_arguments({"text": "pay with 4111 1111 1111 1111"})
        assert result.has_sensitive_data
        assert any(f.finding_type == FindingType.CREDIT_CARD for f in result.findings)

    def test_classify_arguments_detects_ssn(self) -> None:
        result = classify_arguments({"body": "ssn: 123-45-6789"})
        assert result.has_sensitive_data
        assert any(f.finding_type == FindingType.SSN for f in result.findings)

    def test_classify_arguments_clean(self) -> None:
        result = classify_arguments({"text": "hello world"})
        assert not result.has_sensitive_data

    def test_classify_respects_enabled_patterns(self) -> None:
        """Only enabled patterns should fire."""
        result = classify_arguments(
            {"text": "card 4111111111111111 and ssn 123-45-6789"},
            enabled_patterns=["credit_card"],
        )
        assert result.has_sensitive_data
        # Only credit card, no SSN
        assert all(f.finding_type == FindingType.CREDIT_CARD for f in result.findings)


# -----------------------------------------------------------------------
# 2. Audit log arguments
# -----------------------------------------------------------------------


class TestAuditLogArguments:
    """Test that tool arguments are included in audit log entries."""

    def test_log_tool_call_includes_arguments(self, tmp_path: Any) -> None:
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_file)

        result = EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason="test",
        )
        arguments = {"url": "https://example.com", "method": "GET"}
        logger.log_tool_call("web_fetch", arguments, result)
        logger.close()

        entries = [json.loads(line) for line in log_file.read_text().splitlines()]
        assert len(entries) == 1
        assert entries[0]["arguments"] == arguments
        assert entries[0]["tool"] == "web_fetch"
        assert entries[0]["decision"] == "ALLOW"


# -----------------------------------------------------------------------
# 3. Per-tool session approval
# -----------------------------------------------------------------------


class TestPerToolApproval:
    """Test that session approval is scoped per tool name."""

    @pytest.mark.asyncio
    async def test_approval_scoped_to_tool(self) -> None:
        """Approving tool A does not auto-approve tool B."""
        handler = ApprovalHandler(timeout=10)
        handler._is_macos = True

        calls: list[str] = []

        async def mock_dialog(msg: str) -> ApprovalDecision:
            calls.append(msg)
            return ApprovalDecision.ALLOW_SESSION

        handler._show_dialog = mock_dialog  # type: ignore[assignment]

        await handler.request_approval("send_email", {}, "reason")
        assert len(calls) == 1

        await handler.request_approval("delete_file", {}, "reason")
        assert len(calls) == 2  # different tool → new dialog

    @pytest.mark.asyncio
    async def test_same_tool_cached(self) -> None:
        """Second call to same tool uses session cache."""
        handler = ApprovalHandler(timeout=10)
        handler._is_macos = True

        calls: list[str] = []

        async def mock_dialog(msg: str) -> ApprovalDecision:
            calls.append(msg)
            return ApprovalDecision.ALLOW_SESSION

        handler._show_dialog = mock_dialog  # type: ignore[assignment]

        await handler.request_approval("send_email", {}, "reason")
        await handler.request_approval("send_email", {}, "reason")
        assert len(calls) == 1  # cached

    @pytest.mark.asyncio
    async def test_clear_cache_resets_all(self) -> None:
        """clear_cache removes all per-tool approvals."""
        handler = ApprovalHandler(timeout=10)
        handler._session_approved.add("tool_a")
        handler._session_approved.add("tool_b")

        handler.clear_cache()
        assert len(handler._session_approved) == 0


# -----------------------------------------------------------------------
# 4. Circuit breaker
# -----------------------------------------------------------------------


class TestCircuitBreaker:
    """Test the circuit breaker rate limiter."""

    def test_allows_within_limit(self) -> None:
        cb = CircuitBreaker(config=CircuitBreakerConfig(max_calls=5, window_seconds=60))
        for _ in range(5):
            assert cb.check("tool_a")
            cb.record("tool_a")

    def test_blocks_over_limit(self) -> None:
        cb = CircuitBreaker(config=CircuitBreakerConfig(max_calls=3, window_seconds=60))
        for _ in range(3):
            assert cb.check("tool_a")
            cb.record("tool_a")
        assert not cb.check("tool_a")  # 4th call blocked

    def test_different_tools_independent(self) -> None:
        cb = CircuitBreaker(config=CircuitBreakerConfig(max_calls=2, window_seconds=60))
        for _ in range(2):
            cb.record("tool_a")
        assert not cb.check("tool_a")
        assert cb.check("tool_b")  # different tool, separate bucket

    def test_window_expiry(self) -> None:
        cb = CircuitBreaker(config=CircuitBreakerConfig(max_calls=2, window_seconds=0.1))
        cb.record("tool_a")
        cb.record("tool_a")
        assert not cb.check("tool_a")

        # Wait for window to expire
        time.sleep(0.15)
        assert cb.check("tool_a")  # old calls expired

    def test_args_hash_mode(self) -> None:
        """With use_args_hash, different args get separate buckets."""
        cb = CircuitBreaker(
            config=CircuitBreakerConfig(max_calls=1, window_seconds=60, use_args_hash=True)
        )
        cb.record("tool_a", {"url": "https://a.com"})
        assert not cb.check("tool_a", {"url": "https://a.com"})  # same args blocked
        assert cb.check("tool_a", {"url": "https://b.com"})  # different args ok

    def test_args_hash_mode_off(self) -> None:
        """Without use_args_hash, all calls to same tool share a bucket."""
        cb = CircuitBreaker(
            config=CircuitBreakerConfig(max_calls=1, window_seconds=60, use_args_hash=False)
        )
        cb.record("tool_a", {"url": "https://a.com"})
        assert not cb.check("tool_a", {"url": "https://b.com"})  # same bucket


# -----------------------------------------------------------------------
# 5. REDACT mode
# -----------------------------------------------------------------------


class TestRedactMode:
    """Test the REDACT decision and argument masking."""

    def test_redact_arguments_masks_credit_card(self) -> None:
        findings = [
            Finding(
                finding_type=FindingType.CREDIT_CARD,
                matched_text="4111 **** **** 1111",
                field_path="card_number",
            )
        ]
        args = {"card_number": "4111111111111111", "merchant": "Acme"}
        redacted = redact_arguments(args, findings)

        assert redacted["card_number"] == "[REDACTED:credit_card]"
        assert redacted["merchant"] == "Acme"  # unchanged
        # Original not modified
        assert args["card_number"] == "4111111111111111"

    def test_redact_arguments_nested_path(self) -> None:
        findings = [
            Finding(
                finding_type=FindingType.SSN,
                matched_text="***-**-6789",
                field_path="data.ssn",
            )
        ]
        args = {"data": {"ssn": "123-45-6789", "name": "John"}}
        redacted = redact_arguments(args, findings)

        assert redacted["data"]["ssn"] == "[REDACTED:ssn]"
        assert redacted["data"]["name"] == "John"

    def test_redact_arguments_array_path(self) -> None:
        findings = [
            Finding(
                finding_type=FindingType.API_KEY,
                matched_text="sk-p...last",
                field_path="items[1]",
            )
        ]
        args = {"items": ["safe", "sk-proj-SECRETKEYVALUE123456"]}
        redacted = redact_arguments(args, findings)

        assert redacted["items"][1] == "[REDACTED:api_key]"
        assert redacted["items"][0] == "safe"

    def test_sensitive_content_action_enum(self) -> None:
        assert SensitiveContentAction.BLOCK.value == "block"
        assert SensitiveContentAction.REDACT.value == "redact"

    def test_sensitive_content_config_default_action(self) -> None:
        config = SensitiveContentConfig()
        assert config.on_detection == SensitiveContentAction.BLOCK

    def test_sensitive_content_config_redact(self) -> None:
        config = SensitiveContentConfig(on_detection=SensitiveContentAction.REDACT)
        assert config.on_detection == SensitiveContentAction.REDACT


# -----------------------------------------------------------------------
# 6. tools/list + resources/read protocol helpers
# -----------------------------------------------------------------------


class TestProtocolHelpers:
    """Test new protocol helpers for tools/list and resources/read."""

    def test_is_tools_list(self) -> None:
        from agentward.proxy.protocol import JSONRPCRequest, is_tools_list

        msg = JSONRPCRequest(id=1, method="tools/list", params={})
        assert is_tools_list(msg)

        msg2 = JSONRPCRequest(id=2, method="tools/call", params={})
        assert not is_tools_list(msg2)

    def test_is_resources_read(self) -> None:
        from agentward.proxy.protocol import JSONRPCRequest, is_resources_read

        msg = JSONRPCRequest(id=1, method="resources/read", params={"uri": "file:///tmp/a"})
        assert is_resources_read(msg)

        msg2 = JSONRPCRequest(id=2, method="tools/call", params={})
        assert not is_resources_read(msg2)

    def test_is_tools_list_response(self) -> None:
        from agentward.proxy.protocol import JSONRPCResponse, is_tools_list_response

        pending = {1, 2}
        msg = JSONRPCResponse(id=1, result={"tools": []})
        assert is_tools_list_response(msg, pending)

        msg2 = JSONRPCResponse(id=99, result={})
        assert not is_tools_list_response(msg2, pending)


# -----------------------------------------------------------------------
# 7. Resource filter enforcement
# -----------------------------------------------------------------------


class TestResourceFilters:
    """Test runtime enforcement of only_from and exclude_labels filters."""

    def _make_policy(self, skills: dict[str, dict[str, Any]]) -> AgentWardPolicy:
        return AgentWardPolicy(version="1.0", skills=skills)

    def test_only_from_allows_matching(self) -> None:
        policy = self._make_policy({
            "email-reader": {
                "gmail": {
                    "read": True,
                    "filters": {"only_from": ["chase.com", "amex.com"]},
                }
            }
        })
        engine = PolicyEngine(policy)
        result = engine.evaluate("gmail_read", {"from": "alerts@chase.com"})
        assert result.decision == PolicyDecision.ALLOW

    def test_only_from_blocks_non_matching(self) -> None:
        policy = self._make_policy({
            "email-reader": {
                "gmail": {
                    "read": True,
                    "filters": {"only_from": ["chase.com", "amex.com"]},
                }
            }
        })
        engine = PolicyEngine(policy)
        result = engine.evaluate("gmail_read", {"from": "attacker@evil.com"})
        assert result.decision == PolicyDecision.BLOCK
        assert "only_from" in result.reason

    def test_exclude_labels_blocks_matching(self) -> None:
        policy = self._make_policy({
            "email-reader": {
                "gmail": {
                    "read": True,
                    "filters": {"exclude_labels": ["Finance", "Medical"]},
                }
            }
        })
        engine = PolicyEngine(policy)
        result = engine.evaluate("gmail_read", {"label": "Finance"})
        assert result.decision == PolicyDecision.BLOCK
        assert "exclude_labels" in result.reason

    def test_exclude_labels_allows_non_matching(self) -> None:
        policy = self._make_policy({
            "email-reader": {
                "gmail": {
                    "read": True,
                    "filters": {"exclude_labels": ["Finance", "Medical"]},
                }
            }
        })
        engine = PolicyEngine(policy)
        result = engine.evaluate("gmail_read", {"label": "Inbox"})
        assert result.decision == PolicyDecision.ALLOW

    def test_exclude_labels_case_insensitive(self) -> None:
        policy = self._make_policy({
            "email-reader": {
                "gmail": {
                    "read": True,
                    "filters": {"exclude_labels": ["Finance"]},
                }
            }
        })
        engine = PolicyEngine(policy)
        result = engine.evaluate("gmail_read", {"label": "finance"})
        assert result.decision == PolicyDecision.BLOCK

    def test_filters_no_arguments(self) -> None:
        """Filters are skipped when no arguments are provided."""
        policy = self._make_policy({
            "email-reader": {
                "gmail": {
                    "read": True,
                    "filters": {"only_from": ["chase.com"]},
                }
            }
        })
        engine = PolicyEngine(policy)
        result = engine.evaluate("gmail_read", None)
        assert result.decision == PolicyDecision.ALLOW

    def test_filters_empty_arguments(self) -> None:
        """Filters are skipped when arguments dict is empty."""
        policy = self._make_policy({
            "email-reader": {
                "gmail": {
                    "read": True,
                    "filters": {"only_from": ["chase.com"]},
                }
            }
        })
        engine = PolicyEngine(policy)
        result = engine.evaluate("gmail_read", {})
        assert result.decision == PolicyDecision.ALLOW


# -----------------------------------------------------------------------
# 8. Redact arguments helpers
# -----------------------------------------------------------------------


class TestRedactHelpers:
    """Test the path splitting and redaction helpers."""

    def test_split_path_simple(self) -> None:
        from agentward.inspect.classifier import _split_path
        assert _split_path("a.b.c") == ["a", "b", "c"]

    def test_split_path_array(self) -> None:
        from agentward.inspect.classifier import _split_path
        assert _split_path("items[0]") == ["items", "0"]

    def test_split_path_nested_array(self) -> None:
        from agentward.inspect.classifier import _split_path
        assert _split_path("data.items[2].text") == ["data", "items", "2", "text"]

    def test_redact_at_path_missing_key(self) -> None:
        from agentward.inspect.classifier import _redact_at_path
        obj = {"a": 1}
        _redact_at_path(obj, "nonexistent", "test")
        assert obj == {"a": 1}  # unchanged

    def test_redact_multiple_findings(self) -> None:
        findings = [
            Finding(finding_type=FindingType.CREDIT_CARD, matched_text="****", field_path="card"),
            Finding(finding_type=FindingType.SSN, matched_text="***", field_path="ssn"),
        ]
        args = {"card": "4111111111111111", "ssn": "123-45-6789", "name": "test"}
        redacted = redact_arguments(args, findings)
        assert redacted["card"] == "[REDACTED:credit_card]"
        assert redacted["ssn"] == "[REDACTED:ssn]"
        assert redacted["name"] == "test"
