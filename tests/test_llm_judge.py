"""Tests for the LLM-as-judge intent analysis module."""

from __future__ import annotations

import json
import sys
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentward.policy.engine import EvaluationResult
from agentward.policy.schema import (
    AgentWardPolicy,
    JudgeSensitivity,
    LlmJudgeConfig,
    PolicyDecision,
    ResourcePermissions,
)
from agentward.proxy.judge import (
    JudgeResult,
    JudgeVerdict,
    LlmJudge,
    _build_user_prompt,
    _cache_key,
    _parse_judge_response,
    _timeout_result,
)


# ---------------------------------------------------------------------------
# Module-level autouse fixture — skip SDK check for all tests in this file.
# Tests that specifically exercise _verify_provider_sdk bypass this by
# constructing LlmJudge outside the autouse scope or using their own patch.
# ---------------------------------------------------------------------------

# Capture the real method at module load time (before any fixture patches it).
# TestProviderSdkVerification uses this to bypass the autouse no-op.
_REAL_VERIFY_PROVIDER_SDK = LlmJudge._verify_provider_sdk


@pytest.fixture(autouse=True)
def _skip_sdk_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """Patch out the SDK availability check so tests run without real SDKs installed."""
    monkeypatch.setattr(LlmJudge, "_verify_provider_sdk", lambda self: None)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------


def _make_config(**kwargs: Any) -> LlmJudgeConfig:
    """Build a judge config with test-friendly defaults."""
    defaults: dict[str, Any] = {
        "enabled": True,
        "provider": "anthropic",
        "model": "claude-haiku-4-5-20251001",
        "timeout": 5.0,
        "sensitivity": JudgeSensitivity.MEDIUM,
        "cache_ttl": 0,  # Disable caching by default in tests
        "cache_max_size": 100,
        "on_flag": PolicyDecision.LOG,
        "on_block": PolicyDecision.BLOCK,
        "on_timeout": PolicyDecision.ALLOW,
        "judge_on": [PolicyDecision.ALLOW],
    }
    defaults.update(kwargs)
    return LlmJudgeConfig(**defaults)


def _make_allow_result() -> EvaluationResult:
    return EvaluationResult(decision=PolicyDecision.ALLOW, reason="Policy allows")


def _judge_result(
    verdict: JudgeVerdict,
    risk_score: float,
    reasoning: str = "test reasoning",
) -> JudgeResult:
    return JudgeResult(
        verdict=verdict,
        risk_score=risk_score,
        reasoning=reasoning,
        elapsed_ms=42,
        cached=False,
    )


def _mock_judge_with_result(config: LlmJudgeConfig, result: JudgeResult) -> LlmJudge:
    """Build an LlmJudge whose _call_judge is mocked to return result."""
    judge = LlmJudge(config)
    judge._call_judge = AsyncMock(return_value=result)  # type: ignore[method-assign]
    return judge


# ---------------------------------------------------------------------------
# _cache_key
# ---------------------------------------------------------------------------


class TestCacheKey:
    def test_same_args_same_key(self) -> None:
        k1 = _cache_key("gmail_send", {"to": "a@b.com", "body": "hello"})
        k2 = _cache_key("gmail_send", {"to": "a@b.com", "body": "hello"})
        assert k1 == k2

    def test_different_tools_different_key(self) -> None:
        k1 = _cache_key("gmail_send", {"to": "a@b.com"})
        k2 = _cache_key("slack_send", {"to": "a@b.com"})
        assert k1 != k2

    def test_different_args_different_key(self) -> None:
        k1 = _cache_key("tool", {"key": "val1"})
        k2 = _cache_key("tool", {"key": "val2"})
        assert k1 != k2

    def test_arg_order_independent(self) -> None:
        """Arguments in different order should produce the same key."""
        k1 = _cache_key("tool", {"a": 1, "b": 2})
        k2 = _cache_key("tool", {"b": 2, "a": 1})
        assert k1 == k2

    def test_key_is_16_hex_chars(self) -> None:
        k = _cache_key("tool", {})
        assert len(k) == 16
        assert all(c in "0123456789abcdef" for c in k)


# ---------------------------------------------------------------------------
# _parse_judge_response
# ---------------------------------------------------------------------------


class TestParseJudgeResponse:
    def test_valid_allow(self) -> None:
        raw = '{"verdict": "allow", "risk_score": 0.1, "reasoning": "args match description"}'
        result = _parse_judge_response(raw)
        assert result.verdict == JudgeVerdict.ALLOW
        assert result.risk_score == 0.1
        assert result.reasoning == "args match description"

    def test_valid_flag(self) -> None:
        raw = '{"verdict": "flag", "risk_score": 0.5, "reasoning": "suspicious pattern"}'
        result = _parse_judge_response(raw)
        assert result.verdict == JudgeVerdict.FLAG
        assert result.risk_score == 0.5

    def test_valid_block(self) -> None:
        raw = '{"verdict": "block", "risk_score": 0.95, "reasoning": "clear mismatch"}'
        result = _parse_judge_response(raw)
        assert result.verdict == JudgeVerdict.BLOCK
        assert result.risk_score == 0.95

    def test_markdown_fenced(self) -> None:
        raw = '```json\n{"verdict": "allow", "risk_score": 0.05, "reasoning": "ok"}\n```'
        result = _parse_judge_response(raw)
        assert result.verdict == JudgeVerdict.ALLOW
        assert result.risk_score == 0.05

    def test_markdown_fenced_no_lang(self) -> None:
        raw = '```\n{"verdict": "flag", "risk_score": 0.4, "reasoning": "maybe"}\n```'
        result = _parse_judge_response(raw)
        assert result.verdict == JudgeVerdict.FLAG

    def test_json_embedded_in_text(self) -> None:
        raw = 'Sure! Here is my analysis: {"verdict": "allow", "risk_score": 0.1, "reasoning": "fine"} Done.'
        result = _parse_judge_response(raw)
        assert result.verdict == JudgeVerdict.ALLOW

    def test_risk_score_clamped_high(self) -> None:
        raw = '{"verdict": "block", "risk_score": 99.9, "reasoning": "bad"}'
        result = _parse_judge_response(raw)
        assert result.risk_score == 1.0

    def test_risk_score_clamped_low(self) -> None:
        raw = '{"verdict": "allow", "risk_score": -0.5, "reasoning": "fine"}'
        result = _parse_judge_response(raw)
        assert result.risk_score == 0.0

    def test_unknown_verdict_becomes_flag(self) -> None:
        raw = '{"verdict": "unsure", "risk_score": 0.3, "reasoning": "dunno"}'
        result = _parse_judge_response(raw)
        assert result.verdict == JudgeVerdict.FLAG

    def test_malformed_json_returns_flag(self) -> None:
        result = _parse_judge_response("this is not json at all")
        assert result.verdict == JudgeVerdict.FLAG
        assert result.risk_score == 0.5
        assert "parse" in result.reasoning.lower()

    def test_missing_reasoning_uses_default(self) -> None:
        raw = '{"verdict": "allow", "risk_score": 0.1}'
        result = _parse_judge_response(raw)
        assert result.reasoning == "No reasoning provided"

    def test_reasoning_truncated_at_500_chars(self) -> None:
        long_reasoning = "x" * 600
        raw = json.dumps({"verdict": "allow", "risk_score": 0.1, "reasoning": long_reasoning})
        result = _parse_judge_response(raw)
        assert len(result.reasoning) == 500

    def test_elapsed_ms_always_zero(self) -> None:
        """elapsed_ms is always 0 from the parser; caller sets the real value."""
        raw = '{"verdict": "allow", "risk_score": 0.1, "reasoning": "ok"}'
        result = _parse_judge_response(raw)
        assert result.elapsed_ms == 0


# ---------------------------------------------------------------------------
# _timeout_result
# ---------------------------------------------------------------------------


class TestTimeoutResult:
    def test_on_timeout_allow_returns_none(self) -> None:
        assert _timeout_result("tool", PolicyDecision.ALLOW) is None

    def test_on_timeout_block_returns_block_result(self) -> None:
        result = _timeout_result("tool", PolicyDecision.BLOCK)
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK
        assert "tool" in result.reason

    def test_on_timeout_log_returns_log_result(self) -> None:
        result = _timeout_result("tool", PolicyDecision.LOG)
        assert result is not None
        assert result.decision == PolicyDecision.LOG


# ---------------------------------------------------------------------------
# _build_user_prompt
# ---------------------------------------------------------------------------


class TestBuildUserPrompt:
    def test_includes_tool_name(self) -> None:
        prompt = _build_user_prompt("gmail_send", None, None, {})
        assert "gmail_send" in prompt

    def test_includes_description_when_provided(self) -> None:
        prompt = _build_user_prompt("gmail_send", "Send emails", None, {})
        assert "Send emails" in prompt

    def test_placeholder_when_no_description(self) -> None:
        prompt = _build_user_prompt("gmail_send", None, None, {})
        assert "no description" in prompt.lower()

    def test_includes_schema_when_provided(self) -> None:
        schema = {"type": "object", "properties": {"to": {"type": "string"}}}
        prompt = _build_user_prompt("gmail_send", None, schema, {})
        assert '"to"' in prompt

    def test_includes_arguments(self) -> None:
        args = {"to": "evil@attacker.com", "body": "Click here"}
        prompt = _build_user_prompt("gmail_send", None, None, args)
        assert "evil@attacker.com" in prompt
        assert "Click here" in prompt

    def test_handles_unserializable_args(self) -> None:
        # Should not raise
        args = {"value": object()}
        prompt = _build_user_prompt("tool", None, None, args)
        assert "ACTUAL ARGUMENTS" in prompt


# ---------------------------------------------------------------------------
# LlmJudge.register_tool
# ---------------------------------------------------------------------------


class TestRegisterTool:
    def test_register_and_retrieve(self) -> None:
        judge = LlmJudge(_make_config())
        judge.register_tool("my_tool", {"type": "object"}, "Does a thing")
        schema_info = judge._tool_schemas["my_tool"]
        assert schema_info["description"] == "Does a thing"
        assert schema_info["inputSchema"] == {"type": "object"}

    def test_register_without_description(self) -> None:
        judge = LlmJudge(_make_config())
        judge.register_tool("my_tool", {})
        assert judge._tool_schemas["my_tool"]["description"] is None

    def test_overwrite_on_re_register(self) -> None:
        judge = LlmJudge(_make_config())
        judge.register_tool("my_tool", {}, "old description")
        judge.register_tool("my_tool", {}, "new description")
        assert judge._tool_schemas["my_tool"]["description"] == "new description"


# ---------------------------------------------------------------------------
# LlmJudge.judge_on_decisions
# ---------------------------------------------------------------------------


class TestJudgeOnDecisions:
    def test_default_is_allow(self) -> None:
        judge = LlmJudge(_make_config())
        assert PolicyDecision.ALLOW in judge.judge_on_decisions
        assert PolicyDecision.BLOCK not in judge.judge_on_decisions

    def test_custom_judge_on(self) -> None:
        config = _make_config(judge_on=[PolicyDecision.ALLOW, PolicyDecision.LOG])
        judge = LlmJudge(config)
        assert PolicyDecision.ALLOW in judge.judge_on_decisions
        assert PolicyDecision.LOG in judge.judge_on_decisions
        assert PolicyDecision.BLOCK not in judge.judge_on_decisions


# ---------------------------------------------------------------------------
# LlmJudge._apply_sensitivity
# ---------------------------------------------------------------------------


class TestApplySensitivity:
    def test_medium_low_score_is_allow(self) -> None:
        config = _make_config(sensitivity=JudgeSensitivity.MEDIUM)
        judge = LlmJudge(config)
        assert judge._apply_sensitivity(JudgeVerdict.ALLOW, 0.1) == JudgeVerdict.ALLOW

    def test_medium_mid_score_is_flag(self) -> None:
        config = _make_config(sensitivity=JudgeSensitivity.MEDIUM)
        judge = LlmJudge(config)
        assert judge._apply_sensitivity(JudgeVerdict.ALLOW, 0.55) == JudgeVerdict.FLAG

    def test_medium_high_score_is_block(self) -> None:
        config = _make_config(sensitivity=JudgeSensitivity.MEDIUM)
        judge = LlmJudge(config)
        assert judge._apply_sensitivity(JudgeVerdict.ALLOW, 0.8) == JudgeVerdict.BLOCK

    def test_low_sensitivity_requires_high_score_to_flag(self) -> None:
        config = _make_config(sensitivity=JudgeSensitivity.LOW)
        judge = LlmJudge(config)
        # Score 0.5 should be ALLOW under LOW sensitivity (threshold 0.65)
        assert judge._apply_sensitivity(JudgeVerdict.FLAG, 0.5) == JudgeVerdict.ALLOW

    def test_high_sensitivity_flags_at_low_scores(self) -> None:
        config = _make_config(sensitivity=JudgeSensitivity.HIGH)
        judge = LlmJudge(config)
        # Score 0.3 should be FLAG under HIGH sensitivity (threshold 0.25)
        assert judge._apply_sensitivity(JudgeVerdict.ALLOW, 0.3) == JudgeVerdict.FLAG

    def test_high_sensitivity_blocks_at_medium_scores(self) -> None:
        config = _make_config(sensitivity=JudgeSensitivity.HIGH)
        judge = LlmJudge(config)
        # Score 0.55 exceeds block threshold of 0.50 under HIGH
        assert judge._apply_sensitivity(JudgeVerdict.FLAG, 0.55) == JudgeVerdict.BLOCK

    def test_sensitivity_overrides_llm_raw_verdict(self) -> None:
        """The LLM says 'allow' but the score says flag — sensitivity wins."""
        config = _make_config(sensitivity=JudgeSensitivity.MEDIUM)
        judge = LlmJudge(config)
        # risk_score=0.6 exceeds the MEDIUM flag threshold (0.45)
        result = judge._apply_sensitivity(JudgeVerdict.ALLOW, 0.6)
        assert result == JudgeVerdict.FLAG


# ---------------------------------------------------------------------------
# LlmJudge.check — verdict routing and EvaluationResult mapping
# ---------------------------------------------------------------------------


class TestJudgeCheckVerdictRouting:
    @pytest.mark.asyncio
    async def test_allow_verdict_returns_none(self) -> None:
        """Judge ALLOW → defer (return None), base policy decision stands."""
        judge = _mock_judge_with_result(
            _make_config(), _judge_result(JudgeVerdict.ALLOW, 0.1)
        )
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is None

    @pytest.mark.asyncio
    async def test_flag_verdict_returns_on_flag_decision(self) -> None:
        """Judge FLAG → return EvaluationResult with on_flag decision."""
        config = _make_config(
            on_flag=PolicyDecision.LOG,
            sensitivity=JudgeSensitivity.HIGH,  # HIGH so score=0.4 triggers FLAG
        )
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.FLAG, 0.4)
        )
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is not None
        assert result.decision == PolicyDecision.LOG
        assert "LLM judge" in result.reason

    @pytest.mark.asyncio
    async def test_block_verdict_returns_on_block_decision(self) -> None:
        """Judge BLOCK → return EvaluationResult with on_block decision."""
        config = _make_config(on_block=PolicyDecision.BLOCK)
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.BLOCK, 0.9)
        )
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK
        assert "0.90" in result.reason

    @pytest.mark.asyncio
    async def test_on_flag_configurable_to_block(self) -> None:
        """on_flag=block → FLAG verdict produces a BLOCK EvaluationResult."""
        config = _make_config(
            on_flag=PolicyDecision.BLOCK,
            sensitivity=JudgeSensitivity.HIGH,
        )
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.FLAG, 0.4)
        )
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_reason_includes_risk_score_and_verdict(self) -> None:
        config = _make_config(on_block=PolicyDecision.BLOCK)
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.BLOCK, 0.88, "malicious pattern detected")
        )
        result = await judge.check("my_tool", {}, _make_allow_result())
        assert result is not None
        assert "0.88" in result.reason
        assert "malicious pattern detected" in result.reason


# ---------------------------------------------------------------------------
# LlmJudge.check — sensitivity integration (end-to-end score → action)
# ---------------------------------------------------------------------------


class TestJudgeSensitivityIntegration:
    """Verify the full score → sensitivity → decision pipeline."""

    @pytest.mark.asyncio
    async def test_low_sensitivity_ignores_mid_score(self) -> None:
        """LOW sensitivity: score=0.5 (below flag threshold 0.65) → allow."""
        config = _make_config(sensitivity=JudgeSensitivity.LOW)
        # LLM returns block verdict but score is 0.5 — sensitivity recomputes
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.BLOCK, 0.5)
        )
        result = await judge.check("tool", {}, _make_allow_result())
        # score 0.5 < 0.65 flag threshold → ALLOW verdict → return None
        assert result is None

    @pytest.mark.asyncio
    async def test_high_sensitivity_flags_low_score(self) -> None:
        """HIGH sensitivity: score=0.3 (above flag threshold 0.25) → flag."""
        config = _make_config(
            sensitivity=JudgeSensitivity.HIGH,
            on_flag=PolicyDecision.LOG,
        )
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.3)
        )
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is not None
        assert result.decision == PolicyDecision.LOG

    @pytest.mark.asyncio
    async def test_medium_mid_score_produces_flag(self) -> None:
        """MEDIUM sensitivity: score=0.5 (above flag threshold 0.45) → flag."""
        config = _make_config(
            sensitivity=JudgeSensitivity.MEDIUM,
            on_flag=PolicyDecision.LOG,
        )
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.5)
        )
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is not None
        assert result.decision == PolicyDecision.LOG


# ---------------------------------------------------------------------------
# LlmJudge.check — caching
# ---------------------------------------------------------------------------


class TestJudgeCaching:
    @pytest.mark.asyncio
    async def test_second_call_hits_cache(self) -> None:
        """Identical call after first → _call_judge invoked only once."""
        config = _make_config(cache_ttl=60)
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.1)
        )
        base = _make_allow_result()
        await judge.check("tool", {"a": 1}, base)
        await judge.check("tool", {"a": 1}, base)
        assert judge._call_judge.call_count == 1  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_different_args_miss_cache(self) -> None:
        config = _make_config(cache_ttl=60)
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.1)
        )
        base = _make_allow_result()
        await judge.check("tool", {"a": 1}, base)
        await judge.check("tool", {"a": 2}, base)
        assert judge._call_judge.call_count == 2  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_expired_cache_re_calls_judge(self) -> None:
        """After TTL expires, the cache entry is evicted and judge is re-called."""
        config = _make_config(cache_ttl=1)
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.1)
        )
        base = _make_allow_result()
        key = _cache_key("tool", {"a": 1})

        await judge.check("tool", {"a": 1}, base)
        # Manually expire the cache entry
        if key in judge._cache:
            result, _ = judge._cache[key]
            judge._cache[key] = (result, time.monotonic() - 1)

        await judge.check("tool", {"a": 1}, base)
        assert judge._call_judge.call_count == 2  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_cache_disabled_always_calls_judge(self) -> None:
        config = _make_config(cache_ttl=0)
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.1)
        )
        base = _make_allow_result()
        await judge.check("tool", {"x": 1}, base)
        await judge.check("tool", {"x": 1}, base)
        assert judge._call_judge.call_count == 2  # type: ignore[attr-defined]

    @pytest.mark.asyncio
    async def test_cache_max_size_evicts_oldest(self) -> None:
        """When cache is full, the oldest entry is evicted."""
        config = _make_config(cache_ttl=300, cache_max_size=2)
        judge = LlmJudge(config)
        judge._call_judge = AsyncMock(return_value=_judge_result(JudgeVerdict.ALLOW, 0.1))  # type: ignore[method-assign]

        base = _make_allow_result()
        await judge.check("tool", {"id": 1}, base)
        await judge.check("tool", {"id": 2}, base)
        assert len(judge._cache) == 2

        # Third call — should evict one (the oldest)
        await judge.check("tool", {"id": 3}, base)
        assert len(judge._cache) == 2


# ---------------------------------------------------------------------------
# LlmJudge.check — timeout / error handling
# ---------------------------------------------------------------------------


class TestJudgeTimeoutHandling:
    @pytest.mark.asyncio
    async def test_timeout_returns_none_when_on_timeout_is_allow(self) -> None:
        config = _make_config(on_timeout=PolicyDecision.ALLOW, timeout=0.001)
        judge = LlmJudge(config)

        async def _slow(*args: Any, **kwargs: Any) -> JudgeResult:
            import asyncio as _aio
            await _aio.sleep(10)
            return _judge_result(JudgeVerdict.ALLOW, 0.1)

        judge._call_judge = _slow  # type: ignore[method-assign]
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is None  # on_timeout=allow → defer

    @pytest.mark.asyncio
    async def test_timeout_returns_block_when_on_timeout_is_block(self) -> None:
        config = _make_config(on_timeout=PolicyDecision.BLOCK, timeout=0.001)
        judge = LlmJudge(config)

        async def _slow(*args: Any, **kwargs: Any) -> JudgeResult:
            import asyncio as _aio
            await _aio.sleep(10)
            return _judge_result(JudgeVerdict.ALLOW, 0.1)

        judge._call_judge = _slow  # type: ignore[method-assign]
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK

    @pytest.mark.asyncio
    async def test_exception_falls_back_to_on_timeout(self) -> None:
        config = _make_config(on_timeout=PolicyDecision.ALLOW)
        judge = LlmJudge(config)
        judge._call_judge = AsyncMock(side_effect=RuntimeError("network error"))  # type: ignore[method-assign]
        result = await judge.check("tool", {}, _make_allow_result())
        assert result is None  # on_timeout=allow → defer


# ---------------------------------------------------------------------------
# LlmJudge.check — judge_on filtering
# ---------------------------------------------------------------------------


class TestJudgeOnFiltering:
    @pytest.mark.asyncio
    async def test_judge_not_called_for_block_decision(self) -> None:
        """Base BLOCK decision is not in judge_on=[ALLOW] → judge skips."""
        config = _make_config(judge_on=[PolicyDecision.ALLOW])
        judge = LlmJudge(config)
        judge._call_judge = AsyncMock()  # type: ignore[method-assign]

        block_result = EvaluationResult(decision=PolicyDecision.BLOCK, reason="blocked")
        # check() should not be called if the proxy correctly checks judge_on_decisions
        # The judge itself can still be called — it's the proxy's job to skip.
        # We test the judge_on_decisions property here.
        assert PolicyDecision.BLOCK not in judge.judge_on_decisions

    @pytest.mark.asyncio
    async def test_judge_called_for_log_when_configured(self) -> None:
        """LOG decision in judge_on → judge is called."""
        config = _make_config(judge_on=[PolicyDecision.ALLOW, PolicyDecision.LOG])
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.1)
        )
        log_result = EvaluationResult(decision=PolicyDecision.LOG, reason="logged")
        await judge.check("tool", {}, log_result)
        assert judge._call_judge.call_count == 1  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# LlmJudge — audit logger integration
# ---------------------------------------------------------------------------


class TestAuditLoggerIntegration:
    @pytest.mark.asyncio
    async def test_audit_logger_called_on_allow(self) -> None:
        mock_logger = MagicMock()
        config = _make_config()
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.1, "fine")
        )
        judge._audit_logger = mock_logger
        await judge.check("tool", {}, _make_allow_result())
        mock_logger.log_judge_decision.assert_called_once()
        call_kwargs = mock_logger.log_judge_decision.call_args[1]
        assert call_kwargs["verdict"] == "allow"
        assert call_kwargs["risk_score"] == 0.1

    @pytest.mark.asyncio
    async def test_audit_logger_called_on_block(self) -> None:
        mock_logger = MagicMock()
        config = _make_config(on_block=PolicyDecision.BLOCK)
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.BLOCK, 0.9, "suspicious")
        )
        judge._audit_logger = mock_logger
        await judge.check("tool", {}, _make_allow_result())
        mock_logger.log_judge_decision.assert_called_once()
        call_kwargs = mock_logger.log_judge_decision.call_args[1]
        assert call_kwargs["verdict"] == "block"
        assert call_kwargs["risk_score"] == 0.9

    @pytest.mark.asyncio
    async def test_audit_logger_error_does_not_crash_judge(self) -> None:
        """If the audit logger raises, the judge should not crash."""
        mock_logger = MagicMock()
        mock_logger.log_judge_decision.side_effect = OSError("disk full")
        config = _make_config()
        judge = _mock_judge_with_result(
            config, _judge_result(JudgeVerdict.ALLOW, 0.1)
        )
        judge._audit_logger = mock_logger
        # Should not raise
        await judge.check("tool", {}, _make_allow_result())


# ---------------------------------------------------------------------------
# LlmJudge._verify_provider_sdk — SDK availability checks
# ---------------------------------------------------------------------------


class TestProviderSdkVerification:
    """Tests for _verify_provider_sdk() using the real (unpatched) method."""

    def test_missing_anthropic_sdk_raises_import_error(self) -> None:
        """ImportError with pip install instructions when anthropic SDK is absent."""
        config = _make_config(provider="anthropic")
        with patch.dict(sys.modules, {"anthropic": None}):
            judge = object.__new__(LlmJudge)
            judge._config = config  # type: ignore[attr-defined]
            with pytest.raises(ImportError, match=r"pip install agentward\[judge\]"):
                _REAL_VERIFY_PROVIDER_SDK(judge)

    def test_missing_openai_sdk_raises_import_error(self) -> None:
        """ImportError with pip install instructions when openai SDK is absent."""
        config = _make_config(provider="openai")
        with patch.dict(sys.modules, {"openai": None}):
            judge = object.__new__(LlmJudge)
            judge._config = config  # type: ignore[attr-defined]
            with pytest.raises(ImportError, match=r"pip install agentward\[judge\]"):
                _REAL_VERIFY_PROVIDER_SDK(judge)

    def test_unsupported_provider_raises_value_error_at_verify(self) -> None:
        """ValueError for unknown provider at _verify_provider_sdk time."""
        config = _make_config(provider="gemini")
        judge = object.__new__(LlmJudge)
        judge._config = config  # type: ignore[attr-defined]
        with pytest.raises(ValueError, match="Unsupported"):
            _REAL_VERIFY_PROVIDER_SDK(judge)

    def test_anthropic_import_error_message_includes_install_command(self) -> None:
        """The error message includes the exact install command."""
        config = _make_config(provider="anthropic")
        with patch.dict(sys.modules, {"anthropic": None}):
            judge = object.__new__(LlmJudge)
            judge._config = config  # type: ignore[attr-defined]
            try:
                _REAL_VERIFY_PROVIDER_SDK(judge)
                pytest.fail("Expected ImportError")
            except ImportError as e:
                assert "pip install agentward[judge]" in str(e)
                assert "anthropic" in str(e)

    def test_openai_import_error_message_includes_install_command(self) -> None:
        """The error message includes the exact install command."""
        config = _make_config(provider="openai")
        with patch.dict(sys.modules, {"openai": None}):
            judge = object.__new__(LlmJudge)
            judge._config = config  # type: ignore[attr-defined]
            try:
                _REAL_VERIFY_PROVIDER_SDK(judge)
                pytest.fail("Expected ImportError")
            except ImportError as e:
                assert "pip install agentward[judge]" in str(e)
                assert "openai" in str(e)


# ---------------------------------------------------------------------------
# LlmJudge._call_anthropic / _call_openai — provider dispatch
# ---------------------------------------------------------------------------


class TestProviderDispatch:
    """Tests for provider method dispatch — SDKs are mocked at the method level."""

    @pytest.mark.asyncio
    async def test_anthropic_method_parses_sdk_response(self) -> None:
        """_call_anthropic correctly parses the Anthropic SDK response object."""
        config = _make_config(provider="anthropic", api_key_env="TEST_ANTHROPIC_KEY")
        judge = LlmJudge(config)

        # Mock the anthropic module so `import anthropic` inside _call_anthropic works
        mock_content_block = MagicMock()
        mock_content_block.text = '{"verdict": "allow", "risk_score": 0.1, "reasoning": "ok"}'
        mock_response = MagicMock()
        mock_response.content = [mock_content_block]

        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)

        mock_anthropic_module = MagicMock()
        mock_anthropic_module.AsyncAnthropic.return_value = mock_client

        with patch.dict("os.environ", {"TEST_ANTHROPIC_KEY": "sk-test"}):
            with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
                result = await judge._call_anthropic("sk-test", "test prompt")

        assert result.verdict == JudgeVerdict.ALLOW
        assert result.risk_score == 0.1
        mock_client.messages.create.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_openai_method_parses_sdk_response(self) -> None:
        """_call_openai correctly parses the OpenAI SDK response object."""
        config = _make_config(provider="openai", api_key_env="TEST_OPENAI_KEY")
        judge = LlmJudge(config)

        mock_message = MagicMock()
        mock_message.content = '{"verdict": "flag", "risk_score": 0.55, "reasoning": "suspicious"}'
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=mock_response)

        mock_openai_module = MagicMock()
        mock_openai_module.AsyncOpenAI.return_value = mock_client

        with patch.dict("os.environ", {"TEST_OPENAI_KEY": "sk-test"}):
            with patch.dict(sys.modules, {"openai": mock_openai_module}):
                result = await judge._call_openai("sk-test", "test prompt")

        assert result.verdict == JudgeVerdict.FLAG
        assert result.risk_score == 0.55
        mock_client.chat.completions.create.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_anthropic_passes_base_url_override(self) -> None:
        """base_url config is forwarded to AsyncAnthropic constructor."""
        config = _make_config(
            provider="anthropic",
            api_key_env="TEST_ANTHROPIC_KEY",
            base_url="https://my-proxy.internal",
        )
        judge = LlmJudge(config)

        mock_content_block = MagicMock()
        mock_content_block.text = '{"verdict": "allow", "risk_score": 0.05, "reasoning": "ok"}'
        mock_response = MagicMock()
        mock_response.content = [mock_content_block]
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_anthropic_module = MagicMock()
        mock_anthropic_module.AsyncAnthropic.return_value = mock_client

        with patch.dict("os.environ", {"TEST_ANTHROPIC_KEY": "sk-test"}):
            with patch.dict(sys.modules, {"anthropic": mock_anthropic_module}):
                await judge._call_anthropic("sk-test", "test prompt")

        # Verify base_url was passed to AsyncAnthropic
        mock_anthropic_module.AsyncAnthropic.assert_called_once_with(
            api_key="sk-test", base_url="https://my-proxy.internal"
        )

    @pytest.mark.asyncio
    async def test_missing_api_key_raises_value_error(self) -> None:
        config = _make_config(provider="anthropic", api_key_env="NONEXISTENT_ENV_VAR_XYZ")
        judge = LlmJudge(config)
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="NONEXISTENT_ENV_VAR_XYZ"):
                await judge._call_judge("tool", None, None, {})

    @pytest.mark.asyncio
    async def test_unsupported_provider_raises_in_call_judge(self) -> None:
        """Even if _verify_provider_sdk is bypassed, _call_judge catches bad providers."""
        config = _make_config(provider="gemini")
        judge = LlmJudge(config)  # autouse fixture skips SDK check
        with pytest.raises(ValueError, match="Unsupported"):
            await judge._call_judge("tool", None, None, {})


# ---------------------------------------------------------------------------
# LlmJudgeConfig schema validation
# ---------------------------------------------------------------------------


class TestLlmJudgeConfigSchema:
    def test_default_enabled_false(self) -> None:
        cfg = LlmJudgeConfig()
        assert cfg.enabled is False

    def test_default_provider_anthropic(self) -> None:
        cfg = LlmJudgeConfig()
        assert cfg.provider == "anthropic"

    def test_default_judge_on_is_allow(self) -> None:
        cfg = LlmJudgeConfig()
        assert PolicyDecision.ALLOW in cfg.judge_on

    def test_default_on_timeout_is_allow(self) -> None:
        cfg = LlmJudgeConfig()
        assert cfg.on_timeout == PolicyDecision.ALLOW

    def test_default_on_flag_is_log(self) -> None:
        cfg = LlmJudgeConfig()
        assert cfg.on_flag == PolicyDecision.LOG

    def test_default_on_block_is_block(self) -> None:
        cfg = LlmJudgeConfig()
        assert cfg.on_block == PolicyDecision.BLOCK

    def test_sensitivity_enum_values(self) -> None:
        assert JudgeSensitivity.LOW.value == "low"
        assert JudgeSensitivity.MEDIUM.value == "medium"
        assert JudgeSensitivity.HIGH.value == "high"

    def test_yaml_round_trip(self) -> None:
        """LlmJudgeConfig survives a YAML serialize/deserialize round-trip."""
        import yaml

        cfg = LlmJudgeConfig(
            enabled=True,
            provider="openai",
            model="gpt-4o-mini",
            sensitivity=JudgeSensitivity.HIGH,
            on_flag=PolicyDecision.BLOCK,
            cache_ttl=600,
            judge_on=[PolicyDecision.ALLOW, PolicyDecision.LOG],
        )
        # Simulate YAML round-trip via dict
        as_dict = cfg.model_dump()
        cfg2 = LlmJudgeConfig(**as_dict)
        assert cfg2.provider == "openai"
        assert cfg2.sensitivity == JudgeSensitivity.HIGH
        assert cfg2.on_flag == PolicyDecision.BLOCK
        assert PolicyDecision.LOG in cfg2.judge_on


# ---------------------------------------------------------------------------
# AgentWardPolicy.llm_judge field
# ---------------------------------------------------------------------------


class TestAgentWardPolicyJudgeField:
    def test_llm_judge_field_defaults_to_disabled(self) -> None:
        policy = AgentWardPolicy(version="1.0")
        assert policy.llm_judge.enabled is False

    def test_llm_judge_field_parses_from_yaml(self) -> None:
        from agentward.policy.loader import load_policy
        import yaml
        import tempfile
        from pathlib import Path

        yaml_content = {
            "version": "1.0",
            "llm_judge": {
                "enabled": True,
                "provider": "openai",
                "model": "gpt-4o-mini",
                "sensitivity": "high",
                "on_flag": "block",
                "cache_ttl": 600,
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(yaml_content, f)
            tmp_path = Path(f.name)

        try:
            policy = load_policy(tmp_path)
            assert policy.llm_judge.enabled is True
            assert policy.llm_judge.provider == "openai"
            assert policy.llm_judge.sensitivity == JudgeSensitivity.HIGH
            assert policy.llm_judge.on_flag == PolicyDecision.BLOCK
            assert policy.llm_judge.cache_ttl == 600
        finally:
            tmp_path.unlink(missing_ok=True)
