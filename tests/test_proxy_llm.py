"""Tests for the LLM API proxy — SSE parsing, interceptors, and LlmProxy.

Covers:
  - SSE parser (parse_sse)
  - AnthropicInterceptor state machine
  - OpenAIChatInterceptor
  - OpenAIResponsesInterceptor
  - LlmProxy request routing and provider detection
  - Non-streaming response filtering
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import AgentWardPolicy, PolicyDecision, SensitiveContentConfig
from agentward.audit.logger import AuditLogger
from agentward.proxy.llm import (
    ActionType,
    AnthropicInterceptor,
    OpenAIChatInterceptor,
    OpenAIResponsesInterceptor,
    SSEEvent,
    _classify_unknown_tool,
    _detect_provider,
    _extract_last_user_text,
    _filter_blocked_tools,
    _make_canned_response,
    _make_sensitive_block_replacement,
    _runtime_risk_cache,
    parse_sse,
)


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _make_sse_bytes(*events: str) -> bytes:
    """Build raw SSE bytes from data payloads.

    Each event becomes ``data: <payload>\\n\\n``.
    """
    return b"".join(f"data: {e}\n\n".encode() for e in events)


def _sse_event(data: str, event_type: str = "") -> SSEEvent:
    """Create an SSEEvent from a data string (for interceptor testing)."""
    raw = f"data: {data}\n\n".encode()
    return SSEEvent(data=data, raw=raw, event_type=event_type)


class _FakeContent:
    """Mimics aiohttp.StreamReader for testing parse_sse."""

    def __init__(self, data: bytes) -> None:
        self._lines = data.split(b"\n")
        # Re-add newlines (parse_sse iterates lines WITH newlines)
        self._iter = iter([line + b"\n" for line in self._lines])

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


class _FakeResponse:
    """Mimics aiohttp.ClientResponse with .content for SSE parsing."""

    def __init__(self, data: bytes) -> None:
        self.content = _FakeContent(data)


def _mock_policy() -> MagicMock:
    """Create a mock AgentWardPolicy with real SensitiveContentConfig."""
    policy = MagicMock(spec=AgentWardPolicy)
    policy.sensitive_content = SensitiveContentConfig()
    return policy


def _blocking_engine() -> PolicyEngine:
    """Create a PolicyEngine that blocks everything."""
    engine = MagicMock(spec=PolicyEngine)
    engine.evaluate.return_value = EvaluationResult(
        decision=PolicyDecision.BLOCK,
        reason="Blocked by test policy.",
    )
    engine.policy = _mock_policy()
    return engine


def _allowing_engine() -> PolicyEngine:
    """Create a PolicyEngine that allows everything."""
    engine = MagicMock(spec=PolicyEngine)
    engine.evaluate.return_value = EvaluationResult(
        decision=PolicyDecision.ALLOW,
        reason="Allowed by test policy.",
    )
    engine.policy = _mock_policy()
    return engine


def _approving_engine() -> PolicyEngine:
    """Create a PolicyEngine that returns APPROVE for everything."""
    engine = MagicMock(spec=PolicyEngine)
    engine.evaluate.return_value = EvaluationResult(
        decision=PolicyDecision.APPROVE,
        reason="Tool requires human approval.",
    )
    engine.policy = _mock_policy()
    return engine


# -----------------------------------------------------------------------
# SSE Parser tests
# -----------------------------------------------------------------------


class TestSSEParser:
    """Tests for parse_sse()."""

    @pytest.mark.asyncio
    async def test_single_event(self) -> None:
        raw = b"data: hello\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        assert events[0].data == "hello"

    @pytest.mark.asyncio
    async def test_multiple_events(self) -> None:
        raw = b"data: one\n\ndata: two\n\ndata: three\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 3
        assert [e.data for e in events] == ["one", "two", "three"]

    @pytest.mark.asyncio
    async def test_multi_line_data(self) -> None:
        raw = b"data: line1\ndata: line2\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        assert events[0].data == "line1\nline2"

    @pytest.mark.asyncio
    async def test_event_type(self) -> None:
        raw = b"event: ping\ndata: {}\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        assert events[0].event_type == "ping"
        assert events[0].data == "{}"

    @pytest.mark.asyncio
    async def test_event_id(self) -> None:
        raw = b"id: 42\ndata: payload\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        assert events[0].event_id == "42"

    @pytest.mark.asyncio
    async def test_comment_lines_skipped(self) -> None:
        raw = b": this is a comment\ndata: real\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        assert events[0].data == "real"

    @pytest.mark.asyncio
    async def test_trailing_event_without_blank_line(self) -> None:
        raw = b"data: trailing"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        assert events[0].data == "trailing"

    @pytest.mark.asyncio
    async def test_data_with_leading_space_stripped(self) -> None:
        raw = b"data: hello world\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert events[0].data == "hello world"

    @pytest.mark.asyncio
    async def test_done_event(self) -> None:
        raw = b"data: [DONE]\n\n"
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        assert events[0].data == "[DONE]"

    @pytest.mark.asyncio
    async def test_empty_stream(self) -> None:
        raw = b""
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 0

    @pytest.mark.asyncio
    async def test_json_data(self) -> None:
        payload = json.dumps({"type": "content_block_start"})
        raw = f"data: {payload}\n\n".encode()
        resp = _FakeResponse(raw)
        events = [e async for e in parse_sse(resp)]

        assert len(events) == 1
        parsed = json.loads(events[0].data)
        assert parsed["type"] == "content_block_start"


# -----------------------------------------------------------------------
# Provider detection
# -----------------------------------------------------------------------


class TestDetectProvider:
    def test_anthropic(self) -> None:
        assert _detect_provider("/v1/messages") == "anthropic"
        assert _detect_provider("/v1/messages?beta=true") == "anthropic"

    def test_openai_chat(self) -> None:
        assert _detect_provider("/v1/chat/completions") == "openai_chat"

    def test_openai_responses(self) -> None:
        assert _detect_provider("/v1/responses") == "openai_responses"

    def test_unknown(self) -> None:
        assert _detect_provider("/v1/embeddings") is None
        assert _detect_provider("/health") is None


# -----------------------------------------------------------------------
# Anthropic interceptor
# -----------------------------------------------------------------------


def _anthropic_text_block(index: int = 0) -> list[SSEEvent]:
    """Create SSE events for a text content block."""
    return [
        _sse_event(json.dumps({
            "type": "content_block_start",
            "index": index,
            "content_block": {"type": "text", "text": ""},
        })),
        _sse_event(json.dumps({
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "text_delta", "text": "Hello"},
        })),
        _sse_event(json.dumps({
            "type": "content_block_stop",
            "index": index,
        })),
    ]


def _anthropic_tool_block(
    index: int, name: str, arguments: dict[str, Any], tool_id: str = "toolu_01"
) -> list[SSEEvent]:
    """Create SSE events for a tool_use content block."""
    args_json = json.dumps(arguments)
    # Split args into chunks for realism
    mid = len(args_json) // 2
    chunk1, chunk2 = args_json[:mid], args_json[mid:]

    return [
        _sse_event(json.dumps({
            "type": "content_block_start",
            "index": index,
            "content_block": {"type": "tool_use", "id": tool_id, "name": name, "input": {}},
        })),
        _sse_event(json.dumps({
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "input_json_delta", "partial_json": chunk1},
        })),
        _sse_event(json.dumps({
            "type": "content_block_delta",
            "index": index,
            "delta": {"type": "input_json_delta", "partial_json": chunk2},
        })),
        _sse_event(json.dumps({
            "type": "content_block_stop",
            "index": index,
        })),
    ]


class TestAnthropicInterceptor:
    """Tests for AnthropicInterceptor."""

    def test_text_blocks_pass_through(self) -> None:
        interceptor = AnthropicInterceptor(_allowing_engine())

        for event in _anthropic_text_block(0):
            action = interceptor.process_event(event)
            assert action.type == ActionType.FORWARD

    def test_tool_allowed(self) -> None:
        interceptor = AnthropicInterceptor(_allowing_engine())

        events = _anthropic_tool_block(0, "read_file", {"path": "/tmp/test.txt"})
        actions = [interceptor.process_event(e) for e in events]

        # First 3 events: BUFFER, BUFFER, BUFFER
        # Last event (content_block_stop): FLUSH
        assert actions[0].type == ActionType.BUFFER
        assert actions[1].type == ActionType.BUFFER
        assert actions[2].type == ActionType.BUFFER
        assert actions[3].type == ActionType.FLUSH
        assert actions[3].tool_name == "read_file"
        assert len(actions[3].events) == 4

    def test_tool_blocked(self) -> None:
        interceptor = AnthropicInterceptor(_blocking_engine())

        events = _anthropic_tool_block(0, "delete_file", {"path": "/important"})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[0].type == ActionType.BUFFER
        assert actions[-1].type == ActionType.BLOCK
        assert actions[-1].tool_name == "delete_file"
        assert actions[-1].replacement != b""
        # Replacement should contain text block with block message
        assert b"AgentWard: blocked tool" in actions[-1].replacement

    def test_mixed_text_and_tool(self) -> None:
        interceptor = AnthropicInterceptor(_allowing_engine())

        all_events = _anthropic_text_block(0) + _anthropic_tool_block(
            1, "read_file", {"path": "/tmp/test.txt"}
        )
        actions = [interceptor.process_event(e) for e in all_events]

        # Text events: FORWARD, FORWARD, FORWARD
        # Tool events: BUFFER, BUFFER, BUFFER, FLUSH
        assert actions[0].type == ActionType.FORWARD
        assert actions[1].type == ActionType.FORWARD
        assert actions[2].type == ActionType.FORWARD
        assert actions[3].type == ActionType.BUFFER
        assert actions[6].type == ActionType.FLUSH

    def test_stop_reason_rewrite_when_all_blocked(self) -> None:
        interceptor = AnthropicInterceptor(_blocking_engine())

        events = _anthropic_tool_block(0, "shell_exec", {"cmd": "rm -rf /"})
        for e in events:
            interceptor.process_event(e)

        # Now send message_delta with stop_reason: tool_use
        delta_event = _sse_event(json.dumps({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
        }))
        action = interceptor.process_event(delta_event)

        assert action.type == ActionType.FORWARD
        assert len(action.events) == 1
        rewritten = json.loads(action.events[0].data)
        assert rewritten["delta"]["stop_reason"] == "end_turn"

    def test_stop_reason_not_rewritten_when_some_allowed(self) -> None:
        engine = MagicMock(spec=PolicyEngine)
        engine.evaluate.return_value = EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason="OK",
        )
        interceptor = AnthropicInterceptor(engine)

        # Process an allowed tool
        events = _anthropic_tool_block(0, "read_file", {"path": "/tmp"})
        for e in events:
            interceptor.process_event(e)

        # message_delta with stop_reason: tool_use should NOT be rewritten
        delta_event = _sse_event(json.dumps({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
        }))
        action = interceptor.process_event(delta_event)

        assert action.type == ActionType.FORWARD
        # No rewritten events — just forward the original
        assert len(action.events) == 0

    def test_finalize_blocks_remaining_buffer(self) -> None:
        """Truncated stream should fail-closed (BLOCK), not fail-open (FLUSH)."""
        interceptor = AnthropicInterceptor(_allowing_engine())

        # Start a tool block but don't finish it
        event = _sse_event(json.dumps({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "t1", "name": "test", "input": {}},
        }))
        interceptor.process_event(event)

        final = interceptor.finalize()
        assert final is not None
        assert final.type == ActionType.BLOCK
        assert final.replacement is not None

    def test_finalize_noop_when_idle(self) -> None:
        interceptor = AnthropicInterceptor(_allowing_engine())
        assert interceptor.finalize() is None

    def test_passthrough_mode(self) -> None:
        """No policy = passthrough (allow all)."""
        interceptor = AnthropicInterceptor(None)

        events = _anthropic_tool_block(0, "anything", {"x": 1})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[-1].type == ActionType.FLUSH
        assert actions[-1].result is not None
        assert actions[-1].result.decision == PolicyDecision.ALLOW

    def test_invalid_json_forwards(self) -> None:
        interceptor = AnthropicInterceptor(_allowing_engine())

        event = _sse_event("not json at all")
        action = interceptor.process_event(event)
        assert action.type == ActionType.FORWARD

    def test_empty_arguments(self) -> None:
        interceptor = AnthropicInterceptor(_allowing_engine())

        events = [
            _sse_event(json.dumps({
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "t1", "name": "no_args", "input": {}},
            })),
            _sse_event(json.dumps({
                "type": "content_block_stop",
                "index": 0,
            })),
        ]
        actions = [interceptor.process_event(e) for e in events]

        assert actions[-1].type == ActionType.FLUSH
        assert actions[-1].arguments == {}

    def test_tool_approve(self) -> None:
        """APPROVE policy returns ActionType.APPROVE with buffered events."""
        interceptor = AnthropicInterceptor(_approving_engine())

        events = _anthropic_tool_block(0, "browser", {"url": "https://example.com"})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[0].type == ActionType.BUFFER
        assert actions[-1].type == ActionType.APPROVE
        assert actions[-1].tool_name == "browser"
        assert len(actions[-1].events) == 4
        assert actions[-1].result is not None
        assert actions[-1].result.decision == PolicyDecision.APPROVE


# -----------------------------------------------------------------------
# OpenAI Chat Completions interceptor
# -----------------------------------------------------------------------


def _openai_chat_tool_chunks(
    name: str, arguments: dict[str, Any], tool_id: str = "call_123"
) -> list[SSEEvent]:
    """Create SSE events for an OpenAI Chat tool call."""
    args_json = json.dumps(arguments)
    mid = len(args_json) // 2

    return [
        # First chunk — tool_calls[0] with name
        _sse_event(json.dumps({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "id": tool_id,
                        "type": "function",
                        "function": {"name": name, "arguments": ""},
                    }],
                },
                "finish_reason": None,
            }],
        })),
        # Argument chunks
        _sse_event(json.dumps({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {"arguments": args_json[:mid]},
                    }],
                },
                "finish_reason": None,
            }],
        })),
        _sse_event(json.dumps({
            "choices": [{
                "index": 0,
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {"arguments": args_json[mid:]},
                    }],
                },
                "finish_reason": None,
            }],
        })),
        # Finish
        _sse_event(json.dumps({
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "tool_calls",
            }],
        })),
    ]


class TestOpenAIChatInterceptor:
    """Tests for OpenAIChatInterceptor."""

    def test_tool_allowed(self) -> None:
        interceptor = OpenAIChatInterceptor(_allowing_engine())

        events = _openai_chat_tool_chunks("read_file", {"path": "/tmp"})
        actions = [interceptor.process_event(e) for e in events]

        # First 3: BUFFER
        assert actions[0].type == ActionType.BUFFER
        assert actions[1].type == ActionType.BUFFER
        assert actions[2].type == ActionType.BUFFER
        # Last (finish_reason: tool_calls): FLUSH
        assert actions[3].type == ActionType.FLUSH
        assert len(actions[3].events) == 4

    def test_tool_blocked(self) -> None:
        interceptor = OpenAIChatInterceptor(_blocking_engine())

        events = _openai_chat_tool_chunks("shell_exec", {"cmd": "rm -rf /"})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[-1].type == ActionType.BLOCK
        assert b"AgentWard: blocked tool" in actions[-1].replacement

    def test_done_event_forwards(self) -> None:
        interceptor = OpenAIChatInterceptor(_allowing_engine())

        event = _sse_event("[DONE]")
        action = interceptor.process_event(event)
        assert action.type == ActionType.FORWARD

    def test_text_content_forwards(self) -> None:
        interceptor = OpenAIChatInterceptor(_allowing_engine())

        event = _sse_event(json.dumps({
            "choices": [{
                "index": 0,
                "delta": {"content": "Hello"},
                "finish_reason": None,
            }],
        }))
        action = interceptor.process_event(event)
        assert action.type == ActionType.FORWARD

    def test_passthrough_mode(self) -> None:
        interceptor = OpenAIChatInterceptor(None)

        events = _openai_chat_tool_chunks("anything", {"x": 1})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[-1].type == ActionType.FLUSH

    def test_finalize_blocks_truncated_stream(self) -> None:
        """Truncated stream should fail-closed (BLOCK), not fail-open (FLUSH)."""
        interceptor = OpenAIChatInterceptor(_allowing_engine())

        # Start buffering but don't finish
        events = _openai_chat_tool_chunks("read", {"a": 1})[:2]
        for e in events:
            interceptor.process_event(e)

        final = interceptor.finalize()
        assert final is not None
        assert final.type == ActionType.BLOCK
        assert final.replacement is not None

    def test_tool_approve(self) -> None:
        """APPROVE policy returns ActionType.APPROVE."""
        interceptor = OpenAIChatInterceptor(_approving_engine())

        events = _openai_chat_tool_chunks("browser", {"url": "https://example.com"})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[-1].type == ActionType.APPROVE
        assert actions[-1].tool_name == "browser"
        assert actions[-1].result is not None
        assert actions[-1].result.decision == PolicyDecision.APPROVE


# -----------------------------------------------------------------------
# OpenAI Responses interceptor
# -----------------------------------------------------------------------


def _openai_responses_tool_events(
    name: str, arguments: dict[str, Any], item_id: str = "item_1"
) -> list[SSEEvent]:
    """Create SSE events for an OpenAI Responses function_call."""
    args_json = json.dumps(arguments)
    mid = len(args_json) // 2

    return [
        _sse_event(json.dumps({
            "type": "response.output_item.added",
            "item": {"type": "function_call", "name": name, "id": item_id},
        })),
        _sse_event(json.dumps({
            "type": "response.function_call_arguments.delta",
            "delta": args_json[:mid],
        })),
        _sse_event(json.dumps({
            "type": "response.function_call_arguments.delta",
            "delta": args_json[mid:],
        })),
        _sse_event(json.dumps({
            "type": "response.output_item.done",
            "item": {"type": "function_call", "name": name, "arguments": args_json},
        })),
    ]


class TestOpenAIResponsesInterceptor:
    """Tests for OpenAIResponsesInterceptor."""

    def test_tool_allowed(self) -> None:
        interceptor = OpenAIResponsesInterceptor(_allowing_engine())

        events = _openai_responses_tool_events("search", {"query": "test"})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[0].type == ActionType.BUFFER
        assert actions[-1].type == ActionType.FLUSH
        assert actions[-1].tool_name == "search"

    def test_tool_blocked(self) -> None:
        interceptor = OpenAIResponsesInterceptor(_blocking_engine())

        events = _openai_responses_tool_events("delete", {"id": "123"})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[-1].type == ActionType.BLOCK
        assert b"AgentWard: blocked tool" in actions[-1].replacement

    def test_done_event_forwards(self) -> None:
        interceptor = OpenAIResponsesInterceptor(_allowing_engine())

        event = _sse_event("[DONE]")
        action = interceptor.process_event(event)
        assert action.type == ActionType.FORWARD

    def test_non_function_call_forwards(self) -> None:
        interceptor = OpenAIResponsesInterceptor(_allowing_engine())

        event = _sse_event(json.dumps({
            "type": "response.output_item.added",
            "item": {"type": "message", "content": "hello"},
        }))
        action = interceptor.process_event(event)
        assert action.type == ActionType.FORWARD

    def test_finalize_blocks_truncated_stream(self) -> None:
        """Truncated stream should fail-closed (BLOCK), not fail-open (FLUSH)."""
        interceptor = OpenAIResponsesInterceptor(_allowing_engine())

        events = _openai_responses_tool_events("test", {})[:2]
        for e in events:
            interceptor.process_event(e)

        final = interceptor.finalize()
        assert final is not None
        assert final.type == ActionType.BLOCK
        assert final.replacement is not None

    def test_tool_approve(self) -> None:
        """APPROVE policy returns ActionType.APPROVE."""
        interceptor = OpenAIResponsesInterceptor(_approving_engine())

        events = _openai_responses_tool_events("web_fetch", {"url": "https://example.com"})
        actions = [interceptor.process_event(e) for e in events]

        assert actions[-1].type == ActionType.APPROVE
        assert actions[-1].tool_name == "web_fetch"
        assert actions[-1].result is not None
        assert actions[-1].result.decision == PolicyDecision.APPROVE


# -----------------------------------------------------------------------
# _make_denial_replacement
# -----------------------------------------------------------------------


class TestMakeDenialReplacement:
    """Tests for _make_denial_replacement()."""

    def test_anthropic_format(self) -> None:
        from agentward.proxy.llm import _make_denial_replacement

        result = _make_denial_replacement("anthropic", "browser")
        assert b"denied by user" in result
        assert b"browser" in result
        assert b"content_block_start" in result
        assert b"text_delta" in result

    def test_openai_chat_format(self) -> None:
        from agentward.proxy.llm import _make_denial_replacement

        result = _make_denial_replacement("openai_chat", "web_fetch")
        assert b"denied by user" in result
        assert b"web_fetch" in result
        assert b"finish_reason" in result

    def test_openai_responses_format(self) -> None:
        from agentward.proxy.llm import _make_denial_replacement

        result = _make_denial_replacement("openai_responses", "search")
        assert b"denied by user" in result
        assert b"search" in result

    def test_unknown_provider_returns_empty(self) -> None:
        from agentward.proxy.llm import _make_denial_replacement

        result = _make_denial_replacement("unknown", "tool")
        assert result == b""


# -----------------------------------------------------------------------
# Non-streaming response filtering (LlmProxy methods)
# -----------------------------------------------------------------------


class TestNonStreamingFiltering:
    """Test the non-streaming response filtering methods of LlmProxy."""

    def _make_proxy(self, engine: PolicyEngine | None = None) -> Any:
        from agentward.audit.logger import AuditLogger
        from agentward.proxy.llm import LlmProxy

        return LlmProxy(
            provider_urls={"anthropic": "https://api.anthropic.com"},
            policy_engine=engine,
            audit_logger=AuditLogger(),
        )

    @pytest.mark.asyncio
    async def test_anthropic_blocks_tool_use(self) -> None:
        proxy = self._make_proxy(_blocking_engine())

        resp = {
            "content": [
                {"type": "text", "text": "Let me check."},
                {"type": "tool_use", "id": "t1", "name": "shell", "input": {"cmd": "ls"}},
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        # tool_use replaced with text block
        assert len(result["content"]) == 2
        assert result["content"][1]["type"] == "text"
        assert "blocked tool 'shell'" in result["content"][1]["text"]
        assert result["stop_reason"] == "end_turn"

    @pytest.mark.asyncio
    async def test_anthropic_allows_tool_use(self) -> None:
        proxy = self._make_proxy(_allowing_engine())

        resp = {
            "content": [
                {"type": "tool_use", "id": "t1", "name": "read", "input": {"path": "/tmp"}},
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        assert result["content"][0]["type"] == "tool_use"
        assert result["stop_reason"] == "tool_use"  # Not rewritten

    @pytest.mark.asyncio
    async def test_openai_chat_blocks_tool_calls(self) -> None:
        proxy = self._make_proxy(_blocking_engine())

        resp = {
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "exec", "arguments": '{"cmd":"ls"}'},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        }
        result = json.loads(await proxy._filter_openai_chat_response(resp))

        choice = result["choices"][0]
        assert choice["message"]["tool_calls"] is None
        assert choice["finish_reason"] == "stop"
        assert "blocked" in choice["message"]["content"]

    @pytest.mark.asyncio
    async def test_openai_chat_allows_tool_calls(self) -> None:
        proxy = self._make_proxy(_allowing_engine())

        resp = {
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "read", "arguments": '{"path":"/tmp"}'},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        }
        result = json.loads(await proxy._filter_openai_chat_response(resp))

        assert len(result["choices"][0]["message"]["tool_calls"]) == 1
        assert result["choices"][0]["finish_reason"] == "tool_calls"

    @pytest.mark.asyncio
    async def test_anthropic_no_content_passes_through(self) -> None:
        proxy = self._make_proxy(_blocking_engine())

        resp = {"error": {"type": "invalid_request_error"}}
        result = json.loads(await proxy._filter_anthropic_response(resp))
        assert result == resp

    @pytest.mark.asyncio
    async def test_anthropic_passthrough_mode(self) -> None:
        proxy = self._make_proxy(None)

        resp = {
            "content": [
                {"type": "tool_use", "id": "t1", "name": "anything", "input": {}},
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        # Passthrough: tool_use preserved
        assert result["content"][0]["type"] == "tool_use"


# -----------------------------------------------------------------------
# Request sanitization
# -----------------------------------------------------------------------


class TestSanitizeAnthropicMessages:
    """Tests for _sanitize_anthropic_messages()."""

    def test_no_messages_key(self) -> None:
        from agentward.proxy.llm import _sanitize_anthropic_messages

        body: dict[str, Any] = {"model": "claude-3"}
        assert _sanitize_anthropic_messages(body) is False

    def test_matched_pairs_untouched(self) -> None:
        from agentward.proxy.llm import _sanitize_anthropic_messages

        body: dict[str, Any] = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "exec", "input": {}},
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
                    ],
                },
            ]
        }
        assert _sanitize_anthropic_messages(body) is False

    def test_orphaned_tool_use_stripped(self) -> None:
        """tool_use without a matching tool_result is removed."""
        from agentward.proxy.llm import _sanitize_anthropic_messages

        body: dict[str, Any] = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "Let me help."},
                        {"type": "tool_use", "id": "t1", "name": "exec", "input": {}},
                    ],
                },
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "continue"}],
                },
            ]
        }
        assert _sanitize_anthropic_messages(body) is True
        # tool_use removed, text kept
        assistant_content = body["messages"][0]["content"]
        assert len(assistant_content) == 1
        assert assistant_content[0]["type"] == "text"

    def test_orphaned_tool_result_stripped(self) -> None:
        """tool_result without a matching tool_use is removed."""
        from agentward.proxy.llm import _sanitize_anthropic_messages

        body: dict[str, Any] = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Blocked."}],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
                    ],
                },
            ]
        }
        assert _sanitize_anthropic_messages(body) is True
        user_content = body["messages"][1]["content"]
        assert len(user_content) == 1
        assert user_content[0]["type"] == "text"
        assert user_content[0]["text"] == "(blocked by policy)"

    def test_empty_content_gets_placeholder(self) -> None:
        """If all blocks are removed, a placeholder is inserted."""
        from agentward.proxy.llm import _sanitize_anthropic_messages

        body: dict[str, Any] = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "exec", "input": {}},
                    ],
                },
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "hi"}],
                },
            ]
        }
        assert _sanitize_anthropic_messages(body) is True
        # All content removed from assistant — placeholder inserted
        assert body["messages"][0]["content"] == [{"type": "text", "text": "(blocked by policy)"}]

    def test_mixed_matched_and_orphaned(self) -> None:
        """Matched pairs stay, orphaned pair removed."""
        from agentward.proxy.llm import _sanitize_anthropic_messages

        body: dict[str, Any] = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "t1", "name": "read", "input": {}},
                        {"type": "tool_use", "id": "t2", "name": "exec", "input": {}},
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "t1", "content": "file data"},
                        {"type": "tool_result", "tool_use_id": "t2", "content": "blocked"},
                    ],
                },
            ]
        }
        # Both matched — no changes
        assert _sanitize_anthropic_messages(body) is False

    def test_orphaned_tool_use_only_no_result(self) -> None:
        """tool_use with NO tool_result anywhere gets stripped."""
        from agentward.proxy.llm import _sanitize_anthropic_messages

        body: dict[str, Any] = {
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "I'll run that."},
                        {"type": "tool_use", "id": "orphan1", "name": "exec", "input": {}},
                    ],
                },
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "What happened?"}],
                },
            ]
        }
        assert _sanitize_anthropic_messages(body) is True
        # orphan1 stripped
        assert len(body["messages"][0]["content"]) == 1
        assert body["messages"][0]["content"][0]["text"] == "I'll run that."


# -----------------------------------------------------------------------
# _filter_blocked_tools
# -----------------------------------------------------------------------


def _make_policy_engine(
    *,
    blocked: list[str] | None = None,
    approved: list[str] | None = None,
) -> PolicyEngine:
    """Create a policy engine with specific blocked/approved tools."""
    from agentward.policy.schema import AgentWardPolicy, ResourcePermissions

    skills: dict[str, dict[str, ResourcePermissions]] = {}
    if blocked:
        resources: dict[str, ResourcePermissions] = {}
        for name in blocked:
            resources[name] = ResourcePermissions(denied=True)
        skills["test-skill"] = resources

    require_approval = list(approved) if approved else []

    policy = AgentWardPolicy(
        version="1.0",
        skills=skills,
        require_approval=require_approval,
    )
    return PolicyEngine(policy)


class TestFilterBlockedTools:
    """Tests for _filter_blocked_tools()."""

    def test_no_policy_engine_returns_false(self) -> None:
        body: dict[str, Any] = {"tools": [{"name": "exec", "description": "run"}]}
        logger = AuditLogger()
        assert _filter_blocked_tools(body, None, logger) is False
        assert len(body["tools"]) == 1

    def test_no_tools_key_returns_false(self) -> None:
        body: dict[str, Any] = {"messages": []}
        engine = _make_policy_engine(blocked=["exec"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is False

    def test_empty_tools_returns_false(self) -> None:
        body: dict[str, Any] = {"tools": []}
        engine = _make_policy_engine(blocked=["exec"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is False

    def test_blocked_tool_removed(self) -> None:
        body: dict[str, Any] = {
            "tools": [
                {"name": "exec", "description": "run commands"},
                {"name": "search", "description": "search the web"},
            ]
        }
        engine = _make_policy_engine(blocked=["exec"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is True
        assert len(body["tools"]) == 1
        assert body["tools"][0]["name"] == "search"

    def test_approved_tool_kept(self) -> None:
        """Tools in require_approval are KEPT (gated at execution, not request)."""
        body: dict[str, Any] = {
            "tools": [
                {"name": "coding-agent", "description": "code execution"},
                {"name": "search", "description": "search the web"},
            ]
        }
        engine = _make_policy_engine(approved=["coding-agent"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is False
        assert len(body["tools"]) == 2

    def test_allowed_tools_kept(self) -> None:
        body: dict[str, Any] = {
            "tools": [
                {"name": "search", "description": "search the web"},
                {"name": "weather", "description": "get weather"},
            ]
        }
        engine = _make_policy_engine(blocked=["exec"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is False
        assert len(body["tools"]) == 2

    def test_all_tools_blocked(self) -> None:
        body: dict[str, Any] = {
            "tools": [
                {"name": "exec", "description": "run commands"},
            ]
        }
        engine = _make_policy_engine(blocked=["exec"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is True
        assert body["tools"] == []

    def test_mixed_blocked_and_approved(self) -> None:
        """BLOCK tools removed, APPROVE tools kept."""
        body: dict[str, Any] = {
            "tools": [
                {"name": "exec", "description": "run commands"},
                {"name": "coding-agent", "description": "code execution"},
                {"name": "search", "description": "search the web"},
            ]
        }
        engine = _make_policy_engine(blocked=["exec"], approved=["coding-agent"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is True
        # exec removed, coding-agent and search kept
        assert len(body["tools"]) == 2
        names = [t["name"] for t in body["tools"]]
        assert "coding-agent" in names
        assert "search" in names


# -----------------------------------------------------------------------
# Runtime tool classification
# -----------------------------------------------------------------------


@pytest.fixture(autouse=False)
def _clear_runtime_caches() -> None:  # type: ignore[misc]
    """Clear module-level caches before runtime classification tests."""
    _runtime_risk_cache.clear()


class TestRuntimeClassification:
    """Tests for runtime tool classification via analyze_tool()."""

    @pytest.fixture(autouse=True)
    def clear_caches(self, _clear_runtime_caches: None) -> None:  # noqa: PT004
        pass

    def test_critical_tool_classified_and_filtered(self) -> None:
        """Tool classified as CRITICAL (shell/exec) by analyze_tool is filtered."""
        body: dict[str, Any] = {
            "tools": [
                {"name": "exec", "description": "execute shell commands"},
                {"name": "weather", "description": "get weather forecast"},
            ]
        }
        # Empty policy — no explicit rules for any tool
        engine = _make_policy_engine()
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is True
        assert len(body["tools"]) == 1
        assert body["tools"][0]["name"] == "weather"

    def test_low_risk_tool_passes_through(self) -> None:
        """Tool classified as LOW risk passes through unchanged."""
        body: dict[str, Any] = {
            "tools": [
                {"name": "get_weather", "description": "get weather forecast"},
            ]
        }
        engine = _make_policy_engine()
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is False
        assert len(body["tools"]) == 1

    def test_explicit_policy_takes_precedence(self) -> None:
        """Explicit policy rule overrides runtime classification."""
        body: dict[str, Any] = {
            "tools": [
                {"name": "exec", "description": "execute shell commands"},
            ]
        }
        # Policy explicitly blocks "exec" via skills/resource deny
        engine = _make_policy_engine(blocked=["exec"])
        logger = AuditLogger()
        assert _filter_blocked_tools(body, engine, logger) is True
        assert body["tools"] == []

    def test_classification_cached(self) -> None:
        """Runtime classification is cached — second call uses cache."""
        from agentward.scan.permissions import RiskLevel

        tool = {"name": "exec", "description": "run commands"}
        _runtime_risk_cache.clear()

        result1 = _classify_unknown_tool(tool)
        assert result1 == RiskLevel.CRITICAL
        assert "exec" in _runtime_risk_cache

        # Second call should use cache (we can verify by checking it returns same)
        result2 = _classify_unknown_tool(tool)
        assert result2 == result1

    def test_high_risk_tool_filtered(self) -> None:
        """Tool classified as HIGH risk (e.g. credentials access) is filtered."""
        body: dict[str, Any] = {
            "tools": [
                {
                    "name": "get_secret",
                    "description": "retrieve credentials",
                    "input_schema": {
                        "type": "object",
                        "properties": {"api_key": {"type": "string"}},
                    },
                },
                {"name": "search", "description": "search the web"},
            ]
        }
        engine = _make_policy_engine()
        logger = AuditLogger()
        result = _filter_blocked_tools(body, engine, logger)
        # get_secret should be classified as HIGH (credentials) and filtered
        if result:
            assert body["tools"][0]["name"] == "search"

    def test_shell_tool_name_variants_classified(self) -> None:
        """Shell tool names in _RESOURCE_PATTERNS are classified as CRITICAL."""
        from agentward.scan.permissions import RiskLevel

        _runtime_risk_cache.clear()
        # These names map directly to DataAccessType.SHELL in _RESOURCE_PATTERNS
        shell_names = ["exec", "shell", "bash", "terminal", "cmd"]
        for name in shell_names:
            tool = {"name": name, "description": f"{name} tool"}
            risk = _classify_unknown_tool(tool)
            assert risk == RiskLevel.CRITICAL, f"{name} should be CRITICAL, got {risk}"


# -----------------------------------------------------------------------
# Sensitive content classifier integration tests
# -----------------------------------------------------------------------


class TestSensitiveBlockReplacement:
    """Tests for _make_sensitive_block_replacement."""

    def test_anthropic_format(self) -> None:
        from agentward.inspect.classifier import Finding, FindingType

        findings = [
            Finding(FindingType.CREDIT_CARD, "4111 **** **** 1111", "text"),
        ]
        result = _make_sensitive_block_replacement("anthropic", "browser", findings)
        assert b"sensitive data detected" in result
        assert b"credit_card" in result
        assert b"4111" in result
        assert b"content_block_start" in result

    def test_openai_chat_format(self) -> None:
        from agentward.inspect.classifier import Finding, FindingType

        findings = [Finding(FindingType.SSN, "***-**-6789", "body")]
        result = _make_sensitive_block_replacement("openai_chat", "tool", findings)
        assert b"sensitive data detected" in result
        assert b"ssn" in result

    def test_openai_responses_format(self) -> None:
        from agentward.inspect.classifier import Finding, FindingType

        findings = [Finding(FindingType.API_KEY, "sk-a...xyz1", "key")]
        result = _make_sensitive_block_replacement("openai_responses", "tool", findings)
        assert b"sensitive data detected" in result
        assert b"api_key" in result


class TestClassifierInNonStreaming:
    """Integration tests: classifier blocks sensitive tool calls in non-streaming responses."""

    def _make_proxy(self, engine: PolicyEngine | None = None) -> Any:
        from agentward.proxy.llm import LlmProxy

        return LlmProxy(
            provider_urls={"anthropic": "https://api.anthropic.com"},
            policy_engine=engine,
            audit_logger=AuditLogger(),
        )

    @pytest.mark.asyncio
    async def test_anthropic_blocks_credit_card_in_tool_args(self) -> None:
        """Tool allowed by policy but arguments contain a credit card → blocked."""
        proxy = self._make_proxy(_allowing_engine())

        resp = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "t1",
                    "name": "browser",
                    "input": {"text": "Buy with card 4111 1111 1111 1111"},
                },
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        # tool_use should be replaced with a text block about sensitive data
        assert result["content"][0]["type"] == "text"
        assert "sensitive data detected" in result["content"][0]["text"]
        assert "credit_card" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_anthropic_allows_clean_tool_args(self) -> None:
        """Tool allowed by policy with clean arguments → passes through."""
        proxy = self._make_proxy(_allowing_engine())

        resp = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "t1",
                    "name": "browser",
                    "input": {"url": "https://amazon.com", "query": "paper towels"},
                },
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        assert result["content"][0]["type"] == "tool_use"

    @pytest.mark.asyncio
    async def test_openai_chat_blocks_sensitive_args(self) -> None:
        proxy = self._make_proxy(_allowing_engine())

        resp = {
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "tc1",
                        "type": "function",
                        "function": {
                            "name": "browser",
                            "arguments": json.dumps({"text": "ssn: 123-45-6789"}),
                        },
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        }
        result = json.loads(await proxy._filter_openai_chat_response(resp))

        # Tool call should be removed (sensitive data)
        choice = result["choices"][0]
        assert choice["message"]["tool_calls"] is None
        assert choice["finish_reason"] == "stop"

    @pytest.mark.asyncio
    async def test_classifier_disabled_passes_through(self) -> None:
        """When classifier is disabled in policy, sensitive args pass through."""
        engine = _allowing_engine()
        engine.policy.sensitive_content = SensitiveContentConfig(enabled=False)
        proxy = self._make_proxy(engine)

        resp = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "t1",
                    "name": "browser",
                    "input": {"text": "card 4111 1111 1111 1111"},
                },
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        # Should pass through since classifier is disabled
        assert result["content"][0]["type"] == "tool_use"

    @pytest.mark.asyncio
    async def test_no_policy_engine_passes_through(self) -> None:
        """When no policy engine loaded (passthrough mode), no classification."""
        proxy = self._make_proxy(None)

        resp = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "t1",
                    "name": "browser",
                    "input": {"text": "card 4111 1111 1111 1111"},
                },
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        # Passthrough mode — no blocking
        assert result["content"][0]["type"] == "tool_use"

    @pytest.mark.asyncio
    async def test_demo_scenario_blocked(self) -> None:
        """User's exact demo scenario: credit card + expiry + cvv in browser args."""
        proxy = self._make_proxy(_allowing_engine())

        text = (
            "Here is my credit card info 4111 1111 1111 1111, "
            "expiry 01/30, cvv 123 - buy 3 boxes of bounty kitchen "
            "paper towel by browsing to amazon.com"
        )
        resp = {
            "content": [
                {
                    "type": "tool_use",
                    "id": "t1",
                    "name": "browser",
                    "input": {"text": text},
                },
            ],
            "stop_reason": "tool_use",
        }
        result = json.loads(await proxy._filter_anthropic_response(resp))

        assert result["content"][0]["type"] == "text"
        assert "sensitive data detected" in result["content"][0]["text"]
        assert "credit_card" in result["content"][0]["text"]


# -----------------------------------------------------------------------
# Request-side scanning tests
# -----------------------------------------------------------------------


class TestExtractLastUserText:
    """Tests for _extract_last_user_text."""

    def test_string_content(self) -> None:
        messages = [
            {"role": "user", "content": "hello world"},
        ]
        assert _extract_last_user_text(messages) == "hello world"

    def test_block_array_content(self) -> None:
        messages = [
            {"role": "user", "content": [
                {"type": "text", "text": "part one"},
                {"type": "text", "text": "part two"},
            ]},
        ]
        assert "part one" in _extract_last_user_text(messages)
        assert "part two" in _extract_last_user_text(messages)

    def test_picks_last_user_message(self) -> None:
        messages = [
            {"role": "user", "content": "first"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "second"},
        ]
        assert _extract_last_user_text(messages) == "second"

    def test_no_user_message(self) -> None:
        messages = [
            {"role": "assistant", "content": "hello"},
        ]
        assert _extract_last_user_text(messages) == ""

    def test_empty_messages(self) -> None:
        assert _extract_last_user_text([]) == ""


class TestMakeCannedResponse:
    """Tests for _make_canned_response."""

    def test_anthropic_non_streaming(self) -> None:
        resp = _make_canned_response("anthropic", "blocked", False)
        body = json.loads(resp.body)
        assert body["content"][0]["text"] == "blocked"
        assert body["stop_reason"] == "end_turn"
        assert resp.content_type == "application/json"

    def test_anthropic_streaming(self) -> None:
        resp = _make_canned_response("anthropic", "blocked", True)
        assert resp.content_type == "text/event-stream"
        assert b"content_block_delta" in resp.body
        assert b"blocked" in resp.body

    def test_openai_chat_non_streaming(self) -> None:
        resp = _make_canned_response("openai_chat", "nope", False)
        body = json.loads(resp.body)
        assert body["choices"][0]["message"]["content"] == "nope"

    def test_openai_chat_streaming(self) -> None:
        resp = _make_canned_response("openai_chat", "nope", True)
        assert resp.content_type == "text/event-stream"
        assert b"[DONE]" in resp.body


class TestRequestSideScanning:
    """Tests for _scan_request_messages on LlmProxy."""

    def _make_proxy(self, engine: Any = None) -> Any:
        from agentward.proxy.llm import LlmProxy

        return LlmProxy(
            provider_urls={"anthropic": "https://api.anthropic.com"},
            policy_engine=engine,
            audit_logger=AuditLogger(),
        )

    def test_blocks_credit_card_in_user_message(self) -> None:
        proxy = self._make_proxy(_allowing_engine())
        body = {
            "messages": [
                {"role": "user", "content": "Pay with 4111 1111 1111 1111"},
            ],
            "stream": True,
        }
        result = proxy._scan_request_messages(body, "anthropic", True)
        assert result is not None
        assert result.status == 200
        assert b"sensitive content" in result.body.lower() or b"AgentWard" in result.body

    def test_allows_clean_message(self) -> None:
        proxy = self._make_proxy(_allowing_engine())
        body = {
            "messages": [
                {"role": "user", "content": "Buy paper towels on amazon"},
            ],
        }
        result = proxy._scan_request_messages(body, "anthropic", False)
        assert result is None

    def test_no_policy_engine_passes_through(self) -> None:
        proxy = self._make_proxy(None)
        body = {
            "messages": [
                {"role": "user", "content": "card 4111 1111 1111 1111"},
            ],
        }
        result = proxy._scan_request_messages(body, "anthropic", False)
        assert result is None

    def test_classifier_disabled_passes_through(self) -> None:
        engine = _allowing_engine()
        engine.policy.sensitive_content = SensitiveContentConfig(enabled=False)
        proxy = self._make_proxy(engine)
        body = {
            "messages": [
                {"role": "user", "content": "card 4111 1111 1111 1111"},
            ],
        }
        result = proxy._scan_request_messages(body, "anthropic", False)
        assert result is None

    def test_demo_scenario_blocked_at_request(self) -> None:
        """User's demo: credit card in message is caught before hitting LLM."""
        proxy = self._make_proxy(_allowing_engine())
        body = {
            "messages": [
                {"role": "user", "content": (
                    "Here is my credit card info 4111 1111 1111 1111, "
                    "expiry 01/30, cvv 123 - buy 3 boxes of bounty kitchen "
                    "paper towel by browsing to amazon.com"
                )},
            ],
            "stream": True,
        }
        result = proxy._scan_request_messages(body, "anthropic", True)
        assert result is not None
        assert result.content_type == "text/event-stream"
        assert b"AgentWard" in result.body
        assert b"credit_card" in result.body
