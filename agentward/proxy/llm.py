"""LLM API reverse proxy with tool_use interception.

Sits between an agent runtime (e.g., ClawdBot/OpenClaw) and LLM provider
APIs (Anthropic, OpenAI).  Intercepts the **response** stream (SSE) and
evaluates ``tool_use`` / ``tool_calls`` blocks against the loaded policy
*before* the agent runtime sees them.  Blocked tool_use blocks are
surgically removed from the stream and replaced with a text notice.

Architecture:
  Agent Runtime (ClawdBot)
    → HTTP POST http://127.0.0.1:{listen_port}/v1/messages
  AgentWard LLM Proxy
    → HTTPS POST https://api.anthropic.com/v1/messages  (real provider)
      ← SSE streaming response
    ← Filtered stream (blocked tool_use blocks removed)
  Agent Runtime receives filtered stream
"""

from __future__ import annotations

import asyncio
import json as _json
import signal
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from sys import platform as _platform
from typing import Any, AsyncIterator

import aiohttp
from aiohttp import ClientSession, web
from rich.console import Console

from agentward.audit.logger import AuditLogger
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import PolicyDecision
from agentward.proxy.http import (
    _cleanup_stale_proxy,
    _identify_port_blocker,
    _remove_pid_file,
    _write_pid_file,
)

_console = Console(stderr=True)

_DEFAULT_LLM_PROXY_PORT = 18900

# Provider defaults — used when no explicit baseUrl is set.
_PROVIDER_DEFAULTS: dict[str, str] = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "openai-codex": "https://api.openai.com",
}

# Headers that must not be forwarded (hop-by-hop).
_HOP_BY_HOP = frozenset(
    {
        "transfer-encoding",
        "keep-alive",
        "te",
        "trailers",
        "proxy-authorization",
        "proxy-authenticate",
    }
)


# -----------------------------------------------------------------------
# SSE Parser
# -----------------------------------------------------------------------


@dataclass
class SSEEvent:
    """A single Server-Sent Event parsed from the stream."""

    data: str  # The ``data:`` payload (joined if multi-line)
    raw: bytes  # The raw bytes exactly as received (for transparent forwarding)
    event_type: str = ""  # The ``event:`` field, if present
    event_id: str = ""  # The ``id:`` field, if present


async def parse_sse(
    response: aiohttp.ClientResponse,
) -> AsyncIterator[SSEEvent]:
    """Parse an SSE byte stream into discrete events.

    Handles the full SSE spec:
    - ``data:`` lines (may be multi-line, joined with ``\\n``)
    - ``event:`` lines
    - ``id:`` lines
    - Comment lines (``:``) — included in raw bytes, no data emitted
    - Empty lines as event delimiters

    Yields:
        SSEEvent for each complete event (delimited by a blank line).
    """
    data_lines: list[str] = []
    event_type = ""
    event_id = ""
    raw_chunks: list[bytes] = []

    async for raw_line in response.content:
        line = raw_line.decode("utf-8", errors="replace")
        raw_chunks.append(raw_line)

        stripped = line.rstrip("\r\n")

        # Empty line = event delimiter
        if stripped == "":
            if data_lines:
                yield SSEEvent(
                    data="\n".join(data_lines),
                    raw=b"".join(raw_chunks),
                    event_type=event_type,
                    event_id=event_id,
                )
            # Reset for next event
            data_lines = []
            event_type = ""
            event_id = ""
            raw_chunks = []
            continue

        if stripped.startswith("data:"):
            value = stripped[5:]
            if value.startswith(" "):
                value = value[1:]  # strip optional leading space
            data_lines.append(value)
        elif stripped.startswith("event:"):
            value = stripped[6:]
            if value.startswith(" "):
                value = value[1:]
            event_type = value
        elif stripped.startswith("id:"):
            value = stripped[3:]
            if value.startswith(" "):
                value = value[1:]
            event_id = value
        # Comment lines (starting with ':') and unknown fields are captured
        # in raw_chunks but don't contribute to data.

    # Flush any trailing event without final blank line
    if data_lines:
        yield SSEEvent(
            data="\n".join(data_lines),
            raw=b"".join(raw_chunks),
            event_type=event_type,
            event_id=event_id,
        )


# -----------------------------------------------------------------------
# Interceptor actions
# -----------------------------------------------------------------------


class ActionType(Enum):
    """What the interceptor tells the proxy to do with an SSE event."""

    FORWARD = auto()  # Send to client immediately
    BUFFER = auto()  # Hold internally (tool_use in progress)
    FLUSH = auto()  # Tool allowed — flush buffered events
    BLOCK = auto()  # Tool blocked — drop buffered events, inject replacement


@dataclass
class InterceptAction:
    """Result of processing a single SSE event through an interceptor."""

    type: ActionType
    events: list[SSEEvent] = field(default_factory=list)  # For FLUSH
    replacement: bytes = b""  # For BLOCK — synthetic SSE bytes
    tool_name: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    result: EvaluationResult | None = None  # For audit logging


# -----------------------------------------------------------------------
# Base interceptor
# -----------------------------------------------------------------------


class ToolInterceptor(ABC):
    """Base class for provider-specific SSE tool_use interception."""

    def __init__(self, policy_engine: PolicyEngine | None) -> None:
        self._policy_engine = policy_engine

    def _evaluate(self, tool_name: str, arguments: dict[str, Any]) -> EvaluationResult:
        if self._policy_engine is None:
            return EvaluationResult(
                decision=PolicyDecision.ALLOW,
                reason="No policy loaded (passthrough mode).",
            )
        return self._policy_engine.evaluate(tool_name, arguments)

    @abstractmethod
    def process_event(self, event: SSEEvent) -> InterceptAction:
        """Process a single SSE event and return an action."""

    @abstractmethod
    def finalize(self) -> InterceptAction | None:
        """Called at the end of the stream.  Return any pending action."""


# -----------------------------------------------------------------------
# Anthropic interceptor
# -----------------------------------------------------------------------


class _AnthropicState(Enum):
    IDLE = auto()
    BUFFERING_TOOL = auto()


class AnthropicInterceptor(ToolInterceptor):
    """Intercept tool_use content blocks in Anthropic Messages API SSE.

    Event sequence for a tool_use block:
      content_block_start  (type=tool_use, name, id)
      content_block_delta* (input_json_delta — partial JSON chunks)
      content_block_stop

    Text/thinking blocks pass through immediately.
    """

    def __init__(self, policy_engine: PolicyEngine | None) -> None:
        super().__init__(policy_engine)
        self._state = _AnthropicState.IDLE
        self._buffer: list[SSEEvent] = []
        self._tool_name = ""
        self._tool_id = ""
        self._json_chunks: list[str] = []
        self._block_index: int = 0
        self._any_tool_blocked = False
        self._all_tools_blocked = True  # tracks if ALL tool_use blocks were blocked
        self._seen_any_tool = False

    def process_event(self, event: SSEEvent) -> InterceptAction:
        try:
            parsed = _json.loads(event.data)
        except (ValueError, TypeError):
            return InterceptAction(type=ActionType.FORWARD)

        if not isinstance(parsed, dict):
            return InterceptAction(type=ActionType.FORWARD)

        event_type = parsed.get("type", "")

        if self._state == _AnthropicState.IDLE:
            return self._process_idle(event, parsed, event_type)
        else:  # BUFFERING_TOOL
            return self._process_buffering(event, parsed, event_type)

    def _process_idle(
        self, event: SSEEvent, parsed: dict[str, Any], event_type: str
    ) -> InterceptAction:
        if event_type == "content_block_start":
            block = parsed.get("content_block", {})
            if isinstance(block, dict) and block.get("type") == "tool_use":
                # Start buffering
                self._state = _AnthropicState.BUFFERING_TOOL
                self._buffer = [event]
                self._tool_name = block.get("name", "unknown")
                self._tool_id = block.get("id", "")
                self._json_chunks = []
                self._block_index = parsed.get("index", 0)
                self._seen_any_tool = True
                return InterceptAction(type=ActionType.BUFFER)

        # message_delta may contain stop_reason — rewrite if all tools blocked
        if event_type == "message_delta":
            delta = parsed.get("delta", {})
            if (
                isinstance(delta, dict)
                and delta.get("stop_reason") == "tool_use"
                and self._seen_any_tool
                and self._all_tools_blocked
            ):
                # Rewrite stop_reason since we blocked all tool_use blocks
                delta["stop_reason"] = "end_turn"
                rewritten = _json.dumps(parsed, separators=(",", ":"))
                new_raw = f"event: message_delta\ndata: {rewritten}\n\n".encode()
                return InterceptAction(
                    type=ActionType.FORWARD,
                    events=[SSEEvent(data=rewritten, raw=new_raw, event_type=event.event_type)],
                )

        return InterceptAction(type=ActionType.FORWARD)

    def _process_buffering(
        self, event: SSEEvent, parsed: dict[str, Any], event_type: str
    ) -> InterceptAction:
        self._buffer.append(event)

        if event_type == "content_block_delta":
            delta = parsed.get("delta", {})
            if isinstance(delta, dict) and delta.get("type") == "input_json_delta":
                chunk = delta.get("partial_json", "")
                if chunk:
                    self._json_chunks.append(chunk)
            return InterceptAction(type=ActionType.BUFFER)

        if event_type == "content_block_stop":
            # Tool block complete — evaluate policy
            full_json = "".join(self._json_chunks)
            try:
                arguments = _json.loads(full_json) if full_json else {}
            except (ValueError, TypeError):
                arguments = {}

            if not isinstance(arguments, dict):
                arguments = {}

            result = self._evaluate(self._tool_name, arguments)

            self._state = _AnthropicState.IDLE

            if result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
                self._all_tools_blocked = False
                action = InterceptAction(
                    type=ActionType.FLUSH,
                    events=list(self._buffer),
                    tool_name=self._tool_name,
                    arguments=arguments,
                    result=result,
                )
                self._buffer = []
                return action
            else:
                # BLOCK, APPROVE, REDACT — drop the tool_use block
                self._any_tool_blocked = True
                replacement = self._make_replacement_text(
                    self._block_index, self._tool_name, result.reason
                )
                action = InterceptAction(
                    type=ActionType.BLOCK,
                    replacement=replacement,
                    tool_name=self._tool_name,
                    arguments=arguments,
                    result=result,
                )
                self._buffer = []
                return action

        # Other events during buffering — keep buffering
        return InterceptAction(type=ActionType.BUFFER)

    def finalize(self) -> InterceptAction | None:
        """If stream ends mid-buffer, flush what we have (fail-open)."""
        if self._buffer:
            events = list(self._buffer)
            self._buffer = []
            self._state = _AnthropicState.IDLE
            return InterceptAction(type=ActionType.FLUSH, events=events)
        return None

    @staticmethod
    def _make_replacement_text(index: int, tool_name: str, reason: str) -> bytes:
        """Build SSE bytes for a replacement text block.

        Matches Anthropic's real SSE format: each event has both an
        ``event:`` tag and a ``data:`` line.  Without the ``event:`` tag,
        downstream SSE parsers (including ClawdBot) may silently drop
        the replacement block, resulting in a blank response.
        """
        msg = f"[AgentWard: blocked tool '{tool_name}' — {reason}]"
        events = [
            (
                "content_block_start",
                _json.dumps(
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {"type": "text", "text": ""},
                    },
                    separators=(",", ":"),
                ),
            ),
            (
                "content_block_delta",
                _json.dumps(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": msg},
                    },
                    separators=(",", ":"),
                ),
            ),
            (
                "content_block_stop",
                _json.dumps(
                    {"type": "content_block_stop", "index": index},
                    separators=(",", ":"),
                ),
            ),
        ]
        return b"".join(
            f"event: {etype}\ndata: {data}\n\n".encode()
            for etype, data in events
        )


# -----------------------------------------------------------------------
# OpenAI Chat Completions interceptor
# -----------------------------------------------------------------------


class OpenAIChatInterceptor(ToolInterceptor):
    """Intercept tool_calls in OpenAI Chat Completions SSE.

    Tool calls appear as ``delta.tool_calls[i]`` across multiple chunks.
    The name arrives first, then argument chunks accumulate.
    ``finish_reason: "tool_calls"`` signals completion.
    """

    def __init__(self, policy_engine: PolicyEngine | None) -> None:
        super().__init__(policy_engine)
        # Per-index tracking: {index: {"name": str, "args": str, "id": str}}
        self._tools: dict[int, dict[str, str]] = {}
        self._buffer: list[SSEEvent] = []
        self._buffering = False

    def process_event(self, event: SSEEvent) -> InterceptAction:
        if event.data == "[DONE]":
            return InterceptAction(type=ActionType.FORWARD)

        try:
            parsed = _json.loads(event.data)
        except (ValueError, TypeError):
            return InterceptAction(type=ActionType.FORWARD)

        if not isinstance(parsed, dict):
            return InterceptAction(type=ActionType.FORWARD)

        choices = parsed.get("choices", [])
        if not choices or not isinstance(choices, list):
            return InterceptAction(type=ActionType.FORWARD)

        choice = choices[0]
        if not isinstance(choice, dict):
            return InterceptAction(type=ActionType.FORWARD)

        delta = choice.get("delta", {})
        finish_reason = choice.get("finish_reason")

        # Check for tool_calls in delta
        tool_calls = delta.get("tool_calls", []) if isinstance(delta, dict) else []
        if tool_calls:
            self._buffering = True
            self._buffer.append(event)

            for tc in tool_calls:
                if not isinstance(tc, dict):
                    continue
                idx = tc.get("index", 0)
                if idx not in self._tools:
                    self._tools[idx] = {"name": "", "args": "", "id": ""}
                func = tc.get("function", {})
                if isinstance(func, dict):
                    name = func.get("name", "")
                    if name:
                        self._tools[idx]["name"] = name
                    args_chunk = func.get("arguments", "")
                    if args_chunk:
                        self._tools[idx]["args"] += args_chunk
                tc_id = tc.get("id", "")
                if tc_id:
                    self._tools[idx]["id"] = tc_id

            return InterceptAction(type=ActionType.BUFFER)

        # finish_reason == "tool_calls" — evaluate all accumulated tools
        if finish_reason == "tool_calls" and self._tools:
            self._buffer.append(event)
            return self._evaluate_all()

        # Not tool-related
        if self._buffering:
            self._buffer.append(event)
            return InterceptAction(type=ActionType.BUFFER)

        return InterceptAction(type=ActionType.FORWARD)

    def _evaluate_all(self) -> InterceptAction:
        """Evaluate all accumulated tool calls and produce a single action."""
        all_blocked = True
        blocked_names: list[str] = []
        results: list[tuple[str, dict[str, Any], EvaluationResult]] = []

        for idx in sorted(self._tools):
            tc = self._tools[idx]
            name = tc["name"] or "unknown"
            try:
                args = _json.loads(tc["args"]) if tc["args"] else {}
            except (ValueError, TypeError):
                args = {}
            if not isinstance(args, dict):
                args = {}

            result = self._evaluate(name, args)
            results.append((name, args, result))

            if result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
                all_blocked = False
            else:
                blocked_names.append(name)

        self._buffering = False

        if all_blocked:
            # Replace entire response with text
            reasons = ", ".join(blocked_names)
            replacement_msg = f"[AgentWard: blocked tool(s) '{reasons}']"
            # Build a non-streaming-style text chunk
            replacement = _json.dumps(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"content": replacement_msg},
                            "finish_reason": "stop",
                        }
                    ]
                },
                separators=(",", ":"),
            )
            replacement_bytes = f"data: {replacement}\n\n".encode()

            first_result = results[0] if results else None
            action = InterceptAction(
                type=ActionType.BLOCK,
                replacement=replacement_bytes,
                tool_name=blocked_names[0] if blocked_names else "",
                arguments=first_result[1] if first_result else {},
                result=first_result[2] if first_result else None,
            )
            self._tools.clear()
            self._buffer.clear()
            return action
        else:
            # Some allowed, some blocked — for simplicity in v1, flush all
            # (partial filtering of interleaved chunks is complex)
            events = list(self._buffer)
            first_result = results[0] if results else None
            action = InterceptAction(
                type=ActionType.FLUSH,
                events=events,
                tool_name=first_result[0] if first_result else "",
                arguments=first_result[1] if first_result else {},
                result=first_result[2] if first_result else None,
            )
            self._tools.clear()
            self._buffer.clear()
            return action

    def finalize(self) -> InterceptAction | None:
        if self._buffer:
            events = list(self._buffer)
            self._buffer.clear()
            self._tools.clear()
            self._buffering = False
            return InterceptAction(type=ActionType.FLUSH, events=events)
        return None


# -----------------------------------------------------------------------
# OpenAI Responses interceptor
# -----------------------------------------------------------------------


class OpenAIResponsesInterceptor(ToolInterceptor):
    """Intercept function_call items in OpenAI Responses API SSE.

    Events:
      response.output_item.added  (type=function_call, name)
      response.function_call_arguments.delta  (JSON chunks)
      response.output_item.done   (complete item)
    """

    def __init__(self, policy_engine: PolicyEngine | None) -> None:
        super().__init__(policy_engine)
        self._buffer: list[SSEEvent] = []
        self._buffering = False
        self._tool_name = ""
        self._arg_chunks: list[str] = []

    def process_event(self, event: SSEEvent) -> InterceptAction:
        if event.data == "[DONE]":
            return InterceptAction(type=ActionType.FORWARD)

        try:
            parsed = _json.loads(event.data)
        except (ValueError, TypeError):
            return InterceptAction(type=ActionType.FORWARD)

        if not isinstance(parsed, dict):
            return InterceptAction(type=ActionType.FORWARD)

        event_type = parsed.get("type", "")

        if event_type == "response.output_item.added":
            item = parsed.get("item", {})
            if isinstance(item, dict) and item.get("type") == "function_call":
                self._buffering = True
                self._buffer = [event]
                self._tool_name = item.get("name", "unknown")
                self._arg_chunks = []
                return InterceptAction(type=ActionType.BUFFER)

        if event_type == "response.function_call_arguments.delta" and self._buffering:
            self._buffer.append(event)
            delta = parsed.get("delta", "")
            if isinstance(delta, str):
                self._arg_chunks.append(delta)
            return InterceptAction(type=ActionType.BUFFER)

        if event_type == "response.output_item.done" and self._buffering:
            self._buffer.append(event)

            full_args = "".join(self._arg_chunks)
            try:
                arguments = _json.loads(full_args) if full_args else {}
            except (ValueError, TypeError):
                arguments = {}
            if not isinstance(arguments, dict):
                arguments = {}

            result = self._evaluate(self._tool_name, arguments)
            self._buffering = False

            if result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
                events = list(self._buffer)
                self._buffer.clear()
                return InterceptAction(
                    type=ActionType.FLUSH,
                    events=events,
                    tool_name=self._tool_name,
                    arguments=arguments,
                    result=result,
                )
            else:
                self._buffer.clear()
                # Inject a text output item instead
                msg = f"[AgentWard: blocked tool '{self._tool_name}' — {result.reason}]"
                replacement = _json.dumps(
                    {
                        "type": "response.output_text.done",
                        "text": msg,
                    },
                    separators=(",", ":"),
                )
                return InterceptAction(
                    type=ActionType.BLOCK,
                    replacement=f"data: {replacement}\n\n".encode(),
                    tool_name=self._tool_name,
                    arguments=arguments,
                    result=result,
                )

        if self._buffering:
            self._buffer.append(event)
            return InterceptAction(type=ActionType.BUFFER)

        return InterceptAction(type=ActionType.FORWARD)

    def finalize(self) -> InterceptAction | None:
        if self._buffer:
            events = list(self._buffer)
            self._buffer.clear()
            self._buffering = False
            return InterceptAction(type=ActionType.FLUSH, events=events)
        return None


# -----------------------------------------------------------------------
# LLM Proxy
# -----------------------------------------------------------------------


def _detect_provider(path: str) -> str | None:
    """Detect LLM provider from request path.

    Returns:
        Provider name ("anthropic", "openai_chat", "openai_responses")
        or None for unknown paths.
    """
    if path.startswith("/v1/messages"):
        return "anthropic"
    if path.startswith("/v1/chat/completions"):
        return "openai_chat"
    if path.startswith("/v1/responses"):
        return "openai_responses"
    return None


def _make_interceptor(
    provider: str, policy_engine: PolicyEngine | None
) -> ToolInterceptor:
    """Create the appropriate interceptor for a provider."""
    if provider == "anthropic":
        return AnthropicInterceptor(policy_engine)
    if provider == "openai_chat":
        return OpenAIChatInterceptor(policy_engine)
    if provider == "openai_responses":
        return OpenAIResponsesInterceptor(policy_engine)
    msg = f"Unknown provider: {provider}"
    raise ValueError(msg)


def _filter_blocked_tools(
    body: dict[str, Any],
    policy_engine: PolicyEngine | None,
    audit_logger: AuditLogger,
) -> bool:
    """Remove blocked tools from the ``tools`` array in an Anthropic request.

    Instead of waiting for the LLM to call a blocked tool and then
    intercepting the response (which corrupts conversation history),
    we proactively remove blocked tools from the request so the LLM
    never sees them.

    Args:
        body: The parsed request body (mutated in place).
        policy_engine: The policy engine (None = passthrough, no filtering).
        audit_logger: Audit logger for logging filtered tools.

    Returns:
        True if any tools were removed, False otherwise.
    """
    if policy_engine is None:
        return False

    tools = body.get("tools")
    if not isinstance(tools, list) or not tools:
        return False

    filtered: list[dict[str, Any]] = []
    removed_names: list[str] = []

    for tool in tools:
        if not isinstance(tool, dict):
            filtered.append(tool)
            continue

        name = tool.get("name", "")
        if not name:
            filtered.append(tool)
            continue

        result = policy_engine.evaluate(name, {})
        if result.decision in (PolicyDecision.BLOCK, PolicyDecision.APPROVE):
            removed_names.append(name)
            audit_logger.log_tool_call(name, {}, result)
        else:
            filtered.append(tool)

    if not removed_names:
        return False

    body["tools"] = filtered
    _console.print(
        f"  [bold #ffcc00]Filtered {len(removed_names)} blocked tool(s) "
        f"from request: {', '.join(removed_names)}[/bold #ffcc00]",
        highlight=False,
    )
    return True


def _dump_tool_ids(body: dict[str, Any], label: str) -> None:
    """Debug: dump tool_use and tool_result IDs from messages to stderr."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return
    for i, msg in enumerate(messages):
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "?")
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            btype = block.get("type", "")
            if btype == "tool_use":
                tid = block.get("id", "?")
                name = block.get("name", "?")
                _console.print(
                    f"  [dim]{label} msg[{i}] {role}: tool_use id={tid} name={name}[/dim]",
                    highlight=False,
                )
            elif btype == "tool_result":
                tid = block.get("tool_use_id", "?")
                _console.print(
                    f"  [dim]{label} msg[{i}] {role}: tool_result for={tid}[/dim]",
                    highlight=False,
                )


def _sanitize_anthropic_messages(body: dict[str, Any]) -> bool:
    """Remove orphaned tool_use / tool_result blocks from Anthropic requests.

    When AgentWard blocks a ``tool_use`` in a response, the agent runtime's
    conversation history may become inconsistent:

    - The assistant message may still contain the ``tool_use`` block (if
      the runtime caches the reconstructed message before our interception).
    - The next user message may contain a ``tool_result`` referencing the
      blocked ``tool_use`` ID.

    The Anthropic API requires every ``tool_use`` to have a corresponding
    ``tool_result`` immediately after.  This function strips mismatched
    pairs so the request is valid.

    Args:
        body: The parsed request body (mutated in place).

    Returns:
        True if any modifications were made, False otherwise.
    """
    messages = body.get("messages")
    if not isinstance(messages, list):
        return False

    modified = False

    # Pass 1: Collect all tool_use IDs and tool_result IDs.
    tool_use_ids: set[str] = set()
    tool_result_ids: set[str] = set()

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use":
                tid = block.get("id")
                if tid:
                    tool_use_ids.add(tid)
            elif block.get("type") == "tool_result":
                tid = block.get("tool_use_id")
                if tid:
                    tool_result_ids.add(tid)

    # IDs that have tool_use but no tool_result, or vice versa.
    orphaned_use = tool_use_ids - tool_result_ids
    orphaned_result = tool_result_ids - tool_use_ids

    if not orphaned_use and not orphaned_result:
        return False

    # Pass 2: Strip orphaned blocks.
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content")
        if not isinstance(content, list):
            continue

        filtered = []
        for block in content:
            if not isinstance(block, dict):
                filtered.append(block)
                continue
            if block.get("type") == "tool_use" and block.get("id") in orphaned_use:
                modified = True
                continue  # drop orphaned tool_use
            if block.get("type") == "tool_result" and block.get("tool_use_id") in orphaned_result:
                modified = True
                continue  # drop orphaned tool_result
            filtered.append(block)

        if len(filtered) != len(content):
            # If all content blocks were removed, replace with a placeholder
            # so the message isn't empty (Anthropic rejects empty content).
            if not filtered:
                filtered = [{"type": "text", "text": "(blocked by policy)"}]
            msg["content"] = filtered

    return modified


class LlmProxy:
    """HTTP reverse proxy for LLM API endpoints with SSE tool_use interception.

    Forwards requests to real LLM providers, intercepts SSE response
    streams to evaluate tool_use blocks against the loaded policy, and
    blocks/allows them before the agent runtime sees them.

    Args:
        listen_host: Host to bind the proxy server.
        listen_port: Port to bind the proxy server.
        provider_urls: Mapping of model key → real provider base URL.
        policy_engine: Loaded policy engine (None = passthrough mode).
        audit_logger: Audit logger for tool call decisions.
        policy_path: Path to the policy file (for startup log).
    """

    def __init__(
        self,
        *,
        listen_host: str = "127.0.0.1",
        listen_port: int = _DEFAULT_LLM_PROXY_PORT,
        provider_urls: dict[str, str] | None = None,
        policy_engine: PolicyEngine | None = None,
        audit_logger: AuditLogger,
        policy_path: Path | None = None,
    ) -> None:
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._provider_urls = provider_urls or {}
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._policy_path = policy_path
        self._session: ClientSession | None = None

    async def run(self, shutdown_event: asyncio.Event | None = None) -> None:
        """Start the LLM proxy server and block until shutdown.

        Args:
            shutdown_event: Optional external event to trigger shutdown.
                When running alongside other proxies, pass a shared event
                so a single Ctrl+C stops everything.  If *None*, the proxy
                registers its own signal handlers.
        """
        _cleanup_stale_proxy(self._listen_port)

        app = web.Application()
        app.router.add_route("*", "/{path_info:.*}", self._handle_request)

        runner = web.AppRunner(app)
        await runner.setup()

        try:
            site = web.TCPSite(runner, self._listen_host, self._listen_port)
            await site.start()
        except OSError as e:
            if e.errno == 48:  # Address already in use
                blocker = _identify_port_blocker(self._listen_port)
                msg = f"Port {self._listen_port} is already in use"
                if blocker:
                    msg += f" by {blocker}"
                _console.print(
                    f"[bold red]Error:[/bold red] {msg}",
                    highlight=False,
                )
            else:
                _console.print(
                    f"[bold red]Error:[/bold red] Cannot bind to "
                    f"{self._listen_host}:{self._listen_port}: {e}",
                    highlight=False,
                )
            await runner.cleanup()
            return

        _write_pid_file(self._listen_port)

        own_event = shutdown_event is None
        if shutdown_event is None:
            shutdown_event = asyncio.Event()

        if own_event and _platform != "win32":
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, shutdown_event.set)

        try:
            self._audit_logger.log_llm_startup(
                self._listen_port,
                self._provider_urls,
                self._policy_path,
            )
            _console.print(
                f"[bold #00ff88]LLM proxy listening on "
                f"http://{self._listen_host}:{self._listen_port}[/bold #00ff88]",
            )
            providers = ", ".join(self._provider_urls.values()) or "auto-detect"
            _console.print(f"[dim]Forwarding to: {providers}[/dim]")

            await shutdown_event.wait()
        finally:
            _remove_pid_file(self._listen_port)
            if self._session is not None:
                await self._session.close()
            await runner.cleanup()

    async def _get_session(self) -> ClientSession:
        if self._session is None or self._session.closed:
            self._session = ClientSession()
        return self._session

    # ------------------------------------------------------------------
    # Request routing
    # ------------------------------------------------------------------

    async def _handle_request(self, request: web.Request) -> web.StreamResponse:
        """Route incoming LLM API requests."""
        path = request.path
        provider = _detect_provider(path)

        if provider is None:
            # Unknown path — forward transparently
            return await self._forward_transparent(request)

        # Resolve real provider URL
        real_base_url = self._resolve_provider_url(request)
        if real_base_url is None:
            return web.json_response(
                {"error": {"type": "proxy_error", "message": "Cannot determine upstream provider URL"}},
                status=502,
            )

        # Read body and check if streaming
        raw_body = await request.read()

        try:
            body_json = _json.loads(raw_body)
            is_streaming = body_json.get("stream", False)
        except (ValueError, TypeError):
            body_json = None
            is_streaming = False

        body_modified = False

        if body_json is not None and provider == "anthropic":
            # 1. Strip blocked/approved tools from the tools array so the
            #    LLM never sees them.  This prevents the LLM from calling
            #    blocked tools, avoiding conversation history corruption.
            if _filter_blocked_tools(body_json, self._policy_engine, self._audit_logger):
                body_modified = True

            # 2. Sanitize orphaned tool_use / tool_result blocks from
            #    conversation history.  When we previously blocked a
            #    tool_use in the response stream, the agent runtime may
            #    still have the stale ID in its cached messages.
            # Debug: dump tool_use/tool_result IDs before sanitization
            _dump_tool_ids(body_json, "BEFORE")
            if _sanitize_anthropic_messages(body_json):
                body_modified = True
                _console.print(
                    "  [bold #ffcc00]Sanitizer: stripped orphaned tool_use/tool_result blocks[/bold #ffcc00]",
                    highlight=False,
                )
                _dump_tool_ids(body_json, "AFTER")

        if body_modified and body_json is not None:
            raw_body = _json.dumps(body_json, separators=(",", ":")).encode()

        if is_streaming:
            return await self._handle_streaming(request, raw_body, real_base_url, provider)
        else:
            return await self._handle_non_streaming(request, raw_body, real_base_url, provider)

    def _resolve_provider_url(self, request: web.Request) -> str | None:
        """Resolve the real provider base URL for a request.

        Strategy:
        1. Check provider_urls for any matching entry
        2. Detect from request headers (anthropic-version → Anthropic, etc.)
        3. Return None if unresolvable
        """
        # If we have provider URLs from sidecar, pick the first one
        # (they all point to the same proxy port, so the real URLs are in the sidecar)
        if self._provider_urls:
            # Try to detect from headers which provider this is
            if request.headers.get("anthropic-version") or request.headers.get("x-api-key"):
                for key, url in self._provider_urls.items():
                    if "anthropic" in key.lower() or "anthropic" in url.lower():
                        return url
            if request.headers.get("authorization", "").startswith("Bearer "):
                for key, url in self._provider_urls.items():
                    if "openai" in key.lower() or "openai" in url.lower():
                        return url
            # Fallback: return first URL
            return next(iter(self._provider_urls.values()), None)

        # Detect from headers
        if request.headers.get("anthropic-version") or request.headers.get("x-api-key"):
            return "https://api.anthropic.com"
        if request.headers.get("authorization", "").startswith("Bearer "):
            return "https://api.openai.com"

        return None

    # ------------------------------------------------------------------
    # Streaming handler
    # ------------------------------------------------------------------

    async def _handle_streaming(
        self,
        request: web.Request,
        raw_body: bytes,
        real_base_url: str,
        provider: str,
    ) -> web.StreamResponse:
        """Forward a streaming request, intercepting tool_use in the SSE response."""
        session = await self._get_session()
        upstream_url = real_base_url.rstrip("/") + request.path

        # Copy request headers (filter hop-by-hop)
        fwd_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() not in _HOP_BY_HOP and key.lower() != "host":
                fwd_headers[key] = value

        try:
            upstream = await session.post(
                upstream_url,
                headers=fwd_headers,
                data=raw_body,
                params=request.query,
            )
        except aiohttp.ClientError as e:
            _console.print(
                f"  [bold red]LLM upstream error:[/bold red] {e}",
                highlight=False,
            )
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )

        # If upstream didn't return SSE, forward as-is
        content_type = upstream.headers.get("content-type", "")
        if "text/event-stream" not in content_type:
            body = await upstream.read()
            resp_headers = {
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"
            }
            return web.Response(
                body=body,
                status=upstream.status,
                headers=resp_headers,
            )

        # Stream SSE with interception
        response = web.StreamResponse(status=upstream.status)
        response.content_type = "text/event-stream"
        # Copy relevant upstream headers
        for key, value in upstream.headers.items():
            k_lower = key.lower()
            if k_lower not in _HOP_BY_HOP and k_lower not in ("content-type", "content-length", "transfer-encoding"):
                response.headers[key] = value
        await response.prepare(request)

        interceptor = _make_interceptor(provider, self._policy_engine)

        try:
            async for event in parse_sse(upstream):
                action = interceptor.process_event(event)

                if action.type == ActionType.FORWARD:
                    if action.events:
                        for ev in action.events:
                            await response.write(ev.raw)
                    else:
                        await response.write(event.raw)

                elif action.type == ActionType.BUFFER:
                    pass  # held by interceptor

                elif action.type == ActionType.FLUSH:
                    for ev in action.events:
                        await response.write(ev.raw)
                    if action.result:
                        # Audit logger handles both file + stderr output
                        self._audit_logger.log_tool_call(
                            action.tool_name, action.arguments, action.result
                        )

                elif action.type == ActionType.BLOCK:
                    await response.write(action.replacement)
                    if action.result:
                        # Audit logger handles both file + stderr output
                        self._audit_logger.log_tool_call(
                            action.tool_name, action.arguments, action.result
                        )

            # Finalize — flush any remaining buffer (fail-open)
            final = interceptor.finalize()
            if final is not None:
                if final.type == ActionType.FLUSH:
                    for ev in final.events:
                        await response.write(ev.raw)

        except aiohttp.ClientError as e:
            _console.print(
                f"  [bold red]LLM stream error:[/bold red] {e}",
                highlight=False,
            )

        await response.write_eof()
        # Log to file only — LLM API calls are noisy on stderr
        self._audit_logger.log_http_request(
            "POST", request.path, upstream.status, stderr=False,
        )
        return response

    # ------------------------------------------------------------------
    # Non-streaming handler
    # ------------------------------------------------------------------

    async def _handle_non_streaming(
        self,
        request: web.Request,
        raw_body: bytes,
        real_base_url: str,
        provider: str,
    ) -> web.Response:
        """Forward a non-streaming request, filtering tool_use from the response."""
        session = await self._get_session()
        upstream_url = real_base_url.rstrip("/") + request.path

        fwd_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() not in _HOP_BY_HOP and key.lower() != "host":
                fwd_headers[key] = value

        try:
            async with session.post(
                upstream_url,
                headers=fwd_headers,
                data=raw_body,
                params=request.query,
            ) as upstream:
                body = await upstream.read()
                resp_headers = {
                    k: v
                    for k, v in upstream.headers.items()
                    if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"
                }
        except aiohttp.ClientError as e:
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )

        # Try to filter tool_use from response body
        try:
            resp_json = _json.loads(body)
        except (ValueError, TypeError):
            self._audit_logger.log_http_request("POST", request.path, upstream.status)
            return web.Response(body=body, status=upstream.status, headers=resp_headers)

        if provider == "anthropic":
            body = self._filter_anthropic_response(resp_json)
        elif provider == "openai_chat":
            body = self._filter_openai_chat_response(resp_json)
        # openai_responses non-streaming is rare; pass through

        self._audit_logger.log_http_request("POST", request.path, upstream.status)
        return web.Response(
            body=body if isinstance(body, bytes) else _json.dumps(body).encode(),
            status=upstream.status,
            headers=resp_headers,
            content_type="application/json",
        )

    def _filter_anthropic_response(self, resp: Any) -> bytes:
        """Remove blocked tool_use blocks from a non-streaming Anthropic response."""
        if not isinstance(resp, dict):
            return _json.dumps(resp).encode()

        content = resp.get("content", [])
        if not isinstance(content, list):
            return _json.dumps(resp).encode()

        filtered = []
        any_blocked = False

        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name", "unknown")
                input_args = block.get("input", {})
                if not isinstance(input_args, dict):
                    input_args = {}
                result = self._evaluate(name, input_args)
                self._audit_logger.log_tool_call(name, input_args, result)

                if result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
                    filtered.append(block)
                else:
                    any_blocked = True
                    filtered.append({
                        "type": "text",
                        "text": f"[AgentWard: blocked tool '{name}' — {result.reason}]",
                    })
            else:
                filtered.append(block)

        resp["content"] = filtered
        if any_blocked and resp.get("stop_reason") == "tool_use":
            # Check if ALL tool_use blocks were blocked
            has_remaining_tool = any(
                b.get("type") == "tool_use" for b in filtered if isinstance(b, dict)
            )
            if not has_remaining_tool:
                resp["stop_reason"] = "end_turn"

        return _json.dumps(resp).encode()

    def _filter_openai_chat_response(self, resp: Any) -> bytes:
        """Remove blocked tool_calls from a non-streaming OpenAI Chat response."""
        if not isinstance(resp, dict):
            return _json.dumps(resp).encode()

        choices = resp.get("choices", [])
        if not choices or not isinstance(choices, list):
            return _json.dumps(resp).encode()

        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message", {})
            if not isinstance(message, dict):
                continue
            tool_calls = message.get("tool_calls", [])
            if not tool_calls or not isinstance(tool_calls, list):
                continue

            filtered = []
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    filtered.append(tc)
                    continue
                func = tc.get("function", {})
                name = func.get("name", "unknown") if isinstance(func, dict) else "unknown"
                args_str = func.get("arguments", "{}") if isinstance(func, dict) else "{}"
                try:
                    args = _json.loads(args_str)
                except (ValueError, TypeError):
                    args = {}
                if not isinstance(args, dict):
                    args = {}

                result = self._evaluate(name, args)
                self._audit_logger.log_tool_call(name, args, result)

                if result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
                    filtered.append(tc)

            message["tool_calls"] = filtered if filtered else None
            if not filtered and choice.get("finish_reason") == "tool_calls":
                choice["finish_reason"] = "stop"
                message["content"] = "[AgentWard: all tool calls blocked by policy]"

        return _json.dumps(resp).encode()

    def _evaluate(self, tool_name: str, arguments: dict[str, Any]) -> EvaluationResult:
        if self._policy_engine is None:
            return EvaluationResult(
                decision=PolicyDecision.ALLOW,
                reason="No policy loaded (passthrough mode).",
            )
        return self._policy_engine.evaluate(tool_name, arguments)

    # ------------------------------------------------------------------
    # Transparent forwarding (non-LLM paths)
    # ------------------------------------------------------------------

    async def _forward_transparent(self, request: web.Request) -> web.Response:
        """Forward a request transparently without any inspection."""
        session = await self._get_session()

        # We don't know where to forward — use first provider URL
        if not self._provider_urls:
            return web.json_response(
                {"error": {"type": "proxy_error", "message": "No upstream URL configured"}},
                status=502,
            )

        base_url = next(iter(self._provider_urls.values()))
        url = base_url.rstrip("/") + request.path

        fwd_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() not in _HOP_BY_HOP and key.lower() != "host":
                fwd_headers[key] = value

        raw_body = await request.read()

        try:
            async with session.request(
                request.method,
                url,
                headers=fwd_headers,
                data=raw_body if raw_body else None,
                params=request.query,
            ) as upstream:
                body = await upstream.read()
                resp_headers = {
                    k: v
                    for k, v in upstream.headers.items()
                    if k.lower() not in _HOP_BY_HOP and k.lower() != "content-length"
                }
                return web.Response(
                    body=body,
                    status=upstream.status,
                    headers=resp_headers,
                )
        except aiohttp.ClientError as e:
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )
