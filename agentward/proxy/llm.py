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
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from sys import platform as _platform
from typing import TYPE_CHECKING, Any, AsyncIterator

import aiohttp
from aiohttp import ClientSession, ClientTimeout, web
from rich.console import Console

from agentward.audit.logger import AuditLogger
from agentward.inspect.classifier import ClassificationResult, Finding, classify_arguments
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import PolicyDecision
from agentward.proxy.http import (
    _cleanup_stale_proxy,
    _force_free_port,
    _identify_port_blocker,
    _remove_pid_file,
    _write_pid_file,
)

if TYPE_CHECKING:
    from agentward.proxy.approval import ApprovalHandler

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
    APPROVE = auto()  # Tool needs human approval — hold events until dialog resolves


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

            if result.decision == PolicyDecision.APPROVE:
                # Needs human approval — return APPROVE action with buffered
                # events.  The streaming handler will show a dialog and decide
                # whether to flush or block.
                self._all_tools_blocked = False
                action = InterceptAction(
                    type=ActionType.APPROVE,
                    events=list(self._buffer),
                    tool_name=self._tool_name,
                    arguments=arguments,
                    result=result,
                )
                self._buffer = []
                return action
            elif result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
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
                # BLOCK, REDACT — drop the tool_use block
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
        """If stream ends mid-buffer, drop incomplete tool_use (fail-closed)."""
        if self._buffer:
            self._buffer = []
            self._state = _AnthropicState.IDLE
            # Incomplete tool_use block — drop rather than forwarding
            # un-evaluated content to the agent.
            replacement = self._make_replacement_text(
                self._block_index, self._tool_name or "unknown",
                "Stream ended with incomplete tool_use (dropped by AgentWard)",
            )
            return InterceptAction(type=ActionType.BLOCK, replacement=replacement)
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
        any_approve = False
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

            if result.decision == PolicyDecision.APPROVE:
                all_blocked = False
                any_approve = True
            elif result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
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
        elif any_approve and not blocked_names:
            # At least one tool needs approval, none blocked — return APPROVE
            # Find the first APPROVE result for the dialog
            approve_result = next(
                (r for r in results if r[2].decision == PolicyDecision.APPROVE), results[0]
            )
            events = list(self._buffer)
            action = InterceptAction(
                type=ActionType.APPROVE,
                events=events,
                tool_name=approve_result[0],
                arguments=approve_result[1],
                result=approve_result[2],
            )
            self._tools.clear()
            self._buffer.clear()
            return action
        elif not blocked_names:
            # All tools allowed — flush the buffer
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
        else:
            # Mixed decisions — some allowed, some blocked.
            # SSE chunks interleave data for ALL tool_call indices,
            # so we can't selectively filter. Fail closed: block all.
            reasons = ", ".join(blocked_names)
            replacement_msg = (
                f"[AgentWard: blocked response — tool(s) '{reasons}' "
                f"denied by policy (mixed decisions, failing closed)]"
            )
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

    def finalize(self) -> InterceptAction | None:
        """If stream ends mid-buffer, drop incomplete tool_calls (fail-closed)."""
        if self._buffer:
            self._buffer.clear()
            self._tools.clear()
            self._buffering = False
            # Incomplete tool_calls — drop rather than forwarding
            # un-evaluated content to the agent.
            replacement_msg = (
                "[AgentWard: stream ended with incomplete tool_calls "
                "(dropped by AgentWard)]"
            )
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
            return InterceptAction(
                type=ActionType.BLOCK,
                replacement=f"data: {replacement}\n\n".encode(),
            )
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

            if result.decision == PolicyDecision.APPROVE:
                events = list(self._buffer)
                self._buffer.clear()
                return InterceptAction(
                    type=ActionType.APPROVE,
                    events=events,
                    tool_name=self._tool_name,
                    arguments=arguments,
                    result=result,
                )
            elif result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
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
        """If stream ends mid-buffer, drop incomplete function_call (fail-closed)."""
        if self._buffer:
            self._buffer.clear()
            self._buffering = False
            # Incomplete function_call — drop rather than forwarding
            # un-evaluated content to the agent.
            msg = (
                "[AgentWard: stream ended with incomplete function_call "
                "(dropped by AgentWard)]"
            )
            replacement = _json.dumps(
                {
                    "type": "response.output_text.delta",
                    "delta": msg,
                },
                separators=(",", ":"),
            )
            return InterceptAction(
                type=ActionType.BLOCK,
                replacement=f"data: {replacement}\n\n".encode(),
            )
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


# Cache for runtime tool risk classification — avoids re-analyzing on every request.
_runtime_risk_cache: dict[str, "RiskLevel"] = {}



def _classify_unknown_tool(tool: dict[str, Any]) -> "RiskLevel":
    """Classify an unknown tool at runtime using the scan risk engine.

    For tools that have no policy match, we run the same ``analyze_tool()``
    logic the scanner uses — but against the actual tool definition from the
    LLM API request, not guessed names.  Results are cached per tool name.

    Args:
        tool: A tool dict from the Anthropic ``tools`` array
              (has ``name``, ``description``, ``input_schema``).

    Returns:
        The computed RiskLevel.
    """
    from agentward.scan.enumerator import ToolInfo
    from agentward.scan.permissions import RiskLevel, analyze_tool

    name = tool.get("name", "")
    if name in _runtime_risk_cache:
        return _runtime_risk_cache[name]

    tool_info = ToolInfo(
        name=name,
        description=tool.get("description"),
        input_schema=tool.get("input_schema", {}),
    )
    perm = analyze_tool(tool_info)
    _runtime_risk_cache[name] = perm.risk_level
    return perm.risk_level


def _filter_blocked_tools(
    body: dict[str, Any],
    policy_engine: PolicyEngine | None,
    audit_logger: AuditLogger,
) -> bool:
    """Remove blocked/dangerous tools from the ``tools`` array in an API request.

    Two-pass strategy:

    1. **Policy check:** If the policy engine has an explicit rule for a tool
       (BLOCK, APPROVE, or any resource match), that decision is used.
    2. **Runtime classification:** For tools with NO policy match (the engine
       returned default ALLOW with "No policy rule matches"), run
       ``analyze_tool()`` on the actual tool definition. CRITICAL tools
       (shell/exec) are blocked; HIGH tools (credentials/destructive) are
       gated for approval.  This catches tools like ``exec`` that the policy
       doesn't know about by name but are clearly dangerous by nature.

    Args:
        body: The parsed request body (mutated in place).
        policy_engine: The policy engine (None = passthrough, no filtering).
        audit_logger: Audit logger for logging filtered tools.

    Returns:
        True if any tools were removed, False otherwise.
    """
    from agentward.scan.permissions import RiskLevel

    if policy_engine is None:
        return False

    tools = body.get("tools")
    if not isinstance(tools, list) or not tools:
        return False

    filtered: list[dict[str, Any]] = []
    removed: list[tuple[str, EvaluationResult]] = []

    for tool in tools:
        if not isinstance(tool, dict):
            filtered.append(tool)
            continue

        # Anthropic: {"name": "foo", ...}
        # OpenAI Responses: {"type": "function", "name": "foo", ...}
        # OpenAI Chat: {"type": "function", "function": {"name": "foo", ...}}
        name = tool.get("name", "")
        if not name:
            func = tool.get("function")
            if isinstance(func, dict):
                name = func.get("name", "")
        if not name:
            filtered.append(tool)
            continue

        result = policy_engine.evaluate(name, {})

        # Pass 1: explicit policy decision (APPROVE stays — gated at execution)
        if result.decision == PolicyDecision.BLOCK:
            removed.append((name, result))
            continue

        # Pass 2: runtime classification for unknown tools.
        # When no policy rule matched, the engine returns ALLOW with
        # skill=None and resource=None (the default passthrough).
        if (
            result.decision == PolicyDecision.ALLOW
            and result.skill is None
            and result.resource is None
        ):
            risk = _classify_unknown_tool(tool)
            if risk in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                # Wrap in a BLOCK result for audit logging
                block_result = EvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    reason=f"Tool '{name}' classified as {risk.value} risk by runtime analysis. "
                           f"Removed from LLM request.",
                )
                removed.append((name, block_result))
                continue

        filtered.append(tool)

    if not removed:
        return False

    body["tools"] = filtered

    removed_names = [name for name, _ in removed]
    removed_set = set(removed_names)

    # Reconcile tool_choice — if it pins a now-removed tool, the upstream
    # API will 400.  Downgrade to "auto" and warn.
    _reconcile_tool_choice(body, removed_set)

    # Inject a system-level notice so the LLM knows WHY the tools are
    # unavailable and can tell the user, instead of confabulating reasons.
    notice = (
        "[AgentWard] The following tools have been blocked by policy and are "
        "unavailable: " + ", ".join(removed_names) + ". "
        "If the user asks to use these tools, tell them AgentWard has blocked "
        "them per the security policy. Do not suggest workarounds."
    )
    _inject_system_notice(body, notice)

    for name, result in removed:
        _console.print(
            f"  [bold red]✗ BLOCK[/bold red] {name}",
            highlight=False,
        )
        audit_logger.log_tool_call(name, {}, result)

    return True


def _reconcile_tool_choice(
    body: dict[str, Any],
    removed_names: set[str],
) -> None:
    """Downgrade tool_choice to ``"auto"`` if it pins a removed tool.

    Handles three API formats:

    - **Anthropic**: ``tool_choice: {"type": "tool", "name": "X"}``
    - **OpenAI Chat**: ``tool_choice: {"type": "function", "function": {"name": "X"}}``
    - **OpenAI Responses**: ``tool_choice: {"type": "function", "name": "X"}``

    If ``tool_choice`` is a string (``"auto"``, ``"none"``, ``"required"``,
    ``"any"``), it refers to no specific tool and is left unchanged.

    Args:
        body: The parsed request body (mutated in place).
        removed_names: Set of tool names that were removed.
    """
    tc = body.get("tool_choice")
    if tc is None or not isinstance(tc, dict):
        return  # String values ("auto", "none", etc.) are fine

    # Anthropic format: {"type": "tool", "name": "blocked_tool"}
    pinned_name = tc.get("name")

    # OpenAI Chat format: {"type": "function", "function": {"name": "blocked_tool"}}
    if not pinned_name:
        func = tc.get("function")
        if isinstance(func, dict):
            pinned_name = func.get("name")

    if pinned_name and pinned_name in removed_names:
        body["tool_choice"] = "auto"
        _console.print(
            f"  [yellow]⚠ tool_choice pinned '{pinned_name}' was blocked — "
            f"downgraded to auto[/yellow]",
            highlight=False,
        )


def _inject_system_notice(body: dict[str, Any], notice: str) -> None:
    """Append a notice to the system prompt in the request body.

    Handles both Anthropic (top-level ``system`` field) and OpenAI
    (``messages[0].role == "system"``) formats.

    Args:
        body: The parsed request body (mutated in place).
        notice: The notice text to inject.
    """
    # Anthropic format: top-level "system" field (string or list of blocks)
    if "system" in body:
        system = body["system"]
        if isinstance(system, str):
            body["system"] = system + "\n\n" + notice
        elif isinstance(system, list):
            # Content block array — append a text block
            system.append({"type": "text", "text": notice})
        return

    # OpenAI format: first message with role "system" or "developer"
    messages = body.get("messages")
    if isinstance(messages, list) and messages:
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") in ("system", "developer"):
                content = msg.get("content", "")
                if isinstance(content, str):
                    msg["content"] = content + "\n\n" + notice
                return
        # No system message — prepend one
        messages.insert(0, {"role": "system", "content": notice})


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


def _extract_last_user_text(messages: list[Any]) -> str:
    """Extract the text content from the last user message.

    Handles both string content and content-block arrays (Anthropic format).

    Args:
        messages: The messages array from the request body.

    Returns:
        The concatenated text of the last user message, or empty string.
    """
    # Walk backwards to find the last user message
    for msg in reversed(messages):
        if not isinstance(msg, dict):
            continue
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for block in content:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    if isinstance(text, str):
                        parts.append(text)
            return "\n".join(parts)
    return ""


def _extract_responses_input(body: dict[str, Any]) -> str:
    """Extract user text from an OpenAI Responses API request body.

    The Responses API uses ``input`` (string or list of items) and an
    optional ``instructions`` field instead of a ``messages`` array.

    Args:
        body: The parsed request body.

    Returns:
        Concatenated user text, or empty string if nothing found.
    """
    parts: list[str] = []

    instructions = body.get("instructions")
    if isinstance(instructions, str) and instructions:
        parts.append(instructions)

    input_val = body.get("input")
    if isinstance(input_val, str):
        parts.append(input_val)
    elif isinstance(input_val, list):
        for item in input_val:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                # Message items: {"role": "user", "content": "..."}
                content = item.get("content")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "input_text":
                            text = block.get("text", "")
                            if isinstance(text, str):
                                parts.append(text)

    return "\n".join(parts)


def _make_canned_response(provider: str, message: str, is_streaming: bool) -> web.Response:
    """Build a canned LLM response without forwarding to the provider.

    Returns a normal-looking LLM response containing just a text message,
    so the agent runtime displays it to the user.

    Args:
        provider: The LLM provider identifier.
        message: The text message to include in the response.
        is_streaming: Whether the request expected an SSE stream.

    Returns:
        An aiohttp ``web.Response`` with the canned response body.
    """
    if provider == "anthropic":
        body = _json.dumps({
            "id": "msg_agentward_block",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": message}],
            "model": "agentward-proxy",
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        })
        if is_streaming:
            # Build a minimal SSE stream that delivers the text
            events = [
                f'event: message_start\ndata: {_json.dumps({"type": "message_start", "message": {"id": "msg_agentward_block", "type": "message", "role": "assistant", "content": [], "model": "agentward-proxy", "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 0, "output_tokens": 0}}})}\n\n',
                f'event: content_block_start\ndata: {_json.dumps({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})}\n\n',
                f'event: content_block_delta\ndata: {_json.dumps({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": message}})}\n\n',
                f'event: content_block_stop\ndata: {_json.dumps({"type": "content_block_stop", "index": 0})}\n\n',
                f'event: message_delta\ndata: {_json.dumps({"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 0}})}\n\n',
                f'event: message_stop\ndata: {_json.dumps({"type": "message_stop"})}\n\n',
            ]
            return web.Response(
                body="".join(events).encode(),
                status=200,
                content_type="text/event-stream",
            )
        return web.Response(body=body.encode(), status=200, content_type="application/json")

    elif provider == "openai_chat":
        body = _json.dumps({
            "id": "chatcmpl-agentward-block",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": message},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        })
        if is_streaming:
            events = [
                f'data: {_json.dumps({"choices": [{"index": 0, "delta": {"role": "assistant", "content": message}, "finish_reason": "stop"}]})}\n\n',
                "data: [DONE]\n\n",
            ]
            return web.Response(
                body="".join(events).encode(),
                status=200,
                content_type="text/event-stream",
            )
        return web.Response(body=body.encode(), status=200, content_type="application/json")

    elif provider == "openai_responses":
        body = _json.dumps({
            "id": "resp_agentward_block",
            "object": "response",
            "output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": message}]}],
            "status": "completed",
        })
        if is_streaming:
            events = [
                f'data: {_json.dumps({"type": "response.output_text.done", "text": message})}\n\n',
                "data: [DONE]\n\n",
            ]
            return web.Response(
                body="".join(events).encode(),
                status=200,
                content_type="text/event-stream",
            )
        return web.Response(body=body.encode(), status=200, content_type="application/json")

    # Unknown provider — simple text response
    return web.Response(body=message.encode(), status=200, content_type="text/plain")


def _make_denial_replacement(provider: str, tool_name: str) -> bytes:
    """Build SSE bytes for a user-denied tool call replacement.

    Produces provider-appropriate SSE events so the agent runtime sees a
    text message explaining the tool was denied instead of the tool_use block.

    Args:
        provider: The LLM provider ("anthropic", "openai_chat", "openai_responses").
        tool_name: The denied tool name.

    Returns:
        Raw SSE bytes to write to the client stream.
    """
    msg = f"[AgentWard: tool '{tool_name}' denied by user]"

    if provider == "anthropic":
        # Use index 0 — the interceptor already dropped the original block
        events = [
            (
                "content_block_start",
                _json.dumps(
                    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                    separators=(",", ":"),
                ),
            ),
            (
                "content_block_delta",
                _json.dumps(
                    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": msg}},
                    separators=(",", ":"),
                ),
            ),
            (
                "content_block_stop",
                _json.dumps(
                    {"type": "content_block_stop", "index": 0},
                    separators=(",", ":"),
                ),
            ),
        ]
        return b"".join(f"event: {etype}\ndata: {data}\n\n".encode() for etype, data in events)
    elif provider == "openai_chat":
        replacement = _json.dumps(
            {"choices": [{"index": 0, "delta": {"content": msg}, "finish_reason": "stop"}]},
            separators=(",", ":"),
        )
        return f"data: {replacement}\n\n".encode()
    elif provider == "openai_responses":
        replacement = _json.dumps(
            {"type": "response.output_text.done", "text": msg},
            separators=(",", ":"),
        )
        return f"data: {replacement}\n\n".encode()
    else:
        return b""


def _make_sensitive_block_replacement(
    provider: str,
    tool_name: str,
    findings: list[Finding],
) -> bytes:
    """Build SSE bytes for a tool call blocked by the sensitive content classifier.

    Args:
        provider: The LLM provider ("anthropic", "openai_chat", "openai_responses").
        tool_name: The blocked tool name.
        findings: List of classifier findings (for the message).

    Returns:
        Raw SSE bytes to write to the client stream.
    """
    summary = ", ".join(
        f"{f.finding_type.value} ({f.matched_text})" for f in findings
    )
    msg = f"[AgentWard: blocked tool '{tool_name}' — sensitive data detected: {summary}]"

    if provider == "anthropic":
        events = [
            (
                "content_block_start",
                _json.dumps(
                    {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                    separators=(",", ":"),
                ),
            ),
            (
                "content_block_delta",
                _json.dumps(
                    {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": msg}},
                    separators=(",", ":"),
                ),
            ),
            (
                "content_block_stop",
                _json.dumps(
                    {"type": "content_block_stop", "index": 0},
                    separators=(",", ":"),
                ),
            ),
        ]
        return b"".join(f"event: {etype}\ndata: {data}\n\n".encode() for etype, data in events)
    elif provider == "openai_chat":
        replacement = _json.dumps(
            {"choices": [{"index": 0, "delta": {"content": msg}, "finish_reason": "stop"}]},
            separators=(",", ":"),
        )
        return f"data: {replacement}\n\n".encode()
    elif provider == "openai_responses":
        replacement = _json.dumps(
            {"type": "response.output_text.done", "text": msg},
            separators=(",", ":"),
        )
        return f"data: {replacement}\n\n".encode()
    else:
        return b""


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
        approval_handler: "ApprovalHandler | None" = None,
        dry_run: bool = False,
    ) -> None:
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._provider_urls = provider_urls or {}
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._policy_path = policy_path
        self._approval_handler = approval_handler
        self._dry_run = dry_run
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

        site = web.TCPSite(runner, self._listen_host, self._listen_port)
        try:
            await site.start()
        except OSError as e:
            if e.errno == 48 or "address already in use" in str(e).lower():
                # Attempt to kill stale process and retry
                if _force_free_port(self._listen_port):
                    try:
                        await site.start()
                    except OSError:
                        _console.print(
                            f"[bold red]Error:[/bold red] Port {self._listen_port} "
                            f"still in use after cleanup.",
                            highlight=False,
                        )
                        await runner.cleanup()
                        return
                else:
                    blocker = _identify_port_blocker(self._listen_port)
                    msg = f"Port {self._listen_port} is already in use"
                    if blocker:
                        msg += f" by {blocker}"
                    _console.print(
                        f"[bold red]Error:[/bold red] {msg}",
                        highlight=False,
                    )
                    await runner.cleanup()
                    return
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
            # LLM API calls can take a while (long completions), so use a
            # generous total timeout.  The connect timeout bounds the initial
            # TCP/TLS handshake to the upstream API.
            self._session = ClientSession(
                timeout=ClientTimeout(total=300, connect=30),
            )
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

        if body_json is not None:
            # 1. Strip blocked/dangerous tools from the tools array so the
            #    LLM never sees them.  This prevents the LLM from calling
            #    blocked tools, avoiding conversation history corruption
            #    and repeated blocked calls.
            #    Works for all providers (Anthropic, OpenAI Chat, OpenAI Responses).
            if _filter_blocked_tools(body_json, self._policy_engine, self._audit_logger):
                body_modified = True

            # 2. Sanitize orphaned tool_use / tool_result blocks from
            #    conversation history (Anthropic-only — Anthropic requires
            #    matched tool_use/tool_result pairs).
            if provider == "anthropic":
                if _sanitize_anthropic_messages(body_json):
                    body_modified = True

        if body_modified and body_json is not None:
            raw_body = _json.dumps(body_json, separators=(",", ":")).encode()

        # Scan user messages for sensitive data before sending to LLM
        if body_json is not None:
            block_response = self._scan_request_messages(body_json, provider, is_streaming)
            if block_response is not None:
                return block_response

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

        # Copy request headers (filter hop-by-hop + content-length).
        # content-length must be excluded because the proxy may have modified
        # the body (e.g. filtered blocked tools), making the original length
        # stale.  aiohttp will recompute it from the actual data payload.
        fwd_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() not in _HOP_BY_HOP and key.lower() not in ("host", "content-length"):
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
                    # Classify arguments for sensitive data before flushing
                    classification = self._classify_tool_args(action.arguments)
                    if classification.has_sensitive_data:
                        replacement = _make_sensitive_block_replacement(
                            provider, action.tool_name, classification.findings,
                        )
                        await response.write(replacement)
                        self._audit_logger.log_sensitive_block(
                            action.tool_name, action.arguments, classification.findings,
                        )
                    else:
                        for ev in action.events:
                            await response.write(ev.raw)
                        if action.result:
                            self._audit_logger.log_tool_call(
                                action.tool_name, action.arguments, action.result
                            )

                elif action.type == ActionType.APPROVE and action.result is not None:
                    if self._dry_run:
                        # Dry-run: log and flush without approval dialog
                        self._audit_logger.log_tool_call(
                            action.tool_name, action.arguments, action.result,
                            dry_run=True,
                        )
                        for ev in action.events:
                            await response.write(ev.raw)
                    else:
                        # Pause the SSE stream and show the approval dialog
                        approved = await self._request_approval(
                            action.tool_name, action.arguments, action.result,
                        )
                        if approved:
                            # User approved — classify before flushing
                            classification = self._classify_tool_args(action.arguments)
                            if classification.has_sensitive_data:
                                replacement = _make_sensitive_block_replacement(
                                    provider, action.tool_name, classification.findings,
                                )
                                await response.write(replacement)
                                self._audit_logger.log_sensitive_block(
                                    action.tool_name, action.arguments, classification.findings,
                                )
                            else:
                                for ev in action.events:
                                    await response.write(ev.raw)
                        else:
                            # User denied — inject replacement text block
                            replacement = _make_denial_replacement(
                                provider, action.tool_name,
                            )
                            await response.write(replacement)

                elif action.type == ActionType.BLOCK:
                    if self._dry_run:
                        # Dry-run: log and flush instead of blocking
                        if action.result:
                            self._audit_logger.log_tool_call(
                                action.tool_name, action.arguments, action.result,
                                dry_run=True,
                            )
                        for ev in action.events:
                            await response.write(ev.raw)
                    else:
                        await response.write(action.replacement)
                        if action.result:
                            # Audit logger handles both file + stderr output
                            self._audit_logger.log_tool_call(
                                action.tool_name, action.arguments, action.result
                            )

            # Finalize — drop any remaining incomplete buffer (fail-closed)
            final = interceptor.finalize()
            if final is not None:
                if final.type == ActionType.BLOCK and final.replacement:
                    await response.write(final.replacement)

        except aiohttp.ClientError as e:
            _console.print(
                f"  [bold red]LLM stream error:[/bold red] {e}",
                highlight=False,
            )

        try:
            await response.write_eof()
        except (aiohttp.ClientError, ConnectionResetError, OSError):
            # Client disconnected before we finished writing — normal for
            # long-running SSE streams when the agent runtime cancels.
            pass
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
            if key.lower() not in _HOP_BY_HOP and key.lower() not in ("host", "content-length"):
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
            body = await self._filter_anthropic_response(resp_json)
        elif provider == "openai_chat":
            body = await self._filter_openai_chat_response(resp_json)
        # openai_responses non-streaming is rare; pass through

        self._audit_logger.log_http_request("POST", request.path, upstream.status)
        return web.Response(
            body=body if isinstance(body, bytes) else _json.dumps(body).encode(),
            status=upstream.status,
            headers=resp_headers,
            content_type="application/json",
        )

    async def _filter_anthropic_response(self, resp: Any) -> bytes:
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

                if self._dry_run and result.decision in (
                    PolicyDecision.BLOCK, PolicyDecision.APPROVE,
                ):
                    # Dry-run: log and pass through without blocking/approval
                    self._audit_logger.log_tool_call(
                        name, input_args, result, dry_run=True,
                    )
                    filtered.append(block)
                elif result.decision == PolicyDecision.APPROVE:
                    # Show approval dialog
                    allowed = await self._request_approval(name, input_args, result)
                    if allowed:
                        # Classify before allowing
                        classification = self._classify_tool_args(input_args)
                        if classification.has_sensitive_data:
                            any_blocked = True
                            summary = ", ".join(
                                f.finding_type.value for f in classification.findings
                            )
                            filtered.append({
                                "type": "text",
                                "text": f"[AgentWard: blocked tool '{name}' — sensitive data detected: {summary}]",
                            })
                            self._audit_logger.log_sensitive_block(
                                name, input_args, classification.findings,
                            )
                        else:
                            filtered.append(block)
                    else:
                        any_blocked = True
                        filtered.append({
                            "type": "text",
                            "text": f"[AgentWard: tool '{name}' denied by user]",
                        })
                elif result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
                    # Classify before allowing
                    classification = self._classify_tool_args(input_args)
                    if classification.has_sensitive_data:
                        any_blocked = True
                        summary = ", ".join(
                            f.finding_type.value for f in classification.findings
                        )
                        filtered.append({
                            "type": "text",
                            "text": f"[AgentWard: blocked tool '{name}' — sensitive data detected: {summary}]",
                        })
                        self._audit_logger.log_sensitive_block(
                            name, input_args, classification.findings,
                        )
                    else:
                        self._audit_logger.log_tool_call(name, input_args, result)
                        filtered.append(block)
                else:
                    any_blocked = True
                    self._audit_logger.log_tool_call(name, input_args, result)
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

    async def _filter_openai_chat_response(self, resp: Any) -> bytes:
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

                if self._dry_run and result.decision in (
                    PolicyDecision.BLOCK, PolicyDecision.APPROVE,
                ):
                    # Dry-run: log and pass through
                    self._audit_logger.log_tool_call(
                        name, args, result, dry_run=True,
                    )
                    filtered.append(tc)
                elif result.decision == PolicyDecision.APPROVE:
                    allowed = await self._request_approval(name, args, result)
                    if allowed:
                        classification = self._classify_tool_args(args)
                        if not classification.has_sensitive_data:
                            filtered.append(tc)
                        else:
                            self._audit_logger.log_sensitive_block(
                                name, args, classification.findings,
                            )
                elif result.decision in (PolicyDecision.ALLOW, PolicyDecision.LOG):
                    classification = self._classify_tool_args(args)
                    if classification.has_sensitive_data:
                        self._audit_logger.log_sensitive_block(
                            name, args, classification.findings,
                        )
                    else:
                        self._audit_logger.log_tool_call(name, args, result)
                        filtered.append(tc)
                else:
                    self._audit_logger.log_tool_call(name, args, result)

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

    def _classify_tool_args(self, arguments: dict[str, Any]) -> ClassificationResult:
        """Run the sensitive content classifier on tool call arguments.

        Reads enabled patterns from the policy config. If no policy is loaded
        or the classifier is disabled, returns a clean result.

        Args:
            arguments: The tool call arguments dict.

        Returns:
            A ClassificationResult.
        """
        if self._policy_engine is None:
            return ClassificationResult(has_sensitive_data=False)

        config = self._policy_engine.policy.sensitive_content
        if not config.enabled:
            return ClassificationResult(has_sensitive_data=False)

        return classify_arguments(arguments, enabled_patterns=config.patterns)

    def _scan_request_messages(
        self,
        body: dict[str, Any],
        provider: str,
        is_streaming: bool,
    ) -> web.Response | None:
        """Scan user messages in the request body for sensitive data.

        If sensitive content is found, returns a canned LLM-style response
        that tells the agent about the block.  The request is never forwarded
        to the upstream provider.

        Args:
            body: The parsed request body.
            provider: The LLM provider identifier.
            is_streaming: Whether the request expects an SSE stream.

        Returns:
            A ``web.Response`` if the request should be blocked, None otherwise.
        """
        if self._policy_engine is None:
            return None

        config = self._policy_engine.policy.sensitive_content
        if not config.enabled:
            return None

        # Extract text from user input.
        # Anthropic / OpenAI Chat: body["messages"] (last user message)
        # OpenAI Responses: body["input"] (string or item list) + body["instructions"]
        last_user_text = ""
        messages = body.get("messages")
        if isinstance(messages, list) and messages:
            last_user_text = _extract_last_user_text(messages)

        if not last_user_text:
            # Try OpenAI Responses format
            last_user_text = _extract_responses_input(body)

        if not last_user_text:
            return None

        classification = classify_arguments(
            {"_user_message": last_user_text},
            enabled_patterns=config.patterns,
        )
        if not classification.has_sensitive_data:
            return None

        # Sensitive data found — block the request
        self._audit_logger.log_sensitive_block(
            "_user_message", {}, classification.findings,
        )

        summary = ", ".join(
            f"{f.finding_type.value} ({f.matched_text})" for f in classification.findings
        )
        msg = (
            f"[AgentWard] I've detected sensitive content in your message ({summary}). "
            f"This request has been blocked to protect your data from being sent "
            f"to external services. Please remove sensitive information and try again."
        )

        return _make_canned_response(provider, msg, is_streaming)

    async def _request_approval(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: EvaluationResult,
    ) -> bool:
        """Show an approval dialog and return whether the tool was approved.

        Handles logging, timing, and fallback when no handler is configured.

        Args:
            tool_name: The tool requesting approval.
            arguments: The tool call arguments.
            result: The policy evaluation result.

        Returns:
            True if the user approved the tool call, False otherwise.
        """
        from agentward.proxy.approval import ApprovalDecision, ApprovalHandler

        if self._approval_handler is None:
            # No handler configured — fall back to deny (fail-secure)
            self._audit_logger.log_tool_call(tool_name, arguments, result)
            return False

        start = time.monotonic()
        decision = await self._approval_handler.request_approval(
            tool_name, arguments, result.reason,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)

        # Log the approval dialog interaction
        self._audit_logger.log_approval_dialog(
            tool_name, arguments, decision.value, elapsed_ms,
        )
        self._audit_logger.log_tool_call(tool_name, arguments, result)

        return decision in (ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION)

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
            if key.lower() not in _HOP_BY_HOP and key.lower() not in ("host", "content-length"):
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
