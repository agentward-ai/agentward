"""Session-level evasion detection for AgentWard.

Public API::

    from agentward.session import SessionMonitor, SessionVerdict

``SessionMonitor`` is the proxy-facing façade. Proxies create one instance at
startup (when ``session.enabled: true`` is set), then call
``record_and_check()`` after each per-call decision. The method appends the
call to the session buffer and returns a session-level verdict that the proxy
uses to decide whether to block the call or warn.

The monitor is a no-op when ``policy.enabled`` is False — all calls to
``record_and_check()`` return a CLEAN result immediately.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agentward.session.analyzer import AnalysisResult, SessionAnalyzer, SessionVerdict
from agentward.session.buffer import BufferEntry, SessionBuffer
from agentward.session.policy import SessionAction, SessionPolicy, SessionSensitivity

if TYPE_CHECKING:
    # Only needed for type annotations — deferred by `from __future__ import annotations`.
    # Importing at runtime would create a circular import:
    #   schema.py → session (this __init__) → schema.py
    from agentward.policy.schema import PolicyDecision


@dataclass
class SessionStatus:
    """Runtime status snapshot for a single active session.

    Attributes:
        session_id: Unique session identifier.
        entry_count: Number of tool calls buffered.
        last_verdict: Most recent verdict from the analyzer.
        last_score: Aggregate score from the most recent analysis run.
        triggering_pattern: Name of the highest-scoring pattern, or "".
        paused: Whether the session has been paused due to an evasion verdict.
    """

    session_id: str
    entry_count: int
    last_verdict: SessionVerdict
    last_score: float
    triggering_pattern: str
    paused: bool


# Reusable sentinel for "disabled" state — avoids allocating new objects.
_CLEAN_RESULT = AnalysisResult(
    verdict=SessionVerdict.CLEAN,
    aggregate_score=0.0,
    pattern_results=[],
    triggering_pattern="",
)


class SessionMonitor:
    """Proxy-facing façade for session-level evasion detection.

    Wraps ``SessionBuffer`` and ``SessionAnalyzer`` and exposes a single
    ``record_and_check()`` method that proxies call after each tool invocation.
    When ``policy.enabled`` is False every call is a no-op that returns a CLEAN
    result, so the proxy code path is identical whether the feature is on or off.

    Args:
        policy: Session monitoring configuration from agentward.yaml.
    """

    def __init__(self, policy: SessionPolicy) -> None:
        self._policy = policy
        self._buffer = SessionBuffer(policy.window_size, policy.session_ttl)
        self._analyzer = SessionAnalyzer(policy)
        # Sessions blocked until manually resumed
        self._paused: set[str] = set()
        # Last analysis result per session (for status display and dedup)
        self._last_results: dict[str, AnalysisResult] = {}

    # ------------------------------------------------------------------
    # Core proxy interface
    # ------------------------------------------------------------------

    def record_and_check(
        self,
        session_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        verdict: PolicyDecision,
        tool_description: str | None = None,
    ) -> AnalysisResult:
        """Record a tool call and run session-level pattern analysis.

        This is the hot-path method called by the proxy after every tool call
        that passes per-call policy evaluation. It:
          1. Appends the call to the session ring buffer.
          2. Runs all five pattern matchers against the current window.
          3. Returns the analysis result so the proxy can act on the verdict.

        Call this *after* ``audit_logger.log_tool_call()`` and *before*
        forwarding the message to the real server.

        Args:
            session_id: Unique session identifier (per proxy instance).
            tool_name: The MCP tool name.
            arguments: The tool call arguments (may be redacted).
            verdict: The per-call policy decision (ALLOW, LOG, etc.).
            tool_description: Optional description from tools/list schema.

        Returns:
            The session analysis result. Always returns a CLEAN result when
            the policy is disabled.
        """
        if not self._policy.enabled:
            return _CLEAN_RESULT

        entry = BufferEntry(
            tool_name=tool_name,
            arguments=arguments,
            timestamp=time.monotonic(),
            verdict=verdict,
            tool_description=tool_description,
        )
        self._buffer.add(session_id, entry)
        entries = self._buffer.get(session_id)

        result = self._analyzer.check(session_id, entries)
        self._last_results[session_id] = result
        return result

    # ------------------------------------------------------------------
    # Verdict action helpers
    # ------------------------------------------------------------------

    def is_paused(self, session_id: str) -> bool:
        """Return True if the session has been paused by a prior evasion verdict."""
        return session_id in self._paused

    def pause_session(self, session_id: str) -> None:
        """Mark a session as paused — all further calls from it will be blocked."""
        self._paused.add(session_id)

    def resume_session(self, session_id: str) -> None:
        """Unblock a previously paused session."""
        self._paused.discard(session_id)
        self._buffer.clear_session(session_id)
        self._last_results.pop(session_id, None)

    def should_block(self, result: AnalysisResult) -> bool:
        """Return True if this result warrants blocking the current call.

        Blocking occurs when:
          - Verdict is EVASION_DETECTED and on_evasion is BLOCK or PAUSE.
          - Verdict is SUSPICIOUS and on_suspicious is PAUSE.

        Args:
            result: The analysis result from ``record_and_check()``.

        Returns:
            True if the proxy should send an error response instead of forwarding.
        """
        if result.verdict == SessionVerdict.EVASION_DETECTED:
            return self._policy.on_evasion in (SessionAction.BLOCK, SessionAction.PAUSE)
        if result.verdict == SessionVerdict.SUSPICIOUS:
            return self._policy.on_suspicious == SessionAction.PAUSE
        return False

    def should_pause_session(self, result: AnalysisResult) -> bool:
        """Return True if this result warrants pausing the entire session.

        Args:
            result: The analysis result from ``record_and_check()``.

        Returns:
            True if the proxy should pause the session after this call.
        """
        if result.verdict == SessionVerdict.EVASION_DETECTED:
            return self._policy.on_evasion == SessionAction.PAUSE
        if result.verdict == SessionVerdict.SUSPICIOUS:
            return self._policy.on_suspicious == SessionAction.PAUSE
        return False

    def should_warn(self, result: AnalysisResult) -> bool:
        """Return True if this result warrants a stderr warning (without blocking).

        Args:
            result: The analysis result from ``record_and_check()``.

        Returns:
            True if the proxy should print a warning but allow the call.
        """
        if result.verdict == SessionVerdict.EVASION_DETECTED:
            return self._policy.on_evasion == SessionAction.WARN
        if result.verdict == SessionVerdict.SUSPICIOUS:
            return self._policy.on_suspicious in (SessionAction.WARN,)
        return False

    # ------------------------------------------------------------------
    # Status / inspection
    # ------------------------------------------------------------------

    def active_sessions(self) -> list[SessionStatus]:
        """Return status snapshots for all active (non-expired) sessions."""
        statuses: list[SessionStatus] = []
        for session_id in self._buffer.active_session_ids():
            entries = self._buffer.get(session_id)
            last = self._last_results.get(session_id)
            statuses.append(SessionStatus(
                session_id=session_id,
                entry_count=len(entries),
                last_verdict=last.verdict if last else SessionVerdict.CLEAN,
                last_score=last.aggregate_score if last else 0.0,
                triggering_pattern=last.triggering_pattern if last else "",
                paused=session_id in self._paused,
            ))
        return statuses

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @staticmethod
    def new_session_id(prefix: str = "session") -> str:
        """Generate a new unique session ID with the given prefix.

        Args:
            prefix: Short label describing the proxy type (e.g., "stdio", "http").

        Returns:
            A string like ``"stdio-a3f2c1b04d8e"``.
        """
        return f"{prefix}-{uuid.uuid4().hex[:12]}"

    @staticmethod
    def from_policy(policy: SessionPolicy) -> "SessionMonitor | None":
        """Create a ``SessionMonitor`` from a policy, or return None if disabled.

        This is the canonical constructor used by proxy setup code.

        Args:
            policy: The session policy configuration.

        Returns:
            A ``SessionMonitor`` instance when ``policy.enabled`` is True,
            otherwise ``None`` so the proxy can skip the session check entirely.
        """
        if not policy.enabled:
            return None
        return SessionMonitor(policy)


__all__ = [
    "AnalysisResult",
    "BufferEntry",
    "SessionBuffer",
    "SessionMonitor",
    "SessionPolicy",
    "SessionSensitivity",
    "SessionStatus",
    "SessionVerdict",
]
