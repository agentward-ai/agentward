"""Session buffer — ring buffer of recent tool calls per session.

Stores the last N tool calls per session, with TTL-based session expiry.
Used by the session evasion analyzer to examine call sequences.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Avoid circular import: schema.py imports session/ which would import schema.py.
    # PolicyDecision is only used as a type annotation (deferred by __future__).
    from agentward.policy.schema import PolicyDecision


@dataclass
class BufferEntry:
    """A single tool call record stored in the session buffer.

    Attributes:
        tool_name: The MCP tool name.
        arguments: The tool call arguments (possibly redacted).
        timestamp: Monotonic timestamp when the call was recorded.
        verdict: The per-call policy decision.
        tool_description: Optional tool description from tools/list schema.
    """

    tool_name: str
    arguments: dict[str, Any]
    timestamp: float
    verdict: PolicyDecision
    tool_description: str | None = None


class SessionBuffer:
    """Ring buffer of recent tool calls per session.

    Stores the last ``window_size`` tool calls per session ID. Sessions that
    have not received a new call within ``session_ttl`` seconds are
    automatically expired on the next access to prevent unbounded memory growth.

    Args:
        window_size: Maximum number of entries to retain per session.
        session_ttl: Seconds of inactivity before a session is expired.
    """

    def __init__(self, window_size: int = 50, session_ttl: int = 3600) -> None:
        self._window_size = window_size
        self._session_ttl = session_ttl
        # session_id → deque[BufferEntry] with ring-buffer semantics
        self._sessions: dict[str, deque[BufferEntry]] = {}
        # session_id → last activity timestamp (monotonic)
        self._last_activity: dict[str, float] = {}

    def add(self, session_id: str, entry: BufferEntry) -> None:
        """Add a new entry to the session buffer.

        Creates the session ring buffer on first use. Updates the session's
        last-activity timestamp. When the buffer is full the oldest entry is
        silently dropped (deque maxlen behaviour).

        Args:
            session_id: Unique session identifier.
            entry: The tool call buffer entry to append.
        """
        self._expire_stale()
        if session_id not in self._sessions:
            self._sessions[session_id] = deque(maxlen=self._window_size)
        self._sessions[session_id].append(entry)
        self._last_activity[session_id] = entry.timestamp

    def get(self, session_id: str) -> list[BufferEntry]:
        """Return all entries for a session, oldest first.

        Args:
            session_id: Unique session identifier.

        Returns:
            List of buffer entries (oldest first), or empty list if
            the session does not exist or has been expired.
        """
        if session_id not in self._sessions:
            return []
        return list(self._sessions[session_id])

    def active_session_ids(self) -> list[str]:
        """Return the IDs of all currently active (non-expired) sessions."""
        self._expire_stale()
        return list(self._sessions.keys())

    def session_count(self) -> int:
        """Return the number of currently active sessions."""
        self._expire_stale()
        return len(self._sessions)

    def clear_session(self, session_id: str) -> None:
        """Remove all entries for a specific session.

        Args:
            session_id: The session to clear.
        """
        self._sessions.pop(session_id, None)
        self._last_activity.pop(session_id, None)

    def _expire_stale(self) -> None:
        """Remove sessions that have not received activity within session_ttl."""
        now = time.monotonic()
        stale = [
            sid
            for sid, last in self._last_activity.items()
            if now - last > self._session_ttl
        ]
        for sid in stale:
            self._sessions.pop(sid, None)
            self._last_activity.pop(sid, None)
