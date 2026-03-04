"""Circuit breaker for runaway agent detection.

Tracks tool call frequency per tool name and blocks calls that exceed
a configurable threshold within a sliding time window.  Inspired by
IronCurtain's call-circuit-breaker pattern.

Default: 20 identical calls within 60 seconds triggers a block.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

_console = Console(stderr=True)


@dataclass(frozen=True)
class CircuitBreakerConfig:
    """Configuration for the circuit breaker.

    Attributes:
        max_calls: Maximum number of calls allowed within the time window.
        window_seconds: Sliding window duration in seconds.
        use_args_hash: If True, rate-limit per (tool_name, args_hash) pair.
            If False, rate-limit per tool_name only.
    """

    max_calls: int = 20
    window_seconds: float = 60.0
    use_args_hash: bool = False


@dataclass
class CircuitBreaker:
    """Sliding-window rate limiter for tool calls.

    Tracks timestamps of recent calls and blocks when the count exceeds
    the configured threshold within the time window.

    Args:
        config: Circuit breaker configuration.
    """

    config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    # key → list of call timestamps (monotonic)
    _call_times: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))

    def check(self, tool_name: str, arguments: dict[str, Any] | None = None) -> bool:
        """Check if a tool call should be allowed.

        Args:
            tool_name: The tool being called.
            arguments: The tool call arguments (used for hashing if configured).

        Returns:
            True if the call is allowed, False if rate-limited.
        """
        key = self._make_key(tool_name, arguments)
        now = time.monotonic()
        cutoff = now - self.config.window_seconds

        # Prune expired timestamps
        timestamps = self._call_times[key]
        self._call_times[key] = [t for t in timestamps if t > cutoff]

        return len(self._call_times[key]) < self.config.max_calls

    def record(self, tool_name: str, arguments: dict[str, Any] | None = None) -> None:
        """Record a tool call.

        Call this after check() returns True and the call is forwarded.

        Args:
            tool_name: The tool being called.
            arguments: The tool call arguments.
        """
        key = self._make_key(tool_name, arguments)
        self._call_times[key].append(time.monotonic())

    def _make_key(self, tool_name: str, arguments: dict[str, Any] | None) -> str:
        """Build the rate-limiting key.

        Args:
            tool_name: The tool name.
            arguments: The tool call arguments.

        Returns:
            A string key for the rate limiter bucket.
        """
        if not self.config.use_args_hash or not arguments:
            return tool_name

        # Deterministic hash of arguments for grouping identical calls
        args_str = json.dumps(arguments, sort_keys=True, default=str)
        args_hash = hashlib.md5(args_str.encode()).hexdigest()[:12]
        return f"{tool_name}:{args_hash}"
