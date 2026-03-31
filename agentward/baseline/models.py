"""Data models for behavioral baseline tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ArgumentPattern = Literal[
    "file_path",
    "url",
    "ip_address",
    "email",
    "numeric",
    "boolean",
    "json_string",
    "short_string",
    "long_string",
    "empty",
]


@dataclass
class ToolCallRecord:
    """A single recorded tool call event.

    Attributes:
        server_name: The MCP server name.
        tool_name: The tool name within the server.
        arg_names: List of argument names present in the call.
        arg_patterns: Mapping of argument name to classified pattern type.
        timestamp: Unix timestamp of the call.
        hour_of_day: Hour of day when the call occurred (0-23).
        day_of_week: Day of week (0=Monday, 6=Sunday).
    """

    server_name: str
    tool_name: str
    arg_names: list[str]
    arg_patterns: dict[str, ArgumentPattern]
    timestamp: float
    hour_of_day: int
    day_of_week: int


@dataclass
class ToolBaseline:
    """Baseline statistics for a single tool.

    Attributes:
        tool_name: The tool name.
        call_count: Total number of calls recorded.
        arg_name_sets: All seen argument name combinations as frozensets.
        arg_pattern_distributions: Per-argument pattern frequency counters.
        hourly_distribution: Call counts by hour of day.
        daily_distribution: Call counts by day of week.
    """

    tool_name: str
    call_count: int = 0
    arg_name_sets: list[list[str]] = field(default_factory=list)
    arg_pattern_distributions: dict[str, dict[str, int]] = field(default_factory=dict)
    hourly_distribution: dict[int, int] = field(default_factory=dict)
    daily_distribution: dict[int, int] = field(default_factory=dict)

    def get_frozensets(self) -> list[frozenset[str]]:
        """Return arg_name_sets as frozensets for comparison."""
        return [frozenset(s) for s in self.arg_name_sets]


@dataclass
class ServerBaseline:
    """Baseline for a complete MCP server.

    Attributes:
        server_name: The MCP server name.
        recorded_at: Unix timestamp when this baseline was last saved.
        total_calls: Total number of calls recorded across all tools.
        tools: Per-tool baseline data.
        version: Schema version for forward compatibility.
    """

    server_name: str
    recorded_at: float
    total_calls: int = 0
    tools: dict[str, ToolBaseline] = field(default_factory=dict)
    version: str = "1.0"
