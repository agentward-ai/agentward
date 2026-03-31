"""Behavioral anomaly detection against recorded baselines."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from agentward.baseline.models import ArgumentPattern, ServerBaseline, ToolBaseline
from agentward.baseline.tracker import BaselineTracker


@dataclass
class AnomalyDetail:
    """A single contributing factor to an anomaly score.

    Attributes:
        type: Short identifier for the anomaly type.
        score_contribution: This factor's contribution to the total score (0.0–1.0).
        description: Human-readable description of why this is anomalous.
        tool_name: The tool that triggered this detail.
        arg_name: The specific argument involved, if applicable.
    """

    type: str
    score_contribution: float
    description: str
    tool_name: str
    arg_name: str | None = None


@dataclass
class AnomalyResult:
    """Result of scoring a tool call against a behavioral baseline.

    Attributes:
        server_name: The MCP server name.
        tool_name: The tool name.
        score: Combined anomaly score (0.0 = normal, 1.0 = maximally anomalous).
        is_anomalous: True when score >= warn_threshold.
        details: Breakdown of individual contributing factors.
        baseline_exists: False when no baseline is available (score will be 0.0).
    """

    server_name: str
    tool_name: str
    score: float
    is_anomalous: bool
    details: list[AnomalyDetail] = field(default_factory=list)
    baseline_exists: bool = True


class AnomalyDetector:
    """Compute anomaly scores for tool calls against recorded baselines.

    Scoring factors:
    - New tool (never seen in baseline): +0.8
    - Unknown arg names (args not seen before): +0.4 per new arg (capped at 0.8)
    - Unknown arg pattern (pattern not seen for that arg): +0.3 per arg (capped at 0.6)
    - Time anomaly (hour outside recorded hours): +0.2

    Final score is clamped to [0.0, 1.0].

    Args:
        tracker: :class:`BaselineTracker` to load baselines from.
        warn_threshold: Score at or above which :attr:`AnomalyResult.is_anomalous` is True.
        block_threshold: Score at or above which callers may choose to block the call.
    """

    def __init__(
        self,
        tracker: BaselineTracker,
        warn_threshold: float = 0.3,
        block_threshold: float = 0.8,
    ) -> None:
        self._tracker = tracker
        self.warn_threshold = warn_threshold
        self.block_threshold = block_threshold

    def score(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
        timestamp: float | None = None,
    ) -> AnomalyResult:
        """Compute the anomaly score for a tool call.

        Args:
            server_name: The MCP server name.
            tool_name: The tool name.
            arguments: The tool call arguments.
            timestamp: Unix timestamp of the call (defaults to now).

        Returns:
            An :class:`AnomalyResult` with score and contributing details.
        """
        ts = timestamp if timestamp is not None else time.time()

        baseline = self._tracker.get_baseline(server_name)
        if baseline is None:
            return AnomalyResult(
                server_name=server_name,
                tool_name=tool_name,
                score=0.0,
                is_anomalous=False,
                details=[],
                baseline_exists=False,
            )

        details: list[AnomalyDetail] = []
        total_score = 0.0

        # ── Factor 1: New tool ──────────────────────────────────────────────
        if tool_name not in baseline.tools:
            contribution = 0.8
            total_score += contribution
            details.append(
                AnomalyDetail(
                    type="new_tool",
                    score_contribution=contribution,
                    description=f"Tool '{tool_name}' has never been seen in the baseline",
                    tool_name=tool_name,
                )
            )
            # No further analysis possible without a tool baseline
            score = min(1.0, total_score)
            return AnomalyResult(
                server_name=server_name,
                tool_name=tool_name,
                score=score,
                is_anomalous=score >= self.warn_threshold,
                details=details,
                baseline_exists=True,
            )

        tool_bl: ToolBaseline = baseline.tools[tool_name]
        args = arguments or {}
        arg_names = set(args.keys())

        # ── Factor 2: Unknown arg names ─────────────────────────────────────
        known_arg_name_sets = tool_bl.get_frozensets()
        new_arg_names: list[str] = []
        if known_arg_name_sets:
            # Collect all arg names ever seen for this tool
            all_known_args: set[str] = set()
            for s in known_arg_name_sets:
                all_known_args.update(s)
            new_arg_names = [a for a in arg_names if a not in all_known_args]
        else:
            new_arg_names = list(arg_names)

        if new_arg_names:
            # +0.4 per new arg, capped at 0.8
            arg_contribution = min(0.8, len(new_arg_names) * 0.4)
            total_score += arg_contribution
            for arg in new_arg_names:
                details.append(
                    AnomalyDetail(
                        type="new_arg_pattern",
                        score_contribution=0.4,
                        description=f"Argument '{arg}' has never been seen for tool '{tool_name}'",
                        tool_name=tool_name,
                        arg_name=arg,
                    )
                )

        # ── Factor 3: Unknown arg value pattern ────────────────────────────
        pattern_anomaly_count = 0
        for arg_name, arg_value in args.items():
            if arg_name in new_arg_names:
                continue  # Already flagged above
            from agentward.baseline.tracker import BaselineTracker as _BT
            current_pattern: ArgumentPattern = _BT._classify_arg_value(arg_value)
            known_patterns = tool_bl.arg_pattern_distributions.get(arg_name, {})
            if known_patterns and current_pattern not in known_patterns:
                pattern_anomaly_count += 1
                contribution = 0.3
                total_score += contribution
                details.append(
                    AnomalyDetail(
                        type="arg_value_drift",
                        score_contribution=contribution,
                        description=(
                            f"Argument '{arg_name}' has pattern '{current_pattern}' "
                            f"which was not seen in baseline "
                            f"(known: {', '.join(known_patterns.keys())})"
                        ),
                        tool_name=tool_name,
                        arg_name=arg_name,
                    )
                )

        # ── Factor 4: Time anomaly ──────────────────────────────────────────
        from datetime import datetime, timezone as _tz
        call_hour = datetime.fromtimestamp(ts, tz=_tz.utc).hour
        if tool_bl.hourly_distribution:
            if call_hour not in tool_bl.hourly_distribution:
                contribution = 0.2
                total_score += contribution
                details.append(
                    AnomalyDetail(
                        type="time_anomaly",
                        score_contribution=contribution,
                        description=(
                            f"Tool '{tool_name}' called at hour {call_hour} "
                            f"which is outside its normal hours "
                            f"({sorted(tool_bl.hourly_distribution.keys())})"
                        ),
                        tool_name=tool_name,
                    )
                )

        score = min(1.0, total_score)
        return AnomalyResult(
            server_name=server_name,
            tool_name=tool_name,
            score=score,
            is_anomalous=score >= self.warn_threshold,
            details=details,
            baseline_exists=True,
        )
