"""Session-level evasion analyzer.

Runs all pattern matchers against the current session window and aggregates
their scores into a single ``SessionVerdict``. The verdict thresholds are
tunable via the ``SessionPolicy.sensitivity`` setting.

Aggregation strategy: the maximum individual score is used as the aggregate.
Each pattern independently represents a distinct attack vector, so the presence
of any single strong signal warrants a response regardless of how the others score.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from agentward.session.buffer import BufferEntry
from agentward.session.patterns import ALL_PATTERNS, MatchResult, PatternMatcher

if TYPE_CHECKING:
    from agentward.session.policy import SessionPolicy


class SessionVerdict(str, Enum):
    """Session-level risk assessment.

    CLEAN:            No significant evasion signals in the call window.
    SUSPICIOUS:       One or more patterns raised a moderate signal.
                      Action controlled by ``on_suspicious`` policy setting.
    EVASION_DETECTED: High-confidence evasion signal detected.
                      Action controlled by ``on_evasion`` policy setting.
    """

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    EVASION_DETECTED = "EVASION_DETECTED"


@dataclass
class AnalysisResult:
    """Full result from the session analyzer after one evaluation cycle.

    Attributes:
        verdict: The overall session risk verdict.
        aggregate_score: Maximum score across all matchers (0.0–1.0).
        pattern_results: Individual results from each pattern matcher.
        triggering_pattern: Name of the pattern with the highest score,
                            or empty string if no pattern matched.
    """

    verdict: SessionVerdict
    aggregate_score: float
    pattern_results: list[MatchResult]
    triggering_pattern: str


# Sensitivity level → (suspicious_threshold, evasion_threshold)
# aggregate_score >= evasion_threshold  → EVASION_DETECTED
# aggregate_score >= suspicious_threshold → SUSPICIOUS
# aggregate_score <  suspicious_threshold → CLEAN
_THRESHOLDS: dict[str, tuple[float, float]] = {
    "low":    (0.75, 0.90),
    "medium": (0.50, 0.75),
    "high":   (0.25, 0.55),
}


class SessionAnalyzer:
    """Aggregates pattern matcher results into a session-level verdict.

    Args:
        policy: The session monitoring policy configuration.
        patterns: Optional list of pattern matchers to use. Defaults to
                  ``ALL_PATTERNS`` (all five built-in matchers).
    """

    def __init__(
        self,
        policy: "SessionPolicy",
        patterns: list[PatternMatcher] | None = None,
    ) -> None:
        self._policy = policy
        self._patterns = list(patterns) if patterns is not None else list(ALL_PATTERNS)
        thresholds = _THRESHOLDS.get(
            policy.sensitivity.value, _THRESHOLDS["medium"]
        )
        self._suspicious_threshold, self._evasion_threshold = thresholds

    def check(self, session_id: str, entries: list[BufferEntry]) -> AnalysisResult:
        """Evaluate all patterns against the entry window.

        Args:
            session_id: Session identifier (informational, not used in scoring).
            entries: Recent tool call entries, oldest first.

        Returns:
            An ``AnalysisResult`` with the verdict and supporting evidence.
        """
        results: list[MatchResult] = []
        for pattern in self._patterns:
            try:
                result = pattern.match(entries)
                result.pattern_name = pattern.name
                results.append(result)
            except Exception:
                # Never let a pattern matcher crash the proxy.
                results.append(
                    MatchResult(
                        matched=False,
                        score=0.0,
                        reason="Pattern evaluation error — skipped.",
                        pattern_name=pattern.name,
                    )
                )

        if not results:
            return AnalysisResult(
                verdict=SessionVerdict.CLEAN,
                aggregate_score=0.0,
                pattern_results=[],
                triggering_pattern="",
            )

        best = max(results, key=lambda r: r.score)
        aggregate_score = best.score

        if aggregate_score >= self._evasion_threshold:
            verdict = SessionVerdict.EVASION_DETECTED
        elif aggregate_score >= self._suspicious_threshold:
            verdict = SessionVerdict.SUSPICIOUS
        else:
            verdict = SessionVerdict.CLEAN

        return AnalysisResult(
            verdict=verdict,
            aggregate_score=aggregate_score,
            pattern_results=results,
            triggering_pattern=best.pattern_name if best.score > 0.0 else "",
        )
