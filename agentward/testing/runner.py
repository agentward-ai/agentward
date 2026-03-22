"""Test runner for AgentWard policy regression testing.

Loads the user's policy, fires each probe through the real PolicyEngine,
and classifies the result as PASS / FAIL / GAP / SKIP.

PASS  — the engine returned the verdict the probe expected
FAIL  — the engine returned a different verdict AND had a matching policy
        rule (genuine misconfiguration)
GAP   — the engine returned a different verdict because no policy rule
        covers that tool at all (coverage gap, not a misconfiguration)
SKIP  — the probe required a policy feature (e.g. skill_chaining) that
        is absent from the loaded policy
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agentward.policy.engine import PolicyEngine
from agentward.policy.loader import load_policy
from agentward.policy.schema import AgentWardPolicy
from agentward.testing.models import Probe, ProbeOutcome, ProbeResult

# Substrings that appear in the engine's reason when no policy rule matched
# the tool and the result came from the default_action setting.
_DEFAULT_ACTION_PHRASES: tuple[str, ...] = (
    "No policy rule matches",
    "Allowing by default",
    "Blocked by default (default_action: block)",
    "but no explicit rule for action",
)


@dataclass
class RunnerConfig:
    """Configuration for a single test run."""

    policy_path: Path | None = None
    """Path to the agentward.yaml policy file.
    If None, a bare policy (default_action: allow, no rules) is used so that
    only protected-path probes (safety-floor) can pass."""

    categories: list[str] = field(default_factory=list)
    """Restrict run to these categories (empty = all)."""

    severities: list[str] = field(default_factory=list)
    """Restrict run to these severities (empty = all)."""

    strict: bool = False
    """When True, treat GAP results as failures (exit code 1)."""


class TestRunner:
    """Evaluates a list of probes against a loaded AgentWard policy."""

    def __init__(self, config: RunnerConfig) -> None:
        self._config = config
        self._policy: AgentWardPolicy | None = None
        self._engine: PolicyEngine | None = None

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def load(self) -> None:
        """Load (or build) the policy and construct the engine."""
        if self._config.policy_path is not None:
            self._policy = load_policy(self._config.policy_path)
        else:
            # Minimal passthrough policy — only the safety floor is active
            self._policy = AgentWardPolicy(version="1.0")
        self._engine = PolicyEngine(self._policy)

    @property
    def policy(self) -> AgentWardPolicy:
        """The loaded policy (available after ``load()``)."""
        if self._policy is None:
            raise RuntimeError("Call load() before accessing the policy.")
        return self._policy

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------

    def filter_probes(self, probes: list[Probe]) -> list[Probe]:
        """Apply category / severity filters and return matching probes."""
        result = probes

        if self._config.categories:
            cats = {c.lower() for c in self._config.categories}
            result = [p for p in result if p.category.lower() in cats]

        if self._config.severities:
            sevs = {s.lower() for s in self._config.severities}
            result = [p for p in result if p.severity.lower() in sevs]

        return result

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run_probe(self, probe: Probe) -> ProbeResult:
        """Run a single probe and return its classified result."""
        if self._engine is None or self._policy is None:
            raise RuntimeError("Call load() before run_probe().")

        # --- Skip check -----------------------------------------------
        skip_reason = self._skip_reason(probe)
        if skip_reason is not None:
            return ProbeResult(
                probe=probe,
                outcome=ProbeOutcome.SKIP,
                skip_reason=skip_reason,
            )

        # --- Evaluate -------------------------------------------------
        if probe.chaining_source is not None and probe.chaining_target is not None:
            eval_result = self._engine.evaluate_chaining(
                probe.chaining_source,
                probe.chaining_target,
            )
        else:
            assert probe.tool_name is not None
            eval_result = self._engine.evaluate(
                probe.tool_name,
                probe.arguments or {},
            )

        actual = eval_result.decision.value  # e.g. "BLOCK"
        outcome = self._classify(probe.expected, actual, eval_result.reason)

        return ProbeResult(
            probe=probe,
            outcome=outcome,
            actual_decision=actual,
            actual_reason=eval_result.reason,
        )

    def run_all(self, probes: list[Probe]) -> list[ProbeResult]:
        """Run every probe in order and return all results."""
        return [self.run_probe(p) for p in probes]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _skip_reason(self, probe: Probe) -> str | None:
        """Return a human-readable skip reason, or None to proceed."""
        feature = probe.requires_policy_feature
        if feature is None:
            return None

        policy = self._policy
        assert policy is not None

        fl = feature.lower()
        if fl == "skill_chaining" and not policy.skill_chaining:
            return "Policy has no skill_chaining rules"
        if fl == "require_approval" and not policy.require_approval:
            return "Policy has no require_approval rules"
        if fl == "sensitive_content" and not policy.sensitive_content.enabled:
            return "Policy has sensitive_content.enabled: false"
        if fl == "data_boundaries" and not policy.data_boundaries:
            return "Policy has no data_boundaries"
        if fl == "llm_judge" and not policy.llm_judge.enabled:
            return "Policy has llm_judge.enabled: false"
        return None

    def _classify(self, expected: str, actual: str, reason: str) -> ProbeOutcome:
        """Classify a probe result as PASS / FAIL / GAP."""
        if actual == expected:
            return ProbeOutcome.PASS

        # Check whether the result came from the default action (a gap) or
        # from an explicit policy rule that returned the wrong verdict.
        is_default_result = any(phrase in reason for phrase in _DEFAULT_ACTION_PHRASES)

        if is_default_result and not self._config.strict:
            return ProbeOutcome.GAP

        return ProbeOutcome.FAIL
