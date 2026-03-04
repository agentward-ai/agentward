"""Tests for sequence-aware chaining (SequenceRule matching).

Verifies multi-step pattern matching, wildcards, category wildcards,
coexistence with pairwise rules, deduplication, and edge cases.
"""

from __future__ import annotations

import pytest

from agentward.policy.engine import PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    ChainingMode,
    ChainingRule,
    DataBoundary,
    PolicyDecision,
    ResourcePermissions,
    SequenceAction,
    SequenceRule,
    ViolationAction,
)
from agentward.proxy.chaining import ChainTracker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy(
    chaining_rules: list[str] | None = None,
    sequence_rules: list[SequenceRule] | None = None,
    boundaries: dict[str, DataBoundary] | None = None,
    mode: ChainingMode = ChainingMode.BLANKET,
    skill_chain_depth: int | None = None,
) -> AgentWardPolicy:
    """Build a policy with skills, optional chaining/sequence rules, and boundaries.

    Skills:
      - email-manager:    resource 'gmail'    (tools: gmail_read, gmail_send)
      - web-browser:      resource 'browser'  (tools: browser_navigate)
      - shell-executor:   resource 'shell'    (tools: shell_exec)
      - finance-tool:     resource 'finance'  (tools: finance_query)
      - accounting-tool:  resource 'accounting' (tools: accounting_report)
    """
    skills = {
        "email-manager": {
            "gmail": ResourcePermissions.model_construct(
                denied=False, actions={"read": True, "send": True}, filters={},
            ),
        },
        "web-browser": {
            "browser": ResourcePermissions.model_construct(
                denied=False, actions={"navigate": True}, filters={},
            ),
        },
        "shell-executor": {
            "shell": ResourcePermissions.model_construct(
                denied=False, actions={"exec": True}, filters={},
            ),
        },
        "finance-tool": {
            "finance": ResourcePermissions.model_construct(
                denied=False, actions={"query": True}, filters={},
            ),
        },
        "accounting-tool": {
            "accounting": ResourcePermissions.model_construct(
                denied=False, actions={"report": True}, filters={},
            ),
        },
    }

    rules = [
        ChainingRule(
            source_skill=r.split(" cannot trigger ")[0],
            target_skill=r.split(" cannot trigger ")[1],
        )
        for r in (chaining_rules or [])
    ]

    return AgentWardPolicy(
        version="1.0",
        skills=skills,
        skill_chaining=rules,
        chaining_mode=mode,
        skill_chain_depth=skill_chain_depth,
        require_approval=[],
        data_boundaries=boundaries or {},
        sequence_rules=sequence_rules or [],
    )


def _simulate_calls(tracker: ChainTracker, tool_names: list[str]) -> None:
    """Simulate a sequence of tool calls (record_call only, no check)."""
    for tool in tool_names:
        tracker.record_call(tool, {})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestLiteralThreeStepMatch:
    """Literal 3-step sequence: email → browser → shell."""

    def test_full_sequence_blocks(self) -> None:
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser", "shell-executor"],
                    action=SequenceAction.BLOCK,
                ),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        # email → ok
        result = tracker.check_before_call("gmail_read", {})
        assert result is None
        tracker.record_call("gmail_read", {})

        # browser → ok (only 2 of 3)
        result = tracker.check_before_call("browser_navigate", {})
        assert result is None
        tracker.record_call("browser_navigate", {})

        # shell → BLOCKED (3 of 3)
        result = tracker.check_before_call("shell_exec", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK
        assert "Sequence rule matched" in result.reason
        assert "email-manager" in result.reason

    def test_partial_sequence_no_match(self) -> None:
        """Only 2 of 3 steps → no match."""
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser", "shell-executor"],
                ),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})
        tracker.record_call("browser_navigate", {})

        # finance_query is NOT shell-executor → sequence doesn't match
        result = tracker.check_before_call("finance_query", {})
        assert result is None


class TestAnyWildcard:
    """The ``any`` wildcard matches any skill."""

    def test_any_in_middle(self) -> None:
        """email → ANY → shell should match email → browser → shell."""
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(pattern=["email-manager", "any", "shell-executor"]),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})
        tracker.record_call("browser_navigate", {})

        result = tracker.check_before_call("shell_exec", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK

    def test_any_at_start(self) -> None:
        """any → shell should match browser → shell."""
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(pattern=["any", "shell-executor"]),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("browser_navigate", {})

        result = tracker.check_before_call("shell_exec", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestCategoryWildcard:
    """``any_financial`` matches skills in a zone with classification "financial"."""

    def test_any_financial_matches_finance_tool(self) -> None:
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(pattern=["any_financial", "any", "any_financial"]),
            ],
            boundaries={
                "financial_zone": DataBoundary(
                    skills=["finance-tool", "accounting-tool"],
                    classification="financial",
                    on_violation=ViolationAction.BLOCK_AND_LOG,
                ),
            },
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        # finance-tool → browser → accounting-tool
        tracker.record_call("finance_query", {})
        tracker.record_call("browser_navigate", {})

        result = tracker.check_before_call("accounting_report", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK
        assert "Sequence rule matched" in result.reason

    def test_category_no_matching_boundary(self) -> None:
        """Category wildcard with no matching boundary → matches nothing."""
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(pattern=["any_medical", "shell-executor"]),
            ],
            # No boundary with classification "medical"
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})

        result = tracker.check_before_call("shell_exec", {})
        assert result is None  # "any_medical" matches nothing


class TestApproveAction:
    """Sequence rules can return APPROVE instead of BLOCK."""

    def test_approve_returns_approve_decision(self) -> None:
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser"],
                    action=SequenceAction.APPROVE,
                ),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})

        result = tracker.check_before_call("browser_navigate", {})
        assert result is not None
        assert result.decision == PolicyDecision.APPROVE
        assert "Sequence rule matched" in result.reason


class TestConsecutiveSameSkillDedup:
    """Consecutive calls to the same skill are collapsed (deduped)."""

    def test_dedup_does_not_trigger_false_match(self) -> None:
        """email → email → browser → shell should dedup to email → browser → shell."""
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser", "shell-executor"],
                ),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        # Two email calls back-to-back
        tracker.record_call("gmail_read", {})
        tracker.record_call("gmail_send", {})  # Same skill (email-manager)
        tracker.record_call("browser_navigate", {})

        # Should still match: deduped trailing is [email-manager, web-browser]
        # + target shell-executor = [email-manager, web-browser, shell-executor]
        result = tracker.check_before_call("shell_exec", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestPatternLongerThanHistory:
    """Pattern longer than history → can never match."""

    def test_long_pattern_no_match(self) -> None:
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser", "shell-executor", "finance-tool"],
                ),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        # Only 2 calls + 1 target = 3, but pattern is 4
        tracker.record_call("gmail_read", {})
        tracker.record_call("browser_navigate", {})

        result = tracker.check_before_call("shell_exec", {})
        assert result is None


class TestEmptySequenceRules:
    """When no sequence_rules are defined, check always returns None."""

    def test_no_rules_always_none(self) -> None:
        policy = _make_policy(sequence_rules=[])
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})
        tracker.record_call("browser_navigate", {})

        result = tracker.check_before_call("shell_exec", {})
        assert result is None  # No pairwise rules either


class TestPairwiseAndSequenceCoexistence:
    """Pairwise rules and sequence rules can coexist."""

    def test_pairwise_blocks_before_sequence(self) -> None:
        """Pairwise rule blocks email → browser; sequence only for 3-step."""
        policy = _make_policy(
            chaining_rules=["email-manager cannot trigger web-browser"],
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser", "shell-executor"],
                ),
            ],
            mode=ChainingMode.BLANKET,
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})

        # Pairwise rule blocks email → browser
        result = tracker.check_before_call("browser_navigate", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK

    def test_sequence_fires_even_without_pairwise(self) -> None:
        """Sequence rule fires for 3-step even when no pairwise blocks exist."""
        policy = _make_policy(
            # No pairwise rules
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser", "shell-executor"],
                ),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})
        tracker.record_call("browser_navigate", {})

        result = tracker.check_before_call("shell_exec", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestTwoStepSequence:
    """Two-element sequence (minimum allowed pattern length)."""

    def test_two_step_blocks(self) -> None:
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(pattern=["web-browser", "shell-executor"]),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("browser_navigate", {})

        result = tracker.check_before_call("shell_exec", {})
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestSequenceRuleYamlParsing:
    """Verify SequenceRule parses correctly from dict input (YAML simulation)."""

    def test_parse_from_dict(self) -> None:
        rule = SequenceRule(
            pattern=["email-manager", "web-browser"],
            action=SequenceAction.BLOCK,
        )
        assert rule.pattern == ["email-manager", "web-browser"]
        assert rule.action == SequenceAction.BLOCK

    def test_default_action_is_block(self) -> None:
        rule = SequenceRule(pattern=["a", "b"])
        assert rule.action == SequenceAction.BLOCK

    def test_min_pattern_length_enforced(self) -> None:
        """Pattern with < 2 elements should fail validation."""
        with pytest.raises(Exception):
            SequenceRule(pattern=["only-one"])


class TestMultipleSequenceRules:
    """First matching rule wins (order matters)."""

    def test_first_match_wins(self) -> None:
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(
                    pattern=["email-manager", "web-browser"],
                    action=SequenceAction.APPROVE,
                ),
                SequenceRule(
                    pattern=["email-manager", "web-browser"],
                    action=SequenceAction.BLOCK,
                ),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})

        result = tracker.check_before_call("browser_navigate", {})
        assert result is not None
        # First rule is APPROVE, should win
        assert result.decision == PolicyDecision.APPROVE


class TestSequenceWithUnknownTool:
    """Sequence matching handles unknown tools gracefully."""

    def test_unknown_tool_in_history_skipped(self) -> None:
        """Unknown tools (no skill mapping) are excluded from trailing list."""
        policy = _make_policy(
            sequence_rules=[
                SequenceRule(pattern=["email-manager", "shell-executor"]),
            ],
        )
        engine = PolicyEngine(policy)
        tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

        tracker.record_call("gmail_read", {})
        tracker.record_call("unknown_tool_xyz", {})  # No skill mapping

        result = tracker.check_before_call("shell_exec", {})
        assert result is not None
        # unknown_tool is skipped, so trailing is [email-manager] + target [shell-executor]
        assert result.decision == PolicyDecision.BLOCK
