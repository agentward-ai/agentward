"""Tests for conditional approval rules.

Covers:
  - ApprovalCondition (contains, not_contains, equals, matches)
  - ConditionalApproval matching
  - ApprovalRule parsing and backward compatibility
  - Engine evaluation with conditional rules
  - YAML round-tripping
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.loader import load_policy
from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalCondition,
    ApprovalRule,
    ConditionalApproval,
    PolicyDecision,
)


# ---------------------------------------------------------------------------
# ApprovalCondition
# ---------------------------------------------------------------------------


class TestApprovalCondition:
    """Test individual condition matchers."""

    def test_contains_match(self) -> None:
        cond = ApprovalCondition(contains="@external.com")
        assert cond.check("bob@external.com") is True
        assert cond.check("bob@internal.com") is False

    def test_contains_case_sensitive(self) -> None:
        cond = ApprovalCondition(contains="sudo")
        assert cond.check("sudo rm -rf /") is True
        assert cond.check("SUDO rm -rf /") is False

    def test_not_contains_match(self) -> None:
        cond = ApprovalCondition(not_contains="/tmp/")
        assert cond.check("/home/user/important.txt") is True
        assert cond.check("/tmp/scratch.txt") is False

    def test_equals_match(self) -> None:
        cond = ApprovalCondition(equals="production")
        assert cond.check("production") is True
        assert cond.check("staging") is False

    def test_equals_non_string(self) -> None:
        cond = ApprovalCondition(equals=42)
        assert cond.check(42) is True
        assert cond.check(41) is False

    def test_matches_regex(self) -> None:
        cond = ApprovalCondition(matches=r"\d{3}-\d{2}-\d{4}")
        assert cond.check("SSN: 123-45-6789") is True
        assert cond.check("no SSN here") is False

    def test_multiple_conditions_and_logic(self) -> None:
        """All conditions must pass (AND logic)."""
        cond = ApprovalCondition(contains="sudo", not_contains="--dry-run")
        assert cond.check("sudo rm -rf /") is True
        assert cond.check("sudo rm -rf / --dry-run") is False
        assert cond.check("ls -la") is False

    def test_none_value(self) -> None:
        cond = ApprovalCondition(contains="test")
        assert cond.check(None) is False

    def test_invalid_regex_fails_at_load(self) -> None:
        """Malformed regex in 'matches' should fail at construction time."""
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            ApprovalCondition(matches="[unclosed")

    def test_invalid_regex_via_model_construct_treated_as_non_match(self) -> None:
        """If validator is bypassed, invalid regex is treated as non-match."""
        # model_construct bypasses validators — _compiled_regex stays None
        cond = ApprovalCondition.model_construct(
            contains=None, not_contains=None, equals=None,
            matches="[unclosed",
        )
        # Should not crash — falls back to compile-on-the-fly, catches re.error
        assert cond.check("anything") is False

    def test_at_least_one_required(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            ApprovalCondition()


# ---------------------------------------------------------------------------
# ConditionalApproval
# ---------------------------------------------------------------------------


class TestConditionalApproval:
    """Test conditional approval rule matching."""

    def test_tool_name_match(self) -> None:
        ca = ConditionalApproval(
            tool="gmail_send",
            when={"to": ApprovalCondition(contains="@external.com")},
        )
        assert ca.matches("gmail_send", {"to": "bob@external.com"}) is True
        assert ca.matches("gmail_send", {"to": "bob@internal.com"}) is False
        assert ca.matches("other_tool", {"to": "bob@external.com"}) is False

    def test_no_conditions_always_matches(self) -> None:
        ca = ConditionalApproval(tool="dangerous_tool")
        assert ca.matches("dangerous_tool", {}) is True
        assert ca.matches("dangerous_tool", None) is True

    def test_multiple_argument_conditions(self) -> None:
        ca = ConditionalApproval(
            tool="file_write",
            when={
                "path": ApprovalCondition(not_contains="/tmp/"),
                "content": ApprovalCondition(contains="password"),
            },
        )
        # Both conditions must match
        assert ca.matches("file_write", {
            "path": "/home/user/config.txt",
            "content": "password=secret",
        }) is True
        # Path is /tmp/ — first condition fails
        assert ca.matches("file_write", {
            "path": "/tmp/scratch.txt",
            "content": "password=secret",
        }) is False
        # No password in content — second condition fails
        assert ca.matches("file_write", {
            "path": "/home/user/config.txt",
            "content": "harmless data",
        }) is False

    def test_missing_argument_fails(self) -> None:
        ca = ConditionalApproval(
            tool="shell_exec",
            when={"command": ApprovalCondition(contains="sudo")},
        )
        # Argument not present → condition.check(None) → False
        assert ca.matches("shell_exec", {}) is False

    def test_none_arguments_with_conditions(self) -> None:
        ca = ConditionalApproval(
            tool="shell_exec",
            when={"command": ApprovalCondition(contains="sudo")},
        )
        assert ca.matches("shell_exec", None) is False


# ---------------------------------------------------------------------------
# ApprovalRule
# ---------------------------------------------------------------------------


class TestApprovalRule:
    """Test parsing and backward compatibility."""

    def test_string_parsing(self) -> None:
        rule = ApprovalRule.model_validate("send_email")
        assert rule.tool_name == "send_email"
        assert rule.conditional is None

    def test_dict_parsing(self) -> None:
        rule = ApprovalRule.model_validate({
            "tool": "gmail_send",
            "when": {"to": {"contains": "@external.com"}},
        })
        assert rule.tool_name is None
        assert rule.conditional is not None
        assert rule.conditional.tool == "gmail_send"

    def test_string_equality(self) -> None:
        """ApprovalRule from string must == the original string."""
        rule = ApprovalRule.model_validate("send_email")
        assert rule == "send_email"
        assert "send_email" == rule  # noqa: SIM300

    def test_string_inequality(self) -> None:
        rule = ApprovalRule.model_validate("send_email")
        assert rule != "other_tool"

    def test_hash(self) -> None:
        rule = ApprovalRule.model_validate("send_email")
        assert hash(rule) == hash("send_email")

    def test_in_list(self) -> None:
        rules = [ApprovalRule.model_validate("a"), ApprovalRule.model_validate("b")]
        assert "a" in rules
        assert "c" not in rules

    def test_count_in_list(self) -> None:
        rules = [
            ApprovalRule.model_validate("x"),
            ApprovalRule.model_validate("x"),
            ApprovalRule.model_validate("y"),
        ]
        assert rules.count("x") == 2
        assert rules.count("y") == 1

    def test_invalid_input(self) -> None:
        with pytest.raises(ValueError, match="tool name string"):
            ApprovalRule.model_validate(42)

    def test_string_rule_matches(self) -> None:
        rule = ApprovalRule.model_validate("send_email")
        assert rule.matches("send_email", {}) is True
        assert rule.matches("other", {}) is False

    def test_conditional_rule_matches(self) -> None:
        rule = ApprovalRule.model_validate({
            "tool": "shell_exec",
            "when": {"command": {"contains": "sudo"}},
        })
        assert rule.matches("shell_exec", {"command": "sudo rm -rf /"}) is True
        assert rule.matches("shell_exec", {"command": "ls -la"}) is False
        assert rule.matches("other_tool", {"command": "sudo rm"}) is False


# ---------------------------------------------------------------------------
# Engine evaluation
# ---------------------------------------------------------------------------


class TestEngineConditionalApproval:
    """Test policy engine with conditional approval rules."""

    def _engine(self, rules: list) -> PolicyEngine:
        policy = AgentWardPolicy(version="1.0", require_approval=rules)
        return PolicyEngine(policy)

    def test_string_rule_always_approves(self) -> None:
        engine = self._engine(["shell_exec"])
        result = engine.evaluate("shell_exec", {"command": "anything"})
        assert result.decision == PolicyDecision.APPROVE

    def test_conditional_rule_approves_when_matched(self) -> None:
        engine = self._engine([
            {"tool": "gmail_send", "when": {"to": {"contains": "@external.com"}}},
        ])
        result = engine.evaluate("gmail_send", {"to": "bob@external.com"})
        assert result.decision == PolicyDecision.APPROVE
        assert "condition matched" in result.reason

    def test_conditional_rule_allows_when_not_matched(self) -> None:
        engine = self._engine([
            {"tool": "gmail_send", "when": {"to": {"contains": "@external.com"}}},
        ])
        result = engine.evaluate("gmail_send", {"to": "bob@internal.com"})
        # Condition doesn't match → no approval required → falls through to default
        assert result.decision == PolicyDecision.ALLOW

    def test_mixed_rules(self) -> None:
        """String rules and conditional rules can coexist."""
        engine = self._engine([
            "delete_file",  # always approve
            {"tool": "shell_exec", "when": {"command": {"contains": "sudo"}}},
        ])

        # delete_file always needs approval
        r1 = engine.evaluate("delete_file", {"path": "/tmp/x"})
        assert r1.decision == PolicyDecision.APPROVE

        # shell_exec with sudo needs approval
        r2 = engine.evaluate("shell_exec", {"command": "sudo rm -rf /"})
        assert r2.decision == PolicyDecision.APPROVE

        # shell_exec without sudo → allowed
        r3 = engine.evaluate("shell_exec", {"command": "ls -la"})
        assert r3.decision == PolicyDecision.ALLOW

    def test_conditional_with_regex(self) -> None:
        engine = self._engine([
            {"tool": "api_call", "when": {"url": {"matches": r"https://.*\.prod\."}}},
        ])
        result = engine.evaluate("api_call", {"url": "https://api.prod.example.com"})
        assert result.decision == PolicyDecision.APPROVE

        result = engine.evaluate("api_call", {"url": "https://api.staging.example.com"})
        assert result.decision == PolicyDecision.ALLOW

    def test_conditional_not_contains(self) -> None:
        engine = self._engine([
            {"tool": "file_delete", "when": {"path": {"not_contains": "/tmp/"}}},
        ])
        # Deleting outside /tmp/ requires approval
        result = engine.evaluate("file_delete", {"path": "/home/user/important.txt"})
        assert result.decision == PolicyDecision.APPROVE

        # Deleting inside /tmp/ is allowed
        result = engine.evaluate("file_delete", {"path": "/tmp/scratch.txt"})
        assert result.decision == PolicyDecision.ALLOW

    def test_no_arguments_with_conditional(self) -> None:
        engine = self._engine([
            {"tool": "shell_exec", "when": {"command": {"contains": "sudo"}}},
        ])
        result = engine.evaluate("shell_exec", None)
        # No arguments → condition can't match → allowed
        assert result.decision == PolicyDecision.ALLOW

    def test_conditional_approval_priority_over_resource_perms(self) -> None:
        """Approval rules take priority over resource-level permissions."""
        policy = AgentWardPolicy(
            version="1.0",
            skills={"email": {"gmail": {"read": True, "send": True}}},
            require_approval=[
                {"tool": "gmail_send", "when": {"to": {"contains": "@external.com"}}},
            ],
        )
        engine = PolicyEngine(policy)

        # Condition matches → APPROVE (overrides resource ALLOW)
        result = engine.evaluate("gmail_send", {"to": "bob@external.com"})
        assert result.decision == PolicyDecision.APPROVE

        # Condition doesn't match → falls through to resource check → ALLOW
        result = engine.evaluate("gmail_send", {"to": "bob@internal.com"})
        assert result.decision == PolicyDecision.ALLOW


# ---------------------------------------------------------------------------
# YAML round-trip
# ---------------------------------------------------------------------------


class TestYamlRoundTrip:
    """Test conditional approval rules survive YAML serialization."""

    def test_invalid_regex_in_yaml_fails_at_load(self, tmp_path: Path) -> None:
        """Invalid regex in policy YAML fails at load time, not at runtime."""
        yaml_content = """
version: "1.0"
require_approval:
  - tool: api_call
    when:
      url:
        matches: "[unclosed"
"""
        policy_file = tmp_path / "agentward.yaml"
        policy_file.write_text(yaml_content)

        with pytest.raises(Exception, match="Invalid regex pattern"):
            load_policy(policy_file)

    def test_load_conditional_from_yaml(self, tmp_path: Path) -> None:
        yaml_content = """
version: "1.0"
require_approval:
  - send_email
  - tool: gmail_send
    when:
      to:
        contains: "@external.com"
  - tool: shell_exec
    when:
      command:
        contains: sudo
        not_contains: "--dry-run"
"""
        policy_file = tmp_path / "agentward.yaml"
        policy_file.write_text(yaml_content)

        policy = load_policy(policy_file)

        # String rule
        assert "send_email" in policy.require_approval

        # Conditional rules parsed correctly
        assert len(policy.require_approval) == 3

        # Second rule: gmail_send with contains condition
        rule2 = policy.require_approval[1]
        assert rule2.conditional is not None
        assert rule2.conditional.tool == "gmail_send"
        assert rule2.conditional.when["to"].contains == "@external.com"

        # Third rule: shell_exec with multiple conditions
        rule3 = policy.require_approval[2]
        assert rule3.conditional is not None
        assert rule3.conditional.tool == "shell_exec"
        assert rule3.conditional.when["command"].contains == "sudo"
        assert rule3.conditional.when["command"].not_contains == "--dry-run"

    def test_serialization_round_trip(self, tmp_path: Path) -> None:
        """Serialize → deserialize should preserve conditional rules."""
        from agentward.configure.generator import serialize_policy

        policy = AgentWardPolicy(
            version="1.0",
            require_approval=[
                "always_approve",
                {
                    "tool": "conditional_tool",
                    "when": {"arg": {"contains": "dangerous"}},
                },
            ],
        )

        yaml_str = serialize_policy(policy)
        parsed = yaml.safe_load(yaml_str)

        # String rule preserved
        assert "always_approve" in parsed["require_approval"]

        # Conditional rule preserved
        cond_rules = [r for r in parsed["require_approval"] if isinstance(r, dict)]
        assert len(cond_rules) == 1
        assert cond_rules[0]["tool"] == "conditional_tool"
        assert cond_rules[0]["when"]["arg"]["contains"] == "dangerous"

        # Write and reload through policy loader
        policy_file = tmp_path / "agentward.yaml"
        policy_file.write_text(yaml_str)
        reloaded = load_policy(policy_file)

        # Verify engine still works with reloaded policy
        engine = PolicyEngine(reloaded)
        r1 = engine.evaluate("always_approve", {})
        assert r1.decision == PolicyDecision.APPROVE

        r2 = engine.evaluate("conditional_tool", {"arg": "very dangerous input"})
        assert r2.decision == PolicyDecision.APPROVE

        r3 = engine.evaluate("conditional_tool", {"arg": "safe input"})
        assert r3.decision == PolicyDecision.ALLOW
