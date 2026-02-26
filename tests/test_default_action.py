"""Tests for default_action: block (zero-trust mode).

Verifies that when a policy sets default_action: block, any tool not
matching a policy rule is blocked instead of allowed.
"""

from __future__ import annotations

import pytest

from agentward.policy.engine import PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    DefaultAction,
    PolicyDecision,
    ResourcePermissions,
)


# ---------------------------------------------------------------------------
# DefaultAction enum
# ---------------------------------------------------------------------------


class TestDefaultActionEnum:
    """Verify the DefaultAction enum values."""

    def test_allow_value(self) -> None:
        assert DefaultAction.ALLOW.value == "allow"

    def test_block_value(self) -> None:
        assert DefaultAction.BLOCK.value == "block"

    def test_from_string(self) -> None:
        assert DefaultAction("allow") == DefaultAction.ALLOW
        assert DefaultAction("block") == DefaultAction.BLOCK

    def test_invalid_value(self) -> None:
        with pytest.raises(ValueError):
            DefaultAction("deny")


# ---------------------------------------------------------------------------
# Policy schema
# ---------------------------------------------------------------------------


class TestPolicyDefaultAction:
    """Verify default_action field on AgentWardPolicy."""

    def test_default_is_allow(self) -> None:
        policy = AgentWardPolicy(version="1.0")
        assert policy.default_action == DefaultAction.ALLOW

    def test_explicit_allow(self) -> None:
        policy = AgentWardPolicy(version="1.0", default_action=DefaultAction.ALLOW)
        assert policy.default_action == DefaultAction.ALLOW

    def test_explicit_block(self) -> None:
        policy = AgentWardPolicy(version="1.0", default_action=DefaultAction.BLOCK)
        assert policy.default_action == DefaultAction.BLOCK

    def test_from_yaml_string(self) -> None:
        """Verify pydantic accepts string 'block' as DefaultAction."""
        policy = AgentWardPolicy(version="1.0", default_action="block")  # type: ignore[arg-type]
        assert policy.default_action == DefaultAction.BLOCK


# ---------------------------------------------------------------------------
# Engine: default_action: allow (default behavior)
# ---------------------------------------------------------------------------


class TestEngineDefaultAllow:
    """Verify engine with default_action: allow (passthrough for unknown tools)."""

    @pytest.fixture
    def engine(self) -> PolicyEngine:
        policy = AgentWardPolicy(
            version="1.0",
            default_action=DefaultAction.ALLOW,
            skills={
                "email-manager": {
                    "gmail": ResourcePermissions.model_validate({"read": True, "send": False}),
                },
            },
        )
        return PolicyEngine(policy)

    def test_known_tool_allowed(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("gmail_read")
        assert result.decision == PolicyDecision.ALLOW

    def test_known_tool_blocked(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("gmail_send")
        assert result.decision == PolicyDecision.BLOCK

    def test_unknown_tool_allowed(self, engine: PolicyEngine) -> None:
        result = engine.evaluate("unknown_tool")
        assert result.decision == PolicyDecision.ALLOW
        assert "Allowing by default" in result.reason


# ---------------------------------------------------------------------------
# Engine: default_action: block (zero-trust)
# ---------------------------------------------------------------------------


class TestEngineDefaultBlock:
    """Verify engine with default_action: block (zero-trust for unknown tools)."""

    @pytest.fixture
    def engine(self) -> PolicyEngine:
        policy = AgentWardPolicy(
            version="1.0",
            default_action=DefaultAction.BLOCK,
            skills={
                "email-manager": {
                    "gmail": ResourcePermissions.model_validate({"read": True, "send": False}),
                },
            },
        )
        return PolicyEngine(policy)

    def test_known_tool_allowed(self, engine: PolicyEngine) -> None:
        """Tools that match a policy rule and are allowed should still work."""
        result = engine.evaluate("gmail_read")
        assert result.decision == PolicyDecision.ALLOW

    def test_known_tool_blocked(self, engine: PolicyEngine) -> None:
        """Tools that match a policy rule and are denied should still block."""
        result = engine.evaluate("gmail_send")
        assert result.decision == PolicyDecision.BLOCK

    def test_unknown_tool_blocked(self, engine: PolicyEngine) -> None:
        """Tools that DON'T match any policy rule should be BLOCKED."""
        result = engine.evaluate("unknown_tool")
        assert result.decision == PolicyDecision.BLOCK
        assert "default_action: block" in result.reason

    def test_unknown_tool_reason_mentions_tool_name(
        self, engine: PolicyEngine
    ) -> None:
        result = engine.evaluate("some_random_tool")
        assert "some_random_tool" in result.reason

    def test_multiple_unknown_tools_all_blocked(
        self, engine: PolicyEngine
    ) -> None:
        """Every unknown tool should be blocked, not just the first."""
        for tool in ["tool_a", "tool_b", "shell_exec", "web_browse"]:
            result = engine.evaluate(tool)
            assert result.decision == PolicyDecision.BLOCK, f"{tool} should be blocked"


# ---------------------------------------------------------------------------
# YAML loading with default_action
# ---------------------------------------------------------------------------


class TestDefaultActionYamlLoading:
    """Verify loading default_action from YAML via the policy loader."""

    def test_load_without_default_action(self, tmp_path: object) -> None:
        """YAML without default_action should default to allow."""
        from pathlib import Path

        yaml_path = Path(str(tmp_path)) / "policy.yaml"
        yaml_path.write_text('version: "1.0"\n')

        from agentward.policy.loader import load_policy

        policy = load_policy(yaml_path)
        assert policy.default_action == DefaultAction.ALLOW

    def test_load_with_default_action_block(self, tmp_path: object) -> None:
        """YAML with default_action: block should set zero-trust mode."""
        from pathlib import Path

        yaml_path = Path(str(tmp_path)) / "policy.yaml"
        yaml_path.write_text('version: "1.0"\ndefault_action: block\n')

        from agentward.policy.loader import load_policy

        policy = load_policy(yaml_path)
        assert policy.default_action == DefaultAction.BLOCK

    def test_load_with_default_action_allow(self, tmp_path: object) -> None:
        from pathlib import Path

        yaml_path = Path(str(tmp_path)) / "policy.yaml"
        yaml_path.write_text('version: "1.0"\ndefault_action: allow\n')

        from agentward.policy.loader import load_policy

        policy = load_policy(yaml_path)
        assert policy.default_action == DefaultAction.ALLOW


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestDefaultActionEdgeCases:
    """Edge cases for default_action behavior."""

    def test_require_approval_takes_priority_over_default_block(self) -> None:
        """require_approval should still return APPROVE even in block mode."""
        policy = AgentWardPolicy(
            version="1.0",
            default_action=DefaultAction.BLOCK,
            require_approval=["send_email"],
        )
        engine = PolicyEngine(policy)
        result = engine.evaluate("send_email")
        assert result.decision == PolicyDecision.APPROVE

    def test_empty_skills_block_mode_blocks_everything(self) -> None:
        """With no skills defined and block mode, everything should be blocked."""
        policy = AgentWardPolicy(
            version="1.0",
            default_action=DefaultAction.BLOCK,
        )
        engine = PolicyEngine(policy)
        result = engine.evaluate("any_tool")
        assert result.decision == PolicyDecision.BLOCK

    def test_empty_skills_allow_mode_allows_everything(self) -> None:
        """With no skills defined and allow mode, everything should pass."""
        policy = AgentWardPolicy(
            version="1.0",
            default_action=DefaultAction.ALLOW,
        )
        engine = PolicyEngine(policy)
        result = engine.evaluate("any_tool")
        assert result.decision == PolicyDecision.ALLOW
