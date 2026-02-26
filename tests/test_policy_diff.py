"""Tests for policy diff engine.

Covers:
  - Default action changes
  - Skill/resource/action additions, removals, changes
  - Approval rule additions and removals
  - Chaining rule additions and removals
  - Breaking vs. relaxing classification
  - Empty diffs
  - CLI rendering (smoke test)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentward.policy.diff import (
    ChangeType,
    PolicyChange,
    PolicyDiff,
    diff_policies,
    render_diff,
)
from agentward.policy.schema import (
    AgentWardPolicy,
    ChainingMode,
    DefaultAction,
    ResourcePermissions,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _policy(**kwargs) -> AgentWardPolicy:
    """Create a minimal policy with overrides."""
    defaults = {"version": "1.0"}
    defaults.update(kwargs)
    return AgentWardPolicy(**defaults)


# ---------------------------------------------------------------------------
# Default action
# ---------------------------------------------------------------------------


class TestDefaultActionDiff:
    """Test diffing default_action."""

    def test_no_change(self) -> None:
        old = _policy()
        new = _policy()
        diff = diff_policies(old, new)
        assert diff.is_empty

    def test_allow_to_block(self) -> None:
        old = _policy(default_action="allow")
        new = _policy(default_action="block")
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        c = diff.changes[0]
        assert c.category == "default_action"
        assert c.change_type == ChangeType.CHANGED
        assert c.old_value == "allow"
        assert c.new_value == "block"
        assert diff.breaking == 1

    def test_block_to_allow(self) -> None:
        old = _policy(default_action="block")
        new = _policy(default_action="allow")
        diff = diff_policies(old, new)

        assert diff.relaxing == 1


# ---------------------------------------------------------------------------
# Skills
# ---------------------------------------------------------------------------


class TestSkillsDiff:
    """Test diffing skill/resource/action permissions."""

    def test_add_skill(self) -> None:
        old = _policy()
        new = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"read": True, "send": False})},
        })
        diff = diff_policies(old, new)

        # Two actions added
        assert len(diff.changes) == 2
        paths = {c.path for c in diff.changes}
        assert "email.gmail.read" in paths
        assert "email.gmail.send" in paths

    def test_remove_skill(self) -> None:
        old = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"read": True})},
        })
        new = _policy()
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        assert diff.changes[0].change_type == ChangeType.REMOVED
        assert "gmail" in diff.changes[0].path

    def test_add_resource(self) -> None:
        old = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"read": True})},
        })
        new = _policy(skills={
            "email": {
                "gmail": ResourcePermissions.model_validate({"read": True}),
                "calendar": ResourcePermissions.model_validate({"read": True}),
            },
        })
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        assert diff.changes[0].path == "email.calendar.read"
        assert diff.changes[0].change_type == ChangeType.ADDED

    def test_change_action(self) -> None:
        old = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"send": True})},
        })
        new = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"send": False})},
        })
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        c = diff.changes[0]
        assert c.change_type == ChangeType.CHANGED
        assert c.old_value is True
        assert c.new_value is False
        assert "allowed → denied" in c.description
        assert diff.breaking == 1

    def test_deny_to_allow(self) -> None:
        old = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"send": False})},
        })
        new = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"send": True})},
        })
        diff = diff_policies(old, new)

        assert diff.relaxing == 1
        assert "denied → allowed" in diff.changes[0].description

    def test_denied_resource_added(self) -> None:
        old = _policy(skills={
            "email": {"gmail": ResourcePermissions.model_validate({"read": True})},
        })
        new = _policy(skills={
            "email": {
                "gmail": ResourcePermissions.model_validate({"read": True}),
                "calendar": ResourcePermissions(denied=True),
            },
        })
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        assert diff.changes[0].description.startswith("Denied")
        assert diff.breaking == 1

    def test_denied_flag_change(self) -> None:
        old = _policy(skills={
            "email": {"calendar": ResourcePermissions(denied=True)},
        })
        new = _policy(skills={
            "email": {"calendar": ResourcePermissions.model_validate({"read": True})},
        })
        diff = diff_policies(old, new)

        # denied changed + new action
        denied_changes = [c for c in diff.changes if "denied" in c.path]
        assert len(denied_changes) == 1
        assert "denied → allowed" in denied_changes[0].description


# ---------------------------------------------------------------------------
# Approval rules
# ---------------------------------------------------------------------------


class TestApprovalDiff:
    """Test diffing require_approval."""

    def test_add_approval(self) -> None:
        old = _policy()
        new = _policy(require_approval=["send_email"])
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        assert diff.changes[0].category == "approval"
        assert diff.changes[0].change_type == ChangeType.ADDED
        assert diff.breaking == 1

    def test_remove_approval(self) -> None:
        old = _policy(require_approval=["send_email"])
        new = _policy()
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        assert diff.changes[0].change_type == ChangeType.REMOVED
        assert diff.relaxing == 1

    def test_no_change_approval(self) -> None:
        old = _policy(require_approval=["send_email", "delete_file"])
        new = _policy(require_approval=["send_email", "delete_file"])
        diff = diff_policies(old, new)

        assert diff.is_empty

    def test_add_conditional_approval(self) -> None:
        old = _policy()
        new = _policy(require_approval=[
            {"tool": "gmail_send", "when": {"to": {"contains": "@external.com"}}},
        ])
        diff = diff_policies(old, new)

        cond_changes = [c for c in diff.changes if "conditional" in c.path]
        assert len(cond_changes) == 1
        assert cond_changes[0].change_type == ChangeType.ADDED

    def test_remove_conditional_approval(self) -> None:
        old = _policy(require_approval=[
            {"tool": "gmail_send", "when": {"to": {"contains": "@external.com"}}},
        ])
        new = _policy()
        diff = diff_policies(old, new)

        cond_changes = [c for c in diff.changes if "conditional" in c.path]
        assert len(cond_changes) == 1
        assert cond_changes[0].change_type == ChangeType.REMOVED


# ---------------------------------------------------------------------------
# Chaining rules
# ---------------------------------------------------------------------------


class TestChainingDiff:
    """Test diffing chaining rules."""

    def test_add_chaining_rule(self) -> None:
        old = _policy()
        new = _policy(
            skill_chaining=["email-manager cannot trigger web-browser"],
        )
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        assert diff.changes[0].category == "chaining"
        assert diff.changes[0].change_type == ChangeType.ADDED
        assert diff.breaking == 1

    def test_remove_chaining_rule(self) -> None:
        old = _policy(
            skill_chaining=["email-manager cannot trigger web-browser"],
        )
        new = _policy()
        diff = diff_policies(old, new)

        assert len(diff.changes) == 1
        assert diff.changes[0].change_type == ChangeType.REMOVED
        assert diff.relaxing == 1

    def test_chaining_mode_change(self) -> None:
        old = _policy(chaining_mode="content")
        new = _policy(chaining_mode="blanket")
        diff = diff_policies(old, new)

        mode_changes = [c for c in diff.changes if c.path == "chaining_mode"]
        assert len(mode_changes) == 1
        assert mode_changes[0].old_value == "content"
        assert mode_changes[0].new_value == "blanket"

    def test_chain_depth_change(self) -> None:
        old = _policy()
        new = _policy(skill_chain_depth=3)
        diff = diff_policies(old, new)

        depth_changes = [c for c in diff.changes if c.path == "skill_chain_depth"]
        assert len(depth_changes) == 1
        assert depth_changes[0].old_value == "unlimited"
        assert depth_changes[0].new_value == 3


# ---------------------------------------------------------------------------
# Breaking / relaxing
# ---------------------------------------------------------------------------


class TestBreakingRelaxing:
    """Test breaking vs. relaxing classification."""

    def test_multiple_breaking(self) -> None:
        old = _policy()
        new = _policy(
            default_action="block",
            require_approval=["send_email"],
            skill_chaining=["a cannot trigger b"],
        )
        diff = diff_policies(old, new)

        # default_action→block (1) + approval added (1) + chain added (1) = 3 breaking
        assert diff.breaking == 3

    def test_multiple_relaxing(self) -> None:
        old = _policy(
            default_action="block",
            require_approval=["send_email"],
            skill_chaining=["a cannot trigger b"],
        )
        new = _policy()
        diff = diff_policies(old, new)

        # default_action→allow (1) + approval removed (1) + chain removed (1) = 3 relaxing
        assert diff.relaxing == 3


# ---------------------------------------------------------------------------
# Empty diff
# ---------------------------------------------------------------------------


class TestEmptyDiff:
    """Test identical policies produce empty diff."""

    def test_identical_policies(self) -> None:
        policy = _policy(
            skills={
                "email": {"gmail": ResourcePermissions.model_validate({"read": True, "send": False})},
            },
            require_approval=["send_email"],
            skill_chaining=["email cannot trigger browser"],
        )
        diff = diff_policies(policy, policy)

        assert diff.is_empty
        assert diff.breaking == 0
        assert diff.relaxing == 0


# ---------------------------------------------------------------------------
# Rendering (smoke test)
# ---------------------------------------------------------------------------


class TestRenderDiff:
    """Smoke tests for render_diff."""

    def test_render_empty(self, capsys) -> None:
        from rich.console import Console

        console = Console(stderr=True, force_terminal=False)
        render_diff(PolicyDiff(), console)
        # Should not raise

    def test_render_with_changes(self, capsys) -> None:
        from rich.console import Console

        old = _policy()
        new = _policy(
            default_action="block",
            require_approval=["send_email"],
            skills={
                "email": {"gmail": ResourcePermissions.model_validate({"read": True})},
            },
        )
        diff = diff_policies(old, new)
        console = Console(stderr=True, force_terminal=False)
        render_diff(diff, console)
        # Should not raise
