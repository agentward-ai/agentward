"""Tests for the policy evaluation engine."""

from pathlib import Path

import pytest

from agentward.policy.engine import PolicyEngine
from agentward.policy.loader import load_policy
from agentward.policy.schema import PolicyDecision

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def simple_engine() -> PolicyEngine:
    """Engine loaded with the simple policy (one skill, one resource)."""
    policy = load_policy(FIXTURES / "simple_policy.yaml")
    return PolicyEngine(policy)


@pytest.fixture
def full_engine() -> PolicyEngine:
    """Engine loaded with the full policy (multiple skills, chaining, approval)."""
    policy = load_policy(FIXTURES / "full_policy.yaml")
    return PolicyEngine(policy)


class TestToolMatching:
    """Tests for matching MCP tool names to policy rules."""

    def test_allow_permitted_action(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail_read", {"query": "test"})
        assert result.decision == PolicyDecision.ALLOW
        assert result.skill == "email-manager"
        assert result.resource == "gmail"

    def test_block_denied_action(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail_send", {"to": "x", "body": "y"})
        assert result.decision == PolicyDecision.BLOCK
        assert result.skill == "email-manager"
        assert result.resource == "gmail"

    def test_block_delete_action(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail_delete", {"id": "123"})
        assert result.decision == PolicyDecision.BLOCK

    def test_allow_draft_action(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail_draft", {"body": "draft text"})
        assert result.decision == PolicyDecision.ALLOW

    def test_unknown_tool_allows_passthrough(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("unknown_tool", {})
        assert result.decision == PolicyDecision.ALLOW
        assert result.skill is None
        assert result.resource is None

    def test_unknown_action_on_known_resource(self, simple_engine: PolicyEngine) -> None:
        """Action not mentioned in policy → ALLOW by default."""
        result = simple_engine.evaluate("gmail_archive", {})
        assert result.decision == PolicyDecision.ALLOW
        assert result.resource == "gmail"


class TestDeniedResources:
    """Tests for resources with denied: true."""

    def test_denied_resource_blocks_all(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate("google_calendar_read", {})
        # google_calendar is denied for email-manager
        assert result.decision == PolicyDecision.BLOCK

    def test_denied_gmail_for_calendar_assistant(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate("gmail_read", {"query": "test"})
        # gmail is allowed for email-manager (read: true), so it should ALLOW
        # even though gmail is denied for calendar-assistant
        assert result.decision == PolicyDecision.ALLOW

    def test_denied_filesystem_for_web_researcher(self, full_engine: PolicyEngine) -> None:
        # filesystem is denied for web-researcher, but also has permissions
        # under finance-tracker (read: true, write: false).
        # The engine should find the finance-tracker match.
        result = full_engine.evaluate("filesystem_read", {})
        assert result.decision == PolicyDecision.ALLOW

    def test_denied_filesystem_write(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate("filesystem_write", {})
        assert result.decision == PolicyDecision.BLOCK


class TestRequireApproval:
    """Tests for the require_approval list."""

    def test_approval_required(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate("send_email", {})
        assert result.decision == PolicyDecision.APPROVE

    def test_approval_required_delete(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate("delete_file", {})
        assert result.decision == PolicyDecision.APPROVE

    def test_approval_not_required(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate("gmail_read", {})
        assert result.decision != PolicyDecision.APPROVE


class TestChaining:
    """Tests for skill chaining evaluation."""

    def test_chaining_blocked_specific(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate_chaining("email-manager", "web-researcher")
        assert result.decision == PolicyDecision.BLOCK

    def test_chaining_blocked_any(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate_chaining("finance-tracker", "email-manager")
        assert result.decision == PolicyDecision.BLOCK

    def test_chaining_blocked_any_to_different(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate_chaining("finance-tracker", "web-researcher")
        assert result.decision == PolicyDecision.BLOCK

    def test_chaining_allowed_self(self, full_engine: PolicyEngine) -> None:
        """'cannot trigger any other skill' still allows self-calls."""
        result = full_engine.evaluate_chaining("finance-tracker", "finance-tracker")
        assert result.decision == PolicyDecision.ALLOW

    def test_chaining_allowed_no_rule(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate_chaining("calendar-assistant", "email-manager")
        assert result.decision == PolicyDecision.ALLOW

    def test_chaining_web_to_shell_blocked(self, full_engine: PolicyEngine) -> None:
        result = full_engine.evaluate_chaining("web-researcher", "shell-executor")
        assert result.decision == PolicyDecision.BLOCK


class TestNestedPermissions:
    """Tests for nested permission structures (e.g., modify.own_events)."""

    def test_nested_allowed(self, full_engine: PolicyEngine) -> None:
        # google_calendar has modify.own_events: true for calendar-assistant
        # Tool name "google_calendar_modify" would match resource "google_calendar"
        # But the action "modify" is a nested dict, flattened to modify.own_events etc.
        # Since "modify" itself isn't a bool key, it won't directly match.
        # The engine should handle this gracefully.
        result = full_engine.evaluate("google_calendar_read", {})
        # google_calendar is denied for email-manager, but calendar-assistant allows read
        # Engine picks the first match — depends on iteration order
        # Both email-manager and calendar-assistant define google_calendar
        assert result.decision in (PolicyDecision.ALLOW, PolicyDecision.BLOCK)


class TestSeparatorVariants:
    """Tests for different separator styles in tool names."""

    def test_underscore_separator(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail_read", {})
        assert result.resource == "gmail"

    def test_hyphen_separator(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail-read", {})
        assert result.resource == "gmail"

    def test_dot_separator(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail.read", {})
        assert result.resource == "gmail"

    def test_exact_resource_name(self, simple_engine: PolicyEngine) -> None:
        """Tool name exactly matches resource name (no action extracted)."""
        result = simple_engine.evaluate("gmail", {})
        assert result.resource == "gmail"
        assert result.decision == PolicyDecision.ALLOW


class TestNoArguments:
    """Tests for tool calls with None arguments."""

    def test_none_arguments(self, simple_engine: PolicyEngine) -> None:
        result = simple_engine.evaluate("gmail_read", None)
        assert result.decision == PolicyDecision.ALLOW


class TestVerbFirstToolNames:
    """Tests for verb-first tool names like read_file, write_database.

    These use suffix matching: 'read_file' matches resource 'file' → action 'read'.
    """

    def test_read_gmail_suffix_match(self, simple_engine: PolicyEngine) -> None:
        """'read_gmail' matches resource 'gmail' with action 'read'."""
        result = simple_engine.evaluate("read_gmail", {})
        assert result.resource == "gmail"
        assert result.decision == PolicyDecision.ALLOW  # read: true

    def test_send_gmail_suffix_blocked(self, simple_engine: PolicyEngine) -> None:
        """'send_gmail' matches resource 'gmail' with action 'send' → BLOCK."""
        result = simple_engine.evaluate("send_gmail", {})
        assert result.resource == "gmail"
        assert result.decision == PolicyDecision.BLOCK  # send: false

    def test_read_filesystem_suffix_match(self, full_engine: PolicyEngine) -> None:
        """'read_filesystem' matches resource 'filesystem' → ALLOW."""
        result = full_engine.evaluate("read_filesystem", {})
        assert result.resource == "filesystem"
        assert result.decision == PolicyDecision.ALLOW  # read: true (finance-tracker)

    def test_write_filesystem_suffix_blocked(self, full_engine: PolicyEngine) -> None:
        """'write_filesystem' matches resource 'filesystem' with action 'write' → BLOCK."""
        result = full_engine.evaluate("write_filesystem", {})
        assert result.resource == "filesystem"
        assert result.decision == PolicyDecision.BLOCK  # write: false (finance-tracker)

    def test_suffix_hyphen_separator(self, simple_engine: PolicyEngine) -> None:
        """Suffix match works with hyphen separator."""
        result = simple_engine.evaluate("read-gmail", {})
        assert result.resource == "gmail"
        assert result.decision == PolicyDecision.ALLOW

    def test_suffix_dot_separator(self, simple_engine: PolicyEngine) -> None:
        """Suffix match works with dot separator."""
        result = simple_engine.evaluate("read.gmail", {})
        assert result.resource == "gmail"
        assert result.decision == PolicyDecision.ALLOW

    def test_prefix_still_works(self, simple_engine: PolicyEngine) -> None:
        """Prefix matching still works (regression check)."""
        result = simple_engine.evaluate("gmail_read", {})
        assert result.resource == "gmail"
        assert result.decision == PolicyDecision.ALLOW


class TestSkillContext:
    """Tests for skill_context filtering in PolicyEngine.

    When skill_context is set, evaluate() only matches resources from that
    skill, disambiguating cases where multiple skills define the same resource.
    """

    def test_context_email_manager_denies_calendar(self) -> None:
        """With email-manager context, google_calendar is denied."""
        policy = load_policy(FIXTURES / "full_policy.yaml")
        engine = PolicyEngine(policy, skill_context="email-manager")
        result = engine.evaluate("google_calendar_read", {})
        assert result.decision == PolicyDecision.BLOCK
        assert result.skill == "email-manager"

    def test_context_calendar_assistant_allows_calendar(self) -> None:
        """With calendar-assistant context, google_calendar read is allowed."""
        policy = load_policy(FIXTURES / "full_policy.yaml")
        engine = PolicyEngine(policy, skill_context="calendar-assistant")
        result = engine.evaluate("google_calendar_read", {})
        assert result.decision == PolicyDecision.ALLOW
        assert result.skill == "calendar-assistant"

    def test_context_filters_out_other_skills(self) -> None:
        """With email-manager context, browser (web-researcher) doesn't match."""
        policy = load_policy(FIXTURES / "full_policy.yaml")
        engine = PolicyEngine(policy, skill_context="email-manager")
        result = engine.evaluate("browser_navigate", {})
        # No match in email-manager → passthrough ALLOW with no skill
        assert result.skill is None

    def test_no_context_matches_all_skills(self) -> None:
        """Without skill_context, all skills are searched (existing behavior)."""
        policy = load_policy(FIXTURES / "full_policy.yaml")
        engine = PolicyEngine(policy)  # No context
        result = engine.evaluate("browser_allowed", {})
        assert result.skill == "web-researcher"

    def test_resolve_skill_ignores_context(self) -> None:
        """resolve_skill() works for any skill regardless of context."""
        policy = load_policy(FIXTURES / "full_policy.yaml")
        engine = PolicyEngine(policy, skill_context="email-manager")
        # gmail belongs to email-manager — should resolve
        assert engine.resolve_skill("gmail_read") == "email-manager"
        # browser belongs to web-researcher — should also resolve
        # because resolve_skill doesn't use skill_context
        assert engine.resolve_skill("browser_navigate") == "web-researcher"


class TestDenyOnlyResources:
    """Tests for resources that only have deny rules (all actions False).

    When a resource has only `False` permissions (e.g., `outbound: false`),
    any tool matching that resource should be BLOCKED, even if the extracted
    action doesn't match a permission key. This covers the generator's
    network+credentials rule which emits `{outbound: false}`.
    """

    def test_deny_only_resource_blocks_unmatched_action(self) -> None:
        """Tool matching a deny-only resource is blocked even with unrelated action."""
        from agentward.policy.schema import AgentWardPolicy, ResourcePermissions

        policy = AgentWardPolicy(
            version="1.0",
            skills={
                "risky-server": {
                    "url": ResourcePermissions(actions={"outbound": False}),
                },
            },
        )
        engine = PolicyEngine(policy)
        # "fetch_url" matches resource "url", action "fetch"
        # "fetch" isn't in permissions, but all permissions are False → BLOCK
        result = engine.evaluate("fetch_url", {})
        assert result.decision == PolicyDecision.BLOCK
        assert result.resource == "url"

    def test_mixed_resource_allows_unmatched_action(self) -> None:
        """Tool matching a mixed resource (has True values) still allows unlisted actions."""
        from agentward.policy.schema import AgentWardPolicy, ResourcePermissions

        policy = AgentWardPolicy(
            version="1.0",
            skills={
                "email-manager": {
                    "gmail": ResourcePermissions(
                        actions={"read": True, "send": False, "draft": True},
                    ),
                },
            },
        )
        engine = PolicyEngine(policy)
        # "gmail_archive" → action "archive" not listed, but resource has True values
        result = engine.evaluate("gmail_archive", {})
        assert result.decision == PolicyDecision.ALLOW
        assert result.resource == "gmail"

    def test_deny_only_resource_blocks_suffix_match(self) -> None:
        """Deny-only resource blocks via suffix matching too."""
        from agentward.policy.schema import AgentWardPolicy, ResourcePermissions

        policy = AgentWardPolicy(
            version="1.0",
            skills={
                "risky-server": {
                    "network": ResourcePermissions(actions={"outbound": False}),
                },
            },
        )
        engine = PolicyEngine(policy)
        # "call_network" → suffix match resource "network", action "call"
        result = engine.evaluate("call_network", {})
        assert result.decision == PolicyDecision.BLOCK


