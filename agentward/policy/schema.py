"""Pydantic v2 models for AgentWard policy YAML.

Defines the complete schema for agentward.yaml, including skill permissions,
chaining rules, approval gates, and data boundary zones.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class PolicyDecision(str, Enum):
    """Decision returned by the policy engine for a tool call."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REDACT = "REDACT"
    APPROVE = "APPROVE"
    LOG = "LOG"


class ChainingMode(str, Enum):
    """Enforcement mode for skill chaining rules.

    CONTENT: Inspect tool response content and block only when data
             from a prior response appears in the current tool call's
             arguments (proves actual data flow).
    BLANKET: Block all calls to a target skill after the source skill
             has been called, regardless of argument content.
    """

    CONTENT = "content"
    BLANKET = "blanket"


class ViolationAction(str, Enum):
    """Action to take when a data boundary violation occurs."""

    BLOCK_AND_NOTIFY = "block_and_notify"
    BLOCK_AND_LOG = "block_and_log"
    LOG_ONLY = "log_only"


class ResourcePermissions(BaseModel):
    """Permissions for one resource within a skill.

    Handles two YAML forms:
      1. Shorthand denial:  `google_calendar: { denied: true }`
      2. Action dict:       `gmail: { read: true, send: false, filters: {...} }`

    In both cases, the model normalizes to `denied` + `actions` + `filters`.
    """

    denied: bool = False
    actions: dict[str, bool] = Field(default_factory=dict)
    filters: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def normalize_permissions(cls, data: Any) -> dict[str, Any]:
        """Parse the flexible YAML permission format into normalized fields."""
        if not isinstance(data, dict):
            msg = f"Resource permissions must be a mapping, got {type(data).__name__}"
            raise ValueError(msg)

        # If explicitly denied, nothing else matters
        if data.get("denied") is True:
            return {"denied": True, "actions": {}, "filters": {}}

        actions: dict[str, bool] = {}
        filters: dict[str, list[str]] = {}

        for key, value in data.items():
            if key == "denied":
                continue
            elif key == "filters":
                if not isinstance(value, dict):
                    msg = "filters must be a mapping"
                    raise ValueError(msg)
                for filter_name, filter_values in value.items():
                    if not isinstance(filter_values, list):
                        msg = f"Filter '{filter_name}' must be a list, got {type(filter_values).__name__}"
                        raise ValueError(msg)
                    filters[filter_name] = filter_values
            elif isinstance(value, bool):
                actions[key] = value
            else:
                # Sub-dict for nested permissions (e.g., modify: { own_events: true })
                # Flatten to dotted keys: modify.own_events = true
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                        if isinstance(sub_value, bool):
                            actions[f"{key}.{sub_key}"] = sub_value
                        else:
                            msg = (
                                f"Nested permission '{key}.{sub_key}' must be a bool, "
                                f"got {type(sub_value).__name__}"
                            )
                            raise ValueError(msg)
                else:
                    msg = (
                        f"Permission '{key}' must be a bool or mapping, "
                        f"got {type(value).__name__}"
                    )
                    raise ValueError(msg)

        return {"denied": False, "actions": actions, "filters": filters}

    def is_action_allowed(self, action: str) -> bool | None:
        """Check if a specific action is allowed.

        Args:
            action: The action name to check (e.g., "read", "send", "modify.own_events").

        Returns:
            True if explicitly allowed, False if explicitly denied or resource is denied,
            None if the action is not mentioned in the policy (unknown).
        """
        if self.denied:
            return False
        return self.actions.get(action)


class ChainingRule(BaseModel):
    """A rule controlling skill-to-skill invocation.

    Parsed from strings like:
      - "email-manager cannot trigger web-researcher"
      - "finance-tracker cannot trigger any other skill"
    """

    source_skill: str
    target_skill: str  # "any" means all other skills

    @model_validator(mode="before")
    @classmethod
    def parse_chaining_string(cls, data: Any) -> dict[str, str]:
        """Parse a chaining rule from its string representation."""
        if isinstance(data, dict):
            # Already structured
            if "source_skill" not in data or "target_skill" not in data:
                msg = "ChainingRule dict must have 'source_skill' and 'target_skill'"
                raise ValueError(msg)
            return data

        if not isinstance(data, str):
            msg = f"Chaining rule must be a string or dict, got {type(data).__name__}"
            raise ValueError(msg)

        rule_str = data.strip()

        # Parse: "<source> cannot trigger <target>"
        if " cannot trigger " not in rule_str:
            msg = (
                f"Cannot parse chaining rule: '{rule_str}'. "
                f"Expected format: '<skill> cannot trigger <skill>' "
                f"or '<skill> cannot trigger any other skill'"
            )
            raise ValueError(msg)

        parts = rule_str.split(" cannot trigger ", 1)
        source = parts[0].strip()
        target_raw = parts[1].strip()

        # Handle "any other skill" → "any"
        if target_raw in ("any other skill", "any"):
            target = "any"
        else:
            target = target_raw

        if not source:
            msg = f"Chaining rule source skill is empty: '{rule_str}'"
            raise ValueError(msg)
        if not target:
            msg = f"Chaining rule target skill is empty: '{rule_str}'"
            raise ValueError(msg)

        return {"source_skill": source, "target_skill": target}

    def blocks(self, source: str, target: str) -> bool:
        """Check if this rule blocks a specific skill chain.

        Args:
            source: The skill initiating the chain.
            target: The skill being triggered.

        Returns:
            True if this rule blocks the chain.
        """
        if self.source_skill != source:
            return False
        if self.target_skill == "any":
            return source != target  # "any other skill" — can still call itself
        return self.target_skill == target


class DataBoundary(BaseModel):
    """A data boundary zone for compliance enforcement.

    Defines which skills handle specific data classifications and what
    happens when data flows outside the boundary.
    """

    skills: list[str]
    classification: str
    rules: list[str] = Field(default_factory=list)
    on_violation: ViolationAction = ViolationAction.BLOCK_AND_LOG


class SensitiveContentConfig(BaseModel):
    """Configuration for the sensitive content classifier.

    Controls which data patterns are scanned in tool call arguments.
    When enabled, tool calls containing sensitive data (credit cards, SSNs,
    API keys, etc.) are blocked before reaching the agent runtime.
    """

    enabled: bool = True
    patterns: list[str] = Field(
        default_factory=lambda: [
            "credit_card",
            "ssn",
            "cvv",
            "expiry_date",
            "api_key",
        ],
        description="List of sensitive data pattern names to detect. "
        "Valid values: credit_card, ssn, cvv, expiry_date, api_key.",
    )


class ApprovalCondition(BaseModel):
    """A single condition on a tool argument value.

    Supports:
      - contains: argument string contains this substring
      - not_contains: argument string does NOT contain this substring
      - equals: argument value equals this exactly
      - matches: argument string matches this regex pattern
    """

    contains: str | None = None
    not_contains: str | None = None
    equals: Any | None = None
    matches: str | None = None

    @model_validator(mode="after")
    def at_least_one_condition(self) -> "ApprovalCondition":
        """Ensure at least one condition is set."""
        if all(
            v is None
            for v in (self.contains, self.not_contains, self.equals, self.matches)
        ):
            msg = (
                "Approval condition must specify at least one of: "
                "contains, not_contains, equals, matches"
            )
            raise ValueError(msg)
        return self

    def check(self, value: Any) -> bool:
        """Check if a value matches this condition.

        All specified sub-conditions must pass (AND logic).

        Args:
            value: The argument value to check.

        Returns:
            True if all conditions match.
        """
        import re

        str_value = str(value) if value is not None else ""

        if self.contains is not None and self.contains not in str_value:
            return False
        if self.not_contains is not None and self.not_contains in str_value:
            return False
        if self.equals is not None and value != self.equals:
            return False
        if self.matches is not None and not re.search(self.matches, str_value):
            return False
        return True


class ConditionalApproval(BaseModel):
    """A conditional approval rule: require approval only when conditions match.

    YAML format:
      - tool: gmail_send
        when:
          to:
            contains: "@external.com"

    If the tool name matches but the conditions don't match, the tool call
    proceeds without requiring approval.
    """

    tool: str
    when: dict[str, ApprovalCondition] = Field(default_factory=dict)

    def matches(self, tool_name: str, arguments: dict[str, Any] | None) -> bool:
        """Check if this rule applies to the given tool call.

        Args:
            tool_name: The MCP tool name.
            arguments: The tool call arguments.

        Returns:
            True if the tool name matches AND all conditions are satisfied.
        """
        if tool_name != self.tool:
            return False
        if not self.when:
            return True  # No conditions = always matches (same as plain string)
        if arguments is None:
            return False  # Has conditions but no arguments to check

        for arg_name, condition in self.when.items():
            arg_value = arguments.get(arg_name)
            if not condition.check(arg_value):
                return False
        return True


class ApprovalRule(BaseModel):
    """Union type for require_approval entries.

    Accepts either a plain string (tool name) or a dict with conditional rules.
    """

    tool_name: str | None = None
    conditional: ConditionalApproval | None = None

    @model_validator(mode="before")
    @classmethod
    def parse_approval_rule(cls, data: Any) -> dict[str, Any]:
        """Parse from string or dict."""
        if isinstance(data, str):
            return {"tool_name": data}
        if isinstance(data, dict):
            # Programmatic construction: ApprovalRule(tool_name="...")
            if "tool_name" in data:
                return data
            # YAML deserialization: {tool: "...", when: {...}}
            if "tool" in data:
                return {"conditional": data}
        msg = (
            f"Approval rule must be a tool name string or a dict with 'tool' key, "
            f"got {type(data).__name__}: {data!r}"
        )
        raise ValueError(msg)

    def __eq__(self, other: object) -> bool:
        """Support equality with plain strings for backward compatibility.

        This allows `"tool_name" in policy.require_approval` to work even
        though the list contains ApprovalRule objects.
        """
        if isinstance(other, str):
            return self.tool_name == other
        if isinstance(other, ApprovalRule):
            return (
                self.tool_name == other.tool_name
                and self.conditional == other.conditional
            )
        return NotImplemented

    def __hash__(self) -> int:
        """Hash by tool_name for set/dict compatibility."""
        return hash(self.tool_name)

    def matches(self, tool_name: str, arguments: dict[str, Any] | None) -> bool:
        """Check if this rule requires approval for the given tool call.

        Args:
            tool_name: The MCP tool name.
            arguments: The tool call arguments.

        Returns:
            True if approval is required.
        """
        if self.tool_name is not None:
            return tool_name == self.tool_name
        if self.conditional is not None:
            return self.conditional.matches(tool_name, arguments)
        return False


class DefaultAction(str, Enum):
    """Default action for tools that don't match any policy rule.

    ALLOW: Passthrough — unknown tools are allowed (default, minimizes breakage).
    BLOCK: Zero-trust — only explicitly allowed tools can execute.
    """

    ALLOW = "allow"
    BLOCK = "block"


class AgentWardPolicy(BaseModel):
    """Top-level policy model for agentward.yaml.

    All fields except `version` are optional to support progressive disclosure —
    users can start with just skill permissions and add chaining rules, approval
    gates, and data boundaries as needed.
    """

    version: str
    default_action: DefaultAction = DefaultAction.ALLOW
    skills: dict[str, dict[str, ResourcePermissions]] = Field(default_factory=dict)
    skill_chaining: list[ChainingRule] = Field(default_factory=list)
    chaining_mode: ChainingMode = ChainingMode.CONTENT
    skill_chain_depth: int | None = Field(
        default=None,
        description="Maximum number of consecutive skill-to-skill handoffs allowed "
        "in a single agent turn. When set, any chain exceeding this depth is blocked "
        "regardless of individual chaining rules. None means unlimited.",
    )
    require_approval: list[ApprovalRule] = Field(default_factory=list)
    approval_timeout: int = Field(
        default=60,
        description="Timeout in seconds for approval dialogs. "
        "If the user doesn't respond within this time, the tool call is denied.",
    )
    sensitive_content: SensitiveContentConfig = Field(
        default_factory=SensitiveContentConfig,
        description="Sensitive content classifier configuration.",
    )
    data_boundaries: dict[str, DataBoundary] = Field(default_factory=dict)
