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


class AgentWardPolicy(BaseModel):
    """Top-level policy model for agentward.yaml.

    All fields except `version` are optional to support progressive disclosure —
    users can start with just skill permissions and add chaining rules, approval
    gates, and data boundaries as needed.
    """

    version: str
    skills: dict[str, dict[str, ResourcePermissions]] = Field(default_factory=dict)
    skill_chaining: list[ChainingRule] = Field(default_factory=list)
    chaining_mode: ChainingMode = ChainingMode.CONTENT
    skill_chain_depth: int | None = Field(
        default=None,
        description="Maximum number of consecutive skill-to-skill handoffs allowed "
        "in a single agent turn. When set, any chain exceeding this depth is blocked "
        "regardless of individual chaining rules. None means unlimited.",
    )
    require_approval: list[str] = Field(default_factory=list)
    data_boundaries: dict[str, DataBoundary] = Field(default_factory=dict)
