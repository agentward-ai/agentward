"""Pydantic v2 models for AgentWard policy YAML.

Defines the complete schema for agentward.yaml, including skill permissions,
chaining rules, approval gates, and data boundary zones.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, PrivateAttr, model_validator


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


class SequenceAction(str, Enum):
    """Action to take when a sequence pattern matches."""

    BLOCK = "block"
    APPROVE = "approve"


class SequenceRule(BaseModel):
    """An ordered sequence pattern for multi-step chaining detection.

    Matches when the trailing skill call history ends with the given pattern.
    Pattern elements can be:
      - Literal skill name (e.g., "email-manager")
      - ``"any"`` — matches any single skill
      - ``"any_{classification}"`` — matches any skill in a data boundary zone
        with that classification (e.g., "any_financial" matches skills in zones
        with ``classification: "financial"``).

    YAML format::

        sequence_rules:
          - pattern: [email-manager, web-browser, shell-executor]
            action: block
          - pattern: [any_financial, any, any_financial]
            action: approve
    """

    pattern: list[str] = Field(min_length=2)
    action: SequenceAction = SequenceAction.BLOCK


class DataBoundary(BaseModel):
    """A data boundary zone for compliance enforcement.

    Defines which skills handle specific data classifications and what
    happens when data flows outside the boundary.
    """

    skills: list[str]
    classification: str
    rules: list[str] = Field(default_factory=list)
    on_violation: ViolationAction = ViolationAction.BLOCK_AND_LOG


class SensitiveContentAction(str, Enum):
    """Action to take when sensitive content is detected in tool arguments."""

    BLOCK = "block"
    REDACT = "redact"


class SensitiveContentConfig(BaseModel):
    """Configuration for the sensitive content classifier.

    Controls which data patterns are scanned in tool call arguments.
    When enabled, tool calls containing sensitive data (credit cards, SSNs,
    API keys, etc.) are blocked or redacted before reaching the agent runtime.
    """

    enabled: bool = True
    on_detection: SensitiveContentAction = SensitiveContentAction.BLOCK
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

    _compiled_regex: re.Pattern[str] | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def at_least_one_condition(self) -> "ApprovalCondition":
        """Ensure at least one condition is set and validate regex patterns."""
        if all(
            v is None
            for v in (self.contains, self.not_contains, self.equals, self.matches)
        ):
            msg = (
                "Approval condition must specify at least one of: "
                "contains, not_contains, equals, matches"
            )
            raise ValueError(msg)

        # Compile regex at load time — fail fast on invalid patterns
        # instead of crashing mid-session during proxy evaluation.
        if self.matches is not None:
            try:
                self._compiled_regex = re.compile(self.matches)
            except re.error as e:
                msg = (
                    f"Invalid regex pattern in 'matches': {self.matches!r} — {e}. "
                    f"Fix this pattern in your policy YAML."
                )
                raise ValueError(msg) from e

        return self

    def check(self, value: Any) -> bool:
        """Check if a value matches this condition.

        All specified sub-conditions must pass (AND logic).

        Args:
            value: The argument value to check.

        Returns:
            True if all conditions match.
        """
        str_value = str(value) if value is not None else ""

        if self.contains is not None and self.contains not in str_value:
            return False
        if self.not_contains is not None and self.not_contains in str_value:
            return False
        if self.equals is not None and value != self.equals:
            return False
        if self.matches is not None:
            pattern = self._compiled_regex
            if pattern is None:
                # Fallback: compile on the fly if validator was bypassed
                # (e.g., model_construct). Treat invalid patterns as non-match.
                try:
                    pattern = re.compile(self.matches)
                except re.error:
                    return False
            if not pattern.search(str_value):
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


class JudgeSensitivity(str, Enum):
    """How aggressively the LLM judge flags potential mismatches.

    LOW:    Only block/flag obvious contradictions (high confidence required).
            Minimises false positives; suited for informational tools.
    MEDIUM: Balanced threshold — flags suspicious patterns, blocks clear mismatches.
            Recommended default for most deployments.
    HIGH:   Flag anything ambiguous — suited for high-security contexts where
            false negatives (missed attacks) are worse than false positives.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# PolicyDecision values are uppercase ("ALLOW", "BLOCK", etc.) but YAML
# typically uses lowercase.  These are the LlmJudgeConfig fields that
# accept PolicyDecision values and must be normalised before validation.
_JUDGE_POLICY_DECISION_FIELDS = ("on_flag", "on_block", "on_timeout", "judge_on")


class LlmJudgeConfig(BaseModel):
    """Configuration for the LLM-as-judge intent analysis feature.

    When enabled, each tool call that passes the policy engine receives a
    second-opinion LLM call asking "do these arguments match what this tool
    claims to do?" — catching prompt injection, scope creep, and tools being
    used for undeclared purposes.

    This adds latency (one extra LLM call per tool invocation) and API cost,
    so it is opt-in via ``enabled: true``. Recommended for high-security
    deployments where semantic mismatches need to be caught.

    Example YAML::

        llm_judge:
          enabled: true
          provider: anthropic
          model: claude-haiku-4-5-20251001
          sensitivity: medium
          on_flag: log
          on_block: block
          cache_ttl: 300
    """

    enabled: bool = False
    provider: str = Field(
        default="anthropic",
        description="LLM provider for the judge call: 'anthropic' or 'openai'.",
    )
    model: str = Field(
        default="claude-haiku-4-5-20251001",
        description=(
            "Model ID to use for the judge call. "
            "Prefer fast, cheap models — haiku/gpt-4o-mini — since this runs per tool call."
        ),
    )
    api_key_env: str | None = Field(
        default=None,
        description=(
            "Environment variable containing the API key. "
            "Defaults to ANTHROPIC_API_KEY for Anthropic, OPENAI_API_KEY for OpenAI."
        ),
    )
    base_url: str | None = Field(
        default=None,
        description=(
            "Override the base URL for the LLM API. "
            "Defaults to the provider's standard endpoint."
        ),
    )
    timeout: float = Field(
        default=10.0,
        description="Seconds before a judge LLM call times out.",
    )
    sensitivity: JudgeSensitivity = Field(
        default=JudgeSensitivity.MEDIUM,
        description="How aggressively to flag potential mismatches.",
    )
    on_flag: PolicyDecision = Field(
        default=PolicyDecision.LOG,
        description=(
            "Decision when the judge flags a suspicious call (risk below block threshold). "
            "Default 'log' — proceed but record the suspicion in the audit trail."
        ),
    )
    on_block: PolicyDecision = Field(
        default=PolicyDecision.BLOCK,
        description=(
            "Decision when the judge says the call clearly contradicts the tool's purpose. "
            "Default 'block'."
        ),
    )
    on_timeout: PolicyDecision = Field(
        default=PolicyDecision.ALLOW,
        description=(
            "Decision when the judge LLM call times out or errors. "
            "Default 'allow' (fail-open) to avoid blocking legitimate calls on transient failures."
        ),
    )
    cache_ttl: int = Field(
        default=300,
        description=(
            "Seconds to cache judge decisions for identical tool+argument patterns. "
            "Set to 0 to disable caching. Caching skips the extra LLM call for "
            "repeated identical invocations."
        ),
    )
    cache_max_size: int = Field(
        default=1000,
        description="Maximum number of cached judge decisions (oldest evicted when full).",
    )
    judge_on: list[PolicyDecision] = Field(
        default_factory=lambda: [PolicyDecision.ALLOW],
        description=(
            "Base policy decisions that trigger the judge. "
            "Default [allow]: only second-opinion calls that passed the policy engine. "
            "Add 'log' to also judge LOG decisions."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def normalise_policy_decisions(cls, data: Any) -> Any:
        """Normalise lowercase YAML policy decision strings to uppercase.

        ``PolicyDecision`` enum values are uppercase (``"ALLOW"``, ``"BLOCK"``, …)
        but YAML authors naturally write lowercase.  This validator upper-cases
        the ``on_flag``, ``on_block``, ``on_timeout``, and ``judge_on`` fields
        so both casings are accepted.
        """
        if not isinstance(data, dict):
            return data
        result = dict(data)
        for field in _JUDGE_POLICY_DECISION_FIELDS:
            value = result.get(field)
            if isinstance(value, str):
                result[field] = value.upper()
            elif isinstance(value, list):
                result[field] = [
                    v.upper() if isinstance(v, str) else v for v in value
                ]
        return result


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
    sequence_rules: list[SequenceRule] = Field(
        default_factory=list,
        description="Ordered sequence patterns for multi-step chaining detection. "
        "Matches when the trailing skill history ends with the given pattern.",
    )
    llm_judge: LlmJudgeConfig = Field(
        default_factory=LlmJudgeConfig,
        description=(
            "LLM-as-judge intent analysis configuration. "
            "When enabled, uses a secondary LLM call to detect when a tool's "
            "actual arguments don't match its declared description/purpose."
        ),
    )
