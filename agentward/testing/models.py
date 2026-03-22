"""Data models for AgentWard policy regression testing."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProbeCategory(str, Enum):
    """Attack categories covered by built-in probes."""

    PROTECTED_PATHS = "protected_paths"
    PROMPT_INJECTION = "prompt_injection"
    PATH_TRAVERSAL = "path_traversal"
    SCOPE_CREEP = "scope_creep"
    SKILL_CHAINING = "skill_chaining"
    BOUNDARY_VIOLATION = "boundary_violation"
    PII_INJECTION = "pii_injection"
    DESERIALIZATION = "deserialization"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ProbeSeverity(str, Enum):
    """Risk severity for a probe."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProbeOutcome(str, Enum):
    """Result of running a single probe."""

    PASS = "pass"   # actual decision matches expected
    FAIL = "fail"   # actual decision doesn't match (policy rule exists but is wrong)
    GAP = "gap"     # actual doesn't match because no policy rule covers the tool
    SKIP = "skip"   # probe skipped (required policy feature not present)


@dataclass
class Probe:
    """A single adversarial test case for policy regression testing.

    Probes are loaded from YAML files and describe a crafted tool call
    (or chaining attempt) together with the policy decision that a
    correctly-configured policy should produce.

    Two modes:
      - Regular tool call: set ``tool_name`` + ``arguments``
      - Skill chaining:   set ``chaining_source`` + ``chaining_target``
    """

    name: str
    category: str                          # ProbeCategory value
    severity: str                          # ProbeSeverity value
    description: str
    expected: str                          # PolicyDecision value (BLOCK, APPROVE, …)
    rationale: str = ""

    # Regular tool call probes
    tool_name: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)

    # Skill chaining probes (uses engine.evaluate_chaining)
    chaining_source: str | None = None
    chaining_target: str | None = None

    # When set, probe is skipped if that feature is absent from the policy.
    # Recognised values: skill_chaining, require_approval, sensitive_content,
    #                    data_boundaries, llm_judge
    requires_policy_feature: str | None = None

    # Populated by the loader; used to show origin in --list / verbose output
    source_file: str | None = None


@dataclass
class ProbeResult:
    """Result of running a single probe against the policy engine."""

    probe: Probe
    outcome: ProbeOutcome
    actual_decision: str | None = None    # PolicyDecision value
    actual_reason: str | None = None
    skip_reason: str | None = None
