"""Core data models and evaluation engine for compliance checking.

Defines the control/finding/report data structures and the generic
evaluator that runs any framework's controls against a policy + scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalRule,
    ChainingRule,
    DataBoundary,
    DefaultAction,
    ResourcePermissions,
    SensitiveContentConfig,
    ViolationAction,
)
from agentward.scan.permissions import (
    DataAccessType,
    ScanResult,
    ServerPermissionMap,
    ToolPermission,
)


# -----------------------------------------------------------------------
# Enums
# -----------------------------------------------------------------------


class ComplianceRating(str, Enum):
    """Per-skill compliance rating."""

    GREEN = "green"    # Fully compliant
    YELLOW = "yellow"  # Has recommended (non-required) gaps
    RED = "red"        # Has required control failures


class ControlSeverity(str, Enum):
    """How critical a control is.

    REQUIRED: Failure → RED rating for affected skills.
    RECOMMENDED: Failure → YELLOW rating (best practice, not mandated).
    """

    REQUIRED = "required"
    RECOMMENDED = "recommended"


# -----------------------------------------------------------------------
# Data models
# -----------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyFix:
    """A declarative mutation instruction for auto-fixing a policy.

    fix_type determines what to mutate; params carries the specifics.
    The apply_fixes() function interprets these.
    """

    fix_type: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class ComplianceFinding:
    """A single compliance gap found during evaluation.

    Attributes:
        control_id: Which control produced this finding.
        skill: The skill name (or None for policy-level findings).
        description: Human-readable explanation of the gap.
        fix: Declarative fix instruction (None if no auto-fix available).
        severity: Inherited from the control.
    """

    control_id: str
    skill: str | None
    description: str
    fix: PolicyFix | None
    severity: ControlSeverity


# Type alias for check functions.
# Signature: (policy, scan, analysis) → list[ComplianceFinding]
CheckFunction = Callable[
    ["AgentWardPolicy", "ScanResult | None", "SkillAnalysis"],
    list[ComplianceFinding],
]


@dataclass
class ComplianceControl:
    """A single compliance control (check) within a framework.

    Attributes:
        control_id: Unique identifier (e.g., "hipaa-164.312.a.1").
        section: Regulatory section reference (e.g., "§164.312(a)(1)").
        title: Short title for display.
        description: What this control checks.
        severity: REQUIRED or RECOMMENDED.
        check: Function that evaluates the control against policy + scan.
    """

    control_id: str
    section: str
    title: str
    description: str
    severity: ControlSeverity
    check: CheckFunction


@dataclass
class SkillAnalysis:
    """Pre-computed analysis of skills from policy and scan data.

    Built once by build_skill_analysis() and passed to all control checks,
    so each check doesn't have to re-derive PHI/PII/financial skills.
    """

    phi_skills: set[str] = field(default_factory=set)
    pii_skills: set[str] = field(default_factory=set)
    personal_data_skills: set[str] = field(default_factory=set)
    financial_skills: set[str] = field(default_factory=set)
    cardholder_data_skills: set[str] = field(default_factory=set)
    network_skills: set[str] = field(default_factory=set)
    skill_data_types: dict[str, set[DataAccessType]] = field(default_factory=dict)
    skill_write_capable: dict[str, bool] = field(default_factory=dict)
    all_skills: set[str] = field(default_factory=set)


@dataclass
class ComplianceReport:
    """Complete compliance evaluation result.

    Attributes:
        framework: Which framework was evaluated (e.g., "hipaa").
        findings: All compliance gaps found.
        skill_ratings: Per-skill compliance rating (GREEN/YELLOW/RED).
        controls_checked: Total number of controls evaluated.
        controls_passed: Number of controls that produced no findings.
    """

    framework: str
    findings: list[ComplianceFinding] = field(default_factory=list)
    skill_ratings: dict[str, ComplianceRating] = field(default_factory=dict)
    controls_checked: int = 0
    controls_passed: int = 0


# -----------------------------------------------------------------------
# Heuristic patterns for PHI skill detection
# -----------------------------------------------------------------------

_PHI_NAME_PATTERNS = frozenset({
    "ehr", "clinical", "patient", "medical", "health", "hipaa",
    "diagnosis", "prescription", "lab", "pharmacy", "fhir", "hl7",
    "radiology", "pathology", "vitals", "chart", "encounter",
})


def _is_phi_by_name(skill_name: str) -> bool:
    """Check if a skill name heuristically suggests PHI handling."""
    lower = skill_name.lower()
    for pattern in _PHI_NAME_PATTERNS:
        if pattern in lower:
            return True
    return False


def _is_phi_by_data_access(data_types: set[DataAccessType]) -> bool:
    """Check if a skill's data access pattern suggests PHI handling.

    Heuristic: DATABASE + (EMAIL or NETWORK) is a common EHR pattern.
    """
    if DataAccessType.DATABASE in data_types:
        if DataAccessType.EMAIL in data_types or DataAccessType.NETWORK in data_types:
            return True
    return False


# -----------------------------------------------------------------------
# Heuristic patterns for personal data skill detection (GDPR)
# -----------------------------------------------------------------------

_PERSONAL_DATA_NAME_PATTERNS = frozenset({
    "user", "profile", "customer", "personal", "identity", "account",
    "contact", "crm", "gdpr", "consent", "subscriber", "member",
    "employee", "applicant", "tenant", "citizen", "resident",
})


def _is_personal_data_by_name(skill_name: str) -> bool:
    """Check if a skill name heuristically suggests personal data handling."""
    lower = skill_name.lower()
    for pattern in _PERSONAL_DATA_NAME_PATTERNS:
        if pattern in lower:
            return True
    return False


def _is_personal_data_by_data_access(data_types: set[DataAccessType]) -> bool:
    """Check if a skill's data access pattern suggests personal data handling.

    Heuristic: EMAIL or MESSAGING access implies personal data processing.
    """
    return DataAccessType.EMAIL in data_types or DataAccessType.MESSAGING in data_types


# -----------------------------------------------------------------------
# Heuristic patterns for financial skill detection (SOX)
# -----------------------------------------------------------------------

_FINANCIAL_NAME_PATTERNS = frozenset({
    "finance", "payment", "billing", "invoice", "ledger", "accounting",
    "treasury", "payroll", "expense", "revenue", "tax",
    "quickbooks", "xero", "stripe", "plaid", "banking",
})
# NOTE: "audit" intentionally excluded — too broad (matches "audit-logger").


def _is_financial_by_name(skill_name: str) -> bool:
    """Check if a skill name heuristically suggests financial data handling."""
    lower = skill_name.lower()
    for pattern in _FINANCIAL_NAME_PATTERNS:
        if pattern in lower:
            return True
    return False


# -----------------------------------------------------------------------
# Heuristic patterns for cardholder data skill detection (PCI-DSS)
# -----------------------------------------------------------------------

_CARDHOLDER_NAME_PATTERNS = frozenset({
    "payment", "checkout", "stripe", "braintree", "adyen", "square",
    "cardholder", "pci", "tokenize", "merchant",
})
# NOTE: "card" intentionally excluded — too broad (matches "flashcard-app").
# "cardholder" is specific enough for card-related payment skills.


def _is_cardholder_by_name(skill_name: str) -> bool:
    """Check if a skill name heuristically suggests cardholder data handling."""
    lower = skill_name.lower()
    for pattern in _CARDHOLDER_NAME_PATTERNS:
        if pattern in lower:
            return True
    return False


def _is_cardholder_by_data_access(data_types: set[DataAccessType]) -> bool:
    """Check if a skill's data access pattern suggests cardholder data handling.

    Heuristic: FINANCIAL + NETWORK is a common payment processing pattern.
    """
    return DataAccessType.FINANCIAL in data_types and DataAccessType.NETWORK in data_types


# -----------------------------------------------------------------------
# Shared helpers for framework check functions
# -----------------------------------------------------------------------


def has_approval_for_skill(policy: AgentWardPolicy, skill: str) -> bool:
    """Check if any approval rule covers the given skill by name.

    Unlike ``rule.matches(skill, None)``, this also recognizes conditional
    approval rules whose ``tool`` field matches the skill, regardless of
    whether the argument conditions can be evaluated.  For compliance
    purposes, having *any* approval gate on a skill counts.
    """
    for rule in policy.require_approval:
        # Simple (non-conditional) rule: exact tool_name match
        if rule.tool_name is not None and rule.tool_name == skill:
            return True
        # Conditional rule: tool field match is sufficient for compliance
        if rule.conditional is not None and rule.conditional.tool == skill:
            return True
    return False


def has_write_restriction_for_skill(policy: AgentWardPolicy, skill: str) -> bool:
    """Check if the policy restricts writes on a skill's own resource.

    Looks for write restrictions on the resource matching the skill name.
    Restrictions on unrelated resources do NOT count.

    Counts as restricted if any of:
    - The resource is ``denied: true``
    - ``write: false`` is set explicitly
    - ``delete: false`` is set AND ``write`` is not explicitly ``true``
    """
    if skill not in policy.skills:
        return False
    for resource_name, perms in policy.skills[skill].items():
        if resource_name != skill:
            continue
        if perms.denied:
            return True
        write_val = perms.actions.get("write")
        delete_val = perms.actions.get("delete")
        if write_val is False:
            return True
        if delete_val is False and write_val is not True:
            return True
    return False


def has_outbound_block_for_skill(policy: AgentWardPolicy, skill: str) -> bool:
    """Check if the policy blocks outbound network for a skill.

    Looks for outbound restrictions on either the ``network`` resource
    or the skill's own resource name.
    """
    if skill not in policy.skills:
        return False
    for resource_name, perms in policy.skills[skill].items():
        if resource_name not in ("network", skill):
            continue
        outbound = perms.actions.get("outbound")
        if outbound is False:
            return True
        if perms.denied:
            return True
    return False


# -----------------------------------------------------------------------
# build_skill_analysis
# -----------------------------------------------------------------------


def build_skill_analysis(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
) -> SkillAnalysis:
    """Pre-compute skill classifications from policy and scan data.

    Merges two sources:
    1. Scan results (heuristic): skill names, data access patterns.
    2. Policy (explicit): data_boundaries with classification matching
       framework-specific categories (e.g., "phi", "personal_data").

    Args:
        policy: The loaded AgentWard policy.
        scan: Scan results (may be None if scan wasn't run).

    Returns:
        A SkillAnalysis with all computed skill sets.
    """
    analysis = SkillAnalysis()

    # --- From scan results ---
    if scan is not None:
        for server_map in scan.servers:
            skill_name = server_map.server.name
            analysis.all_skills.add(skill_name)

            data_types: set[DataAccessType] = set()
            has_writes = False

            for tool_perm in server_map.tools:
                for access in tool_perm.data_access:
                    data_types.add(access.type)
                    if access.write:
                        has_writes = True

            analysis.skill_data_types[skill_name] = data_types
            analysis.skill_write_capable[skill_name] = has_writes

            # PHI detection from scan
            if _is_phi_by_name(skill_name) or _is_phi_by_data_access(data_types):
                analysis.phi_skills.add(skill_name)

            # Network detection
            if DataAccessType.NETWORK in data_types:
                analysis.network_skills.add(skill_name)

            # Financial detection (SOX)
            if (
                DataAccessType.FINANCIAL in data_types
                or _is_financial_by_name(skill_name)
            ):
                analysis.financial_skills.add(skill_name)

            # Cardholder data detection (PCI-DSS)
            if (
                _is_cardholder_by_name(skill_name)
                or _is_cardholder_by_data_access(data_types)
            ):
                analysis.cardholder_data_skills.add(skill_name)

            # PII detection (email or messaging implies PII handling)
            if DataAccessType.EMAIL in data_types or DataAccessType.MESSAGING in data_types:
                analysis.pii_skills.add(skill_name)

            # Personal data detection (GDPR) from scan
            if (
                _is_personal_data_by_name(skill_name)
                or _is_personal_data_by_data_access(data_types)
            ):
                analysis.personal_data_skills.add(skill_name)

    # --- From policy data_boundaries ---
    for _zone_name, boundary in policy.data_boundaries.items():
        classification = boundary.classification.lower()
        if classification in ("phi", "protected_health_information"):
            for skill in boundary.skills:
                analysis.phi_skills.add(skill)
                analysis.all_skills.add(skill)
                # PHI skills without scan data: assume write-capable
                # (fail-closed for compliance — if we can't prove it's
                # read-only, treat it as write-capable)
                if skill not in analysis.skill_write_capable:
                    analysis.skill_write_capable[skill] = True
        if classification in ("personal_data", "pii", "gdpr"):
            for skill in boundary.skills:
                analysis.personal_data_skills.add(skill)
                analysis.all_skills.add(skill)
                # Personal data skills without scan data: assume write-capable
                if skill not in analysis.skill_write_capable:
                    analysis.skill_write_capable[skill] = True
        if classification in ("financial", "sox"):
            for skill in boundary.skills:
                analysis.financial_skills.add(skill)
                analysis.all_skills.add(skill)
                if skill not in analysis.skill_write_capable:
                    analysis.skill_write_capable[skill] = True
        if classification in ("cardholder_data", "pci", "pci_dss"):
            for skill in boundary.skills:
                analysis.cardholder_data_skills.add(skill)
                analysis.all_skills.add(skill)
                if skill not in analysis.skill_write_capable:
                    analysis.skill_write_capable[skill] = True

    # --- From policy skills section ---
    for skill_name in policy.skills:
        analysis.all_skills.add(skill_name)

    return analysis


# -----------------------------------------------------------------------
# evaluate_compliance
# -----------------------------------------------------------------------


def evaluate_compliance(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    controls: list[ComplianceControl],
    framework: str,
) -> ComplianceReport:
    """Run all controls against a policy and produce a compliance report.

    Args:
        policy: The loaded AgentWard policy.
        scan: Scan results (may be None).
        controls: List of ComplianceControl objects from the framework.
        framework: Framework name for the report.

    Returns:
        A ComplianceReport with findings and per-skill ratings.
    """
    analysis = build_skill_analysis(policy, scan)
    all_findings: list[ComplianceFinding] = []
    controls_passed = 0

    for control in controls:
        findings = control.check(policy, scan, analysis)
        if findings:
            all_findings.extend(findings)
        else:
            controls_passed += 1

    # Compute per-skill ratings
    skill_ratings: dict[str, ComplianceRating] = {}

    # Start all skills as GREEN
    for skill in analysis.all_skills:
        skill_ratings[skill] = ComplianceRating.GREEN

    # Downgrade based on findings
    for finding in all_findings:
        if finding.skill is None:
            continue  # Policy-level finding, not skill-specific
        if finding.skill not in skill_ratings:
            skill_ratings[finding.skill] = ComplianceRating.GREEN

        if finding.severity == ControlSeverity.REQUIRED:
            skill_ratings[finding.skill] = ComplianceRating.RED
        elif finding.severity == ControlSeverity.RECOMMENDED:
            if skill_ratings[finding.skill] != ComplianceRating.RED:
                skill_ratings[finding.skill] = ComplianceRating.YELLOW

    return ComplianceReport(
        framework=framework,
        findings=all_findings,
        skill_ratings=skill_ratings,
        controls_checked=len(controls),
        controls_passed=controls_passed,
    )


# -----------------------------------------------------------------------
# apply_fixes
# -----------------------------------------------------------------------

# Violation action strictness ordering (higher = stricter)
_VIOLATION_SEVERITY: dict[ViolationAction, int] = {
    ViolationAction.LOG_ONLY: 0,
    ViolationAction.BLOCK_AND_LOG: 1,
    ViolationAction.BLOCK_AND_NOTIFY: 2,
}


def apply_fixes(
    policy: AgentWardPolicy,
    findings: list[ComplianceFinding],
) -> AgentWardPolicy:
    """Deep-copy a policy and apply all declarative fixes from findings.

    Fix types:
    - set_default_action: Set policy.default_action.
    - add_approval_rule: Add a tool to require_approval (if not present).
    - add_chaining_rule: Add a skill chaining rule (if not present).
    - add_data_boundary: Add or merge a data_boundary zone.
    - enable_sensitive_content: Enable sensitive_content scanning + patterns.
    - add_skill_restriction: Add/modify skill resource permissions.

    Args:
        policy: The original policy (not mutated).
        findings: Findings with fix instructions.

    Returns:
        A new AgentWardPolicy with all fixes applied.
    """
    # Deep copy via model serialization to avoid shared mutable references
    fixed = policy.model_copy(deep=True)

    for finding in findings:
        if finding.fix is None:
            continue
        _apply_single_fix(fixed, finding.fix)

    return fixed


def _apply_single_fix(policy: AgentWardPolicy, fix: PolicyFix) -> None:
    """Apply a single PolicyFix mutation to a policy (in place).

    Args:
        policy: The policy to mutate.
        fix: The fix to apply.
    """
    if fix.fix_type == "set_default_action":
        action = fix.params.get("action", "block")
        policy.default_action = DefaultAction(action)

    elif fix.fix_type == "add_approval_rule":
        tool_name = fix.params["tool_name"]
        # Check if already present
        existing_names = {
            r.tool_name for r in policy.require_approval if r.tool_name is not None
        }
        if tool_name not in existing_names:
            policy.require_approval.append(ApprovalRule(tool_name=tool_name))

    elif fix.fix_type == "add_chaining_rule":
        source = fix.params["source_skill"]
        target = fix.params["target_skill"]
        # Check if already present
        existing = {
            (r.source_skill, r.target_skill) for r in policy.skill_chaining
        }
        if (source, target) not in existing:
            policy.skill_chaining.append(
                ChainingRule(source_skill=source, target_skill=target)
            )

    elif fix.fix_type == "add_data_boundary":
        zone_name = fix.params["zone_name"]
        skills = fix.params.get("skills", [])
        classification = fix.params.get("classification", "phi")
        rules = fix.params.get("rules", [])
        on_violation = fix.params.get("on_violation", "block_and_log")

        if zone_name in policy.data_boundaries:
            # Merge: add skills that aren't already listed
            existing = policy.data_boundaries[zone_name]
            for skill in skills:
                if skill not in existing.skills:
                    existing.skills.append(skill)
            # Upgrade on_violation if the fix requests a stricter action
            requested_action = ViolationAction(on_violation)
            if _VIOLATION_SEVERITY[requested_action] > _VIOLATION_SEVERITY[existing.on_violation]:
                existing.on_violation = requested_action
        else:
            policy.data_boundaries[zone_name] = DataBoundary(
                skills=skills,
                classification=classification,
                rules=rules,
                on_violation=ViolationAction(on_violation),
            )

    elif fix.fix_type == "enable_sensitive_content":
        policy.sensitive_content.enabled = True
        patterns_to_add = fix.params.get("patterns", [])
        for pattern in patterns_to_add:
            if pattern not in policy.sensitive_content.patterns:
                policy.sensitive_content.patterns.append(pattern)

    elif fix.fix_type == "add_skill_restriction":
        skill_name = fix.params["skill_name"]
        resource_name = fix.params["resource_name"]
        actions = fix.params.get("actions", {})

        if skill_name not in policy.skills:
            policy.skills[skill_name] = {}

        if resource_name not in policy.skills[skill_name]:
            policy.skills[skill_name][resource_name] = (
                ResourcePermissions.model_construct(
                    denied=False, actions=dict(actions), filters={},
                )
            )
        else:
            # Merge: add new actions, and for existing actions enforce
            # the stricter value (False overrides True for compliance)
            existing = policy.skills[skill_name][resource_name]
            for action_name, allowed in actions.items():
                if action_name not in existing.actions:
                    existing.actions[action_name] = allowed
                elif existing.actions[action_name] is True and allowed is False:
                    # Compliance fix: restriction (False) overrides permission (True)
                    existing.actions[action_name] = allowed

    else:
        msg = (
            f"Unknown fix_type '{fix.fix_type}'. Valid types: "
            f"set_default_action, add_approval_rule, add_chaining_rule, "
            f"add_data_boundary, enable_sensitive_content, add_skill_restriction."
        )
        raise ValueError(msg)
