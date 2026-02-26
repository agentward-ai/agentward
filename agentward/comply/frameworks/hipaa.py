"""HIPAA Security Rule compliance controls.

Covers Technical Safeguards (§164.312) and relevant Administrative
Safeguards (§164.308) as they apply to AI agent tool access policies.

Each control is a ComplianceControl with a check function that inspects
the policy + scan to find gaps.
"""

from __future__ import annotations

from agentward.comply.controls import (
    CheckFunction,
    ComplianceControl,
    ComplianceFinding,
    ControlSeverity,
    PolicyFix,
    SkillAnalysis,
)
from agentward.comply.frameworks import register_framework
from agentward.policy.schema import AgentWardPolicy, DefaultAction, ViolationAction
from agentward.scan.permissions import DataAccessType, ScanResult


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _has_approval_for_skill(policy: AgentWardPolicy, skill: str) -> bool:
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


# -----------------------------------------------------------------------
# Check functions
# -----------------------------------------------------------------------


def _check_access_control(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§164.312(a)(1) — Access Control: PHI skills must have explicit minimal permissions.

    Checks that every PHI skill has explicit resource permissions in the
    policy (not relying on default_action: allow to passthrough).
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.phi_skills):
        if skill not in policy.skills:
            findings.append(ComplianceFinding(
                control_id="hipaa-164.312.a.1",
                skill=skill,
                description=(
                    f"PHI skill '{skill}' has no explicit permissions in policy. "
                    f"HIPAA §164.312(a)(1) requires access controls that restrict "
                    f"access to ePHI to authorized users/processes."
                ),
                fix=PolicyFix(
                    fix_type="add_skill_restriction",
                    params={
                        "skill_name": skill,
                        "resource_name": skill,
                        "actions": {"read": True, "write": False, "delete": False},
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_data_boundary(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§164.312(a)(1) — PHI skills must be covered by a data boundary zone.

    A data boundary with classification "phi" and a blocking violation
    action ensures PHI cannot leak outside designated skills.
    """
    findings: list[ComplianceFinding] = []

    # Find all skills covered by PHI data boundaries with blocking actions
    covered_skills: set[str] = set()
    for _zone_name, boundary in policy.data_boundaries.items():
        if boundary.classification.lower() in ("phi", "protected_health_information"):
            if boundary.on_violation in (
                ViolationAction.BLOCK_AND_NOTIFY,
                ViolationAction.BLOCK_AND_LOG,
            ):
                covered_skills.update(boundary.skills)

    uncovered = sorted(analysis.phi_skills - covered_skills)
    for skill in uncovered:
        findings.append(ComplianceFinding(
            control_id="hipaa-164.312.a.1.boundary",
            skill=skill,
            description=(
                f"PHI skill '{skill}' is not covered by a data boundary zone "
                f"with a blocking violation action. "
                f"HIPAA §164.312(a)(1) requires mechanisms to restrict access to ePHI."
            ),
            fix=PolicyFix(
                fix_type="add_data_boundary",
                params={
                    "zone_name": "hipaa_zone",
                    "skills": [skill],
                    "classification": "phi",
                    "rules": ["phi_data cannot flow outside hipaa_zone"],
                    "on_violation": "block_and_log",
                },
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_audit_controls(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§164.312(b) — Audit Controls: Sensitive content scanning must be enabled.

    The classifier detects SSNs and other PHI patterns in tool call
    arguments, which serves as a compensating control for audit.
    """
    findings: list[ComplianceFinding] = []

    if not policy.sensitive_content.enabled:
        findings.append(ComplianceFinding(
            control_id="hipaa-164.312.b",
            skill=None,
            description=(
                "Sensitive content scanning is disabled. "
                "HIPAA §164.312(b) requires mechanisms that record and examine "
                "activity in systems containing ePHI. Enable the sensitive "
                "content classifier to detect PHI in tool call arguments."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["credit_card", "ssn", "api_key"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))
    elif "ssn" not in policy.sensitive_content.patterns:
        findings.append(ComplianceFinding(
            control_id="hipaa-164.312.b",
            skill=None,
            description=(
                "SSN pattern is not enabled in sensitive content scanning. "
                "SSNs are common PHI identifiers and should be detected."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["ssn"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_integrity(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§164.312(c)(1) — Integrity: PHI skills with write capability need controls.

    Write-capable PHI skills must either have write restricted in the
    policy or require human approval for write operations.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.phi_skills):
        # Check if write-capable from scan
        if not analysis.skill_write_capable.get(skill, False):
            continue

        # Check if policy restricts writes on this skill's own resource
        # Only the skill's own resource counts (not unrelated resources)
        has_write_restriction = False
        if skill in policy.skills:
            for resource_name, perms in policy.skills[skill].items():
                # Only restrictions on the skill's own resource count
                if resource_name != skill:
                    continue
                if perms.denied:
                    has_write_restriction = True
                    break
                write_val = perms.actions.get("write")
                delete_val = perms.actions.get("delete")
                # write: false is always a valid restriction
                if write_val is False:
                    has_write_restriction = True
                    break
                # delete: false counts unless write is explicitly True
                # (write: True + delete: False = partial, but write is allowed)
                if delete_val is False and write_val is not True:
                    has_write_restriction = True
                    break

        # Check if any approval rule covers this skill
        has_approval = _has_approval_for_skill(policy, skill)

        if not has_write_restriction and not has_approval:
            findings.append(ComplianceFinding(
                control_id="hipaa-164.312.c.1",
                skill=skill,
                description=(
                    f"PHI skill '{skill}' has write capability but no write "
                    f"restrictions or approval gates. HIPAA §164.312(c)(1) requires "
                    f"mechanisms to protect ePHI from improper alteration or destruction."
                ),
                fix=PolicyFix(
                    fix_type="add_skill_restriction",
                    params={
                        "skill_name": skill,
                        "resource_name": skill,
                        "actions": {"write": False, "delete": False},
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_authentication(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§164.312(d) — Person/Entity Authentication: PHI tools need approval.

    Tools that can write, send, or delete PHI must require human
    approval, authenticating that a person authorizes the action.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.phi_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        # Check if any approval rule covers this skill
        has_approval = _has_approval_for_skill(policy, skill)

        if not has_approval:
            findings.append(ComplianceFinding(
                control_id="hipaa-164.312.d",
                skill=skill,
                description=(
                    f"PHI skill '{skill}' has write/send/delete capability but "
                    f"does not require human approval. HIPAA §164.312(d) requires "
                    f"procedures to verify the identity of persons seeking access to ePHI."
                ),
                fix=PolicyFix(
                    fix_type="add_approval_rule",
                    params={"tool_name": skill},
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_transmission_security(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§164.312(e)(1) — Transmission Security: PHI skills with network access.

    PHI skills with outbound network access must either block outbound
    or require approval, to prevent unauthorized ePHI transmission.
    """
    findings: list[ComplianceFinding] = []

    phi_with_network = sorted(analysis.phi_skills & analysis.network_skills)

    for skill in phi_with_network:
        # Check if outbound is blocked in policy
        # Only network-related resources or the skill itself count
        has_outbound_block = False
        if skill in policy.skills:
            for resource_name, perms in policy.skills[skill].items():
                # Only network or skill's own resource count
                if resource_name not in ("network", skill):
                    continue
                # Check for explicit outbound restriction
                outbound = perms.actions.get("outbound")
                if outbound is False:
                    has_outbound_block = True
                    break
                # Denied on network resource or skill's own resource blocks outbound
                if perms.denied:
                    has_outbound_block = True
                    break

        # Check if any approval rule covers this skill
        has_approval = _has_approval_for_skill(policy, skill)

        if not has_outbound_block and not has_approval:
            findings.append(ComplianceFinding(
                control_id="hipaa-164.312.e.1",
                skill=skill,
                description=(
                    f"PHI skill '{skill}' has network access but no outbound "
                    f"restrictions or approval gates. HIPAA §164.312(e)(1) requires "
                    f"technical security measures to guard against unauthorized access "
                    f"to ePHI being transmitted over a network."
                ),
                fix=PolicyFix(
                    fix_type="add_skill_restriction",
                    params={
                        "skill_name": skill,
                        "resource_name": "network",
                        "actions": {"outbound": False},
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_isolation(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§164.308(a)(4) — Information Access Management: PHI skill isolation.

    PHI skills must be isolated via chaining rules so they cannot
    trigger non-PHI skills (prevents PHI leaking through chains).
    """
    findings: list[ComplianceFinding] = []

    non_phi_skills = analysis.all_skills - analysis.phi_skills

    for skill in sorted(analysis.phi_skills):
        # Check if there's a chaining rule blocking this skill from non-PHI targets
        blocked_targets: set[str] = set()
        blocks_any = False

        for rule in policy.skill_chaining:
            if rule.source_skill == skill:
                if rule.target_skill == "any":
                    blocks_any = True
                    break
                blocked_targets.add(rule.target_skill)

        if blocks_any:
            continue  # Fully isolated

        # Check if all non-PHI skills are individually blocked
        unblocked = sorted(non_phi_skills - blocked_targets)
        if unblocked and non_phi_skills:
            findings.append(ComplianceFinding(
                control_id="hipaa-164.308.a.4",
                skill=skill,
                description=(
                    f"PHI skill '{skill}' can trigger non-PHI skill(s): "
                    f"{', '.join(unblocked[:5])}"
                    f"{'...' if len(unblocked) > 5 else ''}. "
                    f"HIPAA §164.308(a)(4) requires policies and procedures for "
                    f"authorizing access to ePHI consistent with minimum necessary."
                ),
                fix=PolicyFix(
                    fix_type="add_chaining_rule",
                    params={
                        "source_skill": skill,
                        "target_skill": "any",
                    },
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_default_action(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Best Practice — default_action should be 'block' for HIPAA environments.

    While not strictly required by HIPAA, a zero-trust default (block
    unknown tools) significantly reduces the risk of unauthorized ePHI
    access through tools not covered by the policy.
    """
    findings: list[ComplianceFinding] = []

    if policy.default_action != DefaultAction.BLOCK:
        findings.append(ComplianceFinding(
            control_id="hipaa-default-action",
            skill=None,
            description=(
                "default_action is 'allow' — unknown tools are permitted without "
                "policy rules. For HIPAA environments, 'block' (zero-trust) is "
                "recommended to prevent unauthorized tool access."
            ),
            fix=PolicyFix(
                fix_type="set_default_action",
                params={"action": "block"},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


# -----------------------------------------------------------------------
# Control registry
# -----------------------------------------------------------------------

HIPAA_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="hipaa-164.312.a.1",
        section="§164.312(a)(1)",
        title="Access Control",
        description="PHI skills must have explicit minimal permissions.",
        severity=ControlSeverity.REQUIRED,
        check=_check_access_control,
    ),
    ComplianceControl(
        control_id="hipaa-164.312.a.1.boundary",
        section="§164.312(a)(1)",
        title="Data Boundary",
        description="PHI skills must be covered by a data boundary zone with blocking.",
        severity=ControlSeverity.REQUIRED,
        check=_check_data_boundary,
    ),
    ComplianceControl(
        control_id="hipaa-164.312.b",
        section="§164.312(b)",
        title="Audit Controls",
        description="Sensitive content scanning must be enabled with SSN detection.",
        severity=ControlSeverity.REQUIRED,
        check=_check_audit_controls,
    ),
    ComplianceControl(
        control_id="hipaa-164.312.c.1",
        section="§164.312(c)(1)",
        title="Integrity",
        description="PHI skills with write capability need write restrictions or approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_integrity,
    ),
    ComplianceControl(
        control_id="hipaa-164.312.d",
        section="§164.312(d)",
        title="Authentication",
        description="PHI tools with write/send/delete must require human approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_authentication,
    ),
    ComplianceControl(
        control_id="hipaa-164.312.e.1",
        section="§164.312(e)(1)",
        title="Transmission Security",
        description="PHI skills with network access must block outbound or require approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_transmission_security,
    ),
    ComplianceControl(
        control_id="hipaa-164.308.a.4",
        section="§164.308(a)(4)",
        title="Information Access Management",
        description="PHI skills must be isolated via chaining rules.",
        severity=ControlSeverity.REQUIRED,
        check=_check_isolation,
    ),
    ComplianceControl(
        control_id="hipaa-default-action",
        section="Best Practice",
        title="Zero-Trust Default",
        description="default_action should be 'block' for HIPAA environments.",
        severity=ControlSeverity.RECOMMENDED,
        check=_check_default_action,
    ),
]

# Register on import
register_framework("hipaa", HIPAA_CONTROLS)
