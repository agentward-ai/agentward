"""GDPR compliance controls.

Covers key articles from the General Data Protection Regulation as they
apply to AI agent tool access policies:

- Art. 5(1)(c): Data Minimisation
- Art. 5(2): Accountability
- Art. 25: Data Protection by Design and by Default
- Art. 28: Processor Obligations
- Art. 30: Records of Processing Activities
- Art. 32(1): Security of Processing (integrity, confidentiality, transmission)

Each control is a ComplianceControl with a check function that inspects
the policy + scan to find gaps.
"""

from __future__ import annotations

from agentward.comply.controls import (
    ComplianceControl,
    ComplianceFinding,
    ControlSeverity,
    PolicyFix,
    SkillAnalysis,
    has_approval_for_skill,
    has_outbound_block_for_skill,
    has_write_restriction_for_skill,
)
from agentward.comply.frameworks import register_framework
from agentward.policy.schema import AgentWardPolicy, DefaultAction, ViolationAction
from agentward.scan.permissions import ScanResult


# -----------------------------------------------------------------------
# Check functions
# -----------------------------------------------------------------------


def _check_data_minimisation(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 5(1)(c) — Data Minimisation: personal data skills need explicit permissions.

    Personal data must be adequate, relevant, and limited to what is
    necessary.  Skills handling personal data must have explicit resource
    permissions — not rely on default_action: allow.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.personal_data_skills):
        if skill not in policy.skills:
            findings.append(ComplianceFinding(
                control_id="gdpr-art5.1c",
                skill=skill,
                description=(
                    f"Personal data skill '{skill}' has no explicit permissions in "
                    f"policy. GDPR Art. 5(1)(c) requires that personal data be "
                    f"limited to what is necessary (data minimisation). Add explicit "
                    f"resource permissions to enforce minimum necessary access."
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


def _check_data_protection_by_design(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 25 — Data Protection by Design: personal data skills need a data boundary.

    A data boundary with classification "personal_data" and a blocking
    violation action ensures personal data cannot leak outside designated skills.
    """
    findings: list[ComplianceFinding] = []

    # Find all skills covered by personal data boundaries with blocking actions
    covered_skills: set[str] = set()
    for _zone_name, boundary in policy.data_boundaries.items():
        if boundary.classification.lower() in ("personal_data", "pii", "gdpr"):
            if boundary.on_violation in (
                ViolationAction.BLOCK_AND_NOTIFY,
                ViolationAction.BLOCK_AND_LOG,
            ):
                covered_skills.update(boundary.skills)

    uncovered = sorted(analysis.personal_data_skills - covered_skills)
    for skill in uncovered:
        findings.append(ComplianceFinding(
            control_id="gdpr-art25",
            skill=skill,
            description=(
                f"Personal data skill '{skill}' is not covered by a data boundary "
                f"zone with a blocking violation action. GDPR Art. 25 requires "
                f"appropriate technical measures to implement data protection "
                f"principles by design and by default."
            ),
            fix=PolicyFix(
                fix_type="add_data_boundary",
                params={
                    "zone_name": "gdpr_zone",
                    "skills": [skill],
                    "classification": "personal_data",
                    "rules": ["personal_data cannot flow outside gdpr_zone"],
                    "on_violation": "block_and_log",
                },
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_records_of_processing(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 30 — Records of Processing Activities: sensitive content scanning.

    The classifier detects personal data patterns (SSNs, emails, etc.)
    in tool call arguments, providing an audit trail of processing activities.
    """
    findings: list[ComplianceFinding] = []

    if not policy.sensitive_content.enabled:
        findings.append(ComplianceFinding(
            control_id="gdpr-art30",
            skill=None,
            description=(
                "Sensitive content scanning is disabled. "
                "GDPR Art. 30 requires records of processing activities. "
                "Enable the sensitive content classifier to detect personal "
                "data in tool call arguments and maintain processing records."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["credit_card", "ssn", "api_key"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))
    elif "ssn" not in policy.sensitive_content.patterns:
        findings.append(ComplianceFinding(
            control_id="gdpr-art30",
            skill=None,
            description=(
                "SSN pattern is not enabled in sensitive content scanning. "
                "National identification numbers are personal data under GDPR "
                "and should be detected for processing records."
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
    """Art. 32(1) — Integrity of Processing: write-capable personal data skills.

    Write-capable personal data skills must either have write restricted
    in the policy or require human approval for write operations.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.personal_data_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        if not has_write_restriction_for_skill(policy, skill) \
                and not has_approval_for_skill(policy, skill):
            findings.append(ComplianceFinding(
                control_id="gdpr-art32.integrity",
                skill=skill,
                description=(
                    f"Personal data skill '{skill}' has write capability but no "
                    f"write restrictions or approval gates. GDPR Art. 32(1) requires "
                    f"the ability to ensure the ongoing integrity of processing "
                    f"systems and services."
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


def _check_confidentiality(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 32(1) — Confidentiality of Processing: approval for write operations.

    Tools that can write, send, or delete personal data must require
    human approval, ensuring a person authorizes the processing.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.personal_data_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        has_approval = has_approval_for_skill(policy, skill)

        if not has_approval:
            findings.append(ComplianceFinding(
                control_id="gdpr-art32.auth",
                skill=skill,
                description=(
                    f"Personal data skill '{skill}' has write/send/delete capability "
                    f"but does not require human approval. GDPR Art. 32(1) requires "
                    f"the ability to ensure the ongoing confidentiality of processing "
                    f"systems. Human approval gates provide accountability."
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
    """Art. 32(1) — Transmission Security: personal data skills with network access.

    Personal data skills with outbound network access must either block
    outbound or require approval, to prevent unauthorized data transfers
    (especially cross-border under GDPR Art. 44-49).
    """
    findings: list[ComplianceFinding] = []

    pd_with_network = sorted(analysis.personal_data_skills & analysis.network_skills)

    for skill in pd_with_network:
        if not has_outbound_block_for_skill(policy, skill) \
                and not has_approval_for_skill(policy, skill):
            findings.append(ComplianceFinding(
                control_id="gdpr-art32.transmission",
                skill=skill,
                description=(
                    f"Personal data skill '{skill}' has network access but no "
                    f"outbound restrictions or approval gates. GDPR Art. 32(1) "
                    f"requires appropriate security measures for data transmission. "
                    f"Unrestricted outbound access risks unauthorized cross-border "
                    f"data transfers (Art. 44-49)."
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


def _check_processor_isolation(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 28 — Processor Obligations: personal data skill isolation.

    Personal data skills must be isolated via chaining rules so they
    cannot trigger non-personal-data skills (prevents unauthorized
    processor-to-processor data flows).
    """
    findings: list[ComplianceFinding] = []

    non_pd_skills = analysis.all_skills - analysis.personal_data_skills

    for skill in sorted(analysis.personal_data_skills):
        blocked_targets: set[str] = set()
        blocks_any = False

        for rule in policy.skill_chaining:
            if rule.source_skill == skill:
                if rule.target_skill == "any":
                    blocks_any = True
                    break
                blocked_targets.add(rule.target_skill)

        if blocks_any:
            continue

        unblocked = sorted(non_pd_skills - blocked_targets)
        if unblocked and non_pd_skills:
            findings.append(ComplianceFinding(
                control_id="gdpr-art28",
                skill=skill,
                description=(
                    f"Personal data skill '{skill}' can trigger non-personal-data "
                    f"skill(s): {', '.join(unblocked[:5])}"
                    f"{'...' if len(unblocked) > 5 else ''}. "
                    f"GDPR Art. 28 requires that processors act only on documented "
                    f"instructions. Chaining rules prevent unauthorized data flows "
                    f"between processors."
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


def _check_accountability_default(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 5(2) — Accountability: default_action should be 'block'.

    While not strictly required, a zero-trust default demonstrates the
    accountability principle — the controller must be able to demonstrate
    compliance (Art. 5(2)).
    """
    findings: list[ComplianceFinding] = []

    if policy.default_action != DefaultAction.BLOCK:
        findings.append(ComplianceFinding(
            control_id="gdpr-art5.default",
            skill=None,
            description=(
                "default_action is 'allow' — unknown tools are permitted without "
                "policy rules. For GDPR environments, 'block' (zero-trust) is "
                "recommended to demonstrate the accountability principle (Art. 5(2))."
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

GDPR_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="gdpr-art5.1c",
        section="Art. 5(1)(c)",
        title="Data Minimisation",
        description="Personal data skills must have explicit minimal permissions.",
        severity=ControlSeverity.REQUIRED,
        check=_check_data_minimisation,
    ),
    ComplianceControl(
        control_id="gdpr-art25",
        section="Art. 25",
        title="Data Protection by Design",
        description="Personal data skills must be covered by a data boundary zone with blocking.",
        severity=ControlSeverity.REQUIRED,
        check=_check_data_protection_by_design,
    ),
    ComplianceControl(
        control_id="gdpr-art30",
        section="Art. 30",
        title="Records of Processing",
        description="Sensitive content scanning must be enabled for processing audit trail.",
        severity=ControlSeverity.REQUIRED,
        check=_check_records_of_processing,
    ),
    ComplianceControl(
        control_id="gdpr-art32.integrity",
        section="Art. 32(1)",
        title="Integrity of Processing",
        description="Personal data skills with write capability need write restrictions or approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_integrity,
    ),
    ComplianceControl(
        control_id="gdpr-art32.auth",
        section="Art. 32(1)",
        title="Confidentiality of Processing",
        description="Personal data tools with write/send/delete must require human approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_confidentiality,
    ),
    ComplianceControl(
        control_id="gdpr-art32.transmission",
        section="Art. 32(1)",
        title="Transmission Security",
        description="Personal data skills with network access must block outbound or require approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_transmission_security,
    ),
    ComplianceControl(
        control_id="gdpr-art28",
        section="Art. 28",
        title="Processor Obligations",
        description="Personal data skills must be isolated via chaining rules.",
        severity=ControlSeverity.REQUIRED,
        check=_check_processor_isolation,
    ),
    ComplianceControl(
        control_id="gdpr-art5.default",
        section="Art. 5(2)",
        title="Accountability Default",
        description="default_action should be 'block' for GDPR environments.",
        severity=ControlSeverity.RECOMMENDED,
        check=_check_accountability_default,
    ),
]

# Register on import
register_framework("gdpr", GDPR_CONTROLS)
