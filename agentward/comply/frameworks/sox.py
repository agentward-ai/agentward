"""SOX (Sarbanes-Oxley) Section 404 compliance controls.

Covers internal controls over financial reporting as they apply to
AI agent tool access policies:

- §404 Access Control: Financial skills need explicit permissions
- §404 Data Boundary: Financial skills covered by data boundary zones
- §404 Audit Trail: Sensitive content scanning for financial patterns
- §404 Integrity Controls: Write restrictions on financial skills
- §404 Authorization Controls: Human approval for financial write ops
- §404 Network Segregation: Outbound restrictions on financial skills
- §404 Segregation of Duties: Chaining isolation for financial skills
- §404 Zero-Trust Default: default_action should be 'block'

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


def _check_access_control(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§404 — Access Control: financial skills must have explicit minimal permissions.

    Checks that every financial skill has explicit resource permissions in
    the policy (not relying on default_action: allow to passthrough).
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.financial_skills):
        if skill not in policy.skills:
            findings.append(ComplianceFinding(
                control_id="sox-404.access",
                skill=skill,
                description=(
                    f"Financial skill '{skill}' has no explicit permissions in "
                    f"policy. SOX §404 requires internal controls over financial "
                    f"reporting, including access restrictions on systems that "
                    f"process financial data."
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
    """§404 — Data Boundary: financial skills must be covered by a data boundary zone.

    A data boundary with classification "financial" and a blocking violation
    action ensures financial data cannot leak outside designated skills.
    """
    findings: list[ComplianceFinding] = []

    # Find all skills covered by financial data boundaries with blocking actions
    covered_skills: set[str] = set()
    for _zone_name, boundary in policy.data_boundaries.items():
        if boundary.classification.lower() in ("financial", "sox"):
            if boundary.on_violation in (
                ViolationAction.BLOCK_AND_NOTIFY,
                ViolationAction.BLOCK_AND_LOG,
            ):
                covered_skills.update(boundary.skills)

    uncovered = sorted(analysis.financial_skills - covered_skills)
    for skill in uncovered:
        findings.append(ComplianceFinding(
            control_id="sox-404.boundary",
            skill=skill,
            description=(
                f"Financial skill '{skill}' is not covered by a data boundary "
                f"zone with a blocking violation action. SOX §404 requires "
                f"effective internal controls to prevent unauthorized access "
                f"to financial reporting systems."
            ),
            fix=PolicyFix(
                fix_type="add_data_boundary",
                params={
                    "zone_name": "sox_zone",
                    "skills": [skill],
                    "classification": "financial",
                    "rules": ["financial_data cannot flow outside sox_zone"],
                    "on_violation": "block_and_log",
                },
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_audit_trail(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§404 — Audit Trail: sensitive content scanning must be enabled.

    The classifier detects credit card numbers and other financial
    patterns in tool call arguments, providing an audit trail for
    financial data processing.
    """
    findings: list[ComplianceFinding] = []

    if not policy.sensitive_content.enabled:
        findings.append(ComplianceFinding(
            control_id="sox-404.audit",
            skill=None,
            description=(
                "Sensitive content scanning is disabled. "
                "SOX §404 requires adequate internal controls including "
                "audit trails for financial data processing. Enable the "
                "sensitive content classifier to detect financial data "
                "in tool call arguments."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["credit_card", "ssn", "api_key"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))
    elif "credit_card" not in policy.sensitive_content.patterns:
        findings.append(ComplianceFinding(
            control_id="sox-404.audit",
            skill=None,
            description=(
                "Credit card pattern is not enabled in sensitive content "
                "scanning. Financial account numbers should be detected "
                "for SOX audit trail compliance."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["credit_card"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_integrity(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§404 — Integrity Controls: write-capable financial skills need controls.

    Write-capable financial skills must either have write restricted in
    the policy or require human approval for write operations.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.financial_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        if not has_write_restriction_for_skill(policy, skill) \
                and not has_approval_for_skill(policy, skill):
            findings.append(ComplianceFinding(
                control_id="sox-404.integrity",
                skill=skill,
                description=(
                    f"Financial skill '{skill}' has write capability but no "
                    f"write restrictions or approval gates. SOX §404 requires "
                    f"internal controls to ensure the integrity of financial "
                    f"reporting data and prevent unauthorized modifications."
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


def _check_approval(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§404 — Authorization Controls: approval for financial write operations.

    Tools that can write, send, or delete financial data must require
    human approval, ensuring proper authorization of financial transactions.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.financial_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        has_approval = has_approval_for_skill(policy, skill)

        if not has_approval:
            findings.append(ComplianceFinding(
                control_id="sox-404.approval",
                skill=skill,
                description=(
                    f"Financial skill '{skill}' has write/send/delete capability "
                    f"but does not require human approval. SOX §404 requires "
                    f"proper authorization controls for financial transactions "
                    f"and data modifications."
                ),
                fix=PolicyFix(
                    fix_type="add_approval_rule",
                    params={"tool_name": skill},
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_network_segregation(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """§404 — Network Segregation: financial skills with network access.

    Financial skills with outbound network access must either block
    outbound or require approval, to prevent unauthorized data exfiltration
    of financial records.
    """
    findings: list[ComplianceFinding] = []

    fin_with_network = sorted(analysis.financial_skills & analysis.network_skills)

    for skill in fin_with_network:
        if not has_outbound_block_for_skill(policy, skill) \
                and not has_approval_for_skill(policy, skill):
            findings.append(ComplianceFinding(
                control_id="sox-404.network",
                skill=skill,
                description=(
                    f"Financial skill '{skill}' has network access but no "
                    f"outbound restrictions or approval gates. SOX §404 requires "
                    f"controls to prevent unauthorized transmission of financial "
                    f"data outside the organization."
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
    """§404 — Segregation of Duties: financial skill isolation.

    Financial skills must be isolated via chaining rules so they
    cannot trigger non-financial skills (prevents unauthorized
    data flows from financial systems).
    """
    findings: list[ComplianceFinding] = []

    non_fin_skills = analysis.all_skills - analysis.financial_skills

    for skill in sorted(analysis.financial_skills):
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

        unblocked = sorted(non_fin_skills - blocked_targets)
        if unblocked and non_fin_skills:
            findings.append(ComplianceFinding(
                control_id="sox-404.isolation",
                skill=skill,
                description=(
                    f"Financial skill '{skill}' can trigger non-financial "
                    f"skill(s): {', '.join(unblocked[:5])}"
                    f"{'...' if len(unblocked) > 5 else ''}. "
                    f"SOX §404 requires segregation of duties — financial "
                    f"processing skills must be isolated to prevent unauthorized "
                    f"data flows."
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
    """Best Practice — default_action should be 'block' for SOX environments.

    While not strictly required by SOX, a zero-trust default (block
    unknown tools) reduces the risk of unauthorized access to financial
    data through tools not covered by the policy.
    """
    findings: list[ComplianceFinding] = []

    if policy.default_action != DefaultAction.BLOCK:
        findings.append(ComplianceFinding(
            control_id="sox-404.default",
            skill=None,
            description=(
                "default_action is 'allow' — unknown tools are permitted without "
                "policy rules. For SOX environments, 'block' (zero-trust) is "
                "recommended to prevent unauthorized tool access to financial data."
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

SOX_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="sox-404.access",
        section="§404",
        title="Access Control",
        description="Financial skills must have explicit minimal permissions.",
        severity=ControlSeverity.REQUIRED,
        check=_check_access_control,
    ),
    ComplianceControl(
        control_id="sox-404.boundary",
        section="§404",
        title="Data Boundary",
        description="Financial skills must be covered by a data boundary zone with blocking.",
        severity=ControlSeverity.REQUIRED,
        check=_check_data_boundary,
    ),
    ComplianceControl(
        control_id="sox-404.audit",
        section="§404",
        title="Audit Trail",
        description="Sensitive content scanning must be enabled with credit card detection.",
        severity=ControlSeverity.REQUIRED,
        check=_check_audit_trail,
    ),
    ComplianceControl(
        control_id="sox-404.integrity",
        section="§404",
        title="Integrity Controls",
        description="Financial skills with write capability need write restrictions or approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_integrity,
    ),
    ComplianceControl(
        control_id="sox-404.approval",
        section="§404",
        title="Authorization Controls",
        description="Financial tools with write/send/delete must require human approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_approval,
    ),
    ComplianceControl(
        control_id="sox-404.network",
        section="§404",
        title="Network Segregation",
        description="Financial skills with network access must block outbound or require approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_network_segregation,
    ),
    ComplianceControl(
        control_id="sox-404.isolation",
        section="§404",
        title="Segregation of Duties",
        description="Financial skills must be isolated via chaining rules.",
        severity=ControlSeverity.REQUIRED,
        check=_check_isolation,
    ),
    ComplianceControl(
        control_id="sox-404.default",
        section="§404",
        title="Zero-Trust Default",
        description="default_action should be 'block' for SOX environments.",
        severity=ControlSeverity.RECOMMENDED,
        check=_check_default_action,
    ),
]

# Register on import
register_framework("sox", SOX_CONTROLS)
