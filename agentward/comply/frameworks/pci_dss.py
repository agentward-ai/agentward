"""PCI-DSS v4.0 compliance controls.

Covers key requirements from the Payment Card Industry Data Security
Standard as they apply to AI agent tool access policies:

- Req. 1: Network Segmentation (cardholder data environment isolation)
- Req. 3: Protect Stored Data (write restrictions on cardholder skills)
- Req. 6: Secure Default (zero-trust default_action)
- Req. 7: Restrict Access (explicit permissions + data boundary)
- Req. 8: Identify and Authenticate (human approval for write ops)
- Req. 10: Log and Monitor (sensitive content scanning)

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


def _check_restrict_access(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Req. 7 — Restrict Access: cardholder data skills must have explicit permissions.

    Checks that every cardholder data skill has explicit resource
    permissions in the policy (not relying on default_action: allow).
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.cardholder_data_skills):
        if skill not in policy.skills:
            findings.append(ComplianceFinding(
                control_id="pci-req7",
                skill=skill,
                description=(
                    f"Cardholder data skill '{skill}' has no explicit permissions "
                    f"in policy. PCI-DSS Req. 7 requires that access to system "
                    f"components and cardholder data is limited to only those "
                    f"individuals whose job requires such access."
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
    """Req. 7 — Cardholder Data Environment: skills must be in a data boundary.

    A data boundary with classification "cardholder_data" and a blocking
    violation action defines the Cardholder Data Environment (CDE) boundary.
    """
    findings: list[ComplianceFinding] = []

    # Find all skills covered by cardholder data boundaries with blocking actions
    covered_skills: set[str] = set()
    for _zone_name, boundary in policy.data_boundaries.items():
        if boundary.classification.lower() in ("cardholder_data", "pci", "pci_dss"):
            if boundary.on_violation in (
                ViolationAction.BLOCK_AND_NOTIFY,
                ViolationAction.BLOCK_AND_LOG,
            ):
                covered_skills.update(boundary.skills)

    uncovered = sorted(analysis.cardholder_data_skills - covered_skills)
    for skill in uncovered:
        findings.append(ComplianceFinding(
            control_id="pci-req7.boundary",
            skill=skill,
            description=(
                f"Cardholder data skill '{skill}' is not covered by a data "
                f"boundary zone with a blocking violation action. PCI-DSS "
                f"Req. 7 requires defining a Cardholder Data Environment (CDE) "
                f"with access controls to restrict cardholder data flow."
            ),
            fix=PolicyFix(
                fix_type="add_data_boundary",
                params={
                    "zone_name": "pci_zone",
                    "skills": [skill],
                    "classification": "cardholder_data",
                    "rules": ["cardholder_data cannot flow outside pci_zone"],
                    "on_violation": "block_and_log",
                },
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_log_and_monitor(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Req. 10 — Log and Monitor: sensitive content scanning must be enabled.

    PCI-DSS requires logging mechanisms to track access to cardholder
    data. Both credit_card and cvv patterns must be enabled for full
    cardholder data detection.
    """
    findings: list[ComplianceFinding] = []

    if not policy.sensitive_content.enabled:
        findings.append(ComplianceFinding(
            control_id="pci-req10",
            skill=None,
            description=(
                "Sensitive content scanning is disabled. "
                "PCI-DSS Req. 10 requires logging mechanisms to track all "
                "access to network resources and cardholder data. Enable "
                "the sensitive content classifier to detect cardholder data "
                "in tool call arguments."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["credit_card", "cvv", "ssn", "api_key"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))
    else:
        missing: list[str] = []
        if "credit_card" not in policy.sensitive_content.patterns:
            missing.append("credit_card")
        if "cvv" not in policy.sensitive_content.patterns:
            missing.append("cvv")

        if missing:
            findings.append(ComplianceFinding(
                control_id="pci-req10",
                skill=None,
                description=(
                    f"Missing pattern(s) in sensitive content scanning: "
                    f"{', '.join(missing)}. PCI-DSS Req. 10 requires "
                    f"detection of cardholder data including card numbers "
                    f"and verification codes."
                ),
                fix=PolicyFix(
                    fix_type="enable_sensitive_content",
                    params={"patterns": missing},
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_protect_stored_data(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Req. 3 — Protect Stored Data: write-capable cardholder skills need controls.

    Write-capable cardholder data skills must either have write
    restricted in the policy or require human approval.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.cardholder_data_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        if not has_write_restriction_for_skill(policy, skill) \
                and not has_approval_for_skill(policy, skill):
            findings.append(ComplianceFinding(
                control_id="pci-req3",
                skill=skill,
                description=(
                    f"Cardholder data skill '{skill}' has write capability but "
                    f"no write restrictions or approval gates. PCI-DSS Req. 3 "
                    f"requires protection of stored cardholder data, including "
                    f"controls to prevent unauthorized modification."
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


def _check_authenticate(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Req. 8 — Identify and Authenticate: approval for cardholder write ops.

    Tools that can write, send, or delete cardholder data must require
    human approval, ensuring proper identification and authentication
    of users accessing cardholder data.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.cardholder_data_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        has_approval = has_approval_for_skill(policy, skill)

        if not has_approval:
            findings.append(ComplianceFinding(
                control_id="pci-req8",
                skill=skill,
                description=(
                    f"Cardholder data skill '{skill}' has write/send/delete "
                    f"capability but does not require human approval. PCI-DSS "
                    f"Req. 8 requires that access to system components is "
                    f"identified and authenticated."
                ),
                fix=PolicyFix(
                    fix_type="add_approval_rule",
                    params={"tool_name": skill},
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_network_segmentation(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Req. 1 — Network Segmentation: cardholder skills with network access.

    Cardholder data skills with outbound network access must either block
    outbound or require approval, to prevent unauthorized transmission
    of cardholder data outside the CDE.
    """
    findings: list[ComplianceFinding] = []

    cd_with_network = sorted(analysis.cardholder_data_skills & analysis.network_skills)

    for skill in cd_with_network:
        if not has_outbound_block_for_skill(policy, skill) \
                and not has_approval_for_skill(policy, skill):
            findings.append(ComplianceFinding(
                control_id="pci-req1",
                skill=skill,
                description=(
                    f"Cardholder data skill '{skill}' has network access but "
                    f"no outbound restrictions or approval gates. PCI-DSS "
                    f"Req. 1 requires network segmentation to isolate the "
                    f"Cardholder Data Environment (CDE) and restrict unauthorized "
                    f"network traffic."
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
    """Req. 7 — Least Privilege Isolation: cardholder skill chaining rules.

    Cardholder data skills must be isolated via chaining rules so they
    cannot trigger non-cardholder skills (prevents cardholder data
    leaking through skill chains).
    """
    findings: list[ComplianceFinding] = []

    non_cd_skills = analysis.all_skills - analysis.cardholder_data_skills

    for skill in sorted(analysis.cardholder_data_skills):
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

        unblocked = sorted(non_cd_skills - blocked_targets)
        if unblocked and non_cd_skills:
            findings.append(ComplianceFinding(
                control_id="pci-req7.isolation",
                skill=skill,
                description=(
                    f"Cardholder data skill '{skill}' can trigger non-cardholder "
                    f"skill(s): {', '.join(unblocked[:5])}"
                    f"{'...' if len(unblocked) > 5 else ''}. "
                    f"PCI-DSS Req. 7 requires least privilege access — "
                    f"cardholder data skills must be isolated to prevent "
                    f"unauthorized data flows."
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
    """Req. 6 — Secure Default: default_action should be 'block'.

    PCI-DSS Req. 6 requires secure development practices including
    secure default configurations. A zero-trust default prevents
    unauthorized tool access to cardholder data.
    """
    findings: list[ComplianceFinding] = []

    if policy.default_action != DefaultAction.BLOCK:
        findings.append(ComplianceFinding(
            control_id="pci-req6.default",
            skill=None,
            description=(
                "default_action is 'allow' — unknown tools are permitted without "
                "policy rules. For PCI-DSS environments, 'block' (zero-trust) is "
                "recommended per Req. 6 secure default configuration practices."
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

PCI_DSS_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="pci-req7",
        section="Req. 7",
        title="Restrict Access",
        description="Cardholder data skills must have explicit minimal permissions.",
        severity=ControlSeverity.REQUIRED,
        check=_check_restrict_access,
    ),
    ComplianceControl(
        control_id="pci-req7.boundary",
        section="Req. 7",
        title="Cardholder Data Environment",
        description="Cardholder data skills must be covered by a data boundary zone with blocking.",
        severity=ControlSeverity.REQUIRED,
        check=_check_data_boundary,
    ),
    ComplianceControl(
        control_id="pci-req10",
        section="Req. 10",
        title="Log and Monitor",
        description="Sensitive content scanning must be enabled with credit_card and cvv detection.",
        severity=ControlSeverity.REQUIRED,
        check=_check_log_and_monitor,
    ),
    ComplianceControl(
        control_id="pci-req3",
        section="Req. 3",
        title="Protect Stored Data",
        description="Cardholder data skills with write capability need write restrictions or approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_protect_stored_data,
    ),
    ComplianceControl(
        control_id="pci-req8",
        section="Req. 8",
        title="Identify and Authenticate",
        description="Cardholder data tools with write/send/delete must require human approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_authenticate,
    ),
    ComplianceControl(
        control_id="pci-req1",
        section="Req. 1",
        title="Network Segmentation",
        description="Cardholder data skills with network access must block outbound or require approval.",
        severity=ControlSeverity.REQUIRED,
        check=_check_network_segmentation,
    ),
    ComplianceControl(
        control_id="pci-req7.isolation",
        section="Req. 7",
        title="Least Privilege Isolation",
        description="Cardholder data skills must be isolated via chaining rules.",
        severity=ControlSeverity.REQUIRED,
        check=_check_isolation,
    ),
    ComplianceControl(
        control_id="pci-req6.default",
        section="Req. 6",
        title="Secure Default",
        description="default_action should be 'block' for PCI-DSS environments.",
        severity=ControlSeverity.RECOMMENDED,
        check=_check_default_action,
    ),
]

# Register on import
register_framework("pci-dss", PCI_DSS_CONTROLS)
