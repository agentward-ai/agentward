"""DORA (Digital Operational Resilience Act, EU 2022/2554) compliance controls.

Maps AgentWard's existing technical controls to the operational provisions
of DORA that are enforceable through agent tool-call policy:

- Art. 5  — ICT risk management framework: governance baseline (zero-trust,
  third-party registry).
- Art. 9  — Protection and prevention: write-capable third-party services
  must be gated by approval or explicit restriction.
- Art. 10 — Detection: behavioral baseline / anomaly monitoring of
  third-party tool usage.
- Art. 17 — ICT-related incident management: structured audit trail (RFC
  5424 syslog) plus sensitive-content detection.
- Art. 28 — Management of ICT third-party risk: every third-party ICT
  service (each scanned MCP server / skill) must have an explicit policy
  entry, network exposure must be controlled, and inter-service chaining
  depth must be capped to limit concentration risk.

Scope notes
-----------
DORA is broader than data-classification frameworks (HIPAA, SOX, GDPR,
PCI-DSS).  Where those frameworks key off the *kind of data* a skill
handles, DORA keys off the *service relationship* — every proxied
MCP server or skill is treated as a third-party ICT service for the
purposes of these checks.

References
----------
* Regulation (EU) 2022/2554 — DORA primary text
* RTS on ICT risk management framework (Art. 15)
* RTS on classification of major ICT-related incidents (Art. 18)
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
from agentward.policy.schema import AgentWardPolicy, DefaultAction
from agentward.scan.permissions import ScanResult


# -----------------------------------------------------------------------
# Check functions
# -----------------------------------------------------------------------


def _check_governance(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 5 — ICT risk management: zero-trust default action.

    DORA Art. 5(2) requires a sound, comprehensive and well-documented ICT
    risk management framework.  A permissive default (allow unknown tools)
    is incompatible with that obligation.
    """
    findings: list[ComplianceFinding] = []

    if policy.default_action != DefaultAction.BLOCK:
        findings.append(ComplianceFinding(
            control_id="dora-art5.governance",
            skill=None,
            description=(
                "default_action is 'allow' — unknown tools and third-party "
                "ICT services are permitted without explicit policy. "
                "DORA Art. 5(2) requires a documented ICT risk management "
                "framework; a deny-by-default posture is the operational "
                "baseline for that obligation."
            ),
            fix=PolicyFix(
                fix_type="set_default_action",
                params={"action": "block"},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_third_party_registry(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 28 — ICT third-party risk: every third-party service inventoried.

    DORA Art. 28(3) and Art. 29 require financial entities to maintain a
    register of all contractual arrangements with ICT third-party service
    providers. Every scanned MCP server / skill counts as one such service
    and must therefore appear explicitly in the policy.
    """
    findings: list[ComplianceFinding] = []

    # Only meaningful when a scan is present — we need to know what
    # third-party services exist before we can require them in policy.
    if scan is None:
        return findings

    for skill in sorted(analysis.all_skills):
        # Skip policy-only skills (already in policy.skills by definition)
        if skill not in policy.skills:
            findings.append(ComplianceFinding(
                control_id="dora-art28.registry",
                skill=skill,
                description=(
                    f"Third-party ICT service '{skill}' has no explicit "
                    f"entry in the policy. DORA Art. 28 requires financial "
                    f"entities to maintain a register of ICT third-party "
                    f"service providers and to apply governance to each."
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


def _check_third_party_write_authorization(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 9 — Protection and prevention: gate write-capable third parties.

    DORA Art. 9(2)(b) requires entities to "implement strategies, policies,
    procedures, ICT protocols and tools that aim to […] guarantee security
    of […] data in use, in transit and at rest". Write-capable third-party
    services without restrictions or approval gates fail this requirement.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.all_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        if (
            not has_write_restriction_for_skill(policy, skill)
            and not has_approval_for_skill(policy, skill)
        ):
            findings.append(ComplianceFinding(
                control_id="dora-art9.write-control",
                skill=skill,
                description=(
                    f"Third-party ICT service '{skill}' has write capability "
                    f"but no write restrictions or approval gates. "
                    f"DORA Art. 9(2) requires controls that protect the "
                    f"security of data in use and at rest."
                ),
                fix=PolicyFix(
                    fix_type="add_approval_rule",
                    params={"tool_name": skill},
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_outbound_concentration(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 28 — Concentration risk on outbound network calls.

    DORA Art. 28(2) calls out concentration risk explicitly.  Third-party
    services with unrestricted outbound network access are the primary
    vector for that risk in an agent context — they can route data and
    actions to arbitrary external endpoints.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.network_skills):
        if (
            not has_outbound_block_for_skill(policy, skill)
            and not has_approval_for_skill(policy, skill)
        ):
            findings.append(ComplianceFinding(
                control_id="dora-art28.outbound",
                skill=skill,
                description=(
                    f"Third-party ICT service '{skill}' has outbound network "
                    f"access with no restrictions or approval gate. "
                    f"DORA Art. 28(2) requires entities to manage and "
                    f"monitor third-party concentration risk; uncontrolled "
                    f"outbound network is the primary concentration vector."
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


def _check_chain_depth_cap(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 28 — Cascading third-party risk: bound chain depth.

    Without a cap on consecutive skill-to-skill handoffs, a single
    compromised third-party service can drag the entire ICT estate into
    its blast radius.  DORA's third-party-risk obligations require entities
    to limit that propagation surface.
    """
    findings: list[ComplianceFinding] = []

    if policy.skill_chain_depth is None:
        findings.append(ComplianceFinding(
            control_id="dora-art28.chain-depth",
            skill=None,
            description=(
                "skill_chain_depth is unbounded — there is no cap on "
                "consecutive third-party service handoffs. DORA Art. 28 "
                "requires management of cascading and concentration risk "
                "across ICT third-party services. A bounded depth (e.g. "
                "skill_chain_depth: 3) limits how far one compromised "
                "service can propagate."
            ),
            fix=PolicyFix(
                fix_type="set_chain_depth",
                params={"depth": 3},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


def _check_incident_audit_trail(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 17 — Incident management: structured audit trail to SIEM.

    DORA Art. 17(1) requires an ICT-related incident management process
    that detects, manages and notifies incidents.  AgentWard's RFC 5424
    syslog output is the integration point for shipping every policy
    decision into the entity's SIEM / incident-response stack.
    """
    findings: list[ComplianceFinding] = []

    # The syslog file is auto-generated alongside any --log path, so the
    # only failing case at policy-time is a custom syslog_path that is
    # explicitly cleared. We check that audit.syslog_path is not the
    # empty string (None is fine — defaults to JSONL-with-.syslog suffix).
    if (
        policy.audit.syslog_path is not None
        and policy.audit.syslog_path.strip() == ""
    ):
        findings.append(ComplianceFinding(
            control_id="dora-art17.audit-trail",
            skill=None,
            description=(
                "audit.syslog_path is set to an empty string — the RFC 5424 "
                "syslog stream that DORA Art. 17 incident workflows depend "
                "on is disabled. Either remove the field (default) or set "
                "an explicit absolute path readable by your SIEM agent."
            ),
            fix=None,  # tactical: leave to operator to choose a path
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_incident_detection(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 17 — Incident detection: sensitive content scanning enabled.

    DORA Art. 17(3) requires entities to "establish appropriate procedures
    and processes to ensure a consistent and integrated monitoring,
    handling and follow-up of ICT-related incidents".  The sensitive-
    content classifier is one of AgentWard's monitoring primitives — it
    detects credentials, payment-card data and other indicators leaking
    into tool calls.
    """
    findings: list[ComplianceFinding] = []

    if not policy.sensitive_content.enabled:
        findings.append(ComplianceFinding(
            control_id="dora-art17.detection",
            skill=None,
            description=(
                "Sensitive content scanning is disabled. DORA Art. 17(3) "
                "requires consistent monitoring of ICT-related incidents; "
                "the sensitive-content classifier detects credentials and "
                "payment-card data in tool call arguments and is one of "
                "the supported monitoring primitives."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["credit_card", "ssn", "api_key"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))
    elif "api_key" not in policy.sensitive_content.patterns:
        findings.append(ComplianceFinding(
            control_id="dora-art17.detection",
            skill=None,
            description=(
                "API-key pattern is not enabled in sensitive content "
                "scanning. Credential leakage is a category of ICT-related "
                "incident under DORA Art. 17 and should be detected."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["api_key"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_anomaly_detection(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 10 — Detection: behavioral baseline / anomaly monitoring.

    DORA Art. 10(1) requires mechanisms to "promptly detect anomalous
    activities".  AgentWard ships a behavioral baseline check that
    compares each tool call against recorded baselines.  Enabling it is
    the recommended baseline detection control for DORA-scoped
    deployments.
    """
    findings: list[ComplianceFinding] = []

    if not policy.baseline_check:
        findings.append(ComplianceFinding(
            control_id="dora-art10.anomaly",
            skill=None,
            description=(
                "Behavioral baseline anomaly detection (baseline_check) is "
                "disabled. DORA Art. 10(1) requires mechanisms that "
                "promptly detect anomalous activities; AgentWard's baseline "
                "check is the recommended primitive. Note: enabling this "
                "requires recorded baselines — see `agentward baseline`."
            ),
            fix=PolicyFix(
                fix_type="set_policy_flag",
                params={"flag": "baseline_check", "value": True},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


def _check_unregistered_third_party_warning(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 28 — Surface calls to unregistered third-party services.

    DORA Art. 28(3) requires entities to know which ICT third-party
    services are in use.  ``warn_unregistered`` makes AgentWard emit a
    syslog warning whenever a tool call hits a server not present in the
    risk registry — that warning is the entity's signal that a new
    third-party relationship has appeared without governance.
    """
    findings: list[ComplianceFinding] = []

    if not policy.warn_unregistered:
        findings.append(ComplianceFinding(
            control_id="dora-art28.unregistered",
            skill=None,
            description=(
                "warn_unregistered is disabled — AgentWard will not emit "
                "an audit warning when a tool call hits a server outside "
                "the risk registry. DORA Art. 28 expects entities to know "
                "which third-party ICT services are actually in use."
            ),
            fix=PolicyFix(
                fix_type="set_policy_flag",
                params={"flag": "warn_unregistered", "value": True},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


# -----------------------------------------------------------------------
# Control registry
# -----------------------------------------------------------------------

DORA_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="dora-art5.governance",
        section="Art. 5",
        title="ICT Risk Management — Zero-Trust Default",
        description=(
            "default_action must be 'block' to satisfy the documented "
            "deny-by-default posture required for DORA Art. 5 governance."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_governance,
    ),
    ComplianceControl(
        control_id="dora-art28.registry",
        section="Art. 28",
        title="Third-Party Service Register",
        description=(
            "Every scanned third-party ICT service must have an explicit "
            "entry in the policy (DORA Art. 28 register obligation)."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_third_party_registry,
    ),
    ComplianceControl(
        control_id="dora-art9.write-control",
        section="Art. 9",
        title="Protection — Write-Capable Service Control",
        description=(
            "Write-capable third-party services must be gated by approval "
            "or by an explicit write restriction."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_third_party_write_authorization,
    ),
    ComplianceControl(
        control_id="dora-art28.outbound",
        section="Art. 28",
        title="Third-Party Concentration — Outbound Control",
        description=(
            "Network-capable third-party services must block outbound or "
            "require approval to bound concentration risk."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_outbound_concentration,
    ),
    ComplianceControl(
        control_id="dora-art17.audit-trail",
        section="Art. 17",
        title="Incident Management — Audit Trail",
        description=(
            "RFC 5424 syslog output must remain enabled so that ICT-related "
            "incidents can be ingested by the entity's SIEM."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_incident_audit_trail,
    ),
    ComplianceControl(
        control_id="dora-art17.detection",
        section="Art. 17",
        title="Incident Detection — Sensitive Content",
        description=(
            "Sensitive content scanning must be enabled with at least the "
            "API-key pattern for credential-leak detection."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_incident_detection,
    ),
    ComplianceControl(
        control_id="dora-art28.chain-depth",
        section="Art. 28",
        title="Cascading Third-Party Risk — Chain Depth",
        description=(
            "skill_chain_depth should be bounded to limit how far one "
            "compromised third-party service can propagate."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_chain_depth_cap,
    ),
    ComplianceControl(
        control_id="dora-art10.anomaly",
        section="Art. 10",
        title="Detection — Behavioral Baseline",
        description=(
            "Enable baseline_check for prompt detection of anomalous tool "
            "activity, the AgentWard primitive for DORA Art. 10."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_anomaly_detection,
    ),
    ComplianceControl(
        control_id="dora-art28.unregistered",
        section="Art. 28",
        title="Unregistered Third-Party Surfacing",
        description=(
            "warn_unregistered should be enabled so the SIEM is alerted "
            "whenever a tool call hits a server outside the risk registry."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_unregistered_third_party_warning,
    ),
]

# Register on import
register_framework("dora", DORA_CONTROLS)
