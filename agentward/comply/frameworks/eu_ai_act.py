"""EU AI Act (Regulation (EU) 2024/1689) compliance controls.

Maps AgentWard's existing technical controls to the operational
provisions of the EU AI Act that are enforceable through agent
tool-call policy. This is a focused subset — the AI Act has 113
articles plus annexes, of which only a small set translate into
runtime controls a permission proxy can verify.

Articles covered
----------------
- Art. 9   — Risk management system: documented governance baseline
  (zero-trust default action) for AI systems in production.
- Art. 12  — Record-keeping: structured audit trail (RFC 5424 syslog
  output) plus sensitive-content detection in tool arguments.
- Art. 13  — Transparency and provision of information: registry of
  AI components / third-party tools.
- Art. 14  — Human oversight: write-capable and network-capable
  components must be gated by approval or explicit restriction.
- Art. 15  — Accuracy, robustness, cybersecurity: behavioral baseline
  monitoring as the runtime anomaly-detection primitive.
- Art. 25  — Provider / value-chain disclosure: each AI component has
  an accountable owner and a documented subcontractor chain in
  skill_metadata.

Scope notes
-----------
The EU AI Act's most stringent obligations apply to "high-risk AI
systems" listed in Annex III (credit scoring, employment, critical
infrastructure, law enforcement, etc.). A trading agent at a market
maker is not necessarily Annex-III high-risk. However, the *discipline*
described in Articles 9, 12, 13, 14, and 15 is what auditors increasingly
expect any production AI system to follow, and what regulators have
signalled as the de facto baseline.

This framework therefore evaluates AgentWard's policy against that
discipline, not against a specific risk classification. Operators
deploying high-risk AI systems should treat these controls as a floor,
not a ceiling.

References
----------
* Regulation (EU) 2024/1689 — primary text (Articles 9–15, 26)
* Annex IV — technical documentation requirements
* Commission Implementing Regulation expected mid-2026 with
  template forms for the technical-documentation file
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


def _check_risk_management(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 9 — Risk management system: zero-trust default action.

    Art. 9(2) requires "establishment, implementation, documentation
    and maintenance of a risk management system" for high-risk AI.
    A permissive default ("allow unknown tools") is incompatible with
    the documented deny-by-default posture this implies.
    """
    findings: list[ComplianceFinding] = []

    if policy.default_action != DefaultAction.BLOCK:
        findings.append(ComplianceFinding(
            control_id="eu-ai-act.art9-risk-management",
            skill=None,
            description=(
                "default_action is 'allow' — unknown tools and AI "
                "components are permitted without explicit policy. "
                "EU AI Act Art. 9(2) requires a documented risk "
                "management system; a deny-by-default posture is the "
                "operational baseline for that obligation."
            ),
            fix=PolicyFix(
                fix_type="set_default_action",
                params={"action": "block"},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_record_keeping(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 12 — Record-keeping: structured audit trail availability.

    Art. 12(1) requires high-risk AI systems to "technically allow for
    the automatic recording of events ('logs') over the lifetime of the
    system". AgentWard's RFC 5424 syslog file is the integration point
    for shipping every policy decision into the deployer's archival
    stack — fires only when the syslog path is explicitly cleared.
    """
    findings: list[ComplianceFinding] = []

    if (
        policy.audit.syslog_path is not None
        and policy.audit.syslog_path.strip() == ""
    ):
        findings.append(ComplianceFinding(
            control_id="eu-ai-act.art12-record-keeping",
            skill=None,
            description=(
                "audit.syslog_path is set to an empty string — the "
                "RFC 5424 syslog stream that EU AI Act Art. 12 "
                "automatic logging depends on is disabled. Either "
                "remove the field (default) or set an absolute path "
                "readable by your archival agent."
            ),
            fix=None,
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_sensitive_content_detection(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 12 — Record-keeping: detect sensitive content in inputs.

    Art. 12(2)(a) requires logging that enables "identification of
    situations that may result in the AI system presenting a risk".
    The sensitive-content classifier flags credentials, payment-card
    data, and PII in tool-call arguments — a category of risk-relevant
    event that must be recorded.
    """
    findings: list[ComplianceFinding] = []

    if not policy.sensitive_content.enabled:
        findings.append(ComplianceFinding(
            control_id="eu-ai-act.art12-detection",
            skill=None,
            description=(
                "Sensitive content scanning is disabled. EU AI Act "
                "Art. 12(2) requires logging mechanisms that enable "
                "identification of risk-relevant situations; the "
                "sensitive-content classifier detects credentials and "
                "PII in tool call arguments and is the recommended "
                "policy-layer primitive."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["api_key", "credit_card", "ssn"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_transparency(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 13 — Transparency: registry awareness.

    Art. 13(1) requires high-risk AI systems to be "designed and
    developed in such a way to ensure that their operation is
    sufficiently transparent". The MCP risk registry cross-reference,
    when enabled, surfaces known risk metadata for every server a tool
    call hits — a transparency primitive at runtime.
    """
    findings: list[ComplianceFinding] = []

    if not policy.registry_check:
        findings.append(ComplianceFinding(
            control_id="eu-ai-act.art13-transparency",
            skill=None,
            description=(
                "registry_check is disabled — AgentWard will not "
                "cross-reference tool servers against the built-in MCP "
                "risk registry. EU AI Act Art. 13 requires sufficient "
                "operational transparency; surfacing known-risk metadata "
                "in the audit stream is the runtime primitive."
            ),
            fix=PolicyFix(
                fix_type="set_policy_flag",
                params={"flag": "registry_check", "value": True},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


def _check_human_oversight_write(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 14 — Human oversight: gate write-capable components.

    Art. 14(1) requires high-risk AI systems to be "designed and
    developed in such a way, including with appropriate human-machine
    interface tools, that they can be effectively overseen by natural
    persons during the period in which the AI system is in use".

    Write-capable tool calls without an approval gate or explicit
    write restriction execute autonomously without human oversight.
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
                control_id="eu-ai-act.art14-human-oversight-write",
                skill=skill,
                description=(
                    f"AI component '{skill}' has write capability with "
                    f"no approval gate or write restriction. EU AI Act "
                    f"Art. 14 requires effective human oversight of "
                    f"high-risk AI systems; without an approval gate or "
                    f"explicit restriction, the component executes "
                    f"autonomously."
                ),
                fix=PolicyFix(
                    fix_type="add_approval_rule",
                    params={"tool_name": skill},
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_human_oversight_network(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 14 — Human oversight: gate network-capable components.

    Art. 14(4)(d) requires the deployer to be able to "decide, in any
    particular situation, not to use the high-risk AI system or
    otherwise disregard, override or reverse the output". Network-
    capable components without outbound restrictions or approval gates
    can dispatch actions to external systems faster than oversight can
    intervene.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.network_skills):
        if (
            not has_outbound_block_for_skill(policy, skill)
            and not has_approval_for_skill(policy, skill)
        ):
            findings.append(ComplianceFinding(
                control_id="eu-ai-act.art14-human-oversight-network",
                skill=skill,
                description=(
                    f"AI component '{skill}' has outbound network "
                    f"access with no restrictions or approval gate. "
                    f"EU AI Act Art. 14(4)(d) requires the deployer to "
                    f"be able to override or reverse the system's "
                    f"outputs; uncontrolled outbound network can "
                    f"dispatch actions faster than oversight can "
                    f"intervene."
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


def _check_cybersecurity(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 15 — Accuracy, robustness, cybersecurity: anomaly detection.

    Art. 15(1) requires high-risk AI systems to be "designed and
    developed in such a way that they achieve an appropriate level of
    accuracy, robustness and cybersecurity, and perform consistently in
    those respects throughout their lifecycle". AgentWard's behavioral
    baseline detector compares each tool call against recorded baselines
    — the runtime cybersecurity / drift primitive.
    """
    findings: list[ComplianceFinding] = []

    if not policy.baseline_check:
        findings.append(ComplianceFinding(
            control_id="eu-ai-act.art15-cybersecurity",
            skill=None,
            description=(
                "Behavioral baseline anomaly detection (baseline_check) "
                "is disabled. EU AI Act Art. 15 requires mechanisms to "
                "ensure robustness and cybersecurity throughout the "
                "system lifecycle; AgentWard's baseline check compares "
                "each tool call against recorded baselines and is the "
                "recommended runtime primitive. Note: enabling this "
                "requires recorded baselines — see `agentward baseline`."
            ),
            fix=PolicyFix(
                fix_type="set_policy_flag",
                params={"flag": "baseline_check", "value": True},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


def _check_provider_chain(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """Art. 25 — Provider/distributor/importer accountability chain.

    Art. 25 places obligations on every operator in the AI value chain
    (provider, distributor, importer, deployer) and Art. 13(3)(b) requires
    that instructions for use identify the provider. For tool-call agents
    that means each AI component has a documented owner and any
    third-party services along its data path are recorded. AgentWard
    cannot infer those facts; we surface a RECOMMENDED finding when
    `skill_metadata` lacks `owner` or `subcontractor_chain` so the
    operator knows what to fill in for technical-documentation purposes.
    """
    findings: list[ComplianceFinding] = []

    for skill in sorted(analysis.all_skills):
        meta = policy.skill_metadata.get(skill)
        has_owner = bool(meta and meta.owner)
        has_chain = bool(meta and meta.subcontractor_chain)
        if has_owner and has_chain:
            continue
        missing: list[str] = []
        if not has_owner:
            missing.append("owner")
        if not has_chain:
            missing.append("subcontractor_chain")
        findings.append(ComplianceFinding(
            control_id="eu-ai-act.art25-provider-chain",
            skill=skill,
            description=(
                f"AI component '{skill}' is missing "
                f"{' and '.join(missing)} in skill_metadata. EU AI Act "
                f"Art. 25 / Art. 13(3) require the deployer to record "
                f"the accountable party and any third-party providers "
                f"in the AI component's value chain. Document this in "
                f"policy.skill_metadata so the technical-documentation "
                f"file can carry it through."
            ),
            fix=None,  # operator-supplied facts; no auto-fix possible
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


# -----------------------------------------------------------------------
# Control registry
# -----------------------------------------------------------------------

EU_AI_ACT_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="eu-ai-act.art9-risk-management",
        section="Art. 9",
        title="Risk Management System — Zero-Trust Default",
        description=(
            "default_action must be 'block' to satisfy the documented "
            "deny-by-default posture required for Art. 9 risk management."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_risk_management,
    ),
    ComplianceControl(
        control_id="eu-ai-act.art12-record-keeping",
        section="Art. 12",
        title="Record-Keeping — Audit Trail Availability",
        description=(
            "RFC 5424 syslog output must remain enabled so AI-system "
            "events can be ingested by archival / SIEM tooling."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_record_keeping,
    ),
    ComplianceControl(
        control_id="eu-ai-act.art12-detection",
        section="Art. 12",
        title="Record-Keeping — Sensitive Content Detection",
        description=(
            "Sensitive content scanning must be enabled to log "
            "credential / PII exposure as risk-relevant events."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_sensitive_content_detection,
    ),
    ComplianceControl(
        control_id="eu-ai-act.art14-human-oversight-write",
        section="Art. 14",
        title="Human Oversight — Write-Capable Components",
        description=(
            "Write-capable AI components must be gated by approval or "
            "explicit write restriction."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_human_oversight_write,
    ),
    ComplianceControl(
        control_id="eu-ai-act.art14-human-oversight-network",
        section="Art. 14",
        title="Human Oversight — Network-Capable Components",
        description=(
            "Network-capable AI components must block outbound or "
            "require approval to support deployer override."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_human_oversight_network,
    ),
    ComplianceControl(
        control_id="eu-ai-act.art13-transparency",
        section="Art. 13",
        title="Transparency — Registry Cross-Reference",
        description=(
            "registry_check should be enabled so risk metadata for "
            "third-party AI components surfaces in audit events."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_transparency,
    ),
    ComplianceControl(
        control_id="eu-ai-act.art25-provider-chain",
        section="Art. 25",
        title="Provider Chain & Accountable Owner",
        description=(
            "Each AI component should have an accountable owner and a "
            "documented subcontractor chain in skill_metadata for the "
            "Art. 25 / Art. 13(3) value-chain disclosure."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_provider_chain,
    ),
    ComplianceControl(
        control_id="eu-ai-act.art15-cybersecurity",
        section="Art. 15",
        title="Cybersecurity — Behavioral Baseline",
        description=(
            "baseline_check should be enabled for runtime "
            "drift / anomaly detection."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_cybersecurity,
    ),
]

# Register on import
register_framework("eu_ai_act", EU_AI_ACT_CONTROLS)
