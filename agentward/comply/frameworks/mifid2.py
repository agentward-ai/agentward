"""MiFID II / RTS 6 compliance controls — algorithmic trading.

Maps AgentWard's existing technical controls to the operational provisions
of MiFID II (Directive 2014/65/EU) Article 17 — Algorithmic Trading — as
detailed in RTS 6 (Commission Delegated Regulation (EU) 2017/589).

Scope
-----
This framework focuses exclusively on Art. 17 / RTS 6 obligations that
can be enforced through agent tool-call policy.  The wider MiFID II
record-keeping, transaction-reporting and best-execution obligations
(Art. 25, Art. 27, MiFIR Art. 26) are out of scope: they sit in the
trading platform, not in a tool-call policy layer.

Controls implemented
--------------------
- RTS 6 Art. 1   — Documented governance: zero-trust default action.
- RTS 6 Art. 12  — Trading-skill access control: explicit policy entries.
- RTS 6 Art. 13  — Pre-trade controls / kill switch: human approval on
  write-capable trading skills.
- RTS 6 Art. 13  — Outbound venue routing: restrictions or approval on
  network-capable trading skills.
- RTS 6 Art. 14  — Real-time monitoring: behavioral baseline detection.
- RTS 6 Art. 16  — Segregation: trading skills isolated via chaining
  rules and/or a bounded chain depth.
- RTS 6 Art. 18  — Boundary: trading skills covered by a data boundary
  zone with a blocking violation action.
- RTS 6 Art. 28  — Record-keeping: structured audit trail (RFC 5424
  syslog) and credential leak detection in order arguments.

Trading-skill detection
-----------------------
A skill is considered trading-scope when any of the following holds:
1. ``analysis.financial_skills`` contains it (existing financial-name /
   data-access heuristics: stripe, payment, billing, banking, …).
2. Its name matches a MiFID-specific trading pattern (broker, venue,
   exchange, fix, order-management, blotter, rfq, etc.).
3. A ``data_boundary`` in the policy classifies it under ``trading``,
   ``mifid``, ``mifid2``, or ``rts6``.

References
----------
* Directive 2014/65/EU (MiFID II), Article 17
* Commission Delegated Regulation (EU) 2017/589 (RTS 6) — organizational
  requirements for algorithmic trading
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
# Trading-skill detection
# -----------------------------------------------------------------------

# Whole-token matches against the tokenized skill name (split on -, _, .).
# Keep entries that, as a whole word, are unambiguous trading vocabulary.
_TRADING_NAME_TOKENS: frozenset[str] = frozenset({
    "trading", "trader", "broker", "brokerage",
    "execution", "venue", "exchange", "matching",
    "blotter", "rfq", "darkpool", "liquidity",
    "oms", "sor",
})

# Substring phrases — used when the trading concept needs more than one
# token to disambiguate (e.g. "market-data" vs. "data-warehouse").
_TRADING_NAME_PHRASES: frozenset[str] = frozenset({
    "order-management",
    "smart-order-routing",
    "market-data",
    "market-maker",
    "dark-pool",
    "matching-engine",
    "execute-order",
})

# Prefixes — anchored at the start of the name to avoid false positives.
# `fix-` is here so we catch FIX-protocol gateways (`fix-gateway`,
# `fix-engine`) without snagging `bug-fix-tool`.
_TRADING_NAME_PREFIXES: tuple[str, ...] = (
    "fix-",
)


def _name_tokens(name: str) -> set[str]:
    """Tokenize a skill name on common separators."""
    lower = name.lower()
    for sep in ("_", ".", "/"):
        lower = lower.replace(sep, "-")
    return {tok for tok in lower.split("-") if tok}


def _name_matches_trading_pattern(name: str) -> bool:
    """Return True if the skill name matches any trading-naming heuristic."""
    lower = name.lower()
    if any(lower.startswith(prefix) for prefix in _TRADING_NAME_PREFIXES):
        return True
    if _name_tokens(name) & _TRADING_NAME_TOKENS:
        return True
    if any(phrase in lower for phrase in _TRADING_NAME_PHRASES):
        return True
    return False

# Classification labels in policy data_boundaries that explicitly opt a
# skill into MiFID II scope.
_TRADING_BOUNDARY_LABELS: frozenset[str] = frozenset({
    "trading", "mifid", "mifid2", "mifid_ii", "rts6",
})


def _get_trading_skills(
    policy: AgentWardPolicy,
    analysis: SkillAnalysis,
) -> set[str]:
    """Return the set of skills in MiFID II / RTS 6 scope for this policy.

    Combines:
    1. All financial skills detected by build_skill_analysis().
    2. All skills whose name matches a trading-specific pattern.
    3. All skills explicitly classified under trading boundary labels.
    """
    trading: set[str] = set(analysis.financial_skills)

    # Name-based detection across every known skill
    for skill in analysis.all_skills:
        if _name_matches_trading_pattern(skill):
            trading.add(skill)

    # Policy-declared boundary labels
    for _zone, boundary in policy.data_boundaries.items():
        if boundary.classification.lower() in _TRADING_BOUNDARY_LABELS:
            for skill in boundary.skills:
                trading.add(skill)

    return trading


# -----------------------------------------------------------------------
# Check functions
# -----------------------------------------------------------------------


def _check_governance(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 1 — Documented governance: zero-trust default.

    RTS 6 Art. 1(1) requires investment firms to "ensure that their
    trading systems are subject to effective business continuity
    arrangements".  A permissive default action ("allow unknown tools")
    is incompatible with the deny-by-default posture this implies for
    an automated trading agent.
    """
    findings: list[ComplianceFinding] = []

    if policy.default_action != DefaultAction.BLOCK:
        findings.append(ComplianceFinding(
            control_id="mifid2-rts6.governance",
            skill=None,
            description=(
                "default_action is 'allow' — unknown tools may execute "
                "without explicit policy. RTS 6 Art. 1 requires documented "
                "governance over algorithmic trading systems; "
                "deny-by-default is the operational baseline."
            ),
            fix=PolicyFix(
                fix_type="set_default_action",
                params={"action": "block"},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_trading_access_control(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 12 — Trading-skill access control: explicit policy entry.

    RTS 6 Art. 12(1) requires firms to "monitor in real time all
    algorithmic trading activity […] of all their trading systems".
    A trading skill that is not explicitly listed in the policy is, by
    definition, not subject to documented monitoring.
    """
    findings: list[ComplianceFinding] = []

    trading_skills = _get_trading_skills(policy, analysis)

    for skill in sorted(trading_skills):
        if skill not in policy.skills:
            findings.append(ComplianceFinding(
                control_id="mifid2-rts6.access",
                skill=skill,
                description=(
                    f"Trading skill '{skill}' has no explicit permissions "
                    f"in the policy. RTS 6 Art. 12 requires real-time "
                    f"monitoring of all algorithmic trading activity, "
                    f"which presupposes that every trading skill is "
                    f"individually scoped."
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


def _check_pre_trade_controls(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 13 — Pre-trade controls: human approval on write paths.

    RTS 6 Art. 13(1) requires investment firms to apply pre-trade
    controls "for all algorithmic trading activity".  Where AgentWard
    cannot enforce price collars or message-rate caps directly, a
    human-in-the-loop approval gate on write-capable trading skills is
    the analogue available at policy layer — and is also the kill-
    switch primitive required by Art. 18.
    """
    findings: list[ComplianceFinding] = []

    trading_skills = _get_trading_skills(policy, analysis)

    for skill in sorted(trading_skills):
        if not analysis.skill_write_capable.get(skill, False):
            continue

        if (
            not has_write_restriction_for_skill(policy, skill)
            and not has_approval_for_skill(policy, skill)
        ):
            findings.append(ComplianceFinding(
                control_id="mifid2-rts6.pre-trade",
                skill=skill,
                description=(
                    f"Trading skill '{skill}' has write capability with "
                    f"no approval gate or write restriction. RTS 6 Art. 13 "
                    f"requires pre-trade controls on every algorithmic "
                    f"trading activity; without a human-in-the-loop or "
                    f"explicit restriction, AgentWard provides no kill "
                    f"switch for this path (Art. 18)."
                ),
                fix=PolicyFix(
                    fix_type="add_approval_rule",
                    params={"tool_name": skill},
                ),
                severity=ControlSeverity.REQUIRED,
            ))

    return findings


def _check_outbound_routing(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 13 — Outbound venue routing controls.

    Trading skills with outbound network access can route orders to
    external venues.  RTS 6 Art. 13 requires controls over routing of
    orders; without an outbound restriction or approval gate, the agent
    can send orders to any reachable endpoint.
    """
    findings: list[ComplianceFinding] = []

    trading_skills = _get_trading_skills(policy, analysis)
    network_trading = sorted(trading_skills & analysis.network_skills)

    for skill in network_trading:
        if (
            not has_outbound_block_for_skill(policy, skill)
            and not has_approval_for_skill(policy, skill)
        ):
            findings.append(ComplianceFinding(
                control_id="mifid2-rts6.outbound",
                skill=skill,
                description=(
                    f"Trading skill '{skill}' has outbound network access "
                    f"with no restrictions or approval. RTS 6 Art. 13 "
                    f"requires controls over the routing of orders; "
                    f"unrestricted outbound permits routing to any "
                    f"reachable venue without supervision."
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


def _check_boundary(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 18 — Boundary: trading skills inside a blocking zone.

    Defining a data boundary with a blocking violation action ensures
    trading data does not leak into non-trading skills.  This is the
    policy-layer analogue of RTS 6 Art. 18's segregation requirements.
    """
    findings: list[ComplianceFinding] = []

    trading_skills = _get_trading_skills(policy, analysis)

    covered: set[str] = set()
    for _zone, boundary in policy.data_boundaries.items():
        if boundary.classification.lower() in _TRADING_BOUNDARY_LABELS:
            if boundary.on_violation in (
                ViolationAction.BLOCK_AND_NOTIFY,
                ViolationAction.BLOCK_AND_LOG,
            ):
                covered.update(boundary.skills)

    uncovered = sorted(trading_skills - covered)
    for skill in uncovered:
        findings.append(ComplianceFinding(
            control_id="mifid2-rts6.boundary",
            skill=skill,
            description=(
                f"Trading skill '{skill}' is not covered by a data "
                f"boundary with a blocking violation action. RTS 6 Art. 18 "
                f"requires segregation of trading systems; a blocking "
                f"data boundary prevents trading data from flowing into "
                f"non-trading skills."
            ),
            fix=PolicyFix(
                fix_type="add_data_boundary",
                params={
                    "zone_name": "mifid2_zone",
                    "skills": [skill],
                    "classification": "trading",
                    "rules": ["trading_data cannot flow outside mifid2_zone"],
                    "on_violation": "block_and_log",
                },
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_segregation(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 16 — Segregation of duties via chaining rules.

    RTS 6 Art. 16 separates the algorithmic trading function from other
    activities within the firm.  At policy layer, this maps onto chaining
    rules that prevent trading skills from triggering non-trading skills
    (or vice-versa via injected payloads).
    """
    findings: list[ComplianceFinding] = []

    trading_skills = _get_trading_skills(policy, analysis)
    non_trading = analysis.all_skills - trading_skills

    for skill in sorted(trading_skills):
        blocked: set[str] = set()
        blocks_any = False

        for rule in policy.skill_chaining:
            if rule.source_skill == skill:
                if rule.target_skill == "any":
                    blocks_any = True
                    break
                blocked.add(rule.target_skill)

        if blocks_any:
            continue

        unblocked = sorted(non_trading - blocked)
        if unblocked and non_trading:
            findings.append(ComplianceFinding(
                control_id="mifid2-rts6.segregation",
                skill=skill,
                description=(
                    f"Trading skill '{skill}' can trigger non-trading "
                    f"skill(s): {', '.join(unblocked[:5])}"
                    f"{'...' if len(unblocked) > 5 else ''}. RTS 6 Art. 16 "
                    f"requires segregation between the algorithmic trading "
                    f"function and other activities; a chaining rule that "
                    f"isolates the trading skill enforces this at policy "
                    f"layer."
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


def _check_chain_depth_cap(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 16 — Bounded cascade across trading skills.

    A complementary guard to per-skill segregation: even where chaining
    rules exist, an unbounded ``skill_chain_depth`` allows long
    inter-service cascades that defeat the segregation intent.
    """
    findings: list[ComplianceFinding] = []

    trading_skills = _get_trading_skills(policy, analysis)
    if not trading_skills:
        return findings

    if policy.skill_chain_depth is None:
        findings.append(ComplianceFinding(
            control_id="mifid2-rts6.chain-depth",
            skill=None,
            description=(
                "skill_chain_depth is unbounded. With trading skills in "
                "scope, RTS 6 Art. 16 segregation requires a bounded "
                "cascade — a small chain depth (e.g. 3) prevents one "
                "trading skill from triggering an open-ended sequence "
                "of cross-skill handoffs."
            ),
            fix=PolicyFix(
                fix_type="set_chain_depth",
                params={"depth": 3},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


def _check_real_time_monitoring(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 14 — Real-time monitoring of algorithmic trading.

    RTS 6 Art. 14(1) requires "real-time monitoring of […] all
    algorithmic trading activity".  AgentWard's behavioral-baseline
    anomaly detector is the policy-layer monitoring primitive — when
    enabled, every trading-skill call is scored against its baseline
    and surfaced into the audit stream.
    """
    findings: list[ComplianceFinding] = []

    trading_skills = _get_trading_skills(policy, analysis)
    if not trading_skills:
        return findings

    if not policy.baseline_check:
        findings.append(ComplianceFinding(
            control_id="mifid2-rts6.monitoring",
            skill=None,
            description=(
                "baseline_check is disabled. RTS 6 Art. 14 requires "
                "real-time monitoring of algorithmic trading activity; "
                "AgentWard's behavioral baseline detector is the "
                "policy-layer monitoring primitive (recorded baselines "
                "are required to use it — see `agentward baseline`)."
            ),
            fix=PolicyFix(
                fix_type="set_policy_flag",
                params={"flag": "baseline_check", "value": True},
            ),
            severity=ControlSeverity.RECOMMENDED,
        ))

    return findings


def _check_record_keeping_audit(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 28 — Record-keeping: structured audit trail.

    RTS 6 Art. 28 imposes a 5-year retention obligation on records
    relating to algorithmic trading.  AgentWard's RFC 5424 syslog output
    is the integration point for shipping every policy decision into
    the firm's WORM archive / SIEM.  An empty ``audit.syslog_path``
    breaks that integration.
    """
    findings: list[ComplianceFinding] = []

    if (
        policy.audit.syslog_path is not None
        and policy.audit.syslog_path.strip() == ""
    ):
        findings.append(ComplianceFinding(
            control_id="mifid2-rts6.audit",
            skill=None,
            description=(
                "audit.syslog_path is set to an empty string — the RFC "
                "5424 syslog stream that RTS 6 Art. 28 record-keeping "
                "depends on is disabled. Either remove the field or set "
                "an absolute path that your archival agent will read."
            ),
            fix=None,  # operator-chosen path
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


def _check_credential_leak_detection(
    policy: AgentWardPolicy,
    scan: ScanResult | None,
    analysis: SkillAnalysis,
) -> list[ComplianceFinding]:
    """RTS 6 Art. 1 — Information security: credential leak detection.

    RTS 6 Art. 1 expects investment firms to maintain information
    security and resilience.  Sensitive content scanning with at least
    the API-key pattern enabled is the AgentWard primitive that detects
    credentials leaking into order arguments.
    """
    findings: list[ComplianceFinding] = []

    if not policy.sensitive_content.enabled:
        findings.append(ComplianceFinding(
            control_id="mifid2-rts6.credential-detection",
            skill=None,
            description=(
                "Sensitive content scanning is disabled. RTS 6 Art. 1 "
                "requires information-security controls; the sensitive "
                "content classifier detects credentials in tool call "
                "arguments and is the recommended policy-layer primitive."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["api_key", "credit_card"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))
    elif "api_key" not in policy.sensitive_content.patterns:
        findings.append(ComplianceFinding(
            control_id="mifid2-rts6.credential-detection",
            skill=None,
            description=(
                "API-key pattern is not enabled in sensitive content "
                "scanning. Credentials embedded in order requests are a "
                "common information-security failure under RTS 6 Art. 1."
            ),
            fix=PolicyFix(
                fix_type="enable_sensitive_content",
                params={"patterns": ["api_key"]},
            ),
            severity=ControlSeverity.REQUIRED,
        ))

    return findings


# -----------------------------------------------------------------------
# Control registry
# -----------------------------------------------------------------------

MIFID2_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(
        control_id="mifid2-rts6.governance",
        section="RTS 6 Art. 1",
        title="Documented Governance — Zero-Trust Default",
        description=(
            "default_action must be 'block' to satisfy the deny-by-default "
            "posture for algorithmic trading governance."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_governance,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.access",
        section="RTS 6 Art. 12",
        title="Trading-Skill Access Control",
        description=(
            "Every trading skill must have explicit permissions in policy "
            "for real-time monitoring (Art. 12)."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_trading_access_control,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.pre-trade",
        section="RTS 6 Art. 13",
        title="Pre-Trade Controls / Kill Switch",
        description=(
            "Write-capable trading skills must have an approval gate or "
            "explicit write restriction (Art. 13, Art. 18 kill switch)."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_pre_trade_controls,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.outbound",
        section="RTS 6 Art. 13",
        title="Outbound Order Routing",
        description=(
            "Network-capable trading skills must have outbound restrictions "
            "or approval gates."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_outbound_routing,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.boundary",
        section="RTS 6 Art. 18",
        title="Trading Data Boundary",
        description=(
            "Trading skills must be covered by a data boundary with a "
            "blocking violation action."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_boundary,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.segregation",
        section="RTS 6 Art. 16",
        title="Segregation of Duties",
        description=(
            "Trading skills must be isolated from non-trading skills via "
            "chaining rules."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_segregation,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.audit",
        section="RTS 6 Art. 28",
        title="Record-Keeping Audit Trail",
        description=(
            "RFC 5424 syslog output must remain enabled to satisfy 5-year "
            "record-keeping retention via SIEM/WORM archival."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_record_keeping_audit,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.credential-detection",
        section="RTS 6 Art. 1",
        title="Credential Leak Detection",
        description=(
            "Sensitive content scanning with at least the api_key pattern "
            "must be enabled to detect credentials in trading arguments."
        ),
        severity=ControlSeverity.REQUIRED,
        check=_check_credential_leak_detection,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.chain-depth",
        section="RTS 6 Art. 16",
        title="Bounded Inter-Skill Cascade",
        description=(
            "skill_chain_depth should be bounded when trading skills are "
            "in scope to limit segregation-defeating cascades."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_chain_depth_cap,
    ),
    ComplianceControl(
        control_id="mifid2-rts6.monitoring",
        section="RTS 6 Art. 14",
        title="Real-Time Monitoring",
        description=(
            "Behavioral baseline detection (baseline_check) is the "
            "policy-layer monitoring primitive for trading skills."
        ),
        severity=ControlSeverity.RECOMMENDED,
        check=_check_real_time_monitoring,
    ),
]

# Register on import
register_framework("mifid2", MIFID2_CONTROLS)
