"""Compliance-framework suggestions derived from scan results.

When `agentward scan` detects skills with regulatory-relevant data
patterns (PHI, personal data, financial data, trading data, cardholder
data) we surface a hint pointing the operator at the right compliance
framework.  This is purely advisory; the authoritative evaluation runs
through ``agentward comply --framework <name>``.

The hint generator is intentionally conservative:
* A framework is suggested only when at least one skill matches its
  trigger criteria.
* Each suggestion carries the *reason* (which skills triggered it) so
  the user can sanity-check the heuristic.
* Suggestions are ordered by specificity (HIPAA > MiFID II > PCI-DSS >
  GDPR > SOX > DORA) so the most narrow regulatory match appears first.

Detection signal sources (all heuristic):
* `analysis.phi_skills`           → HIPAA
* `analysis.cardholder_data_skills` → PCI-DSS
* `analysis.financial_skills`     → SOX (US public-company reporting)
* `analysis.personal_data_skills` → GDPR
* MiFID II trading-skill detector → MiFID II
* `analysis.financial_skills` ∪ trading skills → DORA
  (also fires when multiple network-capable third-party services are
  present, since DORA scopes the entire ICT estate of a financial entity)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentward.scan.permissions import DataAccessType, ScanResult


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FrameworkSuggestion:
    """A single compliance-framework suggestion.

    Attributes:
        framework: Lowercase framework identifier matching ``--framework``.
        display_name: Human-readable name for the suggestion line.
        reason: Brief explanation of why this framework was suggested.
        triggering_skills: Sorted list of skills that triggered the
            suggestion. May be empty for framework-level triggers (e.g.
            DORA when the rationale is "multiple network services").
        command: The exact CLI command the user can run.
    """

    framework: str
    display_name: str
    reason: str
    triggering_skills: tuple[str, ...]
    command: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize for inclusion in JSON output."""
        return {
            "framework": self.framework,
            "display_name": self.display_name,
            "reason": self.reason,
            "triggering_skills": list(self.triggering_skills),
            "command": self.command,
        }


# ---------------------------------------------------------------------------
# Suggestion generator
# ---------------------------------------------------------------------------

# Order suggestions are emitted in.  Most specific / narrowest scope first
# so the user sees the most actionable regulator match at the top.
_SUGGESTION_ORDER: tuple[str, ...] = (
    "hipaa",
    "mifid2",
    "pci_dss",
    "gdpr",
    "sox",
    "dora",
)


def suggest_frameworks(scan: ScanResult) -> list[FrameworkSuggestion]:
    """Inspect a scan result and return relevant compliance suggestions.

    Args:
        scan: The scan result (typically from ``_run_scan``).

    Returns:
        A list of ``FrameworkSuggestion`` instances ordered by specificity.
        Empty if no framework-relevant signals were detected.
    """
    # Lazy imports to keep the scan module free of compliance dependencies
    # in the common (non-compliance) path.
    from agentward.comply.controls import build_skill_analysis
    from agentward.comply.frameworks.mifid2 import _get_trading_skills
    from agentward.policy.schema import AgentWardPolicy

    # Build a SkillAnalysis using a bare placeholder policy.  At scan
    # time the user hasn't authored a policy yet, so we run the existing
    # detection heuristics with no policy-specific overrides.
    placeholder = AgentWardPolicy(version="1.0")
    analysis = build_skill_analysis(placeholder, scan)
    trading_skills = _get_trading_skills(placeholder, analysis)

    # Count network-capable third parties for the DORA broad-scope trigger.
    network_servers = {
        s.server.name
        for s in scan.servers
        for tool in s.tools
        for access in tool.data_access
        if access.type == DataAccessType.NETWORK
    }

    # Build suggestions in canonical order.
    by_framework: dict[str, FrameworkSuggestion] = {}

    if analysis.phi_skills:
        by_framework["hipaa"] = FrameworkSuggestion(
            framework="hipaa",
            display_name="HIPAA",
            reason=(
                f"{len(analysis.phi_skills)} skill(s) appear to handle "
                f"protected health information (PHI)."
            ),
            triggering_skills=tuple(sorted(analysis.phi_skills)),
            command="agentward comply --framework hipaa",
        )

    if trading_skills:
        by_framework["mifid2"] = FrameworkSuggestion(
            framework="mifid2",
            display_name="MiFID II / RTS 6",
            reason=(
                f"{len(trading_skills)} skill(s) match algorithmic-trading "
                f"patterns (Art. 17 / RTS 6 scope)."
            ),
            triggering_skills=tuple(sorted(trading_skills)),
            command="agentward comply --framework mifid2",
        )

    if analysis.cardholder_data_skills:
        by_framework["pci_dss"] = FrameworkSuggestion(
            framework="pci_dss",
            display_name="PCI-DSS",
            reason=(
                f"{len(analysis.cardholder_data_skills)} skill(s) match "
                f"cardholder-data patterns."
            ),
            triggering_skills=tuple(sorted(analysis.cardholder_data_skills)),
            command="agentward comply --framework pci_dss",
        )

    if analysis.personal_data_skills:
        by_framework["gdpr"] = FrameworkSuggestion(
            framework="gdpr",
            display_name="GDPR",
            reason=(
                f"{len(analysis.personal_data_skills)} skill(s) appear to "
                f"process personal data (email/messaging/identity patterns)."
            ),
            triggering_skills=tuple(sorted(analysis.personal_data_skills)),
            command="agentward comply --framework gdpr",
        )

    if analysis.financial_skills:
        by_framework["sox"] = FrameworkSuggestion(
            framework="sox",
            display_name="SOX §404",
            reason=(
                f"{len(analysis.financial_skills)} skill(s) appear to handle "
                f"financial data."
            ),
            triggering_skills=tuple(sorted(analysis.financial_skills)),
            command="agentward comply --framework sox",
        )

    # DORA: broad scope.  Trigger if any financial / trading skills are
    # detected, OR if at least three network-capable third-party services
    # are present (substantive ICT estate).
    dora_triggers: set[str] = set()
    if analysis.financial_skills:
        dora_triggers.update(analysis.financial_skills)
    if trading_skills:
        dora_triggers.update(trading_skills)
    broad_ict_estate = len(network_servers) >= 3

    if dora_triggers or broad_ict_estate:
        if dora_triggers:
            reason = (
                f"{len(dora_triggers)} financial/trading skill(s) detected "
                f"— DORA applies to ICT services of financial entities."
            )
            triggering = tuple(sorted(dora_triggers))
        else:
            reason = (
                f"{len(network_servers)} network-capable third-party ICT "
                f"service(s) detected — DORA Art. 28 scopes third-party "
                f"risk management."
            )
            triggering = tuple(sorted(network_servers))
        by_framework["dora"] = FrameworkSuggestion(
            framework="dora",
            display_name="DORA (EU 2022/2554)",
            reason=reason,
            triggering_skills=triggering,
            command="agentward comply --framework dora",
        )

    # Emit in canonical order, omit unset entries.
    return [by_framework[name] for name in _SUGGESTION_ORDER if name in by_framework]
