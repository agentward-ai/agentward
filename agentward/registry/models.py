"""Data models for the MCP server risk registry."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

RiskLevel = Literal["critical", "high", "medium", "low"]

# Ordering for risk level comparisons (higher = more severe)
RISK_LEVEL_ORDER: dict[RiskLevel, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


@dataclass
class KnownRisk:
    """A specific known risk for an MCP server.

    Attributes:
        type: Short risk type identifier (e.g. "path-traversal", "credential-exposure").
        description: Human-readable description of the risk.
        severity: Risk severity level.
        cve: Optional CVE identifier if applicable.
    """

    type: str
    description: str
    severity: RiskLevel
    cve: str | None = None


@dataclass
class RecommendedConstraint:
    """A recommended argument constraint for an MCP server.

    Attributes:
        argument: The argument name the constraint applies to.
        constraint: The constraint type (e.g. "must_start_with", "allowed_domains").
        value: The constraint value (type depends on constraint).
    """

    argument: str
    constraint: str
    value: Any


@dataclass
class ServerEntry:
    """A single entry in the MCP server risk registry.

    Attributes:
        name: Canonical server name (e.g. "filesystem").
        package: Primary npm/PyPI package name.
        category: Server category (e.g. "file-access", "code-hosting").
        risk_level: Overall risk level assessment.
        known_risks: List of specific known risks.
        recommended_constraints: Suggested policy constraints.
        aliases: Alternative names or package identifiers.
        last_updated: ISO date when the entry was last reviewed.
        source: How the risk assessment was produced (e.g. "manual-review").
        notes: Optional free-text notes.
    """

    name: str
    package: str
    category: str
    risk_level: RiskLevel
    known_risks: list[KnownRisk] = field(default_factory=list)
    recommended_constraints: list[RecommendedConstraint] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    last_updated: str = ""
    source: str = "manual-review"
    notes: str = ""

    @property
    def top_severity(self) -> RiskLevel:
        """Return the highest severity level among all known risks, or overall risk_level."""
        if not self.known_risks:
            return self.risk_level
        return max(
            (r.severity for r in self.known_risks),
            key=lambda s: RISK_LEVEL_ORDER.get(s, 0),
        )
