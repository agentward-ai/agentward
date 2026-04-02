"""MCP server risk registry for AgentWard.

Provides local risk metadata for 30+ known MCP servers, including
known vulnerability types, severity levels, and recommended policy
constraints.
"""

from agentward.registry.models import (
    KnownRisk,
    RecommendedConstraint,
    RiskLevel,
    ServerEntry,
)
from agentward.registry.npm_advisories import (
    NpmAdvisory,
    NpmAdvisoryRegistry,
    NpmCheckResult,
)
from agentward.registry.registry import ServerRegistry

__all__ = [
    "ServerRegistry",
    "ServerEntry",
    "KnownRisk",
    "RecommendedConstraint",
    "RiskLevel",
    "NpmAdvisoryRegistry",
    "NpmAdvisory",
    "NpmCheckResult",
]
