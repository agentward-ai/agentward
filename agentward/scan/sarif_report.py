"""SARIF (Static Analysis Results Interchange Format) report generator.

Produces a SARIF v2.1.0 report from scan results, suitable for upload to
GitHub's Security tab via the `github/codeql-action/upload-sarif` action.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

import agentward
from agentward.scan.chains import ChainDetection, ChainRisk, detect_chains
from agentward.scan.permissions import (
    RiskLevel,
    ScanResult,
)
from agentward.scan.recommendations import Recommendation, RecommendationSeverity


# Mapping from AgentWard risk levels to SARIF severity levels.
_SARIF_LEVEL = {
    RiskLevel.CRITICAL: "error",
    RiskLevel.HIGH: "warning",
    RiskLevel.MEDIUM: "note",
    RiskLevel.LOW: "note",
}

_REC_SARIF_LEVEL = {
    RecommendationSeverity.CRITICAL: "error",
    RecommendationSeverity.WARNING: "warning",
    RecommendationSeverity.INFO: "note",
}


def generate_sarif(
    scan: ScanResult,
    recommendations: list[Recommendation],
    chains: list[ChainDetection] | None = None,
) -> str:
    """Generate a SARIF v2.1.0 report from scan results.

    Each HIGH or CRITICAL tool gets a SARIF result. Recommendations and
    chain detections also produce results.

    Args:
        scan: The complete scan result.
        recommendations: Generated recommendations.
        chains: Detected skill chains (computed if not provided).

    Returns:
        JSON string of the SARIF report.
    """
    if chains is None:
        chains = detect_chains(scan)

    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    rule_ids: set[str] = set()

    # --- Tool risk results ---
    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            if tool_perm.risk_level in (RiskLevel.LOW,):
                continue  # Only report MEDIUM+ in SARIF

            rule_id = f"agentward/tool-risk/{tool_perm.risk_level.value.lower()}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f"ToolRisk{tool_perm.risk_level.value.title()}",
                    "shortDescription": {
                        "text": f"Tool with {tool_perm.risk_level.value} risk level",
                    },
                    "defaultConfiguration": {
                        "level": _SARIF_LEVEL[tool_perm.risk_level],
                    },
                    "helpUri": "https://agentward.ai/docs/risk-levels",
                })

            reasons = [r for r in tool_perm.risk_reasons if r and r != "Read-only operation"]
            message = (
                f"Tool '{tool_perm.tool.name}' rated {tool_perm.risk_level.value}: "
                + ("; ".join(reasons) if reasons else "No specific reason.")
            )

            results.append({
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[tool_perm.risk_level],
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": server_map.server.name,
                            "uriBaseId": "AGENTWARD_SCAN",
                        },
                    },
                    "logicalLocations": [{
                        "name": tool_perm.tool.name,
                        "kind": "function",
                    }],
                }],
            })

    # --- Chain results ---
    for chain in chains:
        rule_id = f"agentward/chain/{chain.risk.value.lower()}"
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f"SkillChain{chain.risk.value.title()}",
                "shortDescription": {
                    "text": f"{chain.risk.value} risk skill chain detected",
                },
                "defaultConfiguration": {
                    "level": "error" if chain.risk == ChainRisk.CRITICAL else "warning",
                },
                "helpUri": "https://agentward.ai/docs/skill-chains",
            })

        results.append({
            "ruleId": rule_id,
            "level": "error" if chain.risk == ChainRisk.CRITICAL else "warning",
            "message": {
                "text": f"{chain.label}: {chain.description}. {chain.attack_vector}",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": chain.source_server,
                        "uriBaseId": "AGENTWARD_SCAN",
                    },
                },
            }],
        })

    # --- Recommendation results ---
    for rec in recommendations:
        rule_id = f"agentward/recommendation/{rec.severity.value.lower()}"
        if rule_id not in rule_ids:
            rule_ids.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f"Recommendation{rec.severity.value.title()}",
                "shortDescription": {
                    "text": f"{rec.severity.value} severity recommendation",
                },
                "defaultConfiguration": {
                    "level": _REC_SARIF_LEVEL.get(rec.severity, "note"),
                },
                "helpUri": "https://agentward.ai/docs/recommendations",
            })

        results.append({
            "ruleId": rule_id,
            "level": _REC_SARIF_LEVEL.get(rec.severity, "note"),
            "message": {"text": rec.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": rec.target,
                        "uriBaseId": "AGENTWARD_SCAN",
                    },
                },
            }],
        })

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "AgentWard",
                    "informationUri": "https://agentward.ai",
                    "version": agentward.__version__,
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }

    return json.dumps(sarif, indent=2)
