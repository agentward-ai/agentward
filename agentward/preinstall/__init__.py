"""Pre-install security scanner for AgentWard.

Catches deserialization attacks and malicious payloads BEFORE a skill
or MCP server is loaded into the agent's process.

Public API::

    from agentward.preinstall import PreinstallScanner

    scanner = PreinstallScanner()
    report  = scanner.scan(Path("./my-skill/"))

    if report.verdict == ScanVerdict.BLOCK:
        raise RuntimeError(f"Skill refused: {len(report.findings)} threat(s)")

The scanner spawns an isolated subprocess (agentward.preinstall._worker)
that uses only safe parsers:
  - yaml.safe_load   (never yaml.load)
  - ast.parse        (never exec/import)
  - json.loads       (stdlib)
  - tomllib.loads    (stdlib ≥3.11)
"""

from __future__ import annotations

from agentward.preinstall.models import (
    DESERIALIZATION_CATEGORIES,
    PreinstallFinding,
    PreinstallReport,
    ScanVerdict,
    ThreatCategory,
    ThreatLevel,
)
from agentward.preinstall.scanner import PreinstallScanner

__all__ = [
    "PreinstallScanner",
    "PreinstallFinding",
    "PreinstallReport",
    "ScanVerdict",
    "ThreatCategory",
    "ThreatLevel",
    "DESERIALIZATION_CATEGORIES",
]
