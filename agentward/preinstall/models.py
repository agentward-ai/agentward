"""Data models for the pre-install security scanner.

All findings and reports are plain dataclasses, following the same
pattern as ComplianceFinding/ComplianceReport in the comply module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class ThreatLevel(str, Enum):
    """Severity of a pre-install threat finding."""

    CRITICAL = "critical"  # Definite attack vector — do not install
    HIGH = "high"          # Strong indicator of malicious intent
    MEDIUM = "medium"      # Suspicious — investigate before installing
    LOW = "low"            # Weak signal — informational
    INFO = "info"          # Neutral observation


class ThreatCategory(str, Enum):
    """Type of threat detected by the pre-install scanner."""

    YAML_INJECTION = "yaml_injection"
    PICKLE_DESERIALIZATION = "pickle_deserialization"
    EXECUTABLE_HOOK = "executable_hook"
    MALICIOUS_DEPENDENCY = "malicious_dependency"
    TYPOSQUATTING = "typosquatting"
    SUSPICIOUS_SCRIPT = "suspicious_script"


# Categories that represent deserialization attack vectors.
# ANY finding in these categories forces a BLOCK verdict regardless of level,
# because deserialization vulnerabilities enable arbitrary code execution at
# install time — before AgentWard's runtime proxy ever sees a tool call.
DESERIALIZATION_CATEGORIES: frozenset[ThreatCategory] = frozenset({
    ThreatCategory.YAML_INJECTION,
    ThreatCategory.PICKLE_DESERIALIZATION,
})


class ScanVerdict(str, Enum):
    """Overall verdict for a pre-install scan.

    SAFE:  No findings above INFO level.
    WARN:  Only MEDIUM/LOW findings — proceed with caution.
    BLOCK: One or more CRITICAL/HIGH findings — do not install.
    """

    SAFE = "safe"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class PreinstallFinding:
    """A single threat finding from the pre-install scanner.

    Attributes:
        category: Type of threat.
        level: Severity.
        file: Relative path to the file containing the finding.
        line: Line number (1-indexed) within the file, or None.
        description: Human-readable description of the threat.
        evidence: The actual snippet or pattern that triggered the finding.
        recommendation: What to do about it.
    """

    category: ThreatCategory
    level: ThreatLevel
    file: str
    line: int | None
    description: str
    evidence: str
    recommendation: str


@dataclass
class PreinstallReport:
    """Complete pre-install scan result.

    Attributes:
        target: The scanned directory.
        findings: All threat findings, ordered by severity (highest first).
        files_scanned: Total number of files examined.
        scan_duration_ms: Wall-clock scan time in milliseconds.
    """

    target: Path
    findings: list[PreinstallFinding] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_ms: float = 0.0

    @property
    def has_deserialization_risk(self) -> bool:
        """True if any finding is a deserialization attack vector.

        This covers YAML_INJECTION and PICKLE_DESERIALIZATION categories,
        regardless of their severity level.
        """
        return any(f.category in DESERIALIZATION_CATEGORIES for f in self.findings)

    @property
    def verdict(self) -> ScanVerdict:
        """Compute overall verdict from findings.

        Deserialization findings (YAML_INJECTION, PICKLE_DESERIALIZATION)
        always force BLOCK regardless of their severity level, because they
        enable arbitrary code execution at install time.
        """
        # Explicit deser-forced BLOCK — belt-and-suspenders: even if levels were
        # accidentally set below CRITICAL, deser findings still block installation.
        if self.has_deserialization_risk:
            return ScanVerdict.BLOCK
        for f in self.findings:
            if f.level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
                return ScanVerdict.BLOCK
        for f in self.findings:
            if f.level in (ThreatLevel.MEDIUM, ThreatLevel.LOW):
                return ScanVerdict.WARN
        return ScanVerdict.SAFE
