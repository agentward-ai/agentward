"""Pre-install scanner: orchestrates the subprocess worker and returns a report.

The scanner spawns a sandboxed subprocess (agentward.preinstall._worker)
that does all file I/O and parsing in isolation.  If the subprocess
crashes or times out, the scanner returns a BLOCK-verdict report with a
single finding describing the failure so the caller can reject the skill.

Public API:
    scanner = PreinstallScanner(timeout=30)
    report  = scanner.scan(Path("./my-skill/"))
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import fields
from pathlib import Path

from agentward.preinstall.models import (
    PreinstallFinding,
    PreinstallReport,
    ScanVerdict,
    ThreatCategory,
    ThreatLevel,
)


# Default timeout for the worker subprocess (seconds)
_DEFAULT_TIMEOUT = 30

# Findings are sorted: highest threat level first, then by file, then by line
_LEVEL_ORDER: dict[ThreatLevel, int] = {
    ThreatLevel.CRITICAL: 0,
    ThreatLevel.HIGH:     1,
    ThreatLevel.MEDIUM:   2,
    ThreatLevel.LOW:      3,
    ThreatLevel.INFO:     4,
}


class PreinstallScanner:
    """Pre-install security scanner.

    Spawns an isolated subprocess to parse skill manifests and source
    files using only safe parsers, then collects and sorts the findings.

    Args:
        timeout: Maximum seconds to wait for the worker subprocess.
            Defaults to 30.
    """

    def __init__(self, timeout: int = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout

    def scan(self, target: Path) -> PreinstallReport:
        """Scan a skill directory for pre-install security threats.

        Args:
            target: Path to the skill directory to scan.

        Returns:
            A PreinstallReport with findings and an overall verdict.
            If the worker fails or times out, returns a BLOCK-verdict
            report with a single CRITICAL finding explaining the error.
        """
        target = target.resolve()
        start = time.monotonic()

        if not target.exists():
            return self._error_report(
                target,
                f"Target directory does not exist: {target}",
                elapsed_ms=0.0,
            )
        if not target.is_dir():
            return self._error_report(
                target,
                f"Target path is not a directory: {target}",
                elapsed_ms=0.0,
            )

        try:
            result = subprocess.run(
                [sys.executable, "-m", "agentward.preinstall._worker", str(target)],
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            elapsed = (time.monotonic() - start) * 1000
            return self._error_report(
                target,
                f"Pre-install scan timed out after {self._timeout}s. "
                "The skill directory may be too large or contain files that "
                "stall parsing. Treat as untrusted.",
                elapsed_ms=elapsed,
            )
        except OSError as exc:
            elapsed = (time.monotonic() - start) * 1000
            return self._error_report(
                target,
                f"Failed to launch pre-install scanner subprocess: {exc}",
                elapsed_ms=elapsed,
            )

        elapsed = (time.monotonic() - start) * 1000

        # Parse worker output
        raw_output = result.stdout.strip()
        if not raw_output:
            return self._error_report(
                target,
                "Pre-install scanner subprocess produced no output. "
                f"stderr: {result.stderr[:300]}",
                elapsed_ms=elapsed,
            )

        try:
            payload = json.loads(raw_output)
        except json.JSONDecodeError:
            return self._error_report(
                target,
                f"Pre-install scanner output is not valid JSON. "
                f"stdout: {raw_output[:200]}",
                elapsed_ms=elapsed,
            )

        if "error" in payload:
            return self._error_report(
                target,
                f"Pre-install scanner reported an error: {payload['error']}",
                elapsed_ms=elapsed,
            )

        findings = _deserialize_findings(payload.get("findings", []))
        files_scanned = int(payload.get("files_scanned", 0))

        # Sort: CRITICAL first, then HIGH, MEDIUM, LOW, INFO; stable within level
        findings.sort(key=lambda f: (_LEVEL_ORDER.get(f.level, 99), f.file, f.line or 0))

        return PreinstallReport(
            target=target,
            findings=findings,
            files_scanned=files_scanned,
            scan_duration_ms=elapsed,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error_report(
        target: Path,
        message: str,
        elapsed_ms: float,
    ) -> PreinstallReport:
        """Build a BLOCK-verdict report describing a scanner-level failure."""
        finding = PreinstallFinding(
            category=ThreatCategory.SUSPICIOUS_SCRIPT,
            level=ThreatLevel.CRITICAL,
            file="(scanner)",
            line=None,
            description=f"Pre-install scanner error: {message}",
            evidence="",
            recommendation=(
                "Do not install this skill until the scan completes successfully. "
                "Investigate the error and retry."
            ),
        )
        return PreinstallReport(
            target=target,
            findings=[finding],
            files_scanned=0,
            scan_duration_ms=elapsed_ms,
        )


# ---------------------------------------------------------------------------
# Deserialisation helpers
# ---------------------------------------------------------------------------

_FINDING_FIELDS = {f.name for f in fields(PreinstallFinding)}


def _deserialize_findings(raw: list[dict]) -> list[PreinstallFinding]:
    """Convert a list of dicts (from JSON) into PreinstallFinding objects.

    Unknown keys are ignored. Invalid entries are skipped.
    """
    findings: list[PreinstallFinding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        try:
            finding = PreinstallFinding(
                category=ThreatCategory(item["category"]),
                level=ThreatLevel(item["level"]),
                file=str(item.get("file", "(unknown)")),
                line=item.get("line"),
                description=str(item.get("description", "")),
                evidence=str(item.get("evidence", "")),
                recommendation=str(item.get("recommendation", "")),
            )
            findings.append(finding)
        except (KeyError, ValueError):
            continue  # malformed entry — skip silently
    return findings
