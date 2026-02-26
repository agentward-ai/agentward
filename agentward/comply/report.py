"""Rich CLI rendering for compliance reports.

Produces a formatted terminal report with summary panel, skill rating
table, findings grouped by section, and next-steps guidance.
"""

from __future__ import annotations

from typing import Any

from agentward.comply.controls import (
    ComplianceFinding,
    ComplianceRating,
    ComplianceReport,
    ControlSeverity,
)


# Rating display colors
_RATING_COLORS = {
    ComplianceRating.GREEN: "#00ff88",
    ComplianceRating.YELLOW: "#ffcc00",
    ComplianceRating.RED: "#ff3366",
}

_RATING_LABELS = {
    ComplianceRating.GREEN: "PASS",
    ComplianceRating.YELLOW: "WARN",
    ComplianceRating.RED: "FAIL",
}

_SEVERITY_ICONS = {
    ControlSeverity.REQUIRED: "[bold red]!![/bold red]",
    ControlSeverity.RECOMMENDED: "[bold yellow]![/bold yellow]",
}


def render_compliance_report(report: ComplianceReport, console: Any) -> None:
    """Render a compliance report to the terminal using rich.

    Args:
        report: The compliance evaluation result.
        console: A rich Console instance (stderr-routed).
    """
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    framework_upper = report.framework.upper()

    # --- Summary panel ---
    total_findings = len(report.findings)
    required_findings = sum(
        1 for f in report.findings if f.severity == ControlSeverity.REQUIRED
    )
    recommended_findings = total_findings - required_findings

    red_count = sum(
        1 for r in report.skill_ratings.values() if r == ComplianceRating.RED
    )
    yellow_count = sum(
        1 for r in report.skill_ratings.values() if r == ComplianceRating.YELLOW
    )
    green_count = sum(
        1 for r in report.skill_ratings.values() if r == ComplianceRating.GREEN
    )

    if total_findings == 0:
        summary_text = (
            f"[bold #00ff88]All {report.controls_checked} {framework_upper} "
            f"controls passed.[/bold #00ff88]"
        )
    else:
        parts = [
            f"[bold]{report.controls_passed}/{report.controls_checked}[/bold] "
            f"controls passed",
        ]
        if required_findings:
            parts.append(f"[bold red]{required_findings} required[/bold red] gap(s)")
        if recommended_findings:
            parts.append(
                f"[bold yellow]{recommended_findings} recommended[/bold yellow] gap(s)"
            )
        summary_text = " · ".join(parts)

    console.print(
        Panel(
            summary_text,
            title=f"{framework_upper} Compliance Report",
            border_style="#5eead4",
        )
    )

    # --- Skill ratings table ---
    if report.skill_ratings:
        table = Table(
            title="Skill Ratings",
            show_header=True,
            header_style="bold dim",
            border_style="#333333",
            title_style="#5eead4 bold",
            expand=True,
        )
        table.add_column("Skill", style="cyan", ratio=3)
        table.add_column("Rating", justify="center", ratio=1)
        table.add_column("Issues", justify="center", ratio=1)

        for skill in sorted(report.skill_ratings.keys()):
            rating = report.skill_ratings[skill]
            color = _RATING_COLORS[rating]
            label = _RATING_LABELS[rating]

            skill_findings = [
                f for f in report.findings if f.skill == skill
            ]
            issue_count = str(len(skill_findings)) if skill_findings else "—"

            table.add_row(
                skill,
                f"[bold {color}]{label}[/bold {color}]",
                issue_count,
            )

        console.print(table)
        console.print()

    # --- Findings grouped by section ---
    if report.findings:
        # Group findings by control section
        by_section: dict[str, list[ComplianceFinding]] = {}
        for finding in report.findings:
            # Extract section from control_id → look up via HIPAA controls
            section = _get_section_for_control(finding.control_id, report.framework)
            by_section.setdefault(section, []).append(finding)

        for section in sorted(by_section.keys()):
            findings = by_section[section]
            table = Table(
                title=section,
                show_header=True,
                header_style="bold dim",
                border_style="#333333",
                title_style="#5eead4 bold",
                expand=True,
            )
            table.add_column("", width=2, no_wrap=True)
            table.add_column("Skill", style="cyan", ratio=1, no_wrap=True)
            table.add_column("Finding", ratio=4)

            for finding in findings:
                icon = _SEVERITY_ICONS.get(finding.severity, " ")
                skill = finding.skill or "(policy)"
                table.add_row(icon, skill, finding.description)

            console.print(table)
            console.print()

    # --- Next steps ---
    if report.findings:
        fixable = sum(1 for f in report.findings if f.fix is not None)
        console.print(
            f"[dim]Next steps: Run [bold]agentward comply --framework "
            f"{report.framework} --fix[/bold] to auto-generate a compliant "
            f"policy ({fixable} of {total_findings} gaps are auto-fixable).[/dim]"
        )
        console.print()


def render_compliance_json(report: ComplianceReport) -> dict[str, Any]:
    """Convert a compliance report to a JSON-serializable dict.

    Args:
        report: The compliance evaluation result.

    Returns:
        A dict suitable for json.dumps().
    """
    findings_list = []
    for finding in report.findings:
        entry: dict[str, Any] = {
            "control_id": finding.control_id,
            "skill": finding.skill,
            "description": finding.description,
            "severity": finding.severity.value,
            "has_fix": finding.fix is not None,
        }
        if finding.fix is not None:
            entry["fix_type"] = finding.fix.fix_type
        findings_list.append(entry)

    return {
        "framework": report.framework,
        "controls_checked": report.controls_checked,
        "controls_passed": report.controls_passed,
        "findings": findings_list,
        "skill_ratings": {
            skill: rating.value
            for skill, rating in sorted(report.skill_ratings.items())
        },
    }


def _get_section_for_control(control_id: str, framework: str) -> str:
    """Look up the section label for a control_id.

    Falls back to the control_id itself if not found.
    """
    # Lazy import to avoid circular dependency
    from agentward.comply.frameworks import get_framework

    try:
        controls = get_framework(framework)
    except ValueError:
        return control_id

    for control in controls:
        if control.control_id == control_id:
            return f"{control.section} — {control.title}"

    return control_id
