"""Rich CLI rendering for pre-install scan reports.

Produces a formatted terminal report with:
  - A prominent ⚠ DESERIALIZATION ATTACK VECTOR DETECTED banner (when applicable)
  - A summary panel (verdict, file count, timing, deser finding count)
  - A dedicated deserialization findings section (separated from other findings)
  - A full findings table (CRITICAL → INFO)
  - A next-steps hint tailored to the verdict

Color convention matches the rest of AgentWard:
  #00ff88 — SAFE / green
  #ffcc00 — WARN / yellow
  #ff3366 — BLOCK / red
  #5eead4 — teal headings / info
"""

from __future__ import annotations

from typing import Any

from agentward.preinstall.models import (
    DESERIALIZATION_CATEGORIES,
    PreinstallFinding,
    PreinstallReport,
    ScanVerdict,
    ThreatCategory,
    ThreatLevel,
)


# ---------------------------------------------------------------------------
# Display constants
# ---------------------------------------------------------------------------

_LEVEL_COLORS: dict[ThreatLevel, str] = {
    ThreatLevel.CRITICAL: "#ff3366",
    ThreatLevel.HIGH:     "#ff8800",
    ThreatLevel.MEDIUM:   "#ffcc00",
    ThreatLevel.LOW:      "#5eead4",
    ThreatLevel.INFO:     "#888888",
}

_VERDICT_COLORS: dict[ScanVerdict, str] = {
    ScanVerdict.BLOCK: "#ff3366",
    ScanVerdict.WARN:  "#ffcc00",
    ScanVerdict.SAFE:  "#00ff88",
}

_VERDICT_LABELS: dict[ScanVerdict, str] = {
    ScanVerdict.BLOCK: "BLOCK",
    ScanVerdict.WARN:  "WARN",
    ScanVerdict.SAFE:  "SAFE",
}

_CATEGORY_LABELS: dict[ThreatCategory, str] = {
    ThreatCategory.YAML_INJECTION:        "yaml_injection",
    ThreatCategory.PICKLE_DESERIALIZATION: "pickle_deser",
    ThreatCategory.EXECUTABLE_HOOK:       "exec_hook",
    ThreatCategory.MALICIOUS_DEPENDENCY:  "malicious_dep",
    ThreatCategory.TYPOSQUATTING:         "typosquatting",
    ThreatCategory.SUSPICIOUS_SCRIPT:     "suspicious_script",
}


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------


def render_preinstall_report(
    report: PreinstallReport,
    console: Any,
    *,
    verbose: bool = False,
) -> None:
    """Render a pre-install scan report to the terminal using rich.

    Deserialization findings get a dedicated prominent warning banner
    printed BEFORE the main summary, so they cannot be missed.

    Args:
        report: The scan result to render.
        console: A rich Console instance (stderr-routed).
        verbose: If True, include evidence and recommendation columns.
    """
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table

    deser_findings = [
        f for f in report.findings if f.category in DESERIALIZATION_CATEGORIES
    ]
    other_findings = [
        f for f in report.findings if f.category not in DESERIALIZATION_CATEGORIES
    ]

    # -----------------------------------------------------------------------
    # ⚠  DESERIALIZATION ATTACK VECTOR DETECTED  (shown FIRST, before summary)
    # -----------------------------------------------------------------------
    if deser_findings:
        _render_deserialization_banner(deser_findings, console, verbose=verbose)

    verdict = report.verdict
    verdict_color = _VERDICT_COLORS[verdict]
    verdict_label = _VERDICT_LABELS[verdict]

    # --- Count by level ---
    counts: dict[ThreatLevel, int] = {lvl: 0 for lvl in ThreatLevel}
    for f in report.findings:
        counts[f.level] += 1

    # --- Summary panel ---
    name = report.target.name
    deser_count = len(deser_findings)

    if verdict == ScanVerdict.SAFE:
        body = (
            f"[bold {verdict_color}]SAFE[/bold {verdict_color}]  "
            f"No threats detected in '{name}'\n"
            f"[dim]{report.files_scanned} files · {report.scan_duration_ms:.0f}ms[/dim]"
        )
    else:
        parts: list[str] = []
        if deser_count:
            parts.append(
                f"[bold #ff3366]{deser_count} deserialization attack vector(s)[/bold #ff3366]"
            )
        for lvl in (ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM,
                    ThreatLevel.LOW, ThreatLevel.INFO):
            n = counts[lvl]
            if n:
                color = _LEVEL_COLORS[lvl]
                parts.append(f"[bold {color}]{n} {lvl.value}[/bold {color}]")
        summary_findings = " · ".join(parts)
        body = (
            f"[bold {verdict_color}]{verdict_label}[/bold {verdict_color}]  "
            f"'{name}'  —  {summary_findings}\n"
            f"[dim]{report.files_scanned} files · {report.scan_duration_ms:.0f}ms[/dim]"
        )

    console.print(
        Panel(
            body,
            title="Pre-Install Scan",
            border_style=verdict_color,
        )
    )

    if not report.findings:
        return

    # --- Other findings table (non-deserialization) ---
    if other_findings:
        _render_findings_table(other_findings, console, verbose=verbose)

    # --- Next steps ---
    _render_next_steps(report, verdict, console)


def _render_deserialization_banner(
    deser_findings: list[PreinstallFinding],
    console: Any,
    *,
    verbose: bool = False,
) -> None:
    """Render a prominent warning banner for deserialization attack vectors.

    This is printed BEFORE the main summary panel so it cannot be missed.
    """
    from rich.panel import Panel
    from rich.table import Table

    count = len(deser_findings)
    noun = "vector" if count == 1 else "vectors"

    banner_body = (
        f"[bold #ff3366]⚠  DESERIALIZATION ATTACK VECTOR DETECTED  ⚠[/bold #ff3366]\n\n"
        f"[bold]{count} deserialization attack {noun}[/bold] found.\n"
        "Deserialization vulnerabilities allow a malicious skill to execute\n"
        "arbitrary code in your agent's process BEFORE any policy takes effect.\n\n"
        "[bold #ff3366]DO NOT INSTALL THIS SKILL.[/bold #ff3366]"
    )
    console.print(
        Panel(
            banner_body,
            title="⚠  CRITICAL: DESERIALIZATION ATTACK VECTOR DETECTED  ⚠",
            border_style="#ff3366",
            title_align="center",
        )
    )

    # Detailed table of deserialization findings
    table = Table(
        title="Deserialization Attack Vectors",
        show_header=True,
        header_style="bold #ff3366",
        border_style="#ff3366",
        title_style="bold #ff3366",
        expand=True,
    )
    table.add_column("Category",  width=16, no_wrap=True)
    table.add_column("File",      ratio=2)
    table.add_column("Finding",   ratio=4)
    if verbose:
        table.add_column("Evidence", ratio=2)

    for f in deser_findings:
        cat_text = _CATEGORY_LABELS.get(f.category, f.category.value)
        loc = f.file if f.line is None else f"{f.file}:{f.line}"
        row: list[str] = [
            f"[bold #ff3366]{cat_text}[/bold #ff3366]",
            loc,
            f.description,
        ]
        if verbose:
            row.append(f.evidence[:100] if f.evidence else "—")
        table.add_row(*row)

    console.print(table)
    console.print()


def _render_findings_table(
    findings: list[PreinstallFinding],
    console: Any,
    *,
    verbose: bool = False,
) -> None:
    """Render a findings table for non-deserialization findings."""
    from rich.table import Table

    table = Table(
        title="Other Findings",
        show_header=True,
        header_style="bold dim",
        border_style="#333333",
        title_style="#5eead4 bold",
        expand=True,
    )
    table.add_column("Level",    width=10, no_wrap=True)
    table.add_column("Category", width=20, no_wrap=True)
    table.add_column("File",     ratio=2)
    table.add_column("Finding",  ratio=4)

    if verbose:
        table.add_column("Evidence",       ratio=2)
        table.add_column("Recommendation", ratio=3)

    for finding in findings:
        level_color = _LEVEL_COLORS[finding.level]
        level_text = f"[bold {level_color}]{finding.level.value.upper()}[/bold {level_color}]"
        cat_text = _CATEGORY_LABELS.get(finding.category, finding.category.value)
        loc = finding.file if finding.line is None else f"{finding.file}:{finding.line}"

        row: list[str] = [level_text, cat_text, loc, finding.description]
        if verbose:
            row.append(finding.evidence[:100] if finding.evidence else "—")
            row.append(finding.recommendation[:150] if finding.recommendation else "—")

        table.add_row(*row)

    console.print(table)
    console.print()


def _render_next_steps(
    report: PreinstallReport,
    verdict: ScanVerdict,
    console: Any,
) -> None:
    """Print actionable next-steps based on verdict."""
    if verdict == ScanVerdict.BLOCK:
        console.print(
            "[bold #ff3366]Do not install this skill.[/bold #ff3366] "
            "One or more CRITICAL/HIGH threats were detected. "
            "Review the findings above and contact the skill author if this "
            "appears to be a false positive.",
            highlight=False,
        )
    elif verdict == ScanVerdict.WARN:
        console.print(
            "[bold #ffcc00]Proceed with caution.[/bold #ffcc00] "
            "MEDIUM/LOW findings were detected. Review the findings above "
            "before installing this skill in a production environment.",
            highlight=False,
        )

    if report.findings:
        console.print(
            "\n[dim]Run [bold]agentward preinstall --verbose[/bold] to see "
            "evidence snippets and per-finding recommendations.[/dim]",
            highlight=False,
        )


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------


def render_preinstall_json(report: PreinstallReport) -> dict[str, Any]:
    """Serialise a pre-install report to a JSON-compatible dict.

    Args:
        report: The scan result.

    Returns:
        A dict suitable for json.dumps().
    """
    verdict = report.verdict
    deser_count = sum(
        1 for f in report.findings if f.category in DESERIALIZATION_CATEGORIES
    )
    return {
        "target": str(report.target),
        "verdict": verdict.value,
        "has_deserialization_risk": report.has_deserialization_risk,
        "deserialization_findings_count": deser_count,
        "files_scanned": report.files_scanned,
        "scan_duration_ms": report.scan_duration_ms,
        "findings": [
            {
                "category": f.category.value,
                "level": f.level.value,
                "file": f.file,
                "line": f.line,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
        "summary": {
            lvl.value: sum(1 for f in report.findings if f.level == lvl)
            for lvl in ThreatLevel
        },
        "deserialization_categories": [
            c.value for c in DESERIALIZATION_CATEGORIES
        ],
    }


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

_MD_LEVEL_ICONS: dict[ThreatLevel, str] = {
    ThreatLevel.CRITICAL: "🔴",
    ThreatLevel.HIGH:     "🟠",
    ThreatLevel.MEDIUM:   "🟡",
    ThreatLevel.LOW:      "🔵",
    ThreatLevel.INFO:     "⚪",
}

_MD_VERDICT_ICONS: dict[ScanVerdict, str] = {
    ScanVerdict.BLOCK: "🔴 BLOCK",
    ScanVerdict.WARN:  "🟡 WARN",
    ScanVerdict.SAFE:  "🟢 SAFE",
}


def render_preinstall_markdown(report: PreinstallReport) -> str:
    """Render a pre-install scan report as a Markdown document.

    Args:
        report: The scan result.

    Returns:
        A Markdown string suitable for writing to a .md file.
    """
    import datetime

    lines: list[str] = []
    verdict = report.verdict
    deser_findings = [f for f in report.findings if f.category in DESERIALIZATION_CATEGORIES]
    other_findings = [f for f in report.findings if f.category not in DESERIALIZATION_CATEGORIES]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        "# AgentWard Pre-Install Scan Report",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Target** | `{report.target}` |",
        f"| **Verdict** | {_MD_VERDICT_ICONS[verdict]} |",
        f"| **Files scanned** | {report.files_scanned} |",
        f"| **Scan duration** | {report.scan_duration_ms:.0f} ms |",
        f"| **Generated** | {now} |",
        "",
        "---",
        "",
    ]

    # ── Deserialization warning (top of report, before everything else) ─────
    if deser_findings:
        lines += [
            "## ⚠️ DESERIALIZATION ATTACK VECTORS DETECTED",
            "",
            "> [!CAUTION]",
            "> **DO NOT INSTALL THIS SKILL.**  ",
            "> Deserialization vulnerabilities allow a malicious skill to execute arbitrary",
            "> code in your agent's process **before any policy takes effect**.",
            "",
            f"**{len(deser_findings)} deserialization attack vector(s) found.**",
            "",
            "| Category | File | Line | Description | Evidence |",
            "|---|---|---|---|---|",
        ]
        for f in deser_findings:
            cat = _CATEGORY_LABELS.get(f.category, f.category.value)
            line_str = str(f.line) if f.line is not None else "—"
            evidence = f"`{f.evidence[:80]}`" if f.evidence else "—"
            lines.append(
                f"| 🔴 `{cat}` | `{f.file}` | {line_str} "
                f"| {f.description} | {evidence} |"
            )
        lines += [
            "",
            "### Recommendations",
            "",
        ]
        seen: set[str] = set()
        for f in deser_findings:
            if f.recommendation and f.recommendation not in seen:
                lines.append(f"- {f.recommendation}")
                seen.add(f.recommendation)
        lines += ["", "---", ""]

    # ── Summary ─────────────────────────────────────────────────────────────
    lines += ["## Summary", ""]
    if not report.findings:
        lines += ["✅ No threats detected.", ""]
    else:
        lines += [
            "| Severity | Count |",
            "|---|---|",
        ]
        for lvl in ThreatLevel:
            count = sum(1 for f in report.findings if f.level == lvl)
            if count:
                icon = _MD_LEVEL_ICONS[lvl]
                lines.append(f"| {icon} **{lvl.value.upper()}** | {count} |")
        lines += [""]

    # ── All findings ─────────────────────────────────────────────────────────
    if report.findings:
        lines += ["## All Findings", ""]

        # Group by level
        for lvl in ThreatLevel:
            group = [f for f in report.findings if f.level == lvl]
            if not group:
                continue
            icon = _MD_LEVEL_ICONS[lvl]
            lines += [
                f"### {icon} {lvl.value.upper()} ({len(group)})",
                "",
                "| Category | File | Line | Description |",
                "|---|---|---|---|",
            ]
            for f in group:
                cat = _CATEGORY_LABELS.get(f.category, f.category.value)
                line_str = str(f.line) if f.line is not None else "—"
                lines.append(f"| `{cat}` | `{f.file}` | {line_str} | {f.description} |")

            # Evidence + recommendation per finding
            lines += [""]
            for f in group:
                if f.evidence:
                    lines += [f"**Evidence** (`{f.file}`): `{f.evidence[:120]}`  "]
                if f.recommendation:
                    lines += [f"**Fix:** {f.recommendation}", ""]

        lines += ["---", ""]

    # ── Footer ───────────────────────────────────────────────────────────────
    lines += [
        "_Report generated by [AgentWard](https://agentward.ai) "
        f"— pre-install security scanner._",
    ]

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_LEVEL_COLORS: dict[ThreatLevel, tuple[str, str]] = {
    # (background, text)
    ThreatLevel.CRITICAL: ("#3d0000", "#ff4d4d"),
    ThreatLevel.HIGH:     ("#2d1500", "#ff8c00"),
    ThreatLevel.MEDIUM:   ("#2d2200", "#ffc107"),
    ThreatLevel.LOW:      ("#002d35", "#4dd9f0"),
    ThreatLevel.INFO:     ("#1a1a1a", "#888888"),
}

_HTML_VERDICT_STYLES: dict[ScanVerdict, tuple[str, str, str]] = {
    # (background, border, text)
    ScanVerdict.BLOCK: ("#3d0000", "#cc0000", "#ff4d4d"),
    ScanVerdict.WARN:  ("#2d2200", "#b8860b", "#ffc107"),
    ScanVerdict.SAFE:  ("#003d1a", "#00a550", "#00ff88"),
}


def render_preinstall_html(report: PreinstallReport) -> str:
    """Render a pre-install scan report as a self-contained HTML document.

    Dark-themed, color-coded by severity. No external dependencies.

    Args:
        report: The scan result.

    Returns:
        An HTML string suitable for writing to a .html file.
    """
    import datetime
    import html as _html

    def esc(s: str) -> str:
        return _html.escape(str(s))

    verdict = report.verdict
    deser_findings = [f for f in report.findings if f.category in DESERIALIZATION_CATEGORIES]
    other_findings = [f for f in report.findings if f.category not in DESERIALIZATION_CATEGORIES]
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    v_bg, v_border, v_text = _HTML_VERDICT_STYLES[verdict]

    # ── CSS ─────────────────────────────────────────────────────────────────
    css = """
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body {
        background: #0d0d0f; color: #c9d1d9;
        font-family: 'Segoe UI', system-ui, sans-serif;
        font-size: 14px; line-height: 1.6; padding: 32px;
      }
      h1 { color: #e6edf3; font-size: 1.6rem; margin-bottom: 4px; }
      h2 { color: #c9d1d9; font-size: 1.15rem; margin: 32px 0 12px;
           border-bottom: 1px solid #21262d; padding-bottom: 6px; }
      h3 { color: #c9d1d9; font-size: 1rem; margin: 20px 0 8px; }
      a  { color: #58a6ff; text-decoration: none; }
      code {
        background: #161b22; border: 1px solid #30363d;
        border-radius: 4px; padding: 1px 6px;
        font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85em;
      }
      pre {
        background: #161b22; border: 1px solid #30363d; border-radius: 6px;
        padding: 12px 16px; overflow-x: auto; font-size: 0.85em;
        font-family: 'Cascadia Code', 'Fira Code', monospace;
      }
      .meta-grid {
        display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 12px; margin: 16px 0 24px;
      }
      .meta-card {
        background: #161b22; border: 1px solid #21262d;
        border-radius: 8px; padding: 12px 16px;
      }
      .meta-card .label { color: #8b949e; font-size: 0.75rem; text-transform: uppercase;
                          letter-spacing: 0.08em; }
      .meta-card .value { color: #e6edf3; font-size: 1rem; font-weight: 600; margin-top: 2px; }
      .verdict-badge {
        display: inline-block; padding: 6px 20px; border-radius: 20px;
        font-weight: 700; font-size: 1rem; letter-spacing: 0.05em;
        border: 2px solid %(v_border)s; background: %(v_bg)s; color: %(v_text)s;
      }
      .deser-banner {
        background: #200000; border: 2px solid #cc0000;
        border-radius: 10px; padding: 20px 24px; margin: 8px 0 24px;
      }
      .deser-banner h2 {
        color: #ff4d4d; border: none; padding: 0; margin: 0 0 10px;
        font-size: 1.1rem;
      }
      .deser-banner p { color: #ffaaaa; margin: 6px 0; }
      .deser-banner strong { color: #ff4d4d; }
      table {
        width: 100%%; border-collapse: collapse;
        background: #161b22; border-radius: 8px; overflow: hidden;
        border: 1px solid #21262d; margin-bottom: 20px;
      }
      thead th {
        background: #21262d; color: #8b949e; font-size: 0.75rem;
        text-transform: uppercase; letter-spacing: 0.08em;
        padding: 10px 14px; text-align: left;
      }
      tbody tr { border-top: 1px solid #21262d; }
      tbody tr:hover { background: #1c2128; }
      tbody td { padding: 10px 14px; vertical-align: top; color: #c9d1d9; }
      .badge {
        display: inline-block; padding: 2px 10px; border-radius: 12px;
        font-size: 0.75rem; font-weight: 700; letter-spacing: 0.05em;
        white-space: nowrap;
      }
      .badge-critical { background: #3d0000; color: #ff4d4d; border: 1px solid #cc0000; }
      .badge-high     { background: #2d1500; color: #ff8c00; border: 1px solid #cc6600; }
      .badge-medium   { background: #2d2200; color: #ffc107; border: 1px solid #b8860b; }
      .badge-low      { background: #002d35; color: #4dd9f0; border: 1px solid #0891b2; }
      .badge-info     { background: #1a1a1a; color: #888888; border: 1px solid #444; }
      .cat-tag {
        display: inline-block; background: #21262d; color: #8b949e;
        border-radius: 4px; padding: 1px 8px; font-size: 0.8rem;
        font-family: monospace;
      }
      .finding-card {
        border-left: 3px solid #30363d; padding: 10px 14px;
        margin: 8px 0; background: #161b22; border-radius: 0 6px 6px 0;
      }
      .finding-card.critical { border-left-color: #cc0000; }
      .finding-card.high     { border-left-color: #cc6600; }
      .finding-card.medium   { border-left-color: #b8860b; }
      .finding-card.low      { border-left-color: #0891b2; }
      .finding-card .desc { color: #e6edf3; margin-bottom: 6px; }
      .finding-card .rec  { color: #8b949e; font-size: 0.85rem; margin-top: 6px; }
      .summary-grid {
        display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 24px;
      }
      .summary-cell {
        border-radius: 8px; padding: 14px; text-align: center;
      }
      .summary-cell .count { font-size: 1.8rem; font-weight: 700; }
      .summary-cell .label { font-size: 0.7rem; text-transform: uppercase;
                             letter-spacing: 0.1em; margin-top: 2px; }
      hr { border: none; border-top: 1px solid #21262d; margin: 28px 0; }
      footer { color: #444; font-size: 0.8rem; text-align: center; margin-top: 40px; }
    """ % {"v_border": v_border, "v_bg": v_bg, "v_text": v_text}

    # ── Helpers ──────────────────────────────────────────────────────────────
    def badge(level: ThreatLevel) -> str:
        return (
            f'<span class="badge badge-{level.value}">'
            f'{level.value.upper()}</span>'
        )

    def cat_tag(category: ThreatCategory) -> str:
        label = _CATEGORY_LABELS.get(category, category.value)
        return f'<span class="cat-tag">{esc(label)}</span>'

    def summary_cell(level: ThreatLevel, count: int) -> str:
        bg, text = _HTML_LEVEL_COLORS[level]
        return (
            f'<div class="summary-cell" style="background:{bg}; color:{text};">'
            f'  <div class="count">{count}</div>'
            f'  <div class="label">{level.value.upper()}</div>'
            f'</div>'
        )

    # ── Build body ───────────────────────────────────────────────────────────
    body_parts: list[str] = []

    # Title + meta
    body_parts.append(
        f'<h1>🛡️ AgentWard Pre-Install Scan Report</h1>'
        f'<p style="color:#8b949e; margin:4px 0 20px;">'
        f'Generated {esc(now)}</p>'
    )
    body_parts.append('<div class="meta-grid">')
    body_parts.append(
        f'<div class="meta-card"><div class="label">Target</div>'
        f'<div class="value"><code>{esc(str(report.target))}</code></div></div>'
    )
    body_parts.append(
        f'<div class="meta-card"><div class="label">Verdict</div>'
        f'<div class="value"><span class="verdict-badge">{verdict.value.upper()}</span></div></div>'
    )
    body_parts.append(
        f'<div class="meta-card"><div class="label">Files Scanned</div>'
        f'<div class="value">{report.files_scanned}</div></div>'
    )
    body_parts.append(
        f'<div class="meta-card"><div class="label">Scan Duration</div>'
        f'<div class="value">{report.scan_duration_ms:.0f} ms</div></div>'
    )
    body_parts.append('</div>')  # meta-grid

    # Deserialization banner
    if deser_findings:
        body_parts.append('<div class="deser-banner">')
        body_parts.append(
            f'<h2>⚠ DESERIALIZATION ATTACK VECTOR DETECTED</h2>'
            f'<p><strong>{len(deser_findings)} deserialization attack vector(s) found.</strong></p>'
            f'<p>Deserialization vulnerabilities allow a malicious skill to execute arbitrary '
            f'code in your agent\'s process <strong>before any policy takes effect</strong>.</p>'
            f'<p style="margin-top:12px; font-weight:700; color:#ff4d4d; font-size:1rem;">'
            f'DO NOT INSTALL THIS SKILL.</p>'
        )
        body_parts.append(
            '<table style="margin-top:16px; border-color:#cc0000;">'
            '<thead><tr>'
            '<th>Category</th><th>File</th><th>Line</th>'
            '<th>Description</th><th>Evidence</th>'
            '</tr></thead><tbody>'
        )
        for f in deser_findings:
            line_str = str(f.line) if f.line is not None else "—"
            ev = f'<code>{esc(f.evidence[:100])}</code>' if f.evidence else "—"
            body_parts.append(
                f'<tr>'
                f'<td>{cat_tag(f.category)}</td>'
                f'<td><code>{esc(f.file)}</code></td>'
                f'<td>{line_str}</td>'
                f'<td>{esc(f.description)}</td>'
                f'<td style="font-family:monospace; font-size:0.8em;">{ev}</td>'
                f'</tr>'
            )
        body_parts.append('</tbody></table>')
        body_parts.append('</div>')  # deser-banner

    # Summary grid
    body_parts.append('<h2>Summary</h2>')
    if not report.findings:
        body_parts.append('<p style="color:#00ff88;">✅ No threats detected.</p>')
    else:
        body_parts.append('<div class="summary-grid">')
        for lvl in ThreatLevel:
            count = sum(1 for f in report.findings if f.level == lvl)
            body_parts.append(summary_cell(lvl, count))
        body_parts.append('</div>')

    # All findings grouped by level
    if report.findings:
        body_parts.append('<h2>All Findings</h2>')
        for lvl in ThreatLevel:
            group = [f for f in report.findings if f.level == lvl]
            if not group:
                continue
            _, text_color = _HTML_LEVEL_COLORS[lvl]
            body_parts.append(
                f'<h3><span style="color:{text_color};">'
                f'{lvl.value.upper()} ({len(group)})</span></h3>'
            )
            for f in group:
                line_str = f":{f.line}" if f.line is not None else ""
                body_parts.append(
                    f'<div class="finding-card {lvl.value}">'
                    f'  <div style="display:flex; gap:8px; align-items:center; margin-bottom:6px;">'
                    f'    {badge(lvl)} {cat_tag(f.category)}'
                    f'    <code style="color:#8b949e; font-size:0.8em;">'
                    f'{esc(f.file)}{line_str}</code>'
                    f'  </div>'
                    f'  <div class="desc">{esc(f.description)}</div>'
                )
                if f.evidence:
                    body_parts.append(
                        f'  <pre style="margin-top:8px;">{esc(f.evidence)}</pre>'
                    )
                if f.recommendation:
                    body_parts.append(
                        f'  <div class="rec">💡 {esc(f.recommendation)}</div>'
                    )
                body_parts.append('</div>')

    body_parts.append(
        '<footer>Report generated by '
        '<a href="https://agentward.ai">AgentWard</a> '
        f'— pre-install security scanner — {esc(now)}</footer>'
    )

    body = "\n".join(body_parts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentWard Pre-Install Scan — {esc(report.target.name)}</title>
  <style>{css}</style>
</head>
<body>
{body}
</body>
</html>
"""
