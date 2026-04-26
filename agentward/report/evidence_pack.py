"""Build a self-contained HTML Evidence Pack for an audit.

The Evidence Pack is the artefact an auditor receives at the end of a
DORA / EU AI Act / MiFID II review: a single HTML file that records, at
a point in time, the policy under enforcement, the compliance evaluation
result for one or more frameworks, the integrity of the audit log, and
the inventory of third-party tools the agent can reach.

This module produces the HTML deterministically from real inputs — no
template engine, no external assets, no JavaScript. The output is meant
to be archived, printed to PDF, and signed off by a human compliance
officer.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentward import __version__
from agentward.audit.integrity import ChainVerification, verify_log
from agentward.comply.controls import (
    ComplianceFinding,
    ComplianceRating,
    ComplianceReport,
    ControlSeverity,
)
from agentward.policy.schema import AgentWardPolicy
from agentward.scan.permissions import ScanResult

# ---------------------------------------------------------------------------
# Data container
# ---------------------------------------------------------------------------


@dataclass
class EvidencePack:
    """Resolved data going into an Evidence Pack render.

    Held as a struct so callers can introspect / test the underlying
    figures without parsing HTML, and so the renderer is pure HTML
    formatting.
    """

    generated_at: str
    agentward_version: str
    policy_path: str
    policy: AgentWardPolicy
    frameworks: list[str]
    reports: dict[str, ComplianceReport] = field(default_factory=dict)
    scan_result: ScanResult | None = None
    audit_log_path: str | None = None
    audit_verification: ChainVerification | None = None
    audit_recent_entries: list[dict[str, Any]] = field(default_factory=list)
    audit_recent_count: int = 0

    def to_html(self) -> str:
        """Render this Evidence Pack as a self-contained HTML document."""
        return _render_html(self)


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------


def build_evidence_pack(
    policy: AgentWardPolicy,
    *,
    policy_path: Path,
    reports: dict[str, ComplianceReport],
    scan_result: ScanResult | None = None,
    audit_log_path: Path | None = None,
    hmac_key: bytes | None = None,
    recent_entry_limit: int = 25,
) -> EvidencePack:
    """Assemble an EvidencePack from already-evaluated inputs.

    The caller is responsible for running scan + compliance evaluation;
    this function only stitches the artefacts together so the HTML
    renderer has a single struct to consume. Keeping evaluation outside
    means we don't accidentally re-run expensive subprocess scans when a
    user just wants to re-render an existing report from cached data.

    Args:
        policy: Loaded `AgentWardPolicy` instance.
        policy_path: Filesystem path the policy came from (shown in the
            HTML header for auditor traceability).
        reports: Mapping of framework name → ComplianceReport. Order is
            preserved in the HTML output.
        scan_result: Optional scan result for the inventory section.
        audit_log_path: Optional path to a JSONL audit log. When
            supplied, integrity is verified and a tail excerpt is
            embedded.
        hmac_key: Optional HMAC key bytes. If None and the env var is
            set, `verify_log` will pick it up. If neither is available,
            integrity verification reports unsigned-only counts.
        recent_entry_limit: Number of audit log entries to include in
            the "recent entries" excerpt. Default 25.

    Returns:
        EvidencePack ready to render via `.to_html()`.
    """
    audit_verification: ChainVerification | None = None
    audit_recent: list[dict[str, Any]] = []
    audit_recent_count = 0

    if audit_log_path is not None:
        if audit_log_path.exists():
            audit_verification = verify_log(audit_log_path, key=hmac_key)
            audit_recent, audit_recent_count = _tail_jsonl(
                audit_log_path, limit=recent_entry_limit,
            )
        else:
            # Caller supplied a path that doesn't exist — surface that as a
            # zero-line verification rather than swallowing the request,
            # so the auditor can see the path was provided but empty.
            audit_verification = ChainVerification(
                total_lines=0, signed_lines=0, unsigned_lines=0,
                ok=True, first_break=None, failures=[],
            )

    return EvidencePack(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        agentward_version=__version__,
        policy_path=str(policy_path),
        policy=policy,
        frameworks=list(reports.keys()),
        reports=reports,
        scan_result=scan_result,
        audit_log_path=str(audit_log_path) if audit_log_path is not None else None,
        audit_verification=audit_verification,
        audit_recent_entries=audit_recent,
        audit_recent_count=audit_recent_count,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tail_jsonl(path: Path, *, limit: int) -> tuple[list[dict[str, Any]], int]:
    """Return (last `limit` parsed entries, total entry count).

    Reads the whole file (audit logs are typically small enough; if they
    aren't, the caller should rotate). Skips blank lines and silently
    drops entries that don't parse as JSON — those are surfaced through
    `verify_log` as failures.
    """
    entries: list[dict[str, Any]] = []
    total = 0
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n").strip()
            if not line:
                continue
            total += 1
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
    if limit > 0:
        entries = entries[-limit:]
    return entries, total


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


_RATING_COLORS = {
    ComplianceRating.GREEN: "#10b981",
    ComplianceRating.YELLOW: "#f59e0b",
    ComplianceRating.RED: "#ef4444",
}

_RATING_LABELS = {
    ComplianceRating.GREEN: "PASS",
    ComplianceRating.YELLOW: "WARN",
    ComplianceRating.RED: "FAIL",
}

_SEVERITY_LABELS = {
    ControlSeverity.REQUIRED: "REQUIRED",
    ControlSeverity.RECOMMENDED: "RECOMMENDED",
}


_CSS = """
* { box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue",
                 Arial, sans-serif;
    color: #111827;
    margin: 0;
    padding: 32px;
    background: #f9fafb;
    line-height: 1.5;
    font-size: 14px;
}
.container { max-width: 1080px; margin: 0 auto; }
h1 { font-size: 28px; margin: 0 0 8px 0; color: #111827; }
h2 {
    font-size: 20px;
    margin: 36px 0 12px 0;
    padding-bottom: 8px;
    border-bottom: 2px solid #e5e7eb;
    color: #1f2937;
}
h3 { font-size: 16px; margin: 24px 0 8px 0; color: #374151; }
.meta {
    color: #6b7280;
    font-size: 13px;
    margin-bottom: 12px;
}
.meta strong { color: #374151; }
.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
    margin: 16px 0 24px 0;
}
.summary-card {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 14px 16px;
}
.summary-card .label {
    color: #6b7280;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 4px;
}
.summary-card .value {
    font-size: 20px;
    font-weight: 600;
    color: #111827;
}
.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: 0.04em;
}
table {
    width: 100%;
    border-collapse: collapse;
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    overflow: hidden;
    margin: 8px 0 20px 0;
    font-size: 13px;
}
th {
    background: #f3f4f6;
    text-align: left;
    padding: 10px 12px;
    font-weight: 600;
    color: #374151;
    border-bottom: 1px solid #e5e7eb;
}
td {
    padding: 10px 12px;
    border-bottom: 1px solid #f3f4f6;
    vertical-align: top;
}
tr:last-child td { border-bottom: none; }
.muted { color: #6b7280; }
.mono { font-family: "SF Mono", "Menlo", "Consolas", monospace; font-size: 12px; }
.kv { font-family: "SF Mono", "Menlo", "Consolas", monospace; font-size: 12px; }
.callout {
    border-left: 4px solid #3b82f6;
    background: #eff6ff;
    padding: 12px 16px;
    margin: 12px 0;
    border-radius: 4px;
    font-size: 13px;
}
.callout.warn {
    border-left-color: #f59e0b;
    background: #fffbeb;
}
.callout.bad {
    border-left-color: #ef4444;
    background: #fef2f2;
}
.callout.good {
    border-left-color: #10b981;
    background: #f0fdf4;
}
.audit-entry {
    background: #ffffff;
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    padding: 10px 12px;
    margin-bottom: 8px;
    font-family: "SF Mono", "Menlo", "Consolas", monospace;
    font-size: 11px;
    word-break: break-all;
}
footer {
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid #e5e7eb;
    color: #6b7280;
    font-size: 12px;
}
@media print {
    body { background: #ffffff; padding: 0; }
    .summary-card, table, .audit-entry { box-shadow: none; }
    h2 { page-break-after: avoid; }
    table { page-break-inside: auto; }
    tr { page-break-inside: avoid; page-break-after: auto; }
}
"""


def _esc(value: Any) -> str:
    """HTML-escape, treating None as empty string."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def _badge(text: str, color: str) -> str:
    return (
        f'<span class="badge" style="background-color: {color};">'
        f'{_esc(text)}</span>'
    )


def _rating_badge(rating: ComplianceRating) -> str:
    return _badge(_RATING_LABELS[rating], _RATING_COLORS[rating])


def _section_header(pack: EvidencePack) -> str:
    owners = sorted({
        meta.owner for meta in pack.policy.skill_metadata.values()
        if meta.owner
    })
    skill_count = len(pack.policy.skills)

    rows = [
        ("AgentWard version", pack.agentward_version),
        ("Generated (UTC)", pack.generated_at),
        ("Policy file", pack.policy_path),
        ("Policy version", pack.policy.version),
        ("Frameworks evaluated", ", ".join(pack.frameworks) or "—"),
        ("Skills under policy", str(skill_count)),
        ("Distinct owners declared", str(len(owners)) if owners else "—"),
        ("Default action", pack.policy.default_action.value),
    ]
    rows_html = "\n".join(
        f'<tr><th style="width: 240px;">{_esc(k)}</th>'
        f'<td class="kv">{_esc(v)}</td></tr>'
        for k, v in rows
    )
    return (
        '<h2>Header</h2>\n'
        '<table>\n'
        f'{rows_html}\n'
        '</table>\n'
    )


def _section_executive_summary(pack: EvidencePack) -> str:
    cards = []
    for fw, report in pack.reports.items():
        required = sum(
            1 for f in report.findings
            if f.severity == ControlSeverity.REQUIRED
        )
        recommended = sum(
            1 for f in report.findings
            if f.severity == ControlSeverity.RECOMMENDED
        )
        if required > 0:
            color = _RATING_COLORS[ComplianceRating.RED]
            label = "REQUIRED GAPS"
        elif recommended > 0:
            color = _RATING_COLORS[ComplianceRating.YELLOW]
            label = "RECOMMENDED ONLY"
        else:
            color = _RATING_COLORS[ComplianceRating.GREEN]
            label = "CLEAN"
        cards.append(
            f'<div class="summary-card">'
            f'<div class="label">{_esc(fw.upper())}</div>'
            f'<div class="value">{required} required · {recommended} recommended</div>'
            f'<div style="margin-top: 6px;">{_badge(label, color)}</div>'
            f'</div>'
        )

    if pack.audit_verification is not None:
        v = pack.audit_verification
        if v.total_lines == 0:
            audit_label = "EMPTY"
            audit_color = "#9ca3af"
        elif v.ok and v.signed_lines > 0:
            audit_label = "VERIFIED"
            audit_color = _RATING_COLORS[ComplianceRating.GREEN]
        elif v.ok and v.signed_lines == 0:
            audit_label = "UNSIGNED"
            audit_color = _RATING_COLORS[ComplianceRating.YELLOW]
        else:
            audit_label = "BROKEN"
            audit_color = _RATING_COLORS[ComplianceRating.RED]
        cards.append(
            f'<div class="summary-card">'
            f'<div class="label">AUDIT CHAIN</div>'
            f'<div class="value">{v.signed_lines}/{v.total_lines} signed</div>'
            f'<div style="margin-top: 6px;">{_badge(audit_label, audit_color)}</div>'
            f'</div>'
        )

    if not cards:
        return ""

    return (
        '<h2>Executive Summary</h2>\n'
        f'<div class="summary-grid">{"".join(cards)}</div>\n'
    )


def _section_policy_summary(pack: EvidencePack) -> str:
    skills = sorted(pack.policy.skills.keys())
    if not skills:
        return (
            '<h2>Policy Summary</h2>\n'
            '<div class="callout warn">No skills declared in policy. '
            'A policy with no skills falls back to the default action '
            'for every tool call.</div>\n'
        )

    rows = []
    for skill in skills:
        meta = pack.policy.skill_metadata.get(skill)
        owner = meta.owner if meta and meta.owner else "—"
        if meta and meta.subcontractor_chain:
            chain_html = "<br>".join(
                f"<span class='mono'>{_esc(s.vendor)}</span> — "
                f"{_esc(s.role)}"
                + (
                    f" <span class='muted'>({_esc(s.data_residency)})</span>"
                    if s.data_residency else ""
                )
                + (
                    f" <span class='muted'>[{_esc(s.contract_status)}]</span>"
                    if s.contract_status else ""
                )
                for s in meta.subcontractor_chain
            )
        else:
            chain_html = "<span class='muted'>— (not documented)</span>"
        resources = ", ".join(sorted(pack.policy.skills[skill].keys())) or "—"
        rows.append(
            f"<tr>"
            f"<td><strong>{_esc(skill)}</strong></td>"
            f"<td class='mono'>{_esc(resources)}</td>"
            f"<td>{_esc(owner)}</td>"
            f"<td>{chain_html}</td>"
            f"</tr>"
        )

    return (
        '<h2>Policy Summary</h2>\n'
        '<table>\n'
        '<tr><th>Skill</th><th>Resources</th><th>Owner</th>'
        '<th>Subcontractor chain</th></tr>\n'
        + "\n".join(rows) + "\n</table>\n"
    )


def _findings_table(findings: list[ComplianceFinding]) -> str:
    if not findings:
        return (
            '<div class="callout good">No findings — every control passed '
            'for this framework.</div>\n'
        )

    by_section: dict[str, list[ComplianceFinding]] = {}
    for f in findings:
        # ComplianceFinding doesn't carry section directly; we group by
        # the control_id prefix before the dot for stability.
        section = f.control_id.split(".", 1)[0]
        by_section.setdefault(section, []).append(f)

    parts: list[str] = []
    for section in sorted(by_section.keys()):
        rows = []
        for f in by_section[section]:
            sev_color = (
                _RATING_COLORS[ComplianceRating.RED]
                if f.severity == ControlSeverity.REQUIRED
                else _RATING_COLORS[ComplianceRating.YELLOW]
            )
            sev_badge = _badge(_SEVERITY_LABELS[f.severity], sev_color)
            fix_text = "auto-fix available" if f.fix is not None else "manual fix required"
            fix_color = "#10b981" if f.fix is not None else "#6b7280"
            rows.append(
                "<tr>"
                f"<td class='mono'>{_esc(f.control_id)}</td>"
                f"<td>{_esc(f.skill or '—')}</td>"
                f"<td>{sev_badge}</td>"
                f"<td>{_esc(f.description)}</td>"
                f"<td>{_badge(fix_text, fix_color)}</td>"
                "</tr>"
            )
        parts.append(
            f"<h3>Section: {_esc(section)}</h3>\n"
            "<table>\n"
            "<tr><th style='width: 220px;'>Control ID</th><th>Skill</th>"
            "<th>Severity</th><th>Description</th><th>Fix</th></tr>\n"
            + "\n".join(rows) + "\n</table>\n"
        )

    return "\n".join(parts)


def _section_framework_findings(pack: EvidencePack) -> str:
    if not pack.reports:
        return ""

    parts: list[str] = ["<h2>Framework Findings</h2>"]
    for fw, report in pack.reports.items():
        required = sum(
            1 for f in report.findings
            if f.severity == ControlSeverity.REQUIRED
        )
        recommended = sum(
            1 for f in report.findings
            if f.severity == ControlSeverity.RECOMMENDED
        )
        red_skills = sum(
            1 for r in report.skill_ratings.values()
            if r == ComplianceRating.RED
        )
        yellow_skills = sum(
            1 for r in report.skill_ratings.values()
            if r == ComplianceRating.YELLOW
        )
        green_skills = sum(
            1 for r in report.skill_ratings.values()
            if r == ComplianceRating.GREEN
        )
        parts.append(
            f"<h3>{_esc(fw.upper())}</h3>\n"
            "<div class='meta'>"
            f"<strong>{required}</strong> required · "
            f"<strong>{recommended}</strong> recommended findings · "
            f"<strong>{red_skills}</strong> RED · "
            f"<strong>{yellow_skills}</strong> YELLOW · "
            f"<strong>{green_skills}</strong> GREEN skills"
            "</div>"
        )
        if report.skill_ratings:
            rating_rows = []
            for skill in sorted(report.skill_ratings.keys()):
                rating = report.skill_ratings[skill]
                rating_rows.append(
                    f"<tr><td><strong>{_esc(skill)}</strong></td>"
                    f"<td>{_rating_badge(rating)}</td></tr>"
                )
            parts.append(
                "<table>\n"
                "<tr><th style='width: 280px;'>Skill</th><th>Rating</th></tr>\n"
                + "\n".join(rating_rows) + "\n</table>\n"
            )
        parts.append(_findings_table(report.findings))

    return "\n".join(parts)


def _section_audit(pack: EvidencePack) -> str:
    if pack.audit_verification is None:
        return (
            "<h2>Audit Log Integrity</h2>\n"
            '<div class="callout">No audit log path supplied. To include '
            'an audit-chain integrity check, re-run with '
            '<code>--audit-log /path/to/audit.jsonl</code>.</div>\n'
        )

    v = pack.audit_verification
    if v.total_lines == 0:
        callout = (
            '<div class="callout">Audit log is empty (0 entries). Either '
            'no traffic has been processed yet or the path was just '
            'created.</div>'
        )
    elif v.ok and v.signed_lines > 0:
        callout = (
            f'<div class="callout good">All {v.signed_lines} signed '
            f'entries verified — HMAC chain is intact.</div>'
        )
    elif v.ok and v.signed_lines == 0:
        callout = (
            '<div class="callout warn">Log contains entries but none are '
            'HMAC-signed. Set <code>AGENTWARD_AUDIT_HMAC_KEY</code> in '
            'the proxy environment to enable tamper-evident logging.</div>'
        )
    else:
        first = v.first_break or "?"
        callout = (
            f'<div class="callout bad">Chain BROKEN at line {first}. '
            f'{len(v.failures)} verification failure(s) recorded — '
            f'see the JSONL log for full detail.</div>'
        )

    rows_html = "\n".join(
        f'<tr><th style="width: 240px;">{_esc(k)}</th>'
        f'<td class="kv">{_esc(v_)}</td></tr>'
        for k, v_ in [
            ("Audit log path", pack.audit_log_path or "—"),
            ("Total entries", v.total_lines),
            ("Signed entries", v.signed_lines),
            ("Unsigned entries", v.unsigned_lines),
            ("Chain intact", "yes" if v.ok else "no"),
            ("First break (line)", v.first_break if v.first_break else "—"),
            ("Failures recorded", len(v.failures)),
        ]
    )

    excerpt = ""
    if pack.audit_recent_entries:
        entries_html = []
        for entry in pack.audit_recent_entries:
            entries_html.append(
                f'<div class="audit-entry">'
                f'{_esc(json.dumps(entry, sort_keys=True))}</div>'
            )
        skipped = max(0, pack.audit_recent_count - len(pack.audit_recent_entries))
        skipped_note = (
            f'<p class="muted">… {skipped} earlier entries omitted '
            f'(showing last {len(pack.audit_recent_entries)}).</p>'
            if skipped > 0 else ""
        )
        excerpt = (
            "<h3>Recent entries</h3>\n"
            f"{skipped_note}"
            + "\n".join(entries_html) + "\n"
        )

    return (
        "<h2>Audit Log Integrity</h2>\n"
        f"{callout}\n"
        "<table>\n" + rows_html + "\n</table>\n"
        + excerpt
    )


def _section_scan_inventory(pack: EvidencePack) -> str:
    if pack.scan_result is None or not pack.scan_result.servers:
        return (
            "<h2>Scan Inventory</h2>\n"
            '<div class="callout">No scan inventory available. '
            'Re-run with a scan target (e.g. '
            '<code>agentward report ~/.cursor/mcp.json</code>) to include '
            'the live tool inventory.</div>\n'
        )

    rows = []
    for server_map in pack.scan_result.servers:
        server = server_map.server
        tool_names = [t.tool.name for t in server_map.tools]
        rows.append(
            "<tr>"
            f"<td><strong>{_esc(server.name)}</strong></td>"
            f"<td class='mono'>{_esc(server.transport.value)}</td>"
            f"<td class='mono'>{_esc(server_map.enumeration_method)}</td>"
            f"<td>{len(tool_names)}</td>"
            f"<td class='mono'>{_esc(', '.join(tool_names) or '—')}</td>"
            f"<td>{_esc(server_map.overall_risk.value)}</td>"
            "</tr>"
        )

    return (
        "<h2>Scan Inventory</h2>\n"
        "<table>\n"
        "<tr><th>Server</th><th>Transport</th><th>Method</th>"
        "<th>Tool count</th><th>Tools</th><th>Risk</th></tr>\n"
        + "\n".join(rows) + "\n</table>\n"
    )


def _section_footer(pack: EvidencePack) -> str:
    return (
        "<footer>\n"
        f"<p>Generated by AgentWard v{_esc(pack.agentward_version)} "
        f"on {_esc(pack.generated_at)}. "
        "This file is automatically produced from policy, scan, and "
        "audit-log inputs at the time of generation. It is not a legal "
        "attestation. A human compliance officer must review and sign "
        "before submitting to a regulator.</p>\n"
        "<p>AgentWard is licensed under the Business Source License 1.1; "
        "this report file is a derivative artefact owned by the deployer.</p>\n"
        "</footer>\n"
    )


def _render_html(pack: EvidencePack) -> str:
    title = f"AgentWard Evidence Pack — {pack.generated_at}"
    body = "".join([
        _section_header(pack),
        _section_executive_summary(pack),
        _section_policy_summary(pack),
        _section_framework_findings(pack),
        _section_audit(pack),
        _section_scan_inventory(pack),
        _section_footer(pack),
    ])
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>{_esc(title)}</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        "<body>\n"
        '<div class="container">\n'
        f"<h1>{_esc(title)}</h1>\n"
        f"{body}\n"
        "</div>\n"
        "</body>\n"
        "</html>\n"
    )
