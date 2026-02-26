"""Self-contained HTML scan report generator.

Produces a single-file HTML report with embedded CSS and data, suitable for
sharing via email, Slack, or hosting on a static site. Styled to match
the agentward.ai dark theme.

The "Lighthouse for agent security" — a shareable snapshot of an agent's
tool permission posture.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

import agentward
from agentward.scan.chains import ChainDetection, ChainRisk, detect_chains
from agentward.scan.permissions import (
    DataAccessType,
    RiskLevel,
    ScanResult,
    ToolPermission,
    ServerPermissionMap,
)
from agentward.scan.recommendations import Recommendation, RecommendationSeverity


# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

_RISK_COLORS = {
    RiskLevel.CRITICAL: "#ff3366",
    RiskLevel.HIGH: "#ff6b35",
    RiskLevel.MEDIUM: "#ffcc00",
    RiskLevel.LOW: "#00ff88",
}

_RISK_LABELS = {
    RiskLevel.CRITICAL: "CRITICAL",
    RiskLevel.HIGH: "HIGH",
    RiskLevel.MEDIUM: "MEDIUM",
    RiskLevel.LOW: "LOW",
}

_ACCESS_ICONS: dict[DataAccessType, str] = {
    DataAccessType.FILESYSTEM: "📁",
    DataAccessType.NETWORK: "🌐",
    DataAccessType.DATABASE: "🗄️",
    DataAccessType.EMAIL: "✉️",
    DataAccessType.MESSAGING: "💬",
    DataAccessType.CREDENTIALS: "🔑",
    DataAccessType.SHELL: "💻",
    DataAccessType.CODE: "📝",
    DataAccessType.BROWSER: "🔍",
    DataAccessType.FINANCIAL: "💰",
}


def generate_scan_html(
    scan: ScanResult,
    recommendations: list[Recommendation],
    chains: list[ChainDetection] | None = None,
) -> str:
    """Generate a self-contained HTML scan report.

    Args:
        scan: The complete scan result.
        recommendations: Generated recommendations.
        chains: Detected skill chains (computed if not provided).

    Returns:
        Complete HTML string.
    """
    if chains is None:
        chains = detect_chains(scan)

    total_tools = sum(len(s.tools) for s in scan.servers)
    total_servers = len(scan.servers)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Risk counts
    risk_counts: dict[RiskLevel, int] = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.LOW: 0,
    }
    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            risk_counts[tool_perm.risk_level] += 1

    # Compute overall score (0-100, higher = more secure)
    score = _compute_score(risk_counts, len(chains))

    # Build HTML sections
    score_html = _score_badge_html(score)
    summary_html = _summary_html(total_tools, total_servers, risk_counts, len(chains), ts)
    table_html = _permission_table_html(scan)
    chains_html = _chains_html(chains) if chains else ""
    recs_html = _recommendations_html(recommendations) if recommendations else ""

    return _wrap_html(score_html, summary_html, table_html, chains_html, recs_html)


def _compute_score(
    risk_counts: dict[RiskLevel, int],
    chain_count: int,
) -> int:
    """Compute a security posture score (0-100).

    Deductions:
      - CRITICAL: -20 each
      - HIGH: -10 each
      - MEDIUM: -3 each
      - Chain: -5 each
    """
    total = 100
    total -= risk_counts.get(RiskLevel.CRITICAL, 0) * 20
    total -= risk_counts.get(RiskLevel.HIGH, 0) * 10
    total -= risk_counts.get(RiskLevel.MEDIUM, 0) * 3
    total -= chain_count * 5
    return max(0, min(100, total))


def _score_color(score: int) -> str:
    """Map a score to a color."""
    if score >= 80:
        return "#00ff88"
    elif score >= 50:
        return "#ffcc00"
    else:
        return "#ff3366"


def _score_badge_html(score: int) -> str:
    """Render the score as a large circular badge."""
    color = _score_color(score)
    return f"""
    <div class="score-badge">
      <svg viewBox="0 0 120 120" width="120" height="120">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#333" stroke-width="8"/>
        <circle cx="60" cy="60" r="54" fill="none" stroke="{color}" stroke-width="8"
          stroke-dasharray="{score * 3.39} 339"
          stroke-dashoffset="0"
          transform="rotate(-90 60 60)"
          stroke-linecap="round"/>
        <text x="60" y="55" text-anchor="middle" fill="{color}"
          font-size="32" font-weight="bold" font-family="monospace">{score}</text>
        <text x="60" y="75" text-anchor="middle" fill="#888"
          font-size="12" font-family="sans-serif">/ 100</text>
      </svg>
      <div class="score-label">Security Score</div>
    </div>
    """


def _summary_html(
    total_tools: int,
    total_servers: int,
    risk_counts: dict[RiskLevel, int],
    chain_count: int,
    timestamp: str,
) -> str:
    """Render the summary stats cards."""
    cards = []
    for level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW):
        count = risk_counts[level]
        if count > 0:
            color = _RISK_COLORS[level]
            label = _RISK_LABELS[level]
            cards.append(
                f'<div class="stat-card" style="border-left: 3px solid {color}">'
                f'<div class="stat-count" style="color: {color}">{count}</div>'
                f'<div class="stat-label">{label}</div></div>'
            )

    if chain_count:
        cards.append(
            f'<div class="stat-card" style="border-left: 3px solid #ffcc00">'
            f'<div class="stat-count" style="color: #ffcc00">{chain_count}</div>'
            f'<div class="stat-label">Chains</div></div>'
        )

    return f"""
    <div class="summary">
      <div class="meta">
        <span>{total_tools} tools</span> · <span>{total_servers} servers</span> · <span>{timestamp}</span>
      </div>
      <div class="stat-cards">{''.join(cards)}</div>
    </div>
    """


def _source_badge(server_map: ServerPermissionMap) -> str:
    """Classify a server into a source badge."""
    transport = server_map.server.transport.value
    if transport == "openclaw":
        return "Skill"
    if transport == "python":
        return "SDK"
    return "MCP"


def _capabilities_label(tool_perm: ToolPermission) -> str:
    """Build capabilities string with icons."""
    seen: set[DataAccessType] = set()
    parts: list[str] = []
    for access in tool_perm.data_access:
        if access.type not in seen:
            seen.add(access.type)
            icon = _ACCESS_ICONS.get(access.type, "")
            parts.append(f"{icon} {access.type.value}")
    return ", ".join(parts) if parts else "—"


def _risk_reason_summary(tool_perm: ToolPermission) -> str:
    """Return a concise risk reason for display."""
    if tool_perm.risk_level == RiskLevel.LOW:
        return ""
    meaningful = [
        r for r in tool_perm.risk_reasons
        if not r.startswith("Annotations ")
        and r != "No specific risk signals detected"
        and r != "Read-only operation"
    ]
    if not meaningful:
        return ""
    return meaningful[-1]


def _permission_table_html(scan: ScanResult) -> str:
    """Render the permission map as an HTML table."""
    rows = []
    for server_map in scan.servers:
        source = _source_badge(server_map)
        for tool_perm in server_map.tools:
            caps = _capabilities_label(tool_perm)
            risk = tool_perm.risk_level
            color = _RISK_COLORS[risk]
            label = _RISK_LABELS[risk]
            why = html.escape(_risk_reason_summary(tool_perm))
            name = html.escape(tool_perm.tool.name)
            rows.append(
                f"<tr>"
                f"<td>{html.escape(source)}</td>"
                f"<td><code>{name}</code></td>"
                f"<td>{caps}</td>"
                f'<td><span class="risk-badge" style="background:{color}20;color:{color}">{label}</span></td>'
                f"<td class=\"reason\">{why}</td>"
                f"</tr>"
            )

    if not rows:
        return "<p class='dim'>No tools found.</p>"

    return f"""
    <h2>Permission Map</h2>
    <table>
      <thead>
        <tr><th>Source</th><th>Tool</th><th>Capabilities</th><th>Risk</th><th>Why</th></tr>
      </thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
    """


def _chains_html(chains: list[ChainDetection]) -> str:
    """Render detected chains."""
    items = []
    for chain in chains:
        risk_color = "#ff3366" if chain.risk == ChainRisk.CRITICAL else "#ffcc00"
        risk_label = chain.risk.value
        items.append(
            f'<div class="chain-item" style="border-left: 3px solid {risk_color}">'
            f'<div class="chain-header">'
            f'<span class="risk-badge" style="background:{risk_color}20;color:{risk_color}">{risk_label}</span>'
            f' <code>{html.escape(chain.label)}</code></div>'
            f'<div class="chain-desc">{html.escape(chain.description)}</div>'
            f"</div>"
        )
    return f"<h2>Skill Chains Detected</h2><div class='chains'>{''.join(items)}</div>"


def _recommendations_html(recommendations: list[Recommendation]) -> str:
    """Render recommendations."""
    items = []
    for i, rec in enumerate(recommendations, 1):
        sev = rec.severity.value
        if sev == "CRITICAL":
            sev_color = "#ff3366"
        elif sev == "WARNING":
            sev_color = "#ffcc00"
        else:
            sev_color = "#5eead4"

        policy_html = ""
        if rec.suggested_policy:
            policy_html = f"<pre><code>{html.escape(rec.suggested_policy)}</code></pre>"

        items.append(
            f'<div class="rec-item">'
            f'<div class="rec-header">'
            f'<span class="risk-badge" style="background:{sev_color}20;color:{sev_color}">{sev}</span>'
            f' {html.escape(rec.message)}</div>'
            f"{policy_html}"
            f"</div>"
        )
    return f"<h2>Recommendations</h2><div class='recs'>{''.join(items)}</div>"


def _wrap_html(
    score_html: str,
    summary_html: str,
    table_html: str,
    chains_html: str,
    recs_html: str,
) -> str:
    """Wrap all sections in a complete HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentWard Scan Report</title>
<style>
  :root {{ --bg: #0a0a0a; --fg: #e0e0e0; --border: #222; --card-bg: #111; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--fg); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.6; padding: 2rem; max-width: 1100px; margin: 0 auto; }}
  h1 {{ color: #00ff88; font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ color: #5eead4; font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
  .header {{ display: flex; align-items: center; gap: 2rem; margin-bottom: 2rem; }}
  .header-text {{ flex: 1; }}
  .header-text p {{ color: #888; font-size: 0.85rem; }}
  .score-badge {{ text-align: center; }}
  .score-label {{ color: #888; font-size: 0.8rem; margin-top: 0.3rem; }}
  .summary {{ margin-bottom: 2rem; }}
  .meta {{ color: #666; font-size: 0.8rem; margin-bottom: 0.8rem; }}
  .stat-cards {{ display: flex; gap: 1rem; flex-wrap: wrap; }}
  .stat-card {{ background: var(--card-bg); padding: 1rem 1.5rem; border-radius: 8px; }}
  .stat-count {{ font-size: 1.8rem; font-weight: bold; }}
  .stat-label {{ font-size: 0.8rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 0.6rem 0.8rem; border-bottom: 2px solid var(--border); color: #888; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
  td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: #151515; }}
  code {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85em; background: #1a1a2e; padding: 0.15em 0.4em; border-radius: 3px; }}
  .risk-badge {{ display: inline-block; padding: 0.15em 0.6em; border-radius: 4px; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.03em; }}
  .reason {{ color: #888; max-width: 300px; }}
  .dim {{ color: #666; }}
  .chain-item, .rec-item {{ background: var(--card-bg); padding: 0.8rem 1rem; border-radius: 6px; margin-bottom: 0.5rem; }}
  .chain-header, .rec-header {{ font-size: 0.9rem; margin-bottom: 0.3rem; }}
  .chain-desc {{ color: #888; font-size: 0.8rem; }}
  .chains, .recs {{ display: flex; flex-direction: column; gap: 0.5rem; }}
  pre {{ background: #1a1a2e; padding: 0.8rem; border-radius: 6px; overflow-x: auto; margin-top: 0.5rem; }}
  pre code {{ background: none; padding: 0; }}
  .footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: #555; font-size: 0.75rem; text-align: center; }}
  .footer a {{ color: #5eead4; text-decoration: none; }}
  @media (max-width: 700px) {{ .header {{ flex-direction: column; gap: 1rem; }} .stat-cards {{ flex-direction: column; }} }}
</style>
</head>
<body>
  <div class="header">
    <div class="header-text">
      <h1>🛡️ AgentWard Scan Report</h1>
      <p>v{agentward.__version__}</p>
    </div>
    {score_html}
  </div>
  {summary_html}
  {table_html}
  {chains_html}
  {recs_html}
  <div class="footer">
    Generated by <a href="https://agentward.ai">AgentWard</a> — open-source permission control plane for AI agents.
  </div>
</body>
</html>"""
