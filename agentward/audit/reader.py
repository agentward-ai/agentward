"""Audit log reader and dashboard.

Reads JSON Lines audit logs produced by the AuditLogger and generates
summary statistics, decision breakdowns, and event timelines.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


@dataclass
class AuditStats:
    """Aggregated statistics from an audit log.

    Attributes:
        total_events: Total number of log entries.
        tool_calls: Number of tool_call events.
        decisions: Counter of decision values (ALLOW, BLOCK, etc.).
        tools: Counter of tool names.
        blocked_tools: Counter of tools that were blocked.
        chain_violations: Number of chain violation blocks.
        dry_run_count: Number of events logged in dry-run mode.
        approvals: Number of approval dialog events.
        sensitive_blocks: Number of sensitive data blocks.
        first_timestamp: Earliest event timestamp (ISO string).
        last_timestamp: Latest event timestamp (ISO string).
        sessions: Number of startup events (proxy sessions).
        entries: Raw list of parsed log entries.
    """

    total_events: int = 0
    tool_calls: int = 0
    decisions: Counter = field(default_factory=Counter)
    tools: Counter = field(default_factory=Counter)
    blocked_tools: Counter = field(default_factory=Counter)
    chain_violations: int = 0
    dry_run_count: int = 0
    approvals: int = 0
    sensitive_blocks: int = 0
    first_timestamp: str | None = None
    last_timestamp: str | None = None
    sessions: int = 0
    entries: list[dict[str, Any]] = field(default_factory=list)


def read_audit_log(
    log_path: Path,
    *,
    decision_filter: str | None = None,
    tool_filter: str | None = None,
    last_n: int | None = None,
) -> AuditStats:
    """Read and aggregate an audit log file.

    Args:
        log_path: Path to the JSON Lines audit log.
        decision_filter: Only include tool_call events with this decision
                         (e.g., "BLOCK", "ALLOW"). Case-insensitive.
        tool_filter: Only include events for this tool name (substring match).
        last_n: Only read the last N lines of the file.

    Returns:
        Aggregated statistics.

    Raises:
        FileNotFoundError: If the log file doesn't exist.
    """
    if not log_path.exists():
        raise FileNotFoundError(
            f"Audit log not found: {log_path}\n"
            f"Run `agentward inspect --log {log_path}` to generate one."
        )

    lines = log_path.read_text(encoding="utf-8").strip().split("\n")
    if last_n is not None and last_n > 0:
        lines = lines[-last_n:]

    stats = AuditStats()

    for line in lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        event = entry.get("event", "")
        tool = entry.get("tool", "")
        decision = entry.get("decision", "")
        timestamp = entry.get("timestamp", "")

        # Apply filters
        if decision_filter and event == "tool_call":
            if decision.upper() != decision_filter.upper():
                continue
        if tool_filter and tool and tool_filter.lower() not in tool.lower():
            continue

        stats.total_events += 1
        stats.entries.append(entry)

        # Track time range
        if timestamp:
            if stats.first_timestamp is None:
                stats.first_timestamp = timestamp
            stats.last_timestamp = timestamp

        # Aggregate by event type
        if event == "tool_call":
            stats.tool_calls += 1
            if decision:
                stats.decisions[decision] += 1
            if tool:
                stats.tools[tool] += 1
            if decision == "BLOCK":
                if tool:
                    stats.blocked_tools[tool] += 1
            if entry.get("chain_violation"):
                stats.chain_violations += 1
            if entry.get("dry_run"):
                stats.dry_run_count += 1
        elif event == "approval_dialog":
            stats.approvals += 1
        elif event == "sensitive_data_blocked":
            stats.sensitive_blocks += 1
        elif event in ("startup", "http_proxy_startup", "llm_proxy_startup"):
            stats.sessions += 1

    return stats


def render_dashboard(
    stats: AuditStats,
    console: Console,
    *,
    show_timeline: bool = False,
    timeline_limit: int = 50,
) -> None:
    """Render the audit dashboard to a rich console.

    Args:
        stats: The aggregated audit statistics.
        console: Rich console for output.
        show_timeline: Whether to show the event timeline.
        timeline_limit: Maximum number of timeline entries to show.
    """
    if stats.total_events == 0:
        console.print("[dim]No events found in audit log.[/dim]")
        return

    # ---- Summary panel ----
    summary_lines = []
    summary_lines.append(f"  Events:     {stats.total_events}")
    summary_lines.append(f"  Tool calls: {stats.tool_calls}")
    summary_lines.append(f"  Sessions:   {stats.sessions}")
    if stats.first_timestamp and stats.last_timestamp:
        summary_lines.append(f"  Time range: {_format_ts(stats.first_timestamp)} → {_format_ts(stats.last_timestamp)}")
    if stats.dry_run_count:
        summary_lines.append(f"  Dry-run:    {stats.dry_run_count}")
    if stats.approvals:
        summary_lines.append(f"  Approvals:  {stats.approvals}")
    if stats.sensitive_blocks:
        summary_lines.append(f"  Sensitive:  {stats.sensitive_blocks} blocked")

    console.print(Panel(
        "\n".join(summary_lines),
        title="[bold]Audit Summary[/bold]",
        border_style="bright_cyan",
        padding=(0, 1),
    ))

    # ---- Decisions breakdown ----
    if stats.decisions:
        table = Table(title="Decisions", show_header=True, header_style="bold")
        table.add_column("Decision", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Bar", min_width=20)

        max_count = max(stats.decisions.values()) if stats.decisions else 1
        for decision, count in stats.decisions.most_common():
            bar_len = int((count / max_count) * 20)
            color = _decision_color(decision)
            bar = f"[{color}]{'█' * bar_len}[/{color}]"
            table.add_row(
                f"[{color}]{decision}[/{color}]",
                str(count),
                bar,
            )

        console.print(table)

    # ---- Top tools ----
    if stats.tools:
        table = Table(title="Top Tools", show_header=True, header_style="bold")
        table.add_column("Tool", style="cyan")
        table.add_column("Calls", justify="right")
        table.add_column("Blocked", justify="right", style="red")

        for tool, count in stats.tools.most_common(15):
            blocked = stats.blocked_tools.get(tool, 0)
            blocked_str = str(blocked) if blocked > 0 else "[dim]-[/dim]"
            table.add_row(tool, str(count), blocked_str)

        console.print(table)

    # ---- Chain violations ----
    if stats.chain_violations:
        console.print(
            f"\n[bold red]⚠ Chain violations: {stats.chain_violations}[/bold red]"
        )

    # ---- Timeline ----
    if show_timeline and stats.entries:
        console.print()
        table = Table(
            title="Event Timeline",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Time", style="dim", width=12)
        table.add_column("Event", width=14)
        table.add_column("Tool", style="cyan")
        table.add_column("Decision")
        table.add_column("Details", style="dim")

        display_entries = stats.entries[-timeline_limit:]
        for entry in display_entries:
            ts = _format_ts(entry.get("timestamp", ""))
            event = entry.get("event", "")
            tool = entry.get("tool", "")
            decision = entry.get("decision", "")
            detail = ""

            if event == "tool_call":
                color = _decision_color(decision)
                decision_str = f"[{color}]{decision}[/{color}]"
                if entry.get("dry_run"):
                    decision_str += " [#5eead4](dry)[/#5eead4]"
                if entry.get("chain_violation"):
                    detail = "chain violation"
            elif event in ("startup", "http_proxy_startup", "llm_proxy_startup"):
                decision_str = ""
                mode = entry.get("mode", "")
                detail = f"mode={mode}"
            elif event == "shutdown":
                decision_str = ""
                detail = entry.get("reason", "")[:40]
            elif event == "approval_dialog":
                decision_str = entry.get("decision", "")
                detail = f"{entry.get('elapsed_ms', '?')}ms"
            elif event == "sensitive_data_blocked":
                decision_str = "[red]SENSITIVE[/red]"
                findings = entry.get("findings", [])
                detail = ", ".join(f.get("type", "") for f in findings) if findings else ""
            else:
                decision_str = ""
                detail = ""

            table.add_row(ts, event, tool, decision_str, detail)

        console.print(table)


def _format_ts(ts: str) -> str:
    """Format an ISO timestamp for display (time only, no date)."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return ts[:19]


def _decision_color(decision: str) -> str:
    """Map a decision string to a rich color."""
    colors = {
        "ALLOW": "#00ff88",
        "BLOCK": "red",
        "APPROVE": "#ffcc00",
        "REDACT": "#ffcc00",
        "LOG": "#5eead4",
    }
    return colors.get(decision, "white")
