"""Live proxy status reporting.

Checks whether an AgentWard proxy is running, reads its audit log for
real-time statistics, and renders a compact status panel.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ProxyInfo:
    """Information about a running (or recently-running) proxy."""

    port: int
    pid: int
    alive: bool
    pid_file: Path


@dataclass
class ProxyStatus:
    """Aggregated proxy status for display."""

    proxies: list[ProxyInfo] = field(default_factory=list)
    audit_log: Path | None = None
    audit_exists: bool = False

    # Counters from audit log (current session only)
    total_calls: int = 0
    decisions: dict[str, int] = field(default_factory=dict)
    blocked_tools: dict[str, int] = field(default_factory=dict)
    chain_violations: int = 0
    sensitive_blocks: int = 0
    approvals: int = 0
    dry_run_count: int = 0

    # Timing
    session_start: str | None = None
    last_event: str | None = None
    uptime_seconds: float | None = None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

_AGENTWARD_DIR = Path.home() / ".agentward"


def find_running_proxies() -> list[ProxyInfo]:
    """Scan PID files in ~/.agentward/ to find running proxy processes.

    Returns:
        List of ProxyInfo for each PID file found (alive or stale).
    """
    results: list[ProxyInfo] = []

    if not _AGENTWARD_DIR.is_dir():
        return results

    for pid_file in sorted(_AGENTWARD_DIR.glob("proxy-*.pid")):
        try:
            port = int(pid_file.stem.split("-", 1)[1])
        except (IndexError, ValueError):
            continue

        try:
            pid = int(pid_file.read_text().strip())
        except (ValueError, OSError):
            continue

        alive = _is_process_alive(pid)
        results.append(ProxyInfo(port=port, pid=pid, alive=alive, pid_file=pid_file))

    return results


def _is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is alive."""
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


# ---------------------------------------------------------------------------
# Audit log reading (current session only)
# ---------------------------------------------------------------------------


def _read_current_session_stats(log_path: Path) -> dict[str, Any]:
    """Read the audit log and compute stats for the most recent session only.

    A "session" starts at the last startup event. We only count events
    from that point onward.

    Args:
        log_path: Path to the JSON Lines audit log.

    Returns:
        Dict with aggregated stats for the current session.
    """
    if not log_path.exists():
        return {}

    try:
        raw = log_path.read_text(encoding="utf-8").strip()
    except OSError:
        return {}

    if not raw:
        return {}

    lines = raw.split("\n")

    # Find last startup event index
    last_startup_idx = -1
    startup_events = {"startup", "http_proxy_startup", "llm_proxy_startup"}
    for i, line in enumerate(lines):
        try:
            entry = json.loads(line)
            if entry.get("event") in startup_events:
                last_startup_idx = i
        except json.JSONDecodeError:
            continue

    # Only count from last startup
    session_lines = lines[last_startup_idx:] if last_startup_idx >= 0 else lines

    total_calls = 0
    decisions: dict[str, int] = {}
    blocked_tools: dict[str, int] = {}
    chain_violations = 0
    sensitive_blocks = 0
    approvals = 0
    dry_run_count = 0
    session_start: str | None = None
    last_event: str | None = None

    for line in session_lines:
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        event = entry.get("event", "")
        ts = entry.get("timestamp", "")

        if ts:
            if session_start is None:
                session_start = ts
            last_event = ts

        if event == "tool_call":
            total_calls += 1
            decision = entry.get("decision", "")
            if decision:
                decisions[decision] = decisions.get(decision, 0) + 1
            tool = entry.get("tool", "")
            if decision == "BLOCK" and tool:
                blocked_tools[tool] = blocked_tools.get(tool, 0) + 1
            if entry.get("chain_violation"):
                chain_violations += 1
            if entry.get("dry_run"):
                dry_run_count += 1
        elif event == "approval_dialog":
            approvals += 1
        elif event == "sensitive_data_blocked":
            sensitive_blocks += 1

    return {
        "total_calls": total_calls,
        "decisions": decisions,
        "blocked_tools": blocked_tools,
        "chain_violations": chain_violations,
        "sensitive_blocks": sensitive_blocks,
        "approvals": approvals,
        "dry_run_count": dry_run_count,
        "session_start": session_start,
        "last_event": last_event,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_status(audit_log: Path | None = None) -> ProxyStatus:
    """Collect proxy status information.

    Args:
        audit_log: Path to the audit log file. If None, uses default.

    Returns:
        ProxyStatus with all collected information.
    """
    status = ProxyStatus()
    status.proxies = find_running_proxies()

    # Determine audit log path
    if audit_log is None:
        audit_log = Path("agentward-audit.jsonl")
    status.audit_log = audit_log
    status.audit_exists = audit_log.exists()

    if status.audit_exists:
        session_stats = _read_current_session_stats(audit_log)
        status.total_calls = session_stats.get("total_calls", 0)
        status.decisions = session_stats.get("decisions", {})
        status.blocked_tools = session_stats.get("blocked_tools", {})
        status.chain_violations = session_stats.get("chain_violations", 0)
        status.sensitive_blocks = session_stats.get("sensitive_blocks", 0)
        status.approvals = session_stats.get("approvals", 0)
        status.dry_run_count = session_stats.get("dry_run_count", 0)
        status.session_start = session_stats.get("session_start")
        status.last_event = session_stats.get("last_event")

        # Compute uptime if we have a session start
        if status.session_start:
            try:
                start_dt = datetime.fromisoformat(status.session_start)
                now = datetime.now(timezone.utc)
                status.uptime_seconds = (now - start_dt).total_seconds()
            except (ValueError, TypeError):
                pass

    return status


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _format_duration(seconds: float) -> str:
    """Format seconds into a human-readable duration string."""
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"


def _format_ts(ts: str) -> str:
    """Format an ISO timestamp for compact display."""
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return ts[:19]


_DECISION_COLORS = {
    "ALLOW": "#00ff88",
    "BLOCK": "red",
    "APPROVE": "#ffcc00",
    "REDACT": "#ffcc00",
    "LOG": "#5eead4",
}


def render_status(status: ProxyStatus, console: Console) -> None:
    """Render proxy status to a rich console.

    Args:
        status: The collected proxy status.
        console: Rich console for output.
    """
    # ---- Proxy process status ----
    if status.proxies:
        for proxy in status.proxies:
            if proxy.alive:
                console.print(
                    f"  [#00ff88]●[/#00ff88] Proxy running on port "
                    f"[bold]{proxy.port}[/bold] (PID {proxy.pid})"
                )
            else:
                console.print(
                    f"  [red]●[/red] Stale PID file for port "
                    f"[bold]{proxy.port}[/bold] (PID {proxy.pid} — not running)"
                )
    else:
        console.print("  [dim]●[/dim] No proxy detected")

    console.print()

    # ---- Session info ----
    if status.session_start:
        info_lines = []
        info_lines.append(
            f"  Session start: {_format_ts(status.session_start)}"
        )
        if status.uptime_seconds is not None:
            info_lines.append(
                f"  Uptime:        {_format_duration(status.uptime_seconds)}"
            )
        if status.last_event:
            info_lines.append(
                f"  Last event:    {_format_ts(status.last_event)}"
            )
        if status.audit_log:
            info_lines.append(
                f"  Audit log:     {status.audit_log}"
            )

        console.print(Panel(
            "\n".join(info_lines),
            title="[bold]Session[/bold]",
            border_style="bright_cyan",
            padding=(0, 1),
        ))

    # ---- Tool call stats ----
    if status.total_calls > 0:
        table = Table(
            title="Tool Call Decisions (Current Session)",
            show_header=True,
            header_style="bold",
        )
        table.add_column("Decision", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("", min_width=15)

        max_count = max(status.decisions.values()) if status.decisions else 1
        # Sort by count descending
        sorted_decisions = sorted(
            status.decisions.items(), key=lambda x: x[1], reverse=True
        )
        for decision, count in sorted_decisions:
            bar_len = int((count / max_count) * 15)
            color = _DECISION_COLORS.get(decision, "white")
            bar = f"[{color}]{'█' * bar_len}[/{color}]"
            table.add_row(
                f"[{color}]{decision}[/{color}]",
                str(count),
                bar,
            )

        total_row = f"[bold]Total: {status.total_calls}[/bold]"
        if status.dry_run_count:
            total_row += f" [#5eead4]({status.dry_run_count} dry-run)[/#5eead4]"

        console.print(table)
        console.print(f"  {total_row}")

        # Blocked tools
        if status.blocked_tools:
            console.print()
            console.print("  [bold red]Blocked tools:[/bold red]")
            for tool, count in sorted(
                status.blocked_tools.items(), key=lambda x: x[1], reverse=True
            ):
                console.print(f"    [red]✗[/red] {tool}: {count}")

        # Chain violations
        if status.chain_violations:
            console.print(
                f"\n  [bold red]⚠ Chain violations: {status.chain_violations}[/bold red]"
            )

        # Approvals
        if status.approvals:
            console.print(f"  [#ffcc00]Approvals: {status.approvals}[/#ffcc00]")

        # Sensitive blocks
        if status.sensitive_blocks:
            console.print(
                f"  [red]Sensitive data blocks: {status.sensitive_blocks}[/red]"
            )

    elif status.audit_exists:
        console.print("[dim]  No tool calls in current session yet.[/dim]")
    elif not status.audit_exists:
        console.print(
            "[dim]  No audit log found. "
            "Run `agentward inspect --log <path>` to start logging.[/dim]"
        )
