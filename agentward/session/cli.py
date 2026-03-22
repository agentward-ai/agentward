"""CLI subcommand: ``agentward session``.

Provides inspection of session-level evasion detection activity by reading
session events from an existing audit log file.

Subcommands:
  agentward session status  — show recent session events from the audit log
  agentward session clear   — clear session pause state (not yet persistent)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

session_app = typer.Typer(
    name="session",
    help="Inspect session-level evasion detection activity.",
    no_args_is_help=True,
)

_console = Console(stderr=True)


@session_app.command("status")
def session_status(
    log: Annotated[
        Optional[Path],
        typer.Option(
            "--log",
            "-l",
            help="Audit log file (.jsonl) to read session events from.",
        ),
    ] = None,
    last: Annotated[
        int,
        typer.Option(
            "--last",
            "-n",
            help="Show only the last N session events.",
        ),
    ] = 50,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output as JSON instead of a rich table.",
        ),
    ] = False,
) -> None:
    """Show recent session-level evasion events from the audit log.

    Reads session_evasion events written by the proxy to the JSONL audit log
    and displays a summary table. Each row shows the session ID, verdict,
    aggregate risk score, and the triggering pattern name.

    Examples:
      agentward session status
      agentward session status --log ./agentward-audit.jsonl
      agentward session status --last 20 --json
    """
    if log is None:
        # Look for the default audit log in the current directory
        candidates = sorted(Path(".").glob("agentward*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not candidates:
            _console.print(
                "[bold red]No audit log found.[/bold red] "
                "Run [bold]agentward inspect[/bold] with [bold]--log[/bold] to enable logging, "
                "then re-run this command with [bold]--log <path>[/bold].",
                highlight=False,
            )
            raise typer.Exit(1)
        log = candidates[0]
        _console.print(f"[dim]Reading from {log}[/dim]", highlight=False)

    if not log.exists():
        _console.print(
            f"[bold red]Audit log not found:[/bold red] {log}",
            highlight=False,
        )
        raise typer.Exit(1)

    events: list[dict] = []
    try:
        with open(log, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if entry.get("event") == "session_evasion":
                    events.append(entry)
    except OSError as e:
        _console.print(f"[bold red]Cannot read audit log:[/bold red] {e}", highlight=False)
        raise typer.Exit(1)

    # Apply --last limit
    events = events[-last:]

    if not events:
        _console.print(
            "[dim]No session evasion events in this log.[/dim]",
            highlight=False,
        )
        raise typer.Exit(0)

    if json_output:
        sys.stdout.write(json.dumps(events, indent=2))
        sys.stdout.write("\n")
        return

    # Rich table output
    table = Table(
        title=f"Session Evasion Events (last {len(events)})",
        show_lines=False,
    )
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Session ID", style="cyan")
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Score", justify="right")
    table.add_column("Pattern", style="dim")
    table.add_column("Tool", style="dim")

    _VERDICT_STYLES = {
        "EVASION_DETECTED": "[bold red]EVASION[/bold red]",
        "SUSPICIOUS": "[bold #ffcc00]SUSPICIOUS[/bold #ffcc00]",
        "CLEAN": "[#00ff88]CLEAN[/#00ff88]",
    }

    for event in events:
        verdict = event.get("verdict", "?")
        verdict_str = _VERDICT_STYLES.get(verdict, verdict)
        score = event.get("aggregate_score", 0.0)
        ts = event.get("timestamp", "")[:19]  # trim microseconds
        table.add_row(
            ts,
            event.get("session_id", "?"),
            verdict_str,
            f"{score:.2f}",
            event.get("triggering_pattern", ""),
            event.get("tool", ""),
        )

    _console.print(table)
