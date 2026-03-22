"""CLI entry point for ``agentward test``.

Registered in the main CLI via:
    from agentward.testing.cli import app as _testing_app
    app.add_typer(_testing_app)

This exposes:
    agentward test [OPTIONS]            – run all probes
    agentward test --list               – list available probes
    agentward test --category X         – filter by attack category
    agentward test --severity Y         – filter by severity
    agentward test --probes path        – add custom probe files/dirs
    agentward test --verbose            – print per-probe detail always
    agentward test --strict             – treat GAPs as failures (CI)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, List, Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="test",
    help=(
        "Run policy regression tests against your live AgentWard configuration.\n\n"
        "Fires curated adversarial tool calls through the policy engine and "
        "reports which attack categories your policy covers."
    ),
    invoke_without_command=True,
    no_args_is_help=False,
)

_console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    policy: Annotated[
        Optional[Path],
        typer.Option(
            "--policy",
            "-p",
            help=(
                "Path to agentward.yaml policy file. "
                "If omitted, only safety-floor probes (protected_paths) can pass."
            ),
        ),
    ] = None,
    category: Annotated[
        Optional[List[str]],
        typer.Option(
            "--category",
            "-c",
            help=(
                "Restrict run to one or more attack categories. "
                "Repeat the flag for multiple categories. "
                "Available: protected_paths, prompt_injection, path_traversal, "
                "scope_creep, skill_chaining, boundary_violation, pii_injection, "
                "deserialization, privilege_escalation."
            ),
        ),
    ] = None,
    severity: Annotated[
        Optional[List[str]],
        typer.Option(
            "--severity",
            "-s",
            help=(
                "Restrict run to one or more severity levels. "
                "Repeat the flag for multiple severities. "
                "Available: critical, high, medium, low."
            ),
        ),
    ] = None,
    probes: Annotated[
        Optional[List[Path]],
        typer.Option(
            "--probes",
            help=(
                "Additional probe file (.yaml) or directory to load. "
                "User probes with the same name as a built-in probe override it. "
                "Repeat the flag to add multiple paths."
            ),
        ),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Print a per-probe result table even when all probes pass.",
        ),
    ] = False,
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            help=(
                "Treat GAP results (policy doesn't cover the attack surface) "
                "as failures. Useful for CI pipelines that enforce full coverage."
            ),
        ),
    ] = False,
    list_probes: Annotated[
        bool,
        typer.Option(
            "--list",
            "-l",
            help="List all available probes (built-in + any --probes paths) and exit.",
        ),
    ] = False,
) -> None:
    """Run policy regression tests to verify your policy blocks what it should."""

    # Subcommand guard (nothing registered, but keeps Typer happy)
    if ctx.invoked_subcommand is not None:
        return

    from agentward.testing.loader import ProbeLoadError, load_all_probes
    from agentward.testing.reporter import TestReporter, exit_code
    from agentward.testing.runner import RunnerConfig, TestRunner

    # ------------------------------------------------------------------
    # Load probes
    # ------------------------------------------------------------------
    extra_probe_paths = list(probes) if probes else []

    try:
        all_probes = load_all_probes(extra_paths=extra_probe_paths)
    except ProbeLoadError as e:
        _console.print(f"[bold red]Error loading probes:[/] {e}")
        raise typer.Exit(1) from e

    # ------------------------------------------------------------------
    # --list mode: catalogue and exit
    # ------------------------------------------------------------------
    if list_probes:
        reporter = TestReporter(_console, verbose=True)
        # Apply category/severity filters so --list respects them too
        filtered = _filter_for_list(
            all_probes,
            categories=list(category) if category else [],
            severities=list(severity) if severity else [],
        )
        reporter.print_probe_list(filtered)
        raise typer.Exit(0)

    # ------------------------------------------------------------------
    # Validate policy path
    # ------------------------------------------------------------------
    if policy is not None and not policy.exists():
        _console.print(
            f"[bold red]Policy file not found:[/] {policy}\n"
            "Create one with [bold]agentward configure[/] or specify a valid path."
        )
        raise typer.Exit(1)

    # ------------------------------------------------------------------
    # Build runner config
    # ------------------------------------------------------------------
    config = RunnerConfig(
        policy_path=policy,
        categories=list(category) if category else [],
        severities=list(severity) if severity else [],
        strict=strict,
    )

    runner = TestRunner(config)
    try:
        runner.load()
    except Exception as e:  # noqa: BLE001
        _console.print(f"[bold red]Failed to load policy:[/] {e}")
        raise typer.Exit(1) from e

    # ------------------------------------------------------------------
    # Filter and run
    # ------------------------------------------------------------------
    probes_to_run = runner.filter_probes(all_probes)

    if not probes_to_run:
        _console.print("[yellow]No probes matched the specified filters.[/]")
        raise typer.Exit(0)

    policy_label = str(policy) if policy else "[dim](no policy — safety floor only)[/]"
    _console.print(
        f"\n[bold]AgentWard Policy Regression Test[/]\n"
        f"  Policy : {policy_label}\n"
        f"  Probes : {len(probes_to_run)} selected "
        f"(of {len(all_probes)} total)\n"
    )

    results = runner.run_all(probes_to_run)

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    reporter = TestReporter(_console, verbose=verbose)
    reporter.print_results(results)

    code = exit_code(results, strict=strict)
    raise typer.Exit(code)


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _filter_for_list(
    probes: list,
    categories: list[str],
    severities: list[str],
) -> list:
    """Apply category/severity filters without a full runner."""
    result = probes
    if categories:
        cats = {c.lower() for c in categories}
        result = [p for p in result if p.category.lower() in cats]
    if severities:
        sevs = {s.lower() for s in severities}
        result = [p for p in result if p.severity.lower() in sevs]
    return result
