"""Rich CLI reporter for AgentWard policy regression test results.

Produces a colour-coded per-probe table, a failed-probe detail section,
an attack-category coverage map, and a summary panel.  Returns an exit
code suitable for CI integration (0 = all pass, 1 = any fail).
"""

from __future__ import annotations

from collections import defaultdict

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agentward.testing.models import Probe, ProbeOutcome, ProbeResult

# -----------------------------------------------------------------------
# Display constants
# -----------------------------------------------------------------------

_OUTCOME_BADGE = {
    ProbeOutcome.PASS: "[bold green]✓ PASS[/]",
    ProbeOutcome.FAIL: "[bold red]✗ FAIL[/]",
    ProbeOutcome.GAP:  "[bold yellow]△ GAP[/]",
    ProbeOutcome.SKIP: "[dim]– SKIP[/]",
}

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}


# -----------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------


class TestReporter:
    """Formats and prints test run results to a Rich Console."""

    def __init__(self, console: Console, verbose: bool = False) -> None:
        self._console = console
        self._verbose = verbose

    def print_results(self, results: list[ProbeResult]) -> None:
        """Print the full report: per-probe table, failures, gaps, coverage, summary."""
        passes = [r for r in results if r.outcome == ProbeOutcome.PASS]
        fails  = [r for r in results if r.outcome == ProbeOutcome.FAIL]
        gaps   = [r for r in results if r.outcome == ProbeOutcome.GAP]
        skips  = [r for r in results if r.outcome == ProbeOutcome.SKIP]

        # Always show the per-probe table when verbose, or when there's something to flag
        if self._verbose or fails or gaps:
            self._print_probe_table(results)

        if fails:
            self._print_failed_detail(fails)

        if gaps:
            self._print_gap_summary(gaps)

        self._print_coverage(results)
        self._print_summary(passes, fails, gaps, skips)

    def print_probe_list(self, probes: list[Probe]) -> None:
        """Print a catalogue of probes (used by --list)."""
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
            padding=(0, 1),
        )
        table.add_column("Name", width=40)
        table.add_column("Category", width=22)
        table.add_column("Severity", width=10)
        table.add_column("Expected", width=9)
        table.add_column("Description")

        for probe in sorted(probes, key=lambda p: (p.category, p.severity, p.name)):
            sev_style = _SEVERITY_STYLE.get(probe.severity.lower(), "")
            sev_str = f"[{sev_style}]{probe.severity}[/]" if sev_style else probe.severity

            table.add_row(
                probe.name,
                probe.category,
                sev_str,
                probe.expected,
                probe.description,
            )

        self._console.print(table)
        self._console.print(f"\n[dim]{len(probes)} probe(s) total[/]")

    # ------------------------------------------------------------------
    # Private sections
    # ------------------------------------------------------------------

    def _print_probe_table(self, results: list[ProbeResult]) -> None:
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
            padding=(0, 1),
        )
        table.add_column("Result", width=12)
        table.add_column("Sev", width=9)
        table.add_column("Category", width=22)
        table.add_column("Probe", width=38)
        table.add_column("Expected → Actual")

        for r in results:
            sev = r.probe.severity.lower()
            sev_style = _SEVERITY_STYLE.get(sev, "")
            sev_str = f"[{sev_style}]{sev}[/]" if sev_style else sev

            if r.outcome == ProbeOutcome.SKIP:
                verdict_str = f"[dim]skipped ({r.skip_reason})[/]"
            elif r.outcome == ProbeOutcome.PASS:
                verdict_str = f"[green]{r.probe.expected}[/] → [green]{r.actual_decision}[/]"
            else:
                verdict_str = (
                    f"[bold]{r.probe.expected}[/] → [bold red]{r.actual_decision}[/]"
                )

            table.add_row(
                _OUTCOME_BADGE[r.outcome],
                sev_str,
                r.probe.category,
                r.probe.name,
                verdict_str,
            )

        self._console.print(table)

    def _print_failed_detail(self, fails: list[ProbeResult]) -> None:
        self._console.print("\n[bold red]Failed Probes — Policy Misconfigurations[/]\n")
        for r in fails:
            self._console.print(f"  [bold red]✗[/]  [bold]{r.probe.name}[/]")
            self._console.print(f"     Description : {r.probe.description}")
            self._console.print(f"     Expected    : [green]{r.probe.expected}[/]")
            self._console.print(f"     Got         : [red]{r.actual_decision}[/]")
            self._console.print(f"     Engine said : {r.actual_reason}")
            if r.probe.rationale:
                self._console.print(f"     Rationale   : [dim]{r.probe.rationale}[/]")
            self._console.print()

    def _print_gap_summary(self, gaps: list[ProbeResult]) -> None:
        self._console.print(
            "\n[bold yellow]Coverage Gaps[/]  "
            "[dim](attack patterns not covered by any policy rule)[/]\n"
        )
        by_cat: dict[str, list[ProbeResult]] = defaultdict(list)
        for r in gaps:
            by_cat[r.probe.category].append(r)

        for cat in sorted(by_cat.keys()):
            cat_gaps = by_cat[cat]
            self._console.print(f"  [yellow]{cat}[/] — {len(cat_gaps)} probe(s) uncovered:")
            for r in cat_gaps:
                self._console.print(f"    [dim]•[/] {r.probe.name}: {r.probe.description}")
        self._console.print()

    def _print_coverage(self, results: list[ProbeResult]) -> None:
        by_cat: dict[str, list[ProbeResult]] = defaultdict(list)
        for r in results:
            by_cat[r.probe.category].append(r)

        self._console.print("\n[bold]Attack Category Coverage[/]\n")
        table = Table(
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
            padding=(0, 1),
        )
        table.add_column("Category", width=24)
        table.add_column("Total", width=6,  justify="right")
        table.add_column("Pass",  width=5,  justify="right")
        table.add_column("Fail",  width=5,  justify="right")
        table.add_column("Gap",   width=5,  justify="right")
        table.add_column("Skip",  width=5,  justify="right")
        table.add_column("Coverage", min_width=28)

        for cat in sorted(by_cat.keys()):
            cat_results = by_cat[cat]
            n_total = len(cat_results)
            n_pass  = sum(1 for r in cat_results if r.outcome == ProbeOutcome.PASS)
            n_fail  = sum(1 for r in cat_results if r.outcome == ProbeOutcome.FAIL)
            n_gap   = sum(1 for r in cat_results if r.outcome == ProbeOutcome.GAP)
            n_skip  = sum(1 for r in cat_results if r.outcome == ProbeOutcome.SKIP)

            active = n_total - n_skip
            pct = (n_pass / active * 100) if active > 0 else 0.0

            bar_color = "green" if pct == 100 else ("yellow" if pct >= 50 else "red")
            bar = _make_bar(pct, width=20)

            table.add_row(
                cat,
                str(n_total),
                f"[green]{n_pass}[/]" if n_pass else "0",
                f"[red]{n_fail}[/]" if n_fail else "0",
                f"[yellow]{n_gap}[/]" if n_gap else "0",
                f"[dim]{n_skip}[/]" if n_skip else "0",
                f"[{bar_color}]{bar}[/] {pct:.0f}%",
            )

        self._console.print(table)

    def _print_summary(
        self,
        passes: list[ProbeResult],
        fails: list[ProbeResult],
        gaps: list[ProbeResult],
        skips: list[ProbeResult],
    ) -> None:
        total = len(passes) + len(fails) + len(gaps) + len(skips)

        if fails:
            status = "[bold red]FAILED[/]"
            border_style = "red"
        elif gaps:
            status = "[bold yellow]GAPS DETECTED[/]"
            border_style = "yellow"
        else:
            status = "[bold green]ALL PASSED[/]"
            border_style = "green"

        lines = [
            f"Status : {status}",
            "",
            f"  Total  : {total}  (skipped: {len(skips)})",
            f"  [green]Passed[/] : {len(passes)}",
        ]
        if fails:
            lines.append(
                f"  [red]Failed[/] : {len(fails)}  "
                "[dim]← policy has active misconfigurations[/]"
            )
        else:
            lines.append("  [dim]Failed[/] : 0")

        if gaps:
            lines.append(
                f"  [yellow]Gaps[/]   : {len(gaps)}  "
                "[dim]← attack surfaces not covered by any rule[/]"
            )
        else:
            lines.append("  [dim]Gaps[/]   : 0")

        self._console.print(
            Panel(
                "\n".join(lines),
                title="[bold]Policy Regression Test Summary[/]",
                border_style=border_style,
                padding=(1, 2),
            )
        )


# -----------------------------------------------------------------------
# Utility
# -----------------------------------------------------------------------


def exit_code(results: list[ProbeResult], strict: bool = False) -> int:
    """Return the appropriate process exit code for the test run.

    Args:
        results: All probe results from the run.
        strict:  When True, GAP results also cause exit code 1.

    Returns:
        0 if all probes passed (or were skipped), 1 otherwise.
    """
    for r in results:
        if r.outcome == ProbeOutcome.FAIL:
            return 1
        if strict and r.outcome == ProbeOutcome.GAP:
            return 1
    return 0


def _make_bar(pct: float, width: int = 20) -> str:
    filled = round(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)
