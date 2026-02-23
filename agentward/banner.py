"""ASCII banner for AgentWard CLI output.

Prints a branded banner at the start of ``agentward scan`` and
``agentward init``. Uses the project's neon-green (#00ff88) color palette.
"""

from __future__ import annotations

from rich.console import Console

from agentward import __version__

# Color palette (matches agentward.ai)
_CLR_GREEN = "#00ff88"
_CLR_DIM = "#555555"

# ASCII logo — shield motif, compact for terminal width.
# Designed for monospace fonts at ≥60 columns.
_LOGO = r"""
     ___                    __ _       __              __
    /   |  ____ ____  ___  / /| |     / /___ __________/ /
   / /| | / __ `/ _ \/ _ \/ __/ | /| / / __ `/ ___/ __  /
  / ___ |/ /_/ /  __/ / / / /_ | |/ |/ / /_/ / /  / /_/ /
 /_/  |_|\__, /\___/_/ /_/\__/ |__/|__/\__,_/_/   \__,_/
        /____/
"""


def print_banner(console: Console) -> None:
    """Print the AgentWard ASCII banner with version.

    Args:
        console: Rich console for output (should be stderr).
    """
    for line in _LOGO.rstrip("\n").split("\n"):
        console.print(f"[{_CLR_GREEN}]{line}[/{_CLR_GREEN}]", highlight=False)
    console.print(
        f"[{_CLR_DIM}]  v{__version__}  ·  agentward.ai[/{_CLR_DIM}]",
        highlight=False,
    )
    console.print()
