"""AgentWard CLI entry point.

Provides the `agentward` command with subcommands:
  - scan: Scan MCP configs, Python tools, and OpenClaw skills
  - configure: Generate smart-default policy YAML from scan results
  - inspect: Start the MCP proxy with policy enforcement
  - setup: Wire AgentWard proxy into MCP configs
  - comply: Not yet implemented (honest error)
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console

from agentward import __version__

app = typer.Typer(
    name="agentward",
    help="Open-source permission control plane for AI agents. Scan, enforce, and audit every tool call.",
    no_args_is_help=True,
)

_console = Console(stderr=True)


def _version_callback(value: bool) -> None:
    if value:
        _console.print(f"agentward {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        Optional[bool],
        typer.Option(
            "--version",
            "-v",
            help="Show version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = None,
) -> None:
    """AgentWard — Permission control plane for AI agents."""


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def inspect(
    ctx: typer.Context,
    policy: Annotated[
        Optional[Path],
        typer.Option(
            "--policy",
            "-p",
            help="Path to agentward.yaml policy file. Without this, runs in passthrough mode (all calls forwarded, only logging).",
        ),
    ] = None,
    log: Annotated[
        Optional[Path],
        typer.Option(
            "--log",
            "-l",
            help="Path to write structured JSON Lines audit log. Without this, logs only to stderr.",
        ),
    ] = None,
    gateway: Annotated[
        Optional[str],
        typer.Option(
            "--gateway",
            "-g",
            help="Gateway to proxy (e.g., 'openclaw'). Runs as HTTP reverse proxy instead of stdio.",
        ),
    ] = None,
    chaining_mode: Annotated[
        Optional[str],
        typer.Option(
            "--chaining-mode",
            help="Chaining enforcement mode: 'content' (default) or 'blanket'. "
            "Overrides the chaining_mode in the policy YAML.",
        ),
    ] = None,
    skill_context: Annotated[
        Optional[str],
        typer.Option(
            "--skill-context",
            help="Skill (server) name for policy disambiguation. When set, only policy "
            "rules for this skill are matched. Useful when multiple skills define the "
            "same resource name.",
        ),
    ] = None,
) -> None:
    """Start the proxy with policy enforcement.

    For MCP servers (stdio), everything after '--' is the server command:
      agentward inspect --policy agentward.yaml -- npx -y @modelcontextprotocol/server-filesystem /tmp

    For gateways (HTTP), use --gateway:
      agentward inspect --policy agentward.yaml --gateway openclaw
    """
    # Load policy if provided
    from agentward.policy.engine import PolicyEngine
    from agentward.policy.loader import PolicyValidationError, load_policy

    policy_engine = None
    policy_path = policy
    if policy is not None:
        try:
            loaded_policy = load_policy(policy)
            policy_engine = PolicyEngine(loaded_policy, skill_context=skill_context)
        except FileNotFoundError as e:
            _console.print(f"[bold red]Error:[/bold red] {e}", highlight=False)
            raise typer.Exit(1) from None
        except PolicyValidationError as e:
            _console.print(f"[bold red]Policy error:[/bold red] {e}", highlight=False)
            raise typer.Exit(1) from None

    # Create audit logger
    from agentward.audit.logger import AuditLogger

    audit_logger = AuditLogger(log_path=log)

    # Create chain tracker if policy has chaining rules
    from agentward.policy.schema import ChainingMode
    from agentward.proxy.chaining import ChainTracker

    chain_tracker: ChainTracker | None = None
    if policy_engine is not None and policy_engine.policy.skill_chaining:
        # Resolve chaining mode: CLI flag → policy YAML → default (content)
        if chaining_mode is not None:
            mode_str = chaining_mode.lower()
            if mode_str not in ("content", "blanket"):
                _console.print(
                    f"[bold red]Error:[/bold red] Invalid chaining mode: {chaining_mode!r}\n"
                    "Valid options: 'content', 'blanket'",
                    highlight=False,
                )
                raise typer.Exit(1)
            mode = ChainingMode(mode_str)
        else:
            mode = policy_engine.policy.chaining_mode

        chain_tracker = ChainTracker(policy_engine=policy_engine, mode=mode)
        _console.print(
            f"  Chaining: [bold]{mode.value}[/bold] mode "
            f"({len(policy_engine.policy.skill_chaining)} rule(s))",
            style="dim",
            highlight=False,
        )

    if gateway is not None:
        # HTTP reverse proxy mode
        _run_gateway_proxy(gateway, policy_engine, audit_logger, policy_path, chain_tracker)
    else:
        # Stdio proxy mode
        server_command = ctx.args
        if not server_command:
            _console.print(
                "[bold red]Error:[/bold red] No server command provided.\n\n"
                "Usage:\n"
                "  agentward inspect [OPTIONS] -- <server command>      (stdio)\n"
                "  agentward inspect [OPTIONS] --gateway openclaw       (HTTP)\n\n"
                "Example:\n"
                "  agentward inspect --policy agentward.yaml -- npx server\n"
                "  agentward inspect --policy agentward.yaml --gateway openclaw",
                highlight=False,
            )
            raise typer.Exit(1)

        from agentward.proxy.server import StdioProxy

        proxy = StdioProxy(
            server_command=server_command,
            policy_engine=policy_engine,
            audit_logger=audit_logger,
            chain_tracker=chain_tracker,
            policy_path=policy_path,
        )

        try:
            asyncio.run(proxy.run())
        except KeyboardInterrupt:
            pass  # Handled by signal handler in proxy


def _run_gateway_proxy(
    gateway_type: str,
    policy_engine: object | None,
    audit_logger: object,
    policy_path: Path | None,
    chain_tracker: object | None = None,
) -> None:
    """Start an HTTP reverse proxy for a gateway.

    Args:
        gateway_type: Gateway identifier ("openclaw" or "clawdbot").
        policy_engine: Loaded policy engine or None for passthrough.
        audit_logger: The audit logger instance.
        policy_path: Path to policy file (for logging).
        chain_tracker: Optional chain tracker for chaining enforcement.
    """
    if gateway_type not in ("clawdbot", "openclaw"):
        _console.print(
            f"[bold red]Error:[/bold red] Unknown gateway type: {gateway_type!r}\n"
            "Supported gateways: openclaw",
            highlight=False,
        )
        raise typer.Exit(1)

    from agentward.proxy.http import HttpProxy
    from agentward.scan.openclaw import find_clawdbot_config
    from agentward.setup import get_clawdbot_gateway_ports, get_clawdbot_llm_proxy_config

    config_path = find_clawdbot_config()
    if config_path is None:
        _console.print(
            "[bold red]Error:[/bold red] OpenClaw config not found.\n"
            "Searched: ~/.openclaw/openclaw.json, ~/.clawdbot/clawdbot.json\n"
            "Is OpenClaw installed?",
            highlight=False,
        )
        raise typer.Exit(1)

    # Check if setup has already swapped the port
    ports = get_clawdbot_gateway_ports(config_path)
    if ports is None:
        _console.print(
            "[bold #ffcc00]Warning:[/bold #ffcc00] OpenClaw gateway port has not been swapped.\n"
            "Run `agentward setup --gateway openclaw` first to configure the port,\n"
            "then run `openclaw gateway restart`.",
            highlight=False,
        )
        raise typer.Exit(1)

    listen_port, backend_port = ports
    backend_url = f"http://127.0.0.1:{backend_port}"

    http_proxy = HttpProxy(
        backend_url=backend_url,
        listen_host="127.0.0.1",
        listen_port=listen_port,
        policy_engine=policy_engine,  # type: ignore[arg-type]
        audit_logger=audit_logger,  # type: ignore[arg-type]
        policy_path=policy_path,
        chain_tracker=chain_tracker,  # type: ignore[arg-type]
    )

    # Check if LLM proxy is configured (baseUrl patching in sidecar)
    llm_config = get_clawdbot_llm_proxy_config(config_path)

    if llm_config is not None:
        from agentward.proxy.llm import LlmProxy

        llm_port, provider_urls = llm_config
        llm_proxy = LlmProxy(
            listen_port=llm_port,
            provider_urls=provider_urls,
            policy_engine=policy_engine,  # type: ignore[arg-type]
            audit_logger=audit_logger,  # type: ignore[arg-type]
            policy_path=policy_path,
        )

        async def _run_both() -> None:
            import signal as _signal

            shutdown = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (_signal.SIGINT, _signal.SIGTERM):
                loop.add_signal_handler(sig, shutdown.set)
            await asyncio.gather(
                http_proxy.run(shutdown_event=shutdown),
                llm_proxy.run(shutdown_event=shutdown),
            )

        try:
            asyncio.run(_run_both())
        except KeyboardInterrupt:
            pass
    else:
        try:
            asyncio.run(http_proxy.run())
        except KeyboardInterrupt:
            pass



# ---------------------------------------------------------------------------
# Shared scan pipeline
# ---------------------------------------------------------------------------


def _print_no_host_error(console: Console) -> None:
    """Print a targeted error when no MCP host is detected on the system."""
    import platform as _platform

    console.print(
        "[bold red]No MCP hosts detected.[/bold red]\n\n"
        "AgentWard scans MCP servers configured in your AI coding tool.\n"
        "No config files were found in any of the standard locations:\n",
        highlight=False,
    )
    system = _platform.system()
    if system == "Darwin":
        console.print("  Claude Desktop:  ~/Library/Application Support/Claude/claude_desktop_config.json", highlight=False)
    elif system == "Linux":
        console.print("  Claude Desktop:  ~/.config/Claude/claude_desktop_config.json", highlight=False)
    console.print("  Cursor:          ~/.cursor/mcp.json", highlight=False)
    console.print("  Claude Code:     .mcp.json  (in current directory)", highlight=False)
    console.print("  VS Code:         .vscode/mcp.json  (in current directory)", highlight=False)
    console.print("  Windsurf:        ~/.codeium/windsurf/mcp_config.json", highlight=False)
    console.print(
        "\n[bold]Get started:[/bold]\n"
        "  1. Install an MCP host: Claude Desktop, Cursor, VS Code, or Claude Code\n"
        "  2. Add MCP servers in your host's settings\n"
        "  3. Run [bold]agentward scan[/bold] again\n\n"
        "  Or scan a specific config: [bold]agentward scan /path/to/mcp.json[/bold]",
        highlight=False,
    )


def _print_empty_config_error(console: Console, config_paths: list[Path]) -> None:
    """Print a targeted error when configs exist but contain no servers."""
    paths_str = "\n".join(f"  - {p}" for p in config_paths)
    console.print(
        f"[bold yellow]No MCP servers configured.[/bold yellow]\n\n"
        f"Found config file(s) but they contain no MCP server definitions:\n"
        f"{paths_str}\n\n"
        f"[bold]Add MCP servers to your config, then run agentward scan again.[/bold]\n\n"
        f"  Example (add to your config's \"mcpServers\" section):\n"
        f"  [dim]\"memory\": {{\n"
        f"    \"command\": \"npx\",\n"
        f"    \"args\": [\"-y\", \"@modelcontextprotocol/server-memory\"]\n"
        f"  }}[/dim]",
        highlight=False,
    )


def _run_scan(
    target: Path | None,
    timeout: float,
    console: Console,
) -> tuple:
    """Run the full scan pipeline and return results.

    Discovers and scans all tool sources (MCP configs, Python files,
    OpenClaw skills), builds the permission map, generates
    recommendations, and detects skill chains.

    Args:
        target: Path to scan (file, directory, or None for auto-discover).
        timeout: Timeout for MCP server enumeration.
        console: Rich console for progress output.

    Returns:
        Tuple of (ScanResult, list[Recommendation], list[Path], list[ChainDetection]).
        The third element is config_paths used as sources.

    Raises:
        typer.Exit: If target doesn't exist or no tools found.
    """
    from agentward.scan.config import (
        ConfigParseError,
        discover_configs,
        parse_config_file,
    )
    from agentward.scan.enumerator import EnumerationResult, enumerate_all
    from agentward.scan.permissions import build_permission_map
    from agentward.scan.recommendations import generate_recommendations

    # Step 1: Find and parse config files
    config_paths: list[Path] = []

    if target is None:
        # Auto-discover
        config_paths = discover_configs()
        if not config_paths:
            console.print(
                "  [dim]No MCP config files found in standard locations[/dim]",
                highlight=False,
            )
            # Don't exit yet — OpenClaw auto-discovery may find something
    elif target.is_dir():
        # Search directory for config files
        known_names = [
            "claude_desktop_config.json",
            "mcp.json",
            ".mcp.json",
            "mcp_config.json",
        ]
        for name in known_names:
            candidate = target / name
            if candidate.exists():
                config_paths.append(candidate)
        # Also check subdirectories
        for subdir in (".cursor", ".vscode"):
            candidate = target / subdir / "mcp.json"
            if candidate.exists():
                config_paths.append(candidate)
        if not config_paths:
            console.print(
                f"  [dim]No MCP config files found in {target}[/dim]",
                highlight=False,
            )
    elif target is not None and target.is_file():
        config_paths = [target]
    elif target is not None:
        console.print(
            f"[bold red]Error:[/bold red] Path does not exist: {target}",
            highlight=False,
        )
        raise typer.Exit(1)

    # Parse all config files
    all_servers = []
    for config_path in config_paths:
        try:
            servers = parse_config_file(config_path)
            all_servers.extend(servers)
            console.print(
                f"  [#00ff88]\u2713[/#00ff88] Parsed {config_path} ({len(servers)} server(s))",
                highlight=False,
            )
        except (FileNotFoundError, ConfigParseError) as e:
            console.print(
                f"  [#ff6b35]\u26a0[/#ff6b35] Skipping {config_path}: {e}",
                highlight=False,
            )

    # Step 2: Enumerate tools from MCP servers
    results: list[EnumerationResult] = []
    if all_servers:
        console.print(f"\n[bold #5eead4]\u26a1 Enumerating tools from {len(all_servers)} server(s)...[/bold #5eead4]")
        results = asyncio.run(enumerate_all(all_servers, timeout=timeout))

        # Print per-server enumeration summary so the user knows what happened
        for r in results:
            if r.tools:
                console.print(
                    f"  [#00ff88]\u2713[/#00ff88] {r.server.name}: {len(r.tools)} tool(s) ({r.enumeration_method})",
                    highlight=False,
                )
            elif r.enumeration_method == "failed":
                console.print(
                    f"  [#ff6b35]\u2716[/#ff6b35] {r.server.name}: enumeration failed"
                    + (f" — {r.error}" if r.error else ""),
                    highlight=False,
                )
            elif r.enumeration_method == "static_inference":
                console.print(
                    f"  [#ffcc00]\u26a0[/#ffcc00] {r.server.name}: could not enumerate tools (server may not be running)",
                    highlight=False,
                )
                if r.error:
                    console.print(
                        f"    [dim]{r.error}[/dim]",
                        highlight=False,
                    )
            else:
                console.print(
                    f"  [#ffcc00]\u26a0[/#ffcc00] {r.server.name}: 0 tools returned",
                    highlight=False,
                )

    # Step 2b: Scan Python source files for tool definitions
    python_results: list[EnumerationResult] = []
    if target is not None and target.is_dir():
        from agentward.scan.skills import scan_directory, tools_to_enumeration_results

        console.print(f"\n[bold #5eead4]\u26a1 Scanning Python files for tool definitions...[/bold #5eead4]")
        py_tools = scan_directory(target)
        if py_tools:
            python_results = tools_to_enumeration_results(py_tools)
            frameworks = {t.framework.value for t in py_tools}
            console.print(
                f"  [#00ff88]\u2713[/#00ff88] Found {len(py_tools)} tool(s) in "
                f"{len(python_results)} file(s) ({', '.join(sorted(frameworks))})",
                highlight=False,
            )
        else:
            console.print(
                f"  [dim]No Python tool definitions found[/dim]",
                highlight=False,
            )

    # Step 2c: Scan OpenClaw skills
    openclaw_results: list[EnumerationResult] = []
    if target is not None and target.is_dir():
        from agentward.scan.openclaw import scan_openclaw_directory

        console.print(f"\n[bold #5eead4]\u26a1 Scanning for OpenClaw skills...[/bold #5eead4]")
        openclaw_results = scan_openclaw_directory(target)
        if openclaw_results:
            total_skills = sum(len(r.tools) for r in openclaw_results)
            console.print(
                f"  [#00ff88]\u2713[/#00ff88] Found {total_skills} skill(s)",
                highlight=False,
            )
        else:
            console.print(
                f"  [dim]No OpenClaw SKILL.md files found[/dim]",
                highlight=False,
            )
    elif target is None:
        # Auto-discover: scan known OpenClaw locations
        from agentward.scan.openclaw import discover_skill_dirs, scan_openclaw

        console.print(f"\n[bold #5eead4]\u26a1 Scanning for OpenClaw skills...[/bold #5eead4]")
        skill_dirs = discover_skill_dirs()
        if skill_dirs:
            for skill_dir, label in skill_dirs:
                console.print(
                    f"  [dim]Found skill directory: {skill_dir} ({label})[/dim]",
                    highlight=False,
                )
        openclaw_results = scan_openclaw()
        if openclaw_results:
            total_skills = sum(len(r.tools) for r in openclaw_results)
            console.print(
                f"  [#00ff88]\u2713[/#00ff88] Found {total_skills} skill(s) across "
                f"{len(openclaw_results)} source(s)",
                highlight=False,
            )
        else:
            console.print(
                f"  [dim]No OpenClaw skills found in known locations[/dim]",
                highlight=False,
            )
            console.print(
                f"  [dim]Tip: agentward scan <path> to scan a specific skill directory[/dim]",
                highlight=False,
            )

    # Combine MCP, Python, and OpenClaw results
    all_results = results + python_results + openclaw_results

    # Post-enumeration: check if all servers failed with the same command not found
    if results and all(r.enumeration_method == "failed" for r in results):
        missing_cmds = set()
        for r in results:
            if r.error and "Command not found" in r.error:
                # Extract the missing command name from error like "Command not found: npx ..."
                parts = r.error.split("Command not found: ")
                if len(parts) > 1:
                    cmd = parts[1].split()[0].strip(".'\"")
                    missing_cmds.add(cmd)
        if missing_cmds:
            cmds = ", ".join(sorted(missing_cmds))
            console.print(
                f"\n  [#ffcc00]Hint:[/#ffcc00] All servers failed because "
                f"[bold]{cmds}[/bold] is not installed.",
                highlight=False,
            )
            if "npx" in missing_cmds:
                console.print(
                    "  [dim]Install Node.js:  brew install node  (macOS)  |  apt install nodejs npm  (Linux)[/dim]",
                    highlight=False,
                )

    if not all_results:
        console.print("")
        if target is None and not config_paths:
            # No MCP configs found anywhere — likely no MCP host installed
            _print_no_host_error(console)
        elif config_paths and not all_servers:
            # Configs found but they contained 0 servers
            _print_empty_config_error(console, config_paths)
        else:
            # Catch-all: configs with servers but everything failed
            console.print(
                "[bold red]Error:[/bold red] No tools found.\n\n"
                "No MCP servers, Python tool definitions, or OpenClaw skills discovered.\n\n"
                "Specify a path directly: [bold]agentward scan /path/to/config.json[/bold]",
                highlight=False,
            )
        raise typer.Exit(1)

    # Step 3: Build permission map
    scan_result = build_permission_map(all_results)
    scan_result.config_sources = [str(p) for p in config_paths]

    # Step 4: Generate recommendations
    recommendations = generate_recommendations(scan_result)

    # Step 5: Detect skill chains
    from agentward.scan.chains import detect_chains

    chains = detect_chains(scan_result)

    return scan_result, recommendations, config_paths, chains


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: Annotated[
        Optional[Path],
        typer.Argument(
            help="Path to MCP config file or directory to scan. "
            "If omitted, auto-discovers config files from known locations.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            "-t",
            help="Timeout in seconds for each server enumeration.",
        ),
    ] = 30.0,
    output_json: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output raw scan result as JSON instead of rich tables.",
        ),
    ] = False,
) -> None:
    """Scan MCP configs, Python codebases, and OpenClaw skills for tool definitions.

    Discovers MCP servers, Python agent tool definitions, and OpenClaw
    skills, enumerates their tools, and analyzes data access patterns and risk levels.

    Examples:
      agentward scan                                    # auto-discover all sources
      agentward scan ~/.cursor/mcp.json                 # scan specific MCP config
      agentward scan ~/project/                         # scan directory (MCP + Python + OpenClaw)
      agentward scan ~/clawd/skills/                    # scan OpenClaw skills directory
      agentward scan --json > report.json               # machine-readable output
    """
    from agentward.scan.report import print_scan_json, print_scan_report

    scan_result, recommendations, _config_paths, chains = _run_scan(target, timeout, _console)

    if output_json:
        output_console = Console()
        print_scan_json(scan_result, output_console)
    else:
        print_scan_report(scan_result, recommendations, _console, chains=chains)


# ---------------------------------------------------------------------------
# configure command
# ---------------------------------------------------------------------------


@app.command()
def configure(
    target: Annotated[
        Optional[Path],
        typer.Argument(
            help="Path to MCP config file or directory to scan. "
            "If omitted, auto-discovers from known locations.",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output path for the generated policy YAML. Default: ./agentward.yaml",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            "-t",
            help="Timeout in seconds for each server enumeration.",
        ),
    ] = 30.0,
) -> None:
    """Generate a smart-default policy YAML based on scan results.

    Scans your tools and skills, then generates an agentward.yaml policy
    with security-aware defaults. Review and customize the generated policy,
    then use it with `agentward inspect --policy agentward.yaml`.

    Examples:
      agentward configure                               # auto-discover and generate
      agentward configure ~/clawd/skills/                # generate from OpenClaw skills
      agentward configure -o my-policy.yaml              # custom output path
    """
    from agentward.configure.generator import generate_policy, write_policy

    # Run the full scan pipeline
    scan_result, _recommendations, _config_paths, _chains = _run_scan(target, timeout, _console)

    # Generate policy
    policy = generate_policy(scan_result)

    # Check if the policy is empty (no tools could be enumerated)
    if not policy.skills and not policy.require_approval and not policy.skill_chaining:
        _console.print(
            "\n[bold yellow]Warning:[/bold yellow] Generated policy is empty — "
            "no tools could be enumerated.\n\n"
            "This usually means MCP servers are not currently running.\n"
            "Try: [bold]agentward configure --timeout 30[/bold]  (give servers more time)\n"
            "Or start your MCP servers first, then re-run configure.\n",
            highlight=False,
        )
        raise typer.Exit(1)

    # Determine output path
    output_path = output or Path("agentward.yaml")

    # Write policy
    try:
        write_policy(policy, output_path)
    except PermissionError:
        _console.print(
            f"\n[bold red]Error:[/bold red] Permission denied writing to {output_path}\n\n"
            f"Use -o to specify a writable path:\n"
            f"  agentward configure -o ~/agentward.yaml",
            highlight=False,
        )
        raise typer.Exit(1)
    except OSError as e:
        _console.print(
            f"\n[bold red]Error:[/bold red] Cannot write to {output_path}: {e}",
            highlight=False,
        )
        raise typer.Exit(1)

    # Summary
    num_skills = len(policy.skills)
    num_approval = len(policy.require_approval)
    num_chaining = len(policy.skill_chaining)

    _console.print()
    _console.print(
        f"[bold #00ff88]\u2713 Generated policy:[/bold #00ff88] {output_path}",
        highlight=False,
    )
    _console.print(
        f"  {num_skills} skill restriction(s), "
        f"{num_approval} approval gate(s), "
        f"{num_chaining} chaining rule(s)",
        highlight=False,
    )
    _console.print()
    _console.print(
        f"[dim]Review the generated policy, then wire it into your IDE:[/dim]",
        highlight=False,
    )
    _console.print(
        f"  agentward setup --policy {output_path}",
        highlight=False,
    )
    _console.print()


@app.command(name="map")
def map_command(
    target: Annotated[
        Optional[Path],
        typer.Argument(
            help="Path to MCP config file or directory to scan. "
            "If omitted, auto-discovers from known locations.",
        ),
    ] = None,
    policy: Annotated[
        Optional[Path],
        typer.Option(
            "--policy",
            "-p",
            help="Path to agentward.yaml policy file. "
            "When loaded, shows ALLOW/BLOCK/APPROVE markers per tool.",
        ),
    ] = None,
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: 'terminal' (rich CLI) or 'mermaid' (diagram).",
        ),
    ] = "terminal",
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output file path for mermaid format. If omitted, prints to stdout.",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            "-t",
            help="Timeout in seconds for each server enumeration.",
        ),
    ] = 30.0,
    output_json: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output graph data as JSON instead of visual rendering.",
        ),
    ] = False,
) -> None:
    """Visualize the permission and chaining graph.

    Shows servers, tools, data access types, risk levels, and detected
    skill chains as a terminal graph or Mermaid diagram.

    Without --policy, shows what your agent has access to.
    With --policy, overlays policy decisions (ALLOW/BLOCK/APPROVE).

    Examples:
      agentward map                                    # terminal visualization
      agentward map --policy agentward.yaml            # with policy overlay
      agentward map --format mermaid -o graph.md       # mermaid diagram to file
      agentward map --json                             # machine-readable output
    """
    from agentward.map import build_map_data, render_json, render_mermaid, render_terminal

    # Validate format
    if fmt not in ("terminal", "mermaid"):
        _console.print(
            f"[bold red]Error:[/bold red] Unknown format: {fmt!r}\n"
            "Valid options: 'terminal', 'mermaid'",
            highlight=False,
        )
        raise typer.Exit(1)

    # Run scan pipeline
    scan_result, _recommendations, _config_paths, chains = _run_scan(target, timeout, _console)

    # Load policy if provided
    policy_engine = None
    if policy is not None:
        from agentward.policy.engine import PolicyEngine
        from agentward.policy.loader import PolicyValidationError, load_policy

        try:
            loaded_policy = load_policy(policy)
            policy_engine = PolicyEngine(loaded_policy)
        except FileNotFoundError as e:
            _console.print(f"[bold red]Error:[/bold red] {e}", highlight=False)
            raise typer.Exit(1) from None
        except PolicyValidationError as e:
            _console.print(f"[bold red]Policy error:[/bold red] {e}", highlight=False)
            raise typer.Exit(1) from None

    # Build graph data
    data = build_map_data(scan_result, chains, policy_engine)

    # Render
    if output_json:
        output_console = Console()
        output_console.print(render_json(data))
    elif fmt == "mermaid":
        mermaid_str = render_mermaid(data)
        if output is not None:
            content = f"```mermaid\n{mermaid_str}```\n"
            output.write_text(content, encoding="utf-8")
            _console.print(
                f"[#00ff88]\u2713[/#00ff88] Mermaid diagram written to {output}",
                highlight=False,
            )
        else:
            # Print to stdout for piping
            output_console = Console()
            output_console.print(mermaid_str, end="")
    else:
        render_terminal(data, _console)


@app.command()
def comply(
    framework: Annotated[
        str,
        typer.Option("--framework", "-f", help="Compliance framework to evaluate against."),
    ] = "hipaa",
    fix: Annotated[
        bool,
        typer.Option("--fix", help="Generate an updated policy with required changes applied."),
    ] = False,
) -> None:
    """Evaluate current policy against a compliance framework.

    Not yet implemented — requires the compliance evaluator and
    framework rule definitions.
    """
    raise NotImplementedError(
        f"agentward comply --framework {framework} is not yet implemented. "
        "It requires the compliance evaluator (agentward/comply/evaluator.py) "
        "and framework rule definitions (agentward/comply/frameworks/)."
    )


@app.command()
def setup(
    config: Annotated[
        Optional[Path],
        typer.Option(
            "--config",
            "-c",
            help="MCP config file to modify. Without this, auto-discovers configs.",
        ),
    ] = None,
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            "-p",
            help="Path to agentward.yaml policy file.",
        ),
    ] = Path("agentward.yaml"),
    log: Annotated[
        Optional[Path],
        typer.Option(
            "--log",
            "-l",
            help="Path for audit log file (passed to proxy).",
        ),
    ] = None,
    undo: Annotated[
        bool,
        typer.Option(
            "--undo",
            help="Remove AgentWard wrapping and restore original commands.",
        ),
    ] = False,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Preview changes without writing to the config file.",
        ),
    ] = False,
    gateway: Annotated[
        Optional[str],
        typer.Option(
            "--gateway",
            "-g",
            help="Gateway type to configure (e.g., 'openclaw'). Swaps the gateway port for proxying.",
        ),
    ] = None,
) -> None:
    """Wire AgentWard proxy into your MCP configs or gateway.

    Rewrites MCP server commands to run through the AgentWard proxy,
    so every tool call is evaluated against your policy.

    For OpenClaw gateway, use --gateway openclaw to swap the gateway port.

    Examples:
      agentward setup --policy agentward.yaml
      agentward setup --config ~/.cursor/mcp.json --policy agentward.yaml
      agentward setup --gateway openclaw
      agentward setup --gateway openclaw --undo
      agentward setup --dry-run --policy agentward.yaml
    """
    from agentward.setup import (
        format_diff,
        read_config,
        unwrap_config,
        wrap_config,
        write_config,
    )

    # Handle gateway mode (OpenClaw)
    if gateway is not None:
        _run_gateway_setup(gateway, undo, dry_run)
        return

    # MCP config mode — find config files
    config_paths: list[Path] = []
    if config is not None:
        config_paths = [config]
    else:
        from agentward.scan.config import discover_configs

        config_paths = discover_configs()
        if not config_paths:
            _console.print(
                "[bold red]Error:[/bold red] No MCP config files found. "
                "Use --config to specify one.",
                highlight=False,
            )
            raise typer.Exit(1)

    if not undo and not policy.exists() and not dry_run:
        _console.print(
            f"[bold red]Error:[/bold red] Policy file not found: {policy}\n"
            f"Run `agentward configure` to generate one first.",
            highlight=False,
        )
        raise typer.Exit(1)

    wrapped_any = False

    for cfg_path in config_paths:
        try:
            original = read_config(cfg_path)
        except (FileNotFoundError, ValueError) as e:
            _console.print(f"[bold red]Error:[/bold red] {e}", highlight=False)
            continue

        if undo:
            try:
                restored, count = unwrap_config(original)
            except ValueError:
                _console.print(
                    f"[dim]{cfg_path}: No MCP servers section — skipping[/dim]",
                    highlight=False,
                )
                continue
            if count == 0:
                _console.print(
                    f"[dim]{cfg_path}: No AgentWard wrapping found — nothing to undo[/dim]",
                    highlight=False,
                )
                continue

            wrapped_any = True
            if dry_run:
                _console.print(f"[bold]Would unwrap {count} server(s) in {cfg_path}[/bold]")
            else:
                write_config(cfg_path, restored, backup=True)
                _console.print(
                    f"[#00ff88]\u2713[/#00ff88] Restored {count} server(s) in {cfg_path}",
                    highlight=False,
                )
        else:
            try:
                wrapped, count = wrap_config(original, policy, log)
            except ValueError:
                _console.print(
                    f"[dim]{cfg_path}: No MCP servers section — skipping[/dim]",
                    highlight=False,
                )
                continue
            if count == 0:
                _console.print(
                    f"[dim]{cfg_path}: No stdio servers to wrap (or already wrapped)[/dim]",
                    highlight=False,
                )
                continue

            wrapped_any = True
            diff = format_diff(original, wrapped)
            _console.print(f"\n[bold]{cfg_path}[/bold] — {count} server(s) to wrap:")
            _console.print(diff, highlight=False)

            if dry_run:
                _console.print("[dim]Dry run — no changes written.[/dim]")
            else:
                backup = write_config(cfg_path, wrapped, backup=True)
                _console.print(
                    f"[#00ff88]\u2713[/#00ff88] Config updated. Backup: {backup}",
                    highlight=False,
                )

    if not dry_run and not undo:
        if wrapped_any:
            _console.print(
                "\n[bold]Next steps:[/bold]\n"
                "  1. Restart your IDE to apply the changes\n"
                "  2. Run `agentward setup --undo` to revert if needed",
                highlight=False,
            )
        else:
            _console.print(
                "\n[bold]No MCP servers were wrapped.[/bold]\n"
                "For OpenClaw skills, use the gateway mode instead:\n"
                "  agentward setup --gateway openclaw --policy agentward.yaml",
                highlight=False,
            )


def _run_gateway_setup(gateway_type: str, undo: bool, dry_run: bool) -> None:
    """Handle gateway port swapping for agentward setup --gateway.

    Args:
        gateway_type: Gateway identifier ("openclaw" or "clawdbot").
        undo: Whether to restore the original port.
        dry_run: Whether to preview changes without writing.
    """
    if gateway_type not in ("clawdbot", "openclaw"):
        _console.print(
            f"[bold red]Error:[/bold red] Unknown gateway type: {gateway_type!r}\n"
            "Supported gateways: openclaw",
            highlight=False,
        )
        raise typer.Exit(1)

    from agentward.scan.openclaw import find_clawdbot_config
    from agentward.setup import (
        read_config,
        unwrap_clawdbot_gateway,
        wrap_clawdbot_gateway,
        write_config,
    )

    config_path = find_clawdbot_config()
    if config_path is None:
        _console.print(
            "[bold red]Error:[/bold red] OpenClaw config not found.\n"
            "Searched: ~/.openclaw/openclaw.json, ~/.clawdbot/clawdbot.json\n"
            "Is OpenClaw installed?",
            highlight=False,
        )
        raise typer.Exit(1)

    try:
        original = read_config(config_path)
    except (FileNotFoundError, ValueError) as e:
        _console.print(f"[bold red]Error:[/bold red] {e}", highlight=False)
        raise typer.Exit(1) from None

    if undo:
        try:
            restored, was_wrapped = unwrap_clawdbot_gateway(original, config_path)
        except ValueError as e:
            _console.print(f"[bold red]Error:[/bold red] {e}", highlight=False)
            raise typer.Exit(1) from None

        if not was_wrapped:
            _console.print(
                "[dim]OpenClaw gateway port has not been modified by AgentWard — nothing to undo[/dim]",
                highlight=False,
            )
            return

        restored_port = restored.get("gateway", {}).get("port", "?")

        if dry_run:
            _console.print(
                f"[bold]Would restore OpenClaw gateway port to {restored_port}[/bold]",
            )
        else:
            write_config(config_path, restored, backup=True)
            _console.print(
                f"[#00ff88]✓[/#00ff88] Restored OpenClaw gateway port to {restored_port}",
                highlight=False,
            )
            _console.print(
                "\n[bold]Next steps:[/bold]\n"
                "  1. Run `openclaw gateway restart` to apply the change\n"
                "  2. Stop the AgentWard proxy if it's running",
                highlight=False,
            )
    else:
        try:
            wrapped, listen_port, backend_port = wrap_clawdbot_gateway(
                original, config_path
            )
        except ValueError as e:
            _console.print(f"[bold red]Error:[/bold red] {e}", highlight=False)
            raise typer.Exit(1) from None

        _console.print(f"[bold]OpenClaw gateway port swap:[/bold]")
        _console.print(f"  OpenClaw gateway: {listen_port} → {backend_port}")
        _console.print(f"  AgentWard proxy will listen on: {listen_port}")

        if dry_run:
            _console.print("\n[dim]Dry run — no changes written.[/dim]")
        else:
            backup = write_config(config_path, wrapped, backup=True)
            _console.print(
                f"\n[#00ff88]✓[/#00ff88] Updated {config_path}",
                highlight=False,
            )
            if backup:
                _console.print(f"  Backup: {backup}", highlight=False)

            _console.print(
                "\n[bold]Next steps:[/bold]\n"
                "  1. Run `openclaw gateway restart` (so it uses the new port)\n"
                "  2. Run: agentward inspect --gateway openclaw --policy agentward.yaml\n"
                "  3. To undo: agentward setup --gateway openclaw --undo",
                highlight=False,
            )
