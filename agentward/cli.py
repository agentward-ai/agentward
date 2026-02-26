"""AgentWard CLI entry point.

Provides the `agentward` command with subcommands:
  - scan: Scan MCP configs, Python tools, and OpenClaw skills
  - configure: Generate smart-default policy YAML from scan results
  - inspect: Start the MCP proxy with policy enforcement
  - setup: Wire AgentWard proxy into MCP configs
  - comply: Evaluate policy against compliance frameworks (HIPAA, etc.)
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

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


# ---------------------------------------------------------------------------
# init command
# ---------------------------------------------------------------------------


@app.command()
def init(
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Run the full scan and show what would be done, without writing anything.",
        ),
    ] = False,
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Skip confirmation prompts. Apply recommended policy immediately.",
        ),
    ] = False,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output path for the generated policy YAML. Default: ./agentward.yaml",
        ),
    ] = None,
) -> None:
    """One-command setup: scan, generate policy, and wrap your agent environment.

    Scans for MCP configs and OpenClaw skills, shows a risk summary,
    generates a recommended policy, and wires AgentWard into OpenClaw.

    Examples:
      agentward init                          # interactive setup
      agentward init --yes                    # non-interactive (CI/CD)
      agentward init --dry-run                # preview without writing
    """
    from agentward.init import run_init

    run_init(
        console=_console,
        dry_run=dry_run,
        yes=yes,
        policy_path=output,
    )


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
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Observe-only mode. Logs what would be blocked without actually "
            "blocking. Use this to test a policy before enforcing it.",
        ),
    ] = False,
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

    if dry_run:
        _console.print(
            "  Mode: [bold #5eead4]dry-run[/bold #5eead4] (observe only, nothing blocked)",
            highlight=False,
        )

    if gateway is not None:
        # HTTP reverse proxy mode
        _run_gateway_proxy(
            gateway, policy_engine, audit_logger, policy_path, chain_tracker,
            dry_run=dry_run,
        )
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
            dry_run=dry_run,
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
    dry_run: bool = False,
) -> None:
    """Start an HTTP reverse proxy for a gateway.

    Args:
        gateway_type: Gateway identifier ("openclaw" or "clawdbot").
        policy_engine: Loaded policy engine or None for passthrough.
        audit_logger: The audit logger instance.
        policy_path: Path to policy file (for logging).
        chain_tracker: Optional chain tracker for chaining enforcement.
        dry_run: If True, observe and log decisions without enforcing.
    """
    if gateway_type not in ("clawdbot", "openclaw"):
        _console.print(
            f"[bold red]Error:[/bold red] Unknown gateway type: {gateway_type!r}\n"
            "Supported gateways: openclaw",
            highlight=False,
        )
        raise typer.Exit(1)

    from agentward.proxy.approval import ApprovalHandler
    from agentward.proxy.http import HttpProxy
    from agentward.proxy.telegram_approval import try_create_bot
    from agentward.scan.openclaw import find_clawdbot_config
    from agentward.setup import (
        get_clawdbot_gateway_ports,
        get_clawdbot_llm_proxy_config,
        get_clawdbot_telegram_proxy_port,
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

    # Create approval handler for APPROVE decisions (with Telegram if available)
    telegram_proxy_port = get_clawdbot_telegram_proxy_port(config_path)
    if telegram_proxy_port is not None:
        telegram_bot = try_create_bot(config_path, proxy_port=telegram_proxy_port)
    else:
        telegram_bot = try_create_bot(config_path)
    approval_timeout = 60
    if policy_engine is not None:
        approval_timeout = policy_engine.policy.approval_timeout
    approval_handler = ApprovalHandler(
        timeout=approval_timeout,
        telegram_bot=telegram_bot,
    )

    http_proxy = HttpProxy(
        backend_url=backend_url,
        listen_host="127.0.0.1",
        listen_port=listen_port,
        policy_engine=policy_engine,  # type: ignore[arg-type]
        audit_logger=audit_logger,  # type: ignore[arg-type]
        policy_path=policy_path,
        chain_tracker=chain_tracker,  # type: ignore[arg-type]
        approval_handler=approval_handler,
        dry_run=dry_run,
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
            approval_handler=approval_handler,
            dry_run=dry_run,
        )

        async def _start_telegram(bot: "Any") -> bool:
            """Start Telegram bot, auto-freeing stale port if needed."""
            from agentward.proxy.http import _force_free_port

            try:
                await bot.start()
                return True
            except OSError:
                if hasattr(bot, "_proxy_port") and _force_free_port(bot._proxy_port):
                    try:
                        await bot.start()
                        return True
                    except OSError as exc:
                        _console.print(
                            f"  [bold yellow]⚠[/bold yellow] Telegram proxy unavailable: {exc}",
                            highlight=False,
                        )
                        return False
                _console.print(
                    f"  [bold yellow]⚠[/bold yellow] Telegram proxy port in use, skipping.",
                    highlight=False,
                )
                return False

        async def _run_both() -> None:
            import signal as _signal

            shutdown = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (_signal.SIGINT, _signal.SIGTERM):
                loop.add_signal_handler(sig, shutdown.set)
            tg_started = False
            if telegram_bot is not None:
                tg_started = await _start_telegram(telegram_bot)
            try:
                await asyncio.gather(
                    http_proxy.run(shutdown_event=shutdown),
                    llm_proxy.run(shutdown_event=shutdown),
                )
            finally:
                if tg_started and telegram_bot is not None:
                    await telegram_bot.stop()

        try:
            asyncio.run(_run_both())
        except KeyboardInterrupt:
            pass
    else:

        async def _run_http_only() -> None:
            tg_started = False
            if telegram_bot is not None:
                tg_started = await _start_telegram(telegram_bot)
            try:
                await http_proxy.run()
            finally:
                if tg_started and telegram_bot is not None:
                    await telegram_bot.stop()

        try:
            asyncio.run(_run_http_only())
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
        # Don't print "not found" — will show in summary below
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
        except (FileNotFoundError, ConfigParseError) as e:
            console.print(
                f"  [#ff6b35]\u26a0[/#ff6b35] Skipping {config_path}: {e}",
                highlight=False,
            )

    # Step 2: Enumerate tools from MCP servers
    results: list[EnumerationResult] = []
    if all_servers:
        results = asyncio.run(enumerate_all(all_servers, timeout=timeout))

        # Only print per-server details for failures/warnings
        for r in results:
            if r.enumeration_method == "failed":
                console.print(
                    f"  [#ff6b35]\u2716[/#ff6b35] {r.server.name}: enumeration failed"
                    + (f" — {r.error}" if r.error else ""),
                    highlight=False,
                )
            elif r.enumeration_method == "static_inference":
                console.print(
                    f"  [#ffcc00]\u26a0[/#ffcc00] {r.server.name}: could not enumerate (server not running?)",
                    highlight=False,
                )

    # Step 2b: Scan Python source files for tool definitions
    python_results: list[EnumerationResult] = []
    if target is not None and target.is_dir():
        from agentward.scan.skills import scan_directory, tools_to_enumeration_results

        py_tools = scan_directory(target)
        if py_tools:
            python_results = tools_to_enumeration_results(py_tools)

    # Step 2c: Scan OpenClaw skills
    openclaw_results: list[EnumerationResult] = []
    if target is not None and target.is_dir():
        from agentward.scan.openclaw import scan_openclaw_directory

        openclaw_results = scan_openclaw_directory(target)
    elif target is None:
        # Auto-discover: scan known OpenClaw locations
        from agentward.scan.openclaw import discover_skill_dirs, scan_openclaw

        skill_dirs = discover_skill_dirs()
        openclaw_results = scan_openclaw()

    # Print a single concise scan summary line
    summary_parts: list[str] = []
    if all_servers:
        n_tools = sum(len(r.tools) for r in results if r.tools)
        summary_parts.append(f"{n_tools} MCP tool(s) from {len(all_servers)} server(s)")
    if python_results:
        n_py = sum(len(r.tools) for r in python_results)
        summary_parts.append(f"{n_py} Python tool(s)")
    if openclaw_results:
        n_oc = sum(len(r.tools) for r in openclaw_results)
        summary_parts.append(f"{n_oc} OpenClaw skill(s)")
    if summary_parts:
        console.print(
            f"[bold #5eead4]\u26a1[/bold #5eead4] Scanned: {', '.join(summary_parts)}",
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
    output_format: Annotated[
        Optional[str],
        typer.Option(
            "--format",
            "-f",
            help="Output format: 'html' for shareable HTML report, 'sarif' for GitHub Security (CI).",
        ),
    ] = None,
) -> None:
    """Scan MCP configs, Python codebases, and OpenClaw skills for tool definitions.

    Discovers MCP servers, Python agent tool definitions, and OpenClaw
    skills, enumerates their tools, and analyzes data access patterns and risk levels.

    A markdown report (agentward-report.md) is written to the current
    directory automatically on every scan.

    Examples:
      agentward scan                                    # auto-discover all sources
      agentward scan ~/.cursor/mcp.json                 # scan specific MCP config
      agentward scan ~/project/                         # scan directory (MCP + Python + OpenClaw)
      agentward scan ~/clawd/skills/                    # scan OpenClaw skills directory
      agentward scan --json > report.json               # machine-readable output
      agentward scan --format html                      # shareable HTML report
      agentward scan --format sarif                     # SARIF for GitHub Security tab
    """
    from agentward.scan.report import (
        generate_scan_markdown,
        print_scan_json,
        print_scan_report,
    )

    scan_result, recommendations, _config_paths, chains = _run_scan(target, timeout, _console)

    if output_json:
        output_console = Console()
        print_scan_json(scan_result, output_console)
    elif output_format == "html":
        from agentward.scan.html_report import generate_scan_html

        html_content = generate_scan_html(scan_result, recommendations, chains=chains)
        report_path = Path("agentward-report.html")
        report_path.write_text(html_content, encoding="utf-8")
        _console.print(
            f"[#00ff88]✓[/#00ff88] HTML report saved to {report_path}",
            highlight=False,
        )
    elif output_format == "sarif":
        from agentward.scan.sarif_report import generate_sarif

        sarif = generate_sarif(scan_result, recommendations, chains=chains)
        report_path = Path("agentward-report.sarif")
        report_path.write_text(sarif, encoding="utf-8")
        _console.print(
            f"[#00ff88]✓[/#00ff88] SARIF report saved to {report_path}",
            highlight=False,
        )
    elif output_format is not None:
        _console.print(
            f"[bold red]Error:[/bold red] Unknown format: {output_format!r}\n"
            "Supported formats: html, sarif",
            highlight=False,
        )
        raise typer.Exit(1)
    else:
        print_scan_report(scan_result, recommendations, _console, chains=chains)

        # Write markdown report (skip in --json/--format modes — stdout is for piping)
        report_path = Path("agentward-report.md")
        md = generate_scan_markdown(scan_result, recommendations, chains=chains)
        report_path.write_text(md, encoding="utf-8")
        _console.print(
            f"[#00ff88]\u2713[/#00ff88] Report saved to {report_path}",
            highlight=False,
        )


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
def audit(
    log: Annotated[
        Path,
        typer.Option(
            "--log",
            "-l",
            help="Path to the JSON Lines audit log file.",
        ),
    ] = Path("agentward-audit.jsonl"),
    decision: Annotated[
        Optional[str],
        typer.Option(
            "--decision",
            "-d",
            help="Filter by decision (e.g., BLOCK, ALLOW, APPROVE).",
        ),
    ] = None,
    tool: Annotated[
        Optional[str],
        typer.Option(
            "--tool",
            "-t",
            help="Filter by tool name (substring match).",
        ),
    ] = None,
    timeline: Annotated[
        bool,
        typer.Option(
            "--timeline",
            help="Show the event timeline.",
        ),
    ] = False,
    last: Annotated[
        Optional[int],
        typer.Option(
            "--last",
            "-n",
            help="Only show the last N log entries.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output raw statistics as JSON.",
        ),
    ] = False,
) -> None:
    """Read and display audit trail from a log file.

    Shows summary statistics, decision breakdowns, and optionally
    a timeline of events from an agentward inspect session.

    Examples:
      agentward audit --log agentward-audit.jsonl
      agentward audit --decision BLOCK --timeline
      agentward audit --tool gmail --last 100
      agentward audit --json
    """
    from agentward.audit.reader import read_audit_log, render_dashboard

    try:
        stats = read_audit_log(
            log,
            decision_filter=decision,
            tool_filter=tool,
            last_n=last,
        )
    except FileNotFoundError as e:
        _console.print(f"[bold red]Error:[/bold red] {e}", highlight=False)
        raise typer.Exit(1) from None

    if json_output:
        import json as _json

        output = {
            "total_events": stats.total_events,
            "tool_calls": stats.tool_calls,
            "sessions": stats.sessions,
            "decisions": dict(stats.decisions),
            "tools": dict(stats.tools.most_common(20)),
            "blocked_tools": dict(stats.blocked_tools),
            "chain_violations": stats.chain_violations,
            "dry_run_count": stats.dry_run_count,
            "approvals": stats.approvals,
            "sensitive_blocks": stats.sensitive_blocks,
            "first_timestamp": stats.first_timestamp,
            "last_timestamp": stats.last_timestamp,
        }
        # JSON output goes to stdout (not stderr) for piping
        print(_json.dumps(output, indent=2))
        return

    from agentward.banner import print_banner

    print_banner(_console)
    render_dashboard(stats, _console, show_timeline=timeline)


@app.command()
def status(
    log: Annotated[
        Path,
        typer.Option("--log", "-l", help="Path to the audit log file."),
    ] = Path("agentward-audit.jsonl"),
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Machine-readable JSON output."),
    ] = False,
) -> None:
    """Show live proxy status and current session statistics.

    Checks for running AgentWard proxy processes and reads the audit log
    to show real-time decision statistics for the current session.
    """
    from agentward.banner import print_banner
    from agentward.status import get_status, render_status

    status_data = get_status(audit_log=log)

    if json_output:
        import json as json_mod

        output = {
            "proxies": [
                {
                    "port": p.port,
                    "pid": p.pid,
                    "alive": p.alive,
                }
                for p in status_data.proxies
            ],
            "audit_log": str(status_data.audit_log) if status_data.audit_log else None,
            "audit_exists": status_data.audit_exists,
            "session": {
                "start": status_data.session_start,
                "last_event": status_data.last_event,
                "uptime_seconds": round(status_data.uptime_seconds, 1) if status_data.uptime_seconds else None,
            },
            "tool_calls": {
                "total": status_data.total_calls,
                "decisions": status_data.decisions,
                "blocked_tools": status_data.blocked_tools,
                "chain_violations": status_data.chain_violations,
                "sensitive_blocks": status_data.sensitive_blocks,
                "approvals": status_data.approvals,
                "dry_run_count": status_data.dry_run_count,
            },
        }
        _console.print_json(json_mod.dumps(output))
        return

    print_banner(_console)
    render_status(status_data, _console)


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
    policy: Annotated[
        Path,
        typer.Option(
            "--policy",
            "-p",
            help="Path to the agentward.yaml policy file to evaluate.",
        ),
    ] = Path("agentward.yaml"),
    target: Annotated[
        Optional[Path],
        typer.Argument(
            help="Path to scan for tool metadata. "
            "If omitted, auto-discovers from known locations.",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Output path for the fixed policy. Default: agentward-<framework>.yaml",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            "-t",
            help="Timeout in seconds for MCP server enumeration.",
        ),
    ] = 15.0,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output report as JSON."),
    ] = False,
) -> None:
    """Evaluate current policy against a compliance framework.

    Loads the policy file, optionally scans for tool metadata, and
    evaluates against the specified framework's controls. Produces a
    compliance delta report showing gaps and required fixes.

    With --fix, generates an updated policy with all required changes
    applied.

    Examples:
      agentward comply --framework hipaa
      agentward comply --framework hipaa --fix
      agentward comply --framework hipaa --json
      agentward comply --framework hipaa --policy custom.yaml
    """
    import json as json_mod

    from agentward.banner import print_banner
    from agentward.comply.controls import apply_fixes, evaluate_compliance
    from agentward.comply.frameworks import get_framework
    from agentward.comply.report import render_compliance_json, render_compliance_report
    from agentward.policy.loader import load_policy

    # Import framework module to trigger registration
    try:
        import agentward.comply.frameworks.hipaa  # noqa: F401
    except Exception as e:
        _console.print(
            f"\n[bold red]Error:[/bold red] Failed to load framework modules: {e}",
            highlight=False,
        )
        raise typer.Exit(1)

    if not json_output:
        print_banner(_console)

    # Load policy
    try:
        loaded_policy = load_policy(policy)
    except FileNotFoundError as e:
        _console.print(f"\n[bold red]Error:[/bold red] {e}", highlight=False)
        raise typer.Exit(1)
    except Exception as e:
        _console.print(f"\n[bold red]Error:[/bold red] {e}", highlight=False)
        raise typer.Exit(1)

    # Run scan (optional — gracefully degrade if no tools found)
    scan_result = None
    try:
        scan_result, _recommendations, _config_paths, _chains = _run_scan(
            target, timeout, _console,
        )
    except (typer.Exit, SystemExit):
        # Scan found nothing — proceed with policy-only checks
        if not json_output:
            _console.print(
                "[dim]No tools discovered — running policy-only compliance checks.[/dim]\n"
            )
    except Exception as e:
        # Scan crashed (PermissionError, UnicodeDecodeError, etc.) — degrade gracefully
        if not json_output:
            _console.print(
                f"[dim]Scan failed ({type(e).__name__}: {e}) "
                f"— running policy-only compliance checks.[/dim]\n"
            )

    # Load framework controls
    try:
        controls = get_framework(framework)
    except ValueError as e:
        _console.print(f"\n[bold red]Error:[/bold red] {e}", highlight=False)
        raise typer.Exit(1)

    # Evaluate compliance
    report = evaluate_compliance(loaded_policy, scan_result, controls, framework)

    # Render rich output (non-JSON, non-fix mode renders here)
    if not json_output:
        render_compliance_report(report, _console)

    # Auto-fix mode
    fix_metadata: dict[str, Any] | None = None
    if fix and report.findings:
        from agentward.configure.generator import write_policy
        from agentward.policy.diff import diff_policies, render_diff

        try:
            fixed_policy = apply_fixes(loaded_policy, report.findings)
        except (KeyError, ValueError, TypeError) as e:
            _console.print(
                f"\n[bold red]Error applying fixes:[/bold red] {e}\n"
                f"[dim]This may indicate a bug in the compliance fix logic. "
                f"Please report this issue.[/dim]",
                highlight=False,
            )
            raise typer.Exit(1)

        diff = diff_policies(loaded_policy, fixed_policy)

        # Write fixed policy
        output_path = output or Path(f"agentward-{framework}.yaml")
        try:
            write_policy(fixed_policy, output_path)
        except PermissionError:
            _console.print(
                f"\n[bold red]Error:[/bold red] Permission denied writing to "
                f"{output_path}\n\nUse -o to specify a writable path.",
                highlight=False,
            )
            raise typer.Exit(1)

        fix_metadata = {
            "fix_applied": True,
            "output_path": str(output_path),
            "changes": len(diff.changes) if not diff.is_empty else 0,
        }

        if not json_output:
            if not diff.is_empty:
                _console.print("[bold]Policy changes to apply:[/bold]\n")
                render_diff(diff, _console)
            _console.print(
                f"\n[bold #00ff88]Fixed policy written to:[/bold #00ff88] {output_path}\n"
                f"[dim]Review the changes, then apply with: "
                f"agentward setup --policy {output_path}[/dim]\n"
            )
    elif fix and not report.findings:
        fix_metadata = {"fix_applied": False, "changes": 0}
        if not json_output:
            _console.print(
                "\n[bold #00ff88]No fixes needed — policy is already compliant.[/bold #00ff88]\n"
            )

    # JSON output — single print with optional fix metadata
    if json_output:
        from rich.console import Console

        output_data = render_compliance_json(report)
        if fix_metadata is not None:
            output_data.update(fix_metadata)
        Console().print_json(json_mod.dumps(output_data))

    # Exit with error code if required controls failed
    required_failures = sum(
        1 for f in report.findings
        if f.severity.value == "required"
    )
    if required_failures > 0:
        if fix:
            # When --fix is used, check if unfixable required gaps remain
            unfixable = sum(
                1 for f in report.findings
                if f.severity.value == "required" and f.fix is None
            )
            if unfixable > 0:
                raise typer.Exit(1)
        else:
            raise typer.Exit(1)


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
                try:
                    write_config(cfg_path, restored, backup=True)
                except PermissionError as exc:
                    _console.print(f"[bold red]Error:[/bold red] {exc}")
                    raise typer.Exit(1) from None
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
                try:
                    backup = write_config(cfg_path, wrapped, backup=True)
                except PermissionError as exc:
                    _console.print(f"[bold red]Error:[/bold red] {exc}")
                    raise typer.Exit(1) from None
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
            try:
                write_config(config_path, restored, backup=True)
            except PermissionError as exc:
                _console.print(f"[bold red]Error:[/bold red] {exc}")
                raise typer.Exit(1) from None
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
            try:
                backup = write_config(config_path, wrapped, backup=True)
            except PermissionError as exc:
                _console.print(f"[bold red]Error:[/bold red] {exc}")
                raise typer.Exit(1) from None
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


@app.command(name="diff")
def diff_command(
    old_policy: Annotated[
        Path,
        typer.Argument(help="Path to the baseline (old) policy YAML file."),
    ],
    new_policy: Annotated[
        Path,
        typer.Argument(help="Path to the updated (new) policy YAML file."),
    ],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output diff as JSON (for CI integration).",
        ),
    ] = False,
) -> None:
    """Compare two AgentWard policy files and show enforcement changes.

    Useful for PR reviews to understand exactly what changed between policy
    versions. Shows breaking vs. relaxing changes.

    Examples:

      agentward diff old.yaml new.yaml                # rich diff output
      agentward diff main.yaml feature.yaml --json    # JSON for CI
    """
    import json

    from agentward.banner import print_banner
    from agentward.policy.diff import diff_policies, render_diff
    from agentward.policy.loader import load_policy

    print_banner(_console)

    try:
        old = load_policy(old_policy)
    except (FileNotFoundError, Exception) as e:
        _console.print(f"[bold red]Error loading {old_policy}:[/bold red] {e}")
        raise typer.Exit(1) from e

    try:
        new = load_policy(new_policy)
    except (FileNotFoundError, Exception) as e:
        _console.print(f"[bold red]Error loading {new_policy}:[/bold red] {e}")
        raise typer.Exit(1) from e

    diff = diff_policies(old, new)

    if json_output:
        output = {
            "total_changes": len(diff.changes),
            "breaking": diff.breaking,
            "relaxing": diff.relaxing,
            "changes": [
                {
                    "category": c.category,
                    "type": c.change_type.value,
                    "path": c.path,
                    "old_value": c.old_value,
                    "new_value": c.new_value,
                    "description": c.description,
                }
                for c in diff.changes
            ],
        }
        # Write JSON to stdout for piping
        from rich.console import Console as _StdoutConsole

        _StdoutConsole().print_json(json.dumps(output))
    else:
        render_diff(diff, _console)

        if diff.is_empty:
            raise typer.Exit(0)

        _console.print(
            f"  [dim]{old_policy} → {new_policy}[/dim]\n",
            highlight=False,
        )


# ---------------------------------------------------------------------------
# sanitize command
# ---------------------------------------------------------------------------


@app.command()
def sanitize(
    file: Annotated[
        Path,
        typer.Argument(help="Path to the file to sanitize (txt, md, csv, json, yaml, pdf, etc.)."),
    ],
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Write sanitized output to this file. Default: stdout.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Output as JSON with entities, mapping, and sanitized text.",
        ),
    ] = False,
    categories: Annotated[
        Optional[str],
        typer.Option(
            "--categories",
            "-c",
            help="Comma-separated PII categories to detect (e.g. 'ssn,credit_card,email'). "
            "Default: all.",
        ),
    ] = None,
    preview: Annotated[
        bool,
        typer.Option(
            "--preview",
            help="Show detected entities without redacting. Dry-run mode.",
        ),
    ] = False,
    report: Annotated[
        bool,
        typer.Option(
            "--report",
            help="Show a summary table of detected PII categories and counts.",
        ),
    ] = False,
    use_ner: Annotated[
        bool,
        typer.Option(
            "--ner",
            help="Enable spaCy NER detection for names, orgs, locations. "
            "Requires: pip install agentward[sanitize]",
        ),
    ] = False,
    confidence: Annotated[
        float,
        typer.Option(
            "--confidence",
            help="Minimum confidence threshold for NER entities (0.0-1.0).",
        ),
    ] = 0.5,
) -> None:
    """Detect and redact PII from files.

    Scans a file for personally identifiable information (credit cards, SSNs,
    emails, phone numbers, API keys, etc.) and outputs a sanitized version
    with PII replaced by numbered placeholders like [CREDIT_CARD_1].

    Examples:

      agentward sanitize patient-notes.txt                  # sanitize to stdout
      agentward sanitize data.csv -o clean.csv              # write to file
      agentward sanitize report.pdf --json                  # JSON with entity map
      agentward sanitize notes.md --preview                 # detect-only, no redaction
      agentward sanitize notes.md --report                  # summary table
      agentward sanitize notes.md --ner                     # enable NER for names/orgs
      agentward sanitize log.txt -c ssn,credit_card,email   # specific categories only
    """
    import json

    from rich.table import Table

    from agentward.banner import print_banner
    from agentward.sanitize.engine import sanitize_file
    from agentward.sanitize.models import PIICategory, SanitizeConfig

    print_banner(_console)

    # Parse category filter.
    cat_set: set[PIICategory] | None = None
    if categories is not None:
        cat_set = set()
        for raw in categories.split(","):
            name = raw.strip().lower()
            if not name:
                continue
            try:
                cat_set.add(PIICategory(name))
            except ValueError:
                _console.print(
                    f"[bold yellow]Warning:[/bold yellow] Unknown category '{name}', skipping. "
                    f"Valid: {', '.join(c.value for c in PIICategory)}",
                )
        if not cat_set:
            _console.print("[bold red]Error:[/bold red] No valid categories specified.")
            raise typer.Exit(1)

    config = SanitizeConfig(
        categories=cat_set,
        min_confidence=confidence,
        use_ner=use_ner,
    )

    try:
        result = sanitize_file(file, config=config)
    except FileNotFoundError as e:
        _console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1) from None
    except ValueError as e:
        _console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1) from None
    except ImportError as e:
        _console.print(f"[bold red]Missing dependency:[/bold red] {e}")
        raise typer.Exit(1) from None

    # Preview mode: show detected entities without redacting.
    # Raw PII text is intentionally NOT printed — only category, offset,
    # length, and placeholder are shown.  This prevents leaking sensitive
    # data into LLM context when the output is captured by an agent.
    if preview:
        if not result.has_pii:
            _console.print("[#00ff88]No PII detected.[/#00ff88]")
            return

        _console.print(f"\n[bold]Detected {len(result.entities)} PII entities:[/bold]\n")
        table = Table(show_header=True, header_style="bold")
        table.add_column("#", style="dim", width=4)
        table.add_column("Category", style="cyan")
        table.add_column("Placeholder", style="yellow")
        table.add_column("Offset", style="dim")
        table.add_column("Length", style="dim")
        table.add_column("Detector", style="dim")

        # Build placeholder names using the same logic as the redactor.
        cat_counters: dict[str, int] = {}
        for i, ent in enumerate(result.entities, 1):
            cat_key = ent.category.value.upper()
            cat_counters[cat_key] = cat_counters.get(cat_key, 0) + 1
            placeholder = f"[{cat_key}_{cat_counters[cat_key]}]"
            table.add_row(
                str(i),
                ent.category.value,
                placeholder,
                f"{ent.start}:{ent.end}",
                str(ent.end - ent.start),
                ent.detector,
            )
        _console.print(table)
        return

    # Report mode: summary table.
    if report:
        if not result.has_pii:
            _console.print("[#00ff88]No PII detected.[/#00ff88]")
            return

        _console.print(f"\n[bold]PII Summary — {file.name}[/bold]\n")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Category", style="cyan")
        table.add_column("Count", justify="right", style="bold")

        for cat_name, count in sorted(result.summary.items()):
            table.add_row(cat_name, str(count))

        table.add_section()
        table.add_row("[bold]Total[/bold]", f"[bold]{len(result.entities)}[/bold]")
        _console.print(table)
        return

    # JSON output.
    if json_output:
        # Stdout JSON intentionally omits raw PII values (entities[].text
        # and entity_map) to prevent leaking sensitive data into LLM context
        # when the output is captured by an agent.
        output_data: dict[str, Any] = {
            "file": str(file),
            "has_pii": result.has_pii,
            "entity_count": len(result.entities),
            "summary": result.summary,
            "entities": [
                {
                    "category": e.category.value,
                    "start": e.start,
                    "end": e.end,
                    "confidence": e.confidence,
                    "detector": e.detector,
                }
                for e in result.entities
            ],
            "sanitized_text": result.sanitized_text,
        }

        # Write the entity map (contains raw PII) to a sidecar file when
        # --output is specified.  This keeps it on disk and out of stdout.
        if output is not None:
            map_path = output.with_suffix(".entity-map.json")
            map_data = {
                "entity_map": result.entity_map,
                "entities": [
                    {
                        "category": e.category.value,
                        "text": e.text,
                        "start": e.start,
                        "end": e.end,
                        "confidence": e.confidence,
                        "detector": e.detector,
                    }
                    for e in result.entities
                ],
            }
            map_path.parent.mkdir(parents=True, exist_ok=True)
            map_path.write_text(json.dumps(map_data, indent=2), encoding="utf-8")
            output_data["entity_map_file"] = str(map_path)
            _console.print(
                f"[dim]Entity map written to {map_path} (contains raw PII — do not share)[/dim]",
                highlight=False,
            )

        # JSON to stdout.
        from rich.console import Console as _StdoutConsole

        _StdoutConsole().print_json(json.dumps(output_data))
        return

    # Default: write sanitized text.
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(result.sanitized_text, encoding="utf-8")
        _console.print(
            f"[#00ff88]Sanitized output written to {output}[/#00ff88]",
            highlight=False,
        )
        if result.has_pii:
            _console.print(
                f"  Redacted {len(result.entities)} entities across "
                f"{len(result.categories_found)} categories.",
                highlight=False,
            )
    else:
        # Stdout: write sanitized text directly.
        sys.stdout.write(result.sanitized_text)
        if not result.sanitized_text.endswith("\n"):
            sys.stdout.write("\n")

        if result.has_pii:
            _console.print(
                f"\n[dim]Redacted {len(result.entities)} entities across "
                f"{len(result.categories_found)} categories.[/dim]",
                highlight=False,
            )
