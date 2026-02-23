"""``agentward init`` — one-command onboarding.

Wraps the four-step flow (scan → configure → setup → wrap) into a single
interactive command.  Designed so a brand-new user can go from
``pip install agentward`` to a fully-enforced OpenClaw setup in under
two minutes.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from agentward.configure.generator import generate_policy, write_policy
from agentward.scan.chains import ChainDetection, detect_chains
from agentward.scan.config import ConfigParseError, discover_configs, parse_config_file
from agentward.scan.enumerator import EnumerationResult, enumerate_all
from agentward.scan.openclaw import find_clawdbot_config, scan_openclaw
from agentward.scan.permissions import (
    RiskLevel,
    ScanResult,
    build_permission_map,
)
from agentward.scan.recommendations import generate_recommendations
from agentward.setup import (
    get_clawdbot_gateway_ports,
    get_clawdbot_llm_proxy_config,
    read_config,
    wrap_clawdbot_gateway,
    write_config,
)

# ---------------------------------------------------------------------------
# Color palette — matches agentward.ai (same as scan/report.py)
# ---------------------------------------------------------------------------

_CLR_LOW = "#00ff88"
_CLR_MEDIUM = "#ffcc00"
_CLR_HIGH = "#ff6b35"
_CLR_CRITICAL = "#ff3366"
_CLR_GREEN = "#00ff88"
_CLR_DIM = "#555555"


# ---------------------------------------------------------------------------
# Scan summary helpers
# ---------------------------------------------------------------------------


def _source_summary(scan: ScanResult) -> list[str]:
    """Build human-readable lines describing what was found.

    Returns one line per config source / server.
    """
    lines: list[str] = []
    for server_map in scan.servers:
        source = server_map.server.source_file
        n_tools = len(server_map.tools)
        kind = server_map.enumeration_method
        # Try to give a friendlier label
        if kind == "openclaw_skill":
            label = f"{n_tools} skill(s)"
        else:
            label = f"{n_tools} tool(s)"
        lines.append(f"  [bold]Found:[/bold] {source} ({label})")
    return lines


def _risk_summary(
    scan: ScanResult,
    chains: list[ChainDetection],
) -> tuple[dict[RiskLevel, list[str]], list[str]]:
    """Build per-risk-level tool lists and chain labels.

    Returns:
        Tuple of (risk_buckets, chain_labels).
        risk_buckets maps RiskLevel → list of tool names.
        chain_labels is a list of "source → target" strings.
    """
    buckets: dict[RiskLevel, list[str]] = {
        RiskLevel.CRITICAL: [],
        RiskLevel.HIGH: [],
        RiskLevel.MEDIUM: [],
        RiskLevel.LOW: [],
    }

    for server_map in scan.servers:
        for tool in server_map.tools:
            buckets[tool.risk_level].append(tool.tool.name)

    chain_labels = [c.label for c in chains]

    return buckets, chain_labels


def _has_any_risk(
    buckets: dict[RiskLevel, list[str]],
    chain_labels: list[str],
) -> bool:
    """True if there are any CRITICAL, HIGH, or chain risks."""
    return bool(
        buckets[RiskLevel.CRITICAL]
        or buckets[RiskLevel.HIGH]
        or chain_labels
    )


def _print_enforcement_summary(
    console: Console,
    scan: ScanResult,
    policy: "AgentWardPolicy",
) -> None:
    """Print what the policy will enforce for each discovered tool.

    Shows a compact per-tool list: BLOCK, APPROVE, or ALLOW.

    Args:
        console: Rich console for output (stderr).
        scan: The scan result with tool info.
        policy: The generated policy.
    """
    from agentward.configure.generator import _OPENCLAW_SKILL_TO_TOOL
    from agentward.policy.engine import PolicyEngine
    from agentward.policy.schema import PolicyDecision

    engine = PolicyEngine(policy)

    console.print("\n[bold]Enforcement:[/bold]", highlight=False)

    for server_map in scan.servers:
        for tool_perm in server_map.tools:
            scanned_name = tool_perm.tool.name
            # Resolve to runtime tool name (what the LLM proxy sees)
            runtime_name = _OPENCLAW_SKILL_TO_TOOL.get(scanned_name, scanned_name)

            result = engine.evaluate(runtime_name, {})

            if result.decision == PolicyDecision.BLOCK:
                console.print(
                    f"  [{_CLR_CRITICAL}]✗ BLOCK[/{_CLR_CRITICAL}]    {scanned_name}",
                    highlight=False,
                )
            elif result.decision == PolicyDecision.APPROVE:
                console.print(
                    f"  [{_CLR_MEDIUM}]⊘ APPROVE[/{_CLR_MEDIUM}]  {scanned_name}",
                    highlight=False,
                )
            else:
                console.print(
                    f"  [{_CLR_GREEN}]✓ ALLOW[/{_CLR_GREEN}]    {scanned_name}",
                    highlight=False,
                )


def print_risk_summary(
    console: Console,
    buckets: dict[RiskLevel, list[str]],
    chain_labels: list[str],
) -> None:
    """Print the risk summary block."""
    if not _has_any_risk(buckets, chain_labels):
        console.print(
            f"\n[bold {_CLR_GREEN}]✓ No high-risk tools detected[/bold {_CLR_GREEN}]",
            highlight=False,
        )
        return

    console.print(f"\n[bold]⚠  Risk summary:[/bold]", highlight=False)

    crit = buckets[RiskLevel.CRITICAL]
    if crit:
        names = ", ".join(crit[:5])
        if len(crit) > 5:
            names += f" (+{len(crit) - 5} more)"
        console.print(
            f"   [{_CLR_CRITICAL}]{len(crit)} CRITICAL[/{_CLR_CRITICAL}]  · {names}",
            highlight=False,
        )

    high = buckets[RiskLevel.HIGH]
    if high:
        names = ", ".join(high[:5])
        if len(high) > 5:
            names += f" (+{len(high) - 5} more)"
        console.print(
            f"   [{_CLR_HIGH}]{len(high)} HIGH[/{_CLR_HIGH}]      · {names}",
            highlight=False,
        )

    medium = buckets[RiskLevel.MEDIUM]
    if medium:
        names = ", ".join(medium[:5])
        if len(medium) > 5:
            names += f" (+{len(medium) - 5} more)"
        console.print(
            f"   [{_CLR_MEDIUM}]{len(medium)} MEDIUM[/{_CLR_MEDIUM}]    · {names}",
            highlight=False,
        )

    if chain_labels:
        console.print(
            f"   [{_CLR_HIGH}]{len(chain_labels)} chain(s)[/{_CLR_HIGH}]  · "
            + ", ".join(chain_labels[:3])
            + (" …" if len(chain_labels) > 3 else ""),
            highlight=False,
        )


# ---------------------------------------------------------------------------
# Policy generation with init-specific defaults
# ---------------------------------------------------------------------------


def generate_init_policy(
    scan: ScanResult,
    chains: list[ChainDetection],
) -> "AgentWardPolicy":
    """Generate a recommended policy with stricter defaults than ``configure``.

    Differences from ``agentward configure``:
      - CRITICAL tools → denied (blocked entirely)
      - HIGH tools → require_approval
      - Everything else → allow (passthrough)

    Runtime tool names that don't appear in the policy (e.g. ``exec`` from
    a ``coding-agent`` skill) are handled by the LLM proxy's runtime
    classification — see ``_filter_blocked_tools()`` in ``proxy/llm.py``.

    Falls back to the standard ``generate_policy`` and then upgrades.
    """
    from agentward.policy.schema import (
        AgentWardPolicy,
        ChainingMode,
        ResourcePermissions,
    )

    # Start with the standard configure output
    policy = generate_policy(scan)

    # Upgrade: block CRITICAL tools (denied at resource level)
    for server_map in scan.servers:
        server_name = server_map.server.name
        for tool in server_map.tools:
            if tool.risk_level == RiskLevel.CRITICAL:
                # Ensure skill exists
                if server_name not in policy.skills:
                    policy.skills[server_name] = {}
                # Infer a resource key from the tool name
                resource_key = tool.tool.name
                policy.skills[server_name][resource_key] = (
                    ResourcePermissions.model_construct(
                        denied=True,
                        actions={},
                        filters={},
                    )
                )

    # Upgrade: add HIGH tools to require_approval if not already there
    approval_set = set(policy.require_approval)
    for server_map in scan.servers:
        for tool in server_map.tools:
            if tool.risk_level == RiskLevel.HIGH:
                if tool.tool.name not in approval_set:
                    policy.require_approval.append(tool.tool.name)
                    approval_set.add(tool.tool.name)

    # Set chaining mode to content (strictest useful default)
    policy.chaining_mode = ChainingMode.CONTENT

    return policy


# ---------------------------------------------------------------------------
# OpenClaw gateway wrapping
# ---------------------------------------------------------------------------


def wrap_openclaw_gateway(console: Console) -> bool:
    """Attempt to wrap the OpenClaw gateway via ``agentward setup``.

    Returns True if wrapping succeeded, False if OpenClaw was not found or
    wrapping failed.
    """
    config_path = find_clawdbot_config()
    if config_path is None:
        return False

    try:
        original = read_config(config_path)
    except (FileNotFoundError, ValueError) as e:
        console.print(
            f"  [{_CLR_HIGH}]⚠[/{_CLR_HIGH}] Could not read OpenClaw config: {e}",
            highlight=False,
        )
        return False

    try:
        wrapped, listen_port, backend_port = wrap_clawdbot_gateway(
            original, config_path
        )
    except ValueError as e:
        # Already wrapped or other issue — that's fine
        console.print(
            f"  [dim]OpenClaw gateway already configured ({e})[/dim]",
            highlight=False,
        )
        return True

    write_config(config_path, wrapped, backup=True)
    console.print(
        f"  [{_CLR_GREEN}]✓[/{_CLR_GREEN}] OpenClaw gateway: port {listen_port} → {backend_port}",
        highlight=False,
    )
    return True


# ---------------------------------------------------------------------------
# Gateway restart
# ---------------------------------------------------------------------------


def _find_gateway_binary() -> str | None:
    """Find the OpenClaw/ClawdBot gateway binary on PATH.

    Returns:
        Binary name ("openclaw" or "clawdbot") if found, None otherwise.
    """
    for name in ("openclaw", "clawdbot"):
        if shutil.which(name) is not None:
            return name
    return None


def _is_port_listening(port: int) -> bool:
    """Check if something is listening on a TCP port.

    Args:
        port: The port number to check.

    Returns:
        True if the port is in use (something listening), False otherwise.
    """
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def restart_openclaw_gateway(console: Console) -> bool:
    """Restart the OpenClaw gateway so it picks up the new port.

    Runs ``openclaw gateway restart`` (or ``clawdbot gateway restart``).

    The health check built into ``openclaw gateway restart`` may report
    failure because it checks the original port — but AgentWard swapped
    the port, so the gateway is actually listening on the backend port.
    If the command fails, we verify the gateway is listening on the
    backend port and treat that as success.

    Args:
        console: Rich console for output (stderr).

    Returns:
        True if the restart command succeeded, False otherwise.
    """
    binary = _find_gateway_binary()
    if binary is None:
        return False

    console.print(
        "  Restarting OpenClaw gateway...",
        style="dim",
        highlight=False,
    )

    try:
        result = subprocess.run(
            [binary, "gateway", "restart"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False

    if result.returncode == 0:
        console.print(
            f"  [{_CLR_GREEN}]✓[/{_CLR_GREEN}]  OpenClaw gateway restarted",
            highlight=False,
        )
        return True

    # Health check failed — but the gateway may actually be running on
    # the swapped backend port.  Verify before giving up.
    config_path = find_clawdbot_config()
    if config_path is not None:
        ports = get_clawdbot_gateway_ports(config_path)
        if ports is not None:
            _listen_port, backend_port = ports
            if _is_port_listening(backend_port):
                console.print(
                    f"  [{_CLR_GREEN}]✓[/{_CLR_GREEN}]  OpenClaw gateway restarted (port {backend_port})",
                    highlight=False,
                )
                return True

    stderr = result.stderr.strip()
    if stderr:
        console.print(
            f"  [{_CLR_HIGH}]⚠[/{_CLR_HIGH}] {stderr}",
            highlight=False,
        )
    return False


# ---------------------------------------------------------------------------
# Proxy startup
# ---------------------------------------------------------------------------


def start_proxy(console: Console, policy_path: Path) -> None:
    """Start the AgentWard proxy in the foreground.

    This is a blocking call — it runs the HTTP proxy (and LLM proxy if
    configured) until interrupted.  Designed as the final step of
    ``agentward init``.

    Args:
        console: Rich console for output (stderr).
        policy_path: Path to the agentward.yaml policy file.
    """
    from agentward.audit.logger import AuditLogger
    from agentward.policy.engine import PolicyEngine
    from agentward.policy.loader import PolicyValidationError, load_policy
    from agentward.policy.schema import ChainingMode
    from agentward.proxy.chaining import ChainTracker
    from agentward.proxy.http import HttpProxy

    # Load policy
    try:
        policy = load_policy(policy_path)
    except (FileNotFoundError, PolicyValidationError) as e:
        console.print(
            f"  [{_CLR_HIGH}]⚠[/{_CLR_HIGH}] Cannot load policy: {e}",
            highlight=False,
        )
        return

    policy_engine = PolicyEngine(policy)
    audit_logger = AuditLogger(log_path=None)

    # Approval handler for APPROVE decisions
    from agentward.proxy.approval import ApprovalHandler

    approval_handler = ApprovalHandler(
        timeout=policy_engine.policy.approval_timeout,
    )

    # Chain tracker
    chain_tracker: ChainTracker | None = None
    if policy_engine.policy.skill_chaining:
        chain_tracker = ChainTracker(
            policy_engine=policy_engine,
            mode=policy_engine.policy.chaining_mode,
        )

    # Find OpenClaw config for port info
    config_path = find_clawdbot_config()
    if config_path is None:
        console.print(
            f"  [{_CLR_HIGH}]⚠[/{_CLR_HIGH}] OpenClaw config not found — cannot start proxy.",
            highlight=False,
        )
        return

    ports = get_clawdbot_gateway_ports(config_path)
    if ports is None:
        console.print(
            f"  [{_CLR_HIGH}]⚠[/{_CLR_HIGH}] Gateway ports not configured — cannot start proxy.",
            highlight=False,
        )
        return

    listen_port, backend_port = ports
    backend_url = f"http://127.0.0.1:{backend_port}"

    http_proxy = HttpProxy(
        backend_url=backend_url,
        listen_host="127.0.0.1",
        listen_port=listen_port,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        policy_path=policy_path,
        chain_tracker=chain_tracker,
        approval_handler=approval_handler,
    )

    # Check for LLM proxy config (baseUrl patching)
    llm_config = get_clawdbot_llm_proxy_config(config_path)

    if llm_config is not None:
        from agentward.proxy.llm import LlmProxy

        llm_port, provider_urls = llm_config
        llm_proxy = LlmProxy(
            listen_port=llm_port,
            provider_urls=provider_urls,
            policy_engine=policy_engine,
            audit_logger=audit_logger,
            policy_path=policy_path,
            approval_handler=approval_handler,
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
# Main init flow
# ---------------------------------------------------------------------------


def run_init(
    console: Console,
    dry_run: bool = False,
    yes: bool = False,
    policy_path: Path | None = None,
) -> None:
    """Execute the full init flow.

    Args:
        console: Rich console for output (must write to stderr).
        dry_run: If True, scan and show what would happen but don't write.
        yes: If True, skip confirmation prompt.
        policy_path: Override for the policy output path (default: ./agentward.yaml).
    """
    output_path = policy_path or Path("agentward.yaml")

    # ------------------------------------------------------------------
    # Step 1: Scan
    # ------------------------------------------------------------------
    from agentward.banner import print_banner

    print_banner(console)
    console.print(
        "[bold]🔍 Scanning your agent environment...[/bold]\n",
        highlight=False,
    )

    # Discover MCP configs
    config_paths = discover_configs()
    all_servers: list[Any] = []
    for config_path in config_paths:
        try:
            servers = parse_config_file(config_path)
            all_servers.extend(servers)
        except (FileNotFoundError, ConfigParseError):
            pass

    # Enumerate MCP tools
    results: list[EnumerationResult] = []
    if all_servers:
        results = asyncio.run(enumerate_all(all_servers, timeout=15.0))

    # Scan OpenClaw skills
    openclaw_results: list[EnumerationResult] = []
    openclaw_results = scan_openclaw()

    all_results = results + openclaw_results

    if not all_results:
        console.print(
            "[bold red]No tools or skills found.[/bold red]\n\n"
            "AgentWard needs at least one MCP host (Cursor, Claude Desktop, VS Code, Windsurf)\n"
            "or OpenClaw skills to generate a policy.\n\n"
            "  Install an MCP host or OpenClaw, then run [bold]agentward init[/bold] again.",
            highlight=False,
        )
        raise typer.Exit(1)

    # Build permission map
    scan_result = build_permission_map(all_results)
    scan_result.config_sources = [str(p) for p in config_paths]

    # Generate recommendations + detect chains
    recommendations = generate_recommendations(scan_result)
    chains = detect_chains(scan_result)

    # ------------------------------------------------------------------
    # Step 2: Print source summary + per-tool risk table
    # ------------------------------------------------------------------
    for line in _source_summary(scan_result):
        console.print(line, highlight=False)

    # Show the scan table (same as `agentward scan`)
    from agentward.scan.report import _print_unified_table

    total_tools = sum(len(s.tools) for s in scan_result.servers)
    if total_tools > 0:
        console.print()
        _print_unified_table(scan_result, console)

    # ------------------------------------------------------------------
    # Step 3: Print risk summary
    # ------------------------------------------------------------------
    buckets, chain_labels = _risk_summary(scan_result, chains)
    print_risk_summary(console, buckets, chain_labels)

    if not _has_any_risk(buckets, chain_labels):
        # Nothing risky — exit cleanly
        console.print("")
        raise typer.Exit(0)

    # ------------------------------------------------------------------
    # Step 4: Confirmation prompt
    # ------------------------------------------------------------------
    console.print("")

    if dry_run:
        # In dry-run we skip the prompt but show what would happen
        pass
    elif not yes:
        try:
            confirmed = typer.confirm(
                "Apply recommended policy and wrap OpenClaw?",
                default=True,
            )
        except typer.Abort:
            confirmed = False

        if not confirmed:
            console.print("\n[dim]No changes made.[/dim]", highlight=False)
            raise typer.Exit(0)

    # ------------------------------------------------------------------
    # Step 5: Check for existing policy file
    # ------------------------------------------------------------------
    if not dry_run and output_path.exists():
        if not yes:
            try:
                overwrite = typer.confirm(
                    f"Policy file already exists ({output_path}). Overwrite?",
                    default=False,
                )
            except typer.Abort:
                overwrite = False

            if not overwrite:
                console.print("\n[dim]No changes made.[/dim]", highlight=False)
                raise typer.Exit(0)

    # ------------------------------------------------------------------
    # Step 6: Generate and write policy
    # ------------------------------------------------------------------
    policy = generate_init_policy(scan_result, chains)

    if dry_run:
        # Show what would be written
        console.print(f"\n[bold]Policy that would be written to {output_path}:[/bold]")
        console.print(f"  {len(policy.skills)} skill restriction(s)", highlight=False)
        console.print(
            f"  {len(policy.require_approval)} approval gate(s)", highlight=False
        )
        console.print(
            f"  {len(policy.skill_chaining)} chaining rule(s)", highlight=False
        )
        console.print(
            f"\n[bold yellow]\\[DRY RUN][/bold yellow] No changes made.",
            highlight=False,
        )
        raise typer.Exit(0)

    # Write the policy
    try:
        write_policy(policy, output_path)
    except PermissionError:
        console.print(
            f"[bold red]Error:[/bold red] Permission denied writing to {output_path}",
            highlight=False,
        )
        raise typer.Exit(1)
    except OSError as e:
        console.print(
            f"[bold red]Error:[/bold red] Cannot write to {output_path}: {e}",
            highlight=False,
        )
        raise typer.Exit(1)

    console.print(
        f"\n[{_CLR_GREEN}]✓[/{_CLR_GREEN}]  Policy written to [bold]{output_path}[/bold]",
        highlight=False,
    )

    # Show what the policy will enforce per tool
    _print_enforcement_summary(console, scan_result, policy)

    # ------------------------------------------------------------------
    # Step 7: Wrap OpenClaw (if present)
    # ------------------------------------------------------------------
    openclaw_wrapped = wrap_openclaw_gateway(console)
    if not openclaw_wrapped:
        console.print(
            f"  [{_CLR_MEDIUM}]⚠[/{_CLR_MEDIUM}]  OpenClaw not detected — "
            "policy written but gateway not wrapped.",
            highlight=False,
        )
        console.print(
            "     You can wrap MCP configs manually:\n"
            f"     [dim]agentward setup --policy {output_path}[/dim]",
            highlight=False,
        )
        console.print("")
        return

    # ------------------------------------------------------------------
    # Step 8: Restart OpenClaw gateway
    # ------------------------------------------------------------------
    restarted = restart_openclaw_gateway(console)
    if not restarted:
        console.print(
            f"  [{_CLR_MEDIUM}]⚠[/{_CLR_MEDIUM}]  Could not restart OpenClaw gateway automatically.",
            highlight=False,
        )
        console.print(
            f"     Run [bold]openclaw gateway restart[/bold] manually, then:\n"
            f"     [dim]agentward inspect --gateway openclaw --policy {output_path}[/dim]",
            highlight=False,
        )
        console.print("")
        return

    # ------------------------------------------------------------------
    # Step 9: Start the proxy (blocking foreground process)
    # ------------------------------------------------------------------
    console.print(
        f"\n[{_CLR_GREEN}]✓[/{_CLR_GREEN}]  "
        f"[bold]Your agents now have boundaries, not blindfolds.[/bold]",
        highlight=False,
    )
    console.print("")

    start_proxy(console, output_path)
