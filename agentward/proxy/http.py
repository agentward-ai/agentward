"""HTTP reverse proxy for gateway-based tool servers (e.g., ClawdBot).

Sits between HTTP clients and a backend gateway server, intercepting
POST /tools-invoke requests for policy evaluation. All other requests
— including WebSocket upgrades — are forwarded as-is.

Architecture:
  Clients (agents, tools, IDE, browser UI)
    ↕ HTTP + WebSocket (this proxy)
  AgentWard HttpProxy (listen_port)
    ↕ HTTP + WebSocket
  Backend Gateway (backend_url)

Policy enforcement only applies to POST /tools-invoke. Every other
request/response (including WebSocket traffic) passes through transparently.
"""

from __future__ import annotations

import asyncio
import itertools
import json as _json
import re
import signal
from datetime import datetime, timezone
from sys import platform as _platform
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import ClientError, ClientSession, ClientWebSocketResponse, web
from rich.console import Console

from agentward.audit.logger import AuditLogger
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import PolicyDecision
from agentward.proxy.approval import ApprovalDecision, ApprovalHandler
from agentward.proxy.chaining import ChainTracker

_console = Console(stderr=True)


def _pid_file_path(port: int) -> Path:
    """Return the path to the PID file for a given listen port."""
    return Path.home() / ".agentward" / f"proxy-{port}.pid"


def _cleanup_stale_proxy(port: int) -> bool:
    """Kill a stale agentward proxy from a previous run on the given port.

    Reads the PID file, checks if the process is still alive, and kills it
    if so. Returns True if a stale process was found and killed.
    """
    import os

    pid_path = _pid_file_path(port)
    if not pid_path.exists():
        return False

    try:
        stale_pid = int(pid_path.read_text().strip())
    except (ValueError, OSError):
        pid_path.unlink(missing_ok=True)
        return False

    # Check if the process is still alive
    try:
        os.kill(stale_pid, 0)  # signal 0 = just check, don't kill
    except ProcessLookupError:
        # Process already gone — clean up PID file
        pid_path.unlink(missing_ok=True)
        return False
    except PermissionError:
        # Process exists but we can't signal it — don't touch it
        return False

    # Verify the process is actually an AgentWard process before killing.
    # PID reuse could cause us to kill an unrelated process.
    try:
        import subprocess as _sp
        cmd_out = _sp.check_output(
            ["ps", "-p", str(stale_pid), "-o", "command="],
            text=True, timeout=5,
        ).strip()
        if "agentward" not in cmd_out.lower():
            # PID was reused by an unrelated process — clean up pidfile only
            _console.print(
                f"  [dim]Stale PID {stale_pid} is not an AgentWard process "
                f"({cmd_out[:60]}); removing pidfile only[/dim]",
                highlight=False,
            )
            pid_path.unlink(missing_ok=True)
            return False
    except Exception:
        # ps failed — process might be a zombie or we can't inspect it.
        # Fall through and attempt cleanup, but only with SIGTERM (no SIGKILL).
        pass

    # Process is alive and confirmed as AgentWard — kill it
    try:
        _console.print(
            f"  [#ffcc00]Killing stale proxy[/#ffcc00] (PID {stale_pid}) on port {port}",
            highlight=False,
        )
        os.kill(stale_pid, signal.SIGTERM)
        # Give it a moment to release the port
        import time
        time.sleep(0.5)
        # Verify it's gone
        try:
            os.kill(stale_pid, 0)
            # Still alive after SIGTERM — force kill
            os.kill(stale_pid, signal.SIGKILL)
            time.sleep(0.3)
        except ProcessLookupError:
            pass
        pid_path.unlink(missing_ok=True)
        return True
    except (ProcessLookupError, PermissionError):
        pid_path.unlink(missing_ok=True)
        return False


def _write_pid_file(port: int) -> None:
    """Write the current process PID to the PID file."""
    import os

    pid_path = _pid_file_path(port)
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    pid_path.write_text(str(os.getpid()))


def _remove_pid_file(port: int) -> None:
    """Remove the PID file on clean shutdown."""
    _pid_file_path(port).unlink(missing_ok=True)


def _identify_port_blocker(port: int) -> str | None:
    """Try to identify the process blocking a port using lsof.

    Returns a human-readable description like "Python (PID 12345) — likely a
    stale agentward inspect", or None if detection fails.
    """
    import subprocess

    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None

        pid = result.stdout.strip().split("\n")[0]

        # Get process name
        ps_result = subprocess.run(
            ["ps", "-p", pid, "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=3,
        )
        proc_name = ps_result.stdout.strip() if ps_result.returncode == 0 else "unknown"

        desc = f"{proc_name} (PID {pid})"
        if "python" in proc_name.lower() or "Python" in proc_name:
            desc += " — likely a stale agentward inspect"
        elif "node" in proc_name.lower():
            desc += " — likely OpenClaw gateway (needs restart?)"
        return desc
    except Exception:
        return None


def _force_free_port(port: int) -> bool:
    """Kill a stale process occupying a port, using lsof as a fallback.

    Used when ``_cleanup_stale_proxy`` (PID-file based) fails but the port
    is still in use.  Only kills Python processes (assumed to be stale
    AgentWard proxies).

    Args:
        port: The TCP port to free.

    Returns:
        True if the port was freed (or was already free), False if we
        could not free it.
    """
    import os
    import subprocess
    import time

    try:
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return True  # nothing listening — port is free

        pids = [p.strip() for p in result.stdout.strip().split("\n") if p.strip()]

        for pid_str in pids:
            pid = int(pid_str)
            # Only kill Python processes (stale AgentWard)
            ps_result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True,
                text=True,
                timeout=3,
            )
            proc_name = ps_result.stdout.strip() if ps_result.returncode == 0 else ""
            if "python" not in proc_name.lower():
                continue

            _console.print(
                f"  [#ffcc00]Killing stale process[/#ffcc00] (PID {pid}) on port {port}",
                highlight=False,
            )
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                    time.sleep(0.3)
                except ProcessLookupError:
                    pass
            except (ProcessLookupError, PermissionError):
                pass

        # Verify the port is now free
        time.sleep(0.2)
        check = subprocess.run(
            ["lsof", "-i", f":{port}", "-sTCP:LISTEN", "-t"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return check.returncode != 0 or not check.stdout.strip()
    except Exception:
        return False


# Headers that must not be forwarded on regular HTTP requests (hop-by-hop).
# Note: 'upgrade' and 'connection' are intentionally excluded here — they
# ARE forwarded for WebSocket upgrade requests (handled separately).
_HOP_BY_HOP_REQUEST = frozenset(
    {
        "transfer-encoding",
        "keep-alive",
        "te",
        "trailers",
        "host",
    }
)

# For responses we also skip content-length because web.Response sets its own.
_HOP_BY_HOP_RESPONSE = _HOP_BY_HOP_REQUEST | {"content-length"}

# The ClawdBot gateway tool invocation endpoint (hyphen, not slash).
_TOOL_INVOKE_PATH = "/tools-invoke"

# Regex for extracting tool invocations from ClawdBot's detailed log.
# Matches: "embedded run tool start: runId=... tool=exec toolCallId=toolu_..."
_TOOL_LOG_RE = re.compile(
    r"embedded run tool (?P<phase>start|end): "
    r"runId=(?P<runId>\S+) "
    r"tool=(?P<tool>\S+) "
    r"toolCallId=(?P<toolCallId>\S+)"
)


def _find_clawdbot_log() -> Path | None:
    """Find the current OpenClaw/ClawdBot detailed log file.

    Checks the new ``/tmp/openclaw/`` directory first, then falls back to the
    legacy ``/tmp/clawdbot/`` path.  The log filename follows the pattern
    ``{name}-YYYY-MM-DD.log``.

    Returns the path for today's date, or None if no log directory exists.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    # Try new path first, then legacy
    for dir_name, file_prefix in [("openclaw", "openclaw"), ("clawdbot", "clawdbot")]:
        log_dir = Path(f"/tmp/{dir_name}")
        if not log_dir.is_dir():
            continue
        log_path = log_dir / f"{file_prefix}-{today}.log"
        if log_path.exists():
            return log_path
    return None


class HttpProxy:
    """HTTP reverse proxy that intercepts tool invocations for policy enforcement.

    Receives all HTTP traffic, evaluates POST /tools-invoke against the loaded
    policy, forwards WebSocket upgrades transparently, and passes everything
    else unchanged to the backend.

    Args:
        backend_url: The URL of the real backend (e.g., "http://127.0.0.1:18790").
        listen_host: Host to bind to. Always "127.0.0.1" for security.
        listen_port: Port to listen on (e.g., 18789).
        policy_engine: Policy engine for tool call evaluation. None = passthrough.
        audit_logger: Structured audit logger.
        policy_path: Path to the loaded policy file (for logging only).
        chain_tracker: Optional chain tracker for runtime skill chaining enforcement.
        approval_handler: Optional handler for APPROVE decisions (macOS dialogs).
    """

    def __init__(
        self,
        backend_url: str,
        listen_host: str,
        listen_port: int,
        policy_engine: PolicyEngine | None,
        audit_logger: AuditLogger,
        policy_path: Path | None = None,
        chain_tracker: ChainTracker | None = None,
        approval_handler: "ApprovalHandler | None" = None,
        dry_run: bool = False,
    ) -> None:
        self._backend_url = backend_url.rstrip("/")
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._policy_path = policy_path
        self._chain_tracker = chain_tracker
        self._approval_handler = approval_handler
        self._dry_run = dry_run
        self._session: ClientSession | None = None
        # Monotonic counter for synthetic request IDs (HTTP has no JSON-RPC ids)
        self._request_counter = itertools.count(1)
        # Map tool_name → FIFO of counter_ids for WS chaining.
        # The interception path (client→backend) pushes counter_ids on record_call.
        self._ws_tool_counter_ids: dict[str, list[int]] = {}
        # Map tool_use_id → counter_id for exact response matching.
        # Populated when tool_use content blocks arrive (observation path),
        # consumed when matching tool_result blocks arrive.
        self._ws_tool_use_to_counter: dict[str, int] = {}
        # Track seen agent lifecycle events to suppress duplicates.
        # ClawdBot can emit the same start/end event multiple times.
        self._seen_lifecycle: set[str] = set()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self, shutdown_event: asyncio.Event | None = None) -> None:
        """Start the HTTP proxy server and block until shutdown.

        Args:
            shutdown_event: Optional external event to trigger shutdown.
                When running alongside other proxies, pass a shared event
                so a single Ctrl+C stops everything.  If *None*, the proxy
                registers its own signal handlers.
        """
        # Kill any stale proxy from a previous run that didn't exit cleanly
        _cleanup_stale_proxy(self._listen_port)

        self._audit_logger.log_http_startup(
            self._listen_port,
            self._backend_url,
            self._policy_path,
        )

        app = web.Application()
        # Catch-all routes — root path and everything under it
        app.router.add_route("*", "/", self._handle_request)
        app.router.add_route("*", "/{path_info:.+}", self._handle_request)

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self._listen_host, self._listen_port)

        # Graceful shutdown on signals
        own_event = shutdown_event is None
        if shutdown_event is None:
            shutdown_event = asyncio.Event()

        if own_event and _platform != "win32":
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, shutdown_event.set)

        try:
            try:
                await site.start()
            except OSError as e:
                if e.errno == 48 or "address already in use" in str(e).lower():
                    # Attempt to kill the stale process and retry
                    if _force_free_port(self._listen_port):
                        try:
                            await site.start()
                        except OSError:
                            _console.print(
                                f"[bold red]Error:[/bold red] Port {self._listen_port} "
                                f"still in use after cleanup.",
                                highlight=False,
                            )
                            return
                    else:
                        blocker = _identify_port_blocker(self._listen_port)
                        msg = (
                            f"[bold red]Error:[/bold red] Port {self._listen_port} "
                            f"is already in use.\n"
                        )
                        if blocker:
                            msg += f"\n  Blocked by: {blocker}\n"
                        msg += (
                            f"\nPossible fixes:\n"
                            f"  1. Kill the stale process:  kill $(lsof -ti :{self._listen_port})\n"
                            f"  2. If OpenClaw is on the wrong port:  openclaw gateway restart\n"
                            f"  3. Check what's there:  lsof -i :{self._listen_port}"
                        )
                        _console.print(msg, highlight=False)
                        return
                else:
                    _console.print(
                        f"[bold red]Error:[/bold red] Failed to bind to "
                        f"{self._listen_host}:{self._listen_port}: {e}",
                        highlight=False,
                    )
                    return

            # Record our PID so the next run can clean us up if we don't exit
            _write_pid_file(self._listen_port)

            _console.print(
                f"[bold #00ff88]Listening on http://{self._listen_host}:{self._listen_port}[/bold #00ff88]",
            )
            _console.print(
                f"[dim]Forwarding to {self._backend_url}[/dim]",
            )
            _console.print("[dim]Press Ctrl+C to stop[/dim]")

            # Start log tailer as a background task
            log_tailer_task = asyncio.create_task(
                self._tail_clawdbot_log(shutdown_event),
            )

            await shutdown_event.wait()
        finally:
            # Cancel log tailer
            if "log_tailer_task" in locals():
                log_tailer_task.cancel()
                try:
                    await log_tailer_task
                except (asyncio.CancelledError, Exception):
                    pass
            _remove_pid_file(self._listen_port)
            if self._session is not None:
                await self._session.close()
            await runner.cleanup()
            self._audit_logger.log_shutdown("signal received")

    async def _get_session(self) -> ClientSession:
        """Get or create the shared HTTP client session."""
        if self._session is None or self._session.closed:
            self._session = ClientSession()
        return self._session

    # ------------------------------------------------------------------
    # ClawdBot log file tailer
    # ------------------------------------------------------------------

    async def _tail_clawdbot_log(self, shutdown_event: asyncio.Event) -> None:
        """Tail ClawdBot's detailed log file to surface tool invocations.

        ClawdBot executes tools server-side in its embedded agent loop and
        does NOT stream tool events over WebSocket. The only way to observe
        tool calls is by tailing the detailed log at /tmp/clawdbot/.

        This coroutine seeks to the end of the log file and watches for new
        ``embedded run tool start/end`` lines, logging them to the AgentWard
        console and audit trail.
        """
        log_path = _find_clawdbot_log()
        if log_path is None:
            _console.print(
                "  [dim]Log tailer: no ClawdBot log found (tool audit from log disabled)[/dim]",
                highlight=False,
            )
            return

        _console.print(
            f"  [dim]Tailing {log_path} for tool invocations[/dim]",
            highlight=False,
        )

        try:
            with open(log_path, "r", encoding="utf-8") as f:
                # Seek to end — we only care about new events
                f.seek(0, 2)

                while not shutdown_event.is_set():
                    line = f.readline()
                    if not line:
                        # No new data — wait briefly before polling again
                        try:
                            await asyncio.wait_for(
                                shutdown_event.wait(), timeout=0.5,
                            )
                            break  # shutdown requested
                        except asyncio.TimeoutError:
                            continue

                    # Extract the message field from the structured JSON log
                    self._process_clawdbot_log_line(line)

        except OSError as e:
            _console.print(
                f"  [dim]Log tailer stopped: {e}[/dim]",
                highlight=False,
            )

    def _process_clawdbot_log_line(self, line: str) -> None:
        """Parse a ClawdBot log line and surface tool invocations."""
        try:
            entry = _json.loads(line)
        except (ValueError, TypeError):
            return

        # The log format has the message in field "1"
        message = entry.get("1", "")
        if not isinstance(message, str):
            return

        match = _TOOL_LOG_RE.search(message)
        if not match:
            return

        phase = match.group("phase")
        tool_name = match.group("tool")
        run_id = match.group("runId")[:8]
        tool_call_id = match.group("toolCallId")

        if phase == "start":
            _console.print(
                f"  [bold #ffcc00]TOOL[/bold #ffcc00] {tool_name} [{run_id}]",
                highlight=False,
            )
            _console.print(
                f"    [dim]toolCallId={tool_call_id}[/dim]",
                highlight=False,
            )

            # Log to audit trail
            result = self._evaluate_tool_call(tool_name, {})
            self._audit_logger.log_tool_call(tool_name, {}, result)

        elif phase == "end":
            _console.print(
                f"  [dim #5eead4]TOOL DONE[/dim #5eead4] {tool_name} [{run_id}]",
                highlight=False,
            )

    # ------------------------------------------------------------------
    # Request routing
    # ------------------------------------------------------------------

    async def _handle_request(self, request: web.Request) -> web.StreamResponse:
        """Route incoming requests.

        - WebSocket upgrade → bidirectional WebSocket proxy
        - POST /tools-invoke → policy-checked tool invocation
        - Everything else → transparent HTTP forward
        """
        # WebSocket upgrade detection
        # Connection header may contain multiple tokens (e.g., "Upgrade, keep-alive")
        connection_tokens = {
            t.strip()
            for t in request.headers.get("Connection", "").lower().split(",")
        }
        if (
            request.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in connection_tokens
        ):
            return await self._handle_websocket(request)

        if request.method == "POST" and request.path == _TOOL_INVOKE_PATH:
            return await self._handle_tool_invoke(request)

        response = await self._forward_request(request)
        self._audit_logger.log_http_request(
            request.method, request.path, response.status,
        )
        return response

    # ------------------------------------------------------------------
    # WebSocket proxy
    # ------------------------------------------------------------------

    async def _handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Proxy a WebSocket connection bidirectionally.

        Accepts the incoming WebSocket from the client, opens a matching
        WebSocket to the backend, and relays messages in both directions.
        All WebSocket traffic passes through transparently — no policy
        evaluation (tool calls go through HTTP POST /tools-invoke, not WS).
        """
        # Build backend WebSocket URL
        backend_ws_url = self._backend_url.replace("http://", "ws://").replace(
            "https://", "wss://"
        )
        backend_ws_url = f"{backend_ws_url}{request.path_qs}"

        # Forward relevant headers to backend (auth, subprotocols, etc.)
        ws_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            lower = key.lower()
            # Skip hop-by-hop and websocket handshake headers (aiohttp handles those)
            if lower in {
                "host",
                "upgrade",
                "connection",
                "sec-websocket-key",
                "sec-websocket-version",
                "sec-websocket-extensions",
            }:
                continue
            ws_headers[key] = value

        # Accept incoming WebSocket from client
        client_ws = web.WebSocketResponse()
        await client_ws.prepare(request)

        session = await self._get_session()

        self._audit_logger.log_http_request(
            "GET", request.path, 101, is_websocket=True,
        )

        try:
            async with session.ws_connect(
                backend_ws_url,
                headers=ws_headers,
                max_msg_size=25 * 1024 * 1024,  # 25MB to match ClawdBot
            ) as backend_ws:
                # Relay in both directions concurrently
                # client→backend: inspected (policy-checks node.invoke frames)
                # backend→client: transparent (forwards everything unchanged)
                await asyncio.gather(
                    self._relay_ws_inspected(client_ws, backend_ws),
                    self._relay_ws_transparent(backend_ws, client_ws),
                )
        except (ClientError, OSError) as e:
            _console.print(
                f"[dim]WebSocket backend connection failed: {e}[/dim]",
            )
            if not client_ws.closed:
                await client_ws.close(
                    code=aiohttp.WSCloseCode.GOING_AWAY,
                    message=b"Backend unavailable",
                )

        self._audit_logger.log_websocket_disconnect(request.path)

        return client_ws

    async def _relay_ws_inspected(
        self,
        source: web.WebSocketResponse | ClientWebSocketResponse,
        dest: web.WebSocketResponse | ClientWebSocketResponse,
    ) -> None:
        """Relay client→backend WebSocket messages, intercepting node.invoke frames.

        Parses TEXT messages as JSON when they may contain a ``node.invoke``
        request.  If the tool call is blocked or requires approval, an error
        response frame is sent back to the *client* and the message is NOT
        forwarded to the backend.  All other messages pass through unchanged.
        """
        async for msg in source:
            if msg.type == aiohttp.WSMsgType.TEXT:
                raw = msg.data

                self._log_client_ws_frame(raw)

                # Fast path: skip JSON parsing for non-tool messages
                if '"node.invoke"' not in raw:
                    await dest.send_str(raw)
                    continue

                # Might be a node.invoke frame — parse JSON
                try:
                    parsed = _json.loads(raw)
                except Exception:
                    _console.print(
                        "[bold #ffcc00]Warning:[/bold #ffcc00] Unparseable WebSocket "
                        "message containing 'node.invoke' — forwarding as-is",
                        highlight=False,
                    )
                    await dest.send_str(raw)
                    continue

                # Only intercept node.invoke request frames
                if not (
                    isinstance(parsed, dict)
                    and parsed.get("type") == "req"
                    and parsed.get("method") == "node.invoke"
                ):
                    await dest.send_str(raw)
                    continue

                # --- node.invoke interception ---
                request_id = parsed.get("id", "")
                params = parsed.get("params", {})
                if not isinstance(params, dict):
                    params = {}
                tool_name = params.get("command", "")
                arguments = params.get("params", {})

                if not isinstance(tool_name, str) or not tool_name:
                    # Can't identify tool — forward as-is
                    await dest.send_str(raw)
                    continue

                if not isinstance(arguments, dict):
                    arguments = {}

                # Evaluate policy
                result = self._evaluate_tool_call(tool_name, arguments)

                if result.decision == PolicyDecision.BLOCK:
                    self._audit_logger.log_tool_call(tool_name, arguments, result)
                    await source.send_str(self._make_ws_error_frame(
                        request_id, "policy_blocked", f"AgentWard: {result.reason}",
                    ))
                    continue

                if result.decision == PolicyDecision.APPROVE:
                    if self._approval_handler is not None:
                        decision = await self._approval_handler.request_approval(
                            tool_name, arguments, result.reason,
                        )
                        self._audit_logger.log_tool_call(tool_name, arguments, result)
                        if decision not in (
                            ApprovalDecision.ALLOW_ONCE,
                            ApprovalDecision.ALLOW_SESSION,
                        ):
                            await source.send_str(self._make_ws_error_frame(
                                request_id, "approval_denied",
                                f"AgentWard: User denied tool '{tool_name}'.",
                            ))
                            continue
                        # Approved — fall through to chaining check + forward
                    else:
                        self._audit_logger.log_tool_call(tool_name, arguments, result)
                        await source.send_str(self._make_ws_error_frame(
                            request_id, "approval_required",
                            f"AgentWard: {result.reason}",
                        ))
                        continue

                # ALLOW, LOG, or approved APPROVE — check chaining rules before forwarding
                if self._chain_tracker is not None:
                    chain_result = self._chain_tracker.check_before_call(
                        tool_name, arguments,
                    )
                    if chain_result is not None and chain_result.decision == PolicyDecision.BLOCK:
                        self._audit_logger.log_tool_call(
                            tool_name, arguments, chain_result, chain_violation=True,
                        )
                        await source.send_str(self._make_ws_error_frame(
                            request_id, "chain_blocked", f"AgentWard: {chain_result.reason}",
                        ))
                        continue
                    counter_id = next(self._request_counter)
                    self._chain_tracker.record_call(
                        tool_name, arguments, request_id=counter_id,
                    )
                    # Track counter_id for response matching in observation path
                    self._ws_tool_counter_ids.setdefault(tool_name, []).append(counter_id)

                # Passed all checks — log and forward
                self._audit_logger.log_tool_call(tool_name, arguments, result)
                await dest.send_str(raw)

            elif msg.type == aiohttp.WSMsgType.BINARY:
                await dest.send_bytes(msg.data)
            elif msg.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.CLOSED,
            ):
                break
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break

        # When source closes, close dest too
        if not dest.closed:
            await dest.close()

    async def _relay_ws_transparent(
        self,
        source: web.WebSocketResponse | ClientWebSocketResponse,
        dest: web.WebSocketResponse | ClientWebSocketResponse,
    ) -> None:
        """Relay backend→client WebSocket messages unchanged."""
        async for msg in source:
            if msg.type == aiohttp.WSMsgType.TEXT:
                self._inspect_backend_event(msg.data)

                await dest.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                await dest.send_bytes(msg.data)
            elif msg.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.CLOSED,
            ):
                break
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break

        # When source closes, close dest too
        if not dest.closed:
            await dest.close()

    @staticmethod
    def _make_ws_error_frame(
        request_id: str,
        error_type: str,
        message: str,
    ) -> str:
        """Build a ClawdBot WebSocket error response frame as a JSON string.

        Args:
            request_id: The ``id`` from the original node.invoke request frame.
            error_type: Error type identifier (e.g., ``policy_blocked``).
            message: Human-readable error message.

        Returns:
            JSON-serialized response frame string.
        """
        return _json.dumps({
            "type": "res",
            "id": request_id,
            "ok": False,
            "payload": {
                "error": {
                    "type": error_type,
                    "message": message,
                },
            },
        })

    # ------------------------------------------------------------------
    # WebSocket frame logging
    # ------------------------------------------------------------------

    # Client→backend WS methods that are high-frequency polling or plumbing.
    # Logging these drowns out meaningful tool-call output.
    _WS_QUIET_METHODS: frozenset[str] = frozenset({
        "node.list",
        "chat.history",
        "chat.send",
        "chat.list",
        "health.check",
    })

    def _log_client_ws_frame(self, raw: str) -> None:
        """Log a client→backend WebSocket frame (compact, low-noise).

        Suppresses high-frequency polling methods (node.list, chat.history,
        etc.) to keep the output focused on tool-call decisions.
        """
        try:
            parsed = _json.loads(raw)
            if not isinstance(parsed, dict):
                return
            method = parsed.get("method", "")
            if method in self._WS_QUIET_METHODS:
                return
        except Exception:
            pass

    def _inspect_backend_event(self, raw: str) -> None:
        """Inspect a backend→client WebSocket frame for tool invocations.

        Logs lifecycle events (start/end), tool use events with full details,
        and skips noisy text-streaming deltas to keep output readable.
        """
        try:
            parsed = _json.loads(raw)
            if not isinstance(parsed, dict):
                return

            frame_type = parsed.get("type", "?")
            event_name = parsed.get("event", parsed.get("method", ""))

            # Only inspect event frames from the agent
            if frame_type != "event" or event_name not in ("agent", "chat"):
                return

            payload = parsed.get("payload", parsed.get("data", {}))
            if not isinstance(payload, dict):
                return

            stream = payload.get("stream", "")
            data = payload.get("data", {})
            if not isinstance(data, dict):
                data = {}

            # --- Lifecycle events: log start/end of agent runs ---
            if stream == "lifecycle":
                phase = data.get("phase", "")
                run_id = str(payload.get("runId", ""))[:8]
                lifecycle_key = f"{phase}:{run_id}"
                if lifecycle_key in self._seen_lifecycle:
                    return  # suppress duplicate
                self._seen_lifecycle.add(lifecycle_key)
                # Prune old entries to avoid unbounded growth
                if len(self._seen_lifecycle) > 100:
                    self._seen_lifecycle.clear()
                if phase == "start":
                    _console.print(
                        f"  [bold #5eead4]▶ agent run[/bold #5eead4] [dim][{run_id}][/dim]",
                        highlight=False,
                    )
                elif phase == "end":
                    _console.print(
                        f"  [dim #5eead4]■ agent run ended[/dim #5eead4] [dim][{run_id}][/dim]",
                        highlight=False,
                    )
                return

            # --- Tool use events: log with full details ---
            # ClawdBot streams tool_use as content blocks in chat events
            # or as dedicated stream types in agent events.
            # Look for tool_use in multiple places:

            # 1. Agent event with stream "tool_use" or "tool" or "tool_result"
            if stream in ("tool_use", "tool", "tool_result"):
                tool_name = data.get("name", data.get("command", "unknown"))
                tool_input = data.get("input", data.get("params", {}))
                run_id = str(payload.get("runId", ""))[:8]

                if stream == "tool_result":
                    # Tool result on agent stream — log and record for chaining
                    is_error = data.get("is_error", False)
                    _console.print(
                        f"  [dim #5eead4]TOOL RESULT[/dim #5eead4] {tool_name}"
                        f"{' [error]' if is_error else ''} [{run_id}]",
                        highlight=False,
                    )
                    if self._chain_tracker is not None:
                        try:
                            tuid = data.get("tool_use_id") or data.get("id")
                            cid = self._ws_tool_use_to_counter.pop(tuid, None) if tuid else None
                            self._chain_tracker.record_response(
                                tool_name, data, request_id=cid,
                            )
                        except Exception:
                            pass  # Best-effort chaining recording
                    return

                # Log as a visible tool call observation
                _console.print(
                    f"  [bold #ffcc00]TOOL[/bold #ffcc00] {tool_name} [{run_id}]",
                    highlight=False,
                )
                if tool_input and isinstance(tool_input, dict):
                    input_str = _json.dumps(tool_input, default=str)
                    if len(input_str) > 200:
                        input_str = input_str[:200] + "..."
                    _console.print(
                        f"    [dim]{input_str}[/dim]",
                        highlight=False,
                    )

                # Also log to audit trail
                result = self._evaluate_tool_call(tool_name, tool_input if isinstance(tool_input, dict) else {})
                self._audit_logger.log_tool_call(
                    tool_name,
                    tool_input if isinstance(tool_input, dict) else {},
                    result,
                )

                # Bridge tool_use_id → counter_id for chaining (same as chat-event path)
                tool_use_id = data.get("id") or data.get("tool_use_id")
                if tool_use_id and self._chain_tracker is not None:
                    cid_stack = self._ws_tool_counter_ids.get(tool_name)
                    if cid_stack:
                        self._ws_tool_use_to_counter[tool_use_id] = cid_stack.pop(0)
                return

            # 2. Chat event with tool_use content blocks
            if event_name == "chat":
                message = payload.get("message", {})
                if isinstance(message, dict):
                    content = message.get("content", [])
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "tool_use":
                                tool_name = block.get("name", "unknown")
                                tool_input = block.get("input", {})
                                run_id = str(payload.get("runId", ""))[:8]

                                _console.print(
                                    f"  [bold #ffcc00]TOOL[/bold #ffcc00] {tool_name} [{run_id}]",
                                    highlight=False,
                                )
                                if tool_input and isinstance(tool_input, dict):
                                    input_str = _json.dumps(tool_input, default=str)
                                    if len(input_str) > 200:
                                        input_str = input_str[:200] + "..."
                                    _console.print(
                                        f"    [dim]{input_str}[/dim]",
                                        highlight=False,
                                    )

                                result = self._evaluate_tool_call(
                                    tool_name,
                                    tool_input if isinstance(tool_input, dict) else {},
                                )
                                self._audit_logger.log_tool_call(
                                    tool_name,
                                    tool_input if isinstance(tool_input, dict) else {},
                                    result,
                                )

                                # Bridge tool_use_id → counter_id for chaining
                                tool_use_id = block.get("id")
                                if tool_use_id and self._chain_tracker is not None:
                                    cid_stack = self._ws_tool_counter_ids.get(tool_name)
                                    if cid_stack:
                                        self._ws_tool_use_to_counter[tool_use_id] = cid_stack.pop(0)

                            elif isinstance(block, dict) and block.get("type") == "tool_result":
                                tool_name = block.get("name", block.get("tool_use_id", "unknown"))
                                is_error = block.get("is_error", False)
                                _console.print(
                                    f"  [dim #5eead4]TOOL RESULT[/dim #5eead4] {tool_name}"
                                    f"{' [error]' if is_error else ''}",
                                    highlight=False,
                                )
                                # Record tool result for content-based chaining.
                                # Use tool_use_id → counter_id mapping for exact
                                # matching; fall back to tool_name if unavailable.
                                if self._chain_tracker is not None:
                                    try:
                                        tuid = block.get("tool_use_id")
                                        cid = self._ws_tool_use_to_counter.pop(tuid, None) if tuid else None
                                        self._chain_tracker.record_response(
                                            tool_name, block, request_id=cid,
                                        )
                                    except Exception:
                                        pass  # Best-effort chaining recording
                return

            # Skip assistant text-streaming deltas (too noisy)
            # stream == "assistant" → token-by-token LLM output

        except Exception:
            pass

    # ------------------------------------------------------------------
    # Tool invocation interception
    # ------------------------------------------------------------------

    async def _handle_tool_invoke(self, request: web.Request) -> web.StreamResponse:
        """Intercept a tool invocation, evaluate policy, forward or block.

        Parses the JSON body for ``tool`` and ``arguments``, runs policy
        evaluation, and either blocks with a JSON error response or forwards
        to the backend.

        The raw body is read once and cached so ``_forward_request`` can
        reuse it (aiohttp request bodies can only be read once).
        """
        # Read raw body once — we'll need it for both parsing and forwarding
        raw_body = await request.read()

        # Parse JSON body for policy evaluation.
        # If the body is unparseable or doesn't look like a tool invocation,
        # reject it — forwarding would let the backend accept a format this
        # proxy doesn't understand, bypassing policy enforcement.
        try:
            body = _json.loads(raw_body)
        except Exception:
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "bad_request",
                        "message": "AgentWard: /tools-invoke body must be valid JSON.",
                    },
                },
                status=400,
            )

        if not isinstance(body, dict) or "tool" not in body:
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "bad_request",
                        "message": "AgentWard: /tools-invoke body must be a JSON object with a 'tool' field.",
                    },
                },
                status=400,
            )

        tool_name = str(body["tool"])
        arguments = body.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}

        # Evaluate policy
        result = self._evaluate_tool_call(tool_name, arguments)

        if result.decision == PolicyDecision.BLOCK:
            if self._dry_run:
                self._audit_logger.log_tool_call(
                    tool_name, arguments, result, dry_run=True,
                )
                # Dry-run: don't actually block — fall through to forward
            else:
                self._audit_logger.log_tool_call(tool_name, arguments, result)
                return web.json_response(
                    {
                        "ok": False,
                        "error": {
                            "type": "policy_blocked",
                            "message": f"AgentWard: {result.reason}",
                        },
                    },
                    status=403,
                )

        if result.decision == PolicyDecision.APPROVE:
            if self._dry_run:
                self._audit_logger.log_tool_call(
                    tool_name, arguments, result, dry_run=True,
                )
                # Dry-run: don't actually gate — fall through to forward
            elif self._approval_handler is not None:
                decision = await self._approval_handler.request_approval(
                    tool_name, arguments, result.reason,
                )
                self._audit_logger.log_tool_call(tool_name, arguments, result)
                if decision not in (
                    ApprovalDecision.ALLOW_ONCE,
                    ApprovalDecision.ALLOW_SESSION,
                ):
                    return web.json_response(
                        {
                            "ok": False,
                            "error": {
                                "type": "approval_denied",
                                "message": f"AgentWard: User denied tool '{tool_name}'.",
                            },
                        },
                        status=403,
                    )
                # Approved — fall through to chaining check + forward
            else:
                # No approval handler — block (backwards compat)
                self._audit_logger.log_tool_call(tool_name, arguments, result)
                return web.json_response(
                    {
                        "ok": False,
                        "error": {
                            "type": "approval_required",
                            "message": f"AgentWard: {result.reason}",
                        },
                    },
                    status=403,
                )

        # ALLOW, LOG, or approved APPROVE — check chaining rules before forwarding
        request_id: int | None = None
        if self._chain_tracker is not None:
            chain_result = self._chain_tracker.check_before_call(
                tool_name, arguments,
            )
            if chain_result is not None and chain_result.decision == PolicyDecision.BLOCK:
                if self._dry_run:
                    self._audit_logger.log_tool_call(
                        tool_name, arguments, chain_result,
                        chain_violation=True, dry_run=True,
                    )
                    # Dry-run: don't actually block chain
                else:
                    self._audit_logger.log_tool_call(
                        tool_name, arguments, chain_result, chain_violation=True,
                    )
                    return web.json_response(
                        {
                            "ok": False,
                            "error": {
                                "type": "chain_blocked",
                                "message": f"AgentWard: {chain_result.reason}",
                            },
                        },
                        status=403,
                    )
            request_id = next(self._request_counter)
            self._chain_tracker.record_call(
                tool_name, arguments, request_id=request_id,
            )

        # Log ALLOW/LOG only after passing all checks (policy + chaining)
        self._audit_logger.log_tool_call(tool_name, arguments, result)

        # Forward to backend and capture response for chain tracking
        response = await self._forward_request(request, raw_body=raw_body)

        # Record response content for chaining detection
        if self._chain_tracker is not None and isinstance(response, web.Response):
            try:
                response_json = _json.loads(response.body)
                self._chain_tracker.record_response(
                    tool_name, response_json, request_id=request_id,
                )
            except Exception:
                pass  # Can't parse — skip chain recording

        return response

    # ------------------------------------------------------------------
    # HTTP forwarding
    # ------------------------------------------------------------------

    async def _forward_request(
        self,
        request: web.Request,
        raw_body: bytes | None = None,
    ) -> web.StreamResponse:
        """Forward an HTTP request to the backend and return the response.

        Copies method, path, query string, headers, and body.

        Args:
            request: The incoming aiohttp request.
            raw_body: Pre-read request body (avoids double-read issue).
                      If None, reads from the request directly.
        """
        session = await self._get_session()

        # Build backend URL
        target_url = f"{self._backend_url}{request.path_qs}"

        # Forward headers, skipping hop-by-hop
        forward_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() not in _HOP_BY_HOP_REQUEST:
                forward_headers[key] = value

        # Use cached body if provided, otherwise read from request
        if raw_body is None:
            raw_body = await request.read()

        try:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                data=raw_body if raw_body else None,
                allow_redirects=False,
            ) as backend_response:
                # Read the full backend response body first, then send as
                # a regular web.Response.  This avoids StreamResponse issues
                # with mismatched Content-Length / Transfer-Encoding headers.
                response_body = await backend_response.read()

                response = web.Response(
                    status=backend_response.status,
                    body=response_body,
                )

                # Copy response headers, skipping hop-by-hop + content-length
                # (web.Response sets its own content-length from the body)
                for key, value in backend_response.headers.items():
                    if key.lower() not in _HOP_BY_HOP_RESPONSE:
                        response.headers[key] = value

                return response

        except ClientError as e:
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "bad_gateway",
                        "message": f"AgentWard: Failed to reach backend at {self._backend_url}: {e}",
                    },
                },
                status=502,
            )

    # ------------------------------------------------------------------
    # Policy evaluation
    # ------------------------------------------------------------------

    def _evaluate_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> EvaluationResult:
        """Evaluate a tool call against the policy engine.

        If no policy engine is loaded (passthrough mode), returns ALLOW.

        Args:
            tool_name: The tool name from the request body.
            arguments: The tool call arguments.

        Returns:
            The evaluation result.
        """
        if self._policy_engine is None:
            return EvaluationResult(
                decision=PolicyDecision.ALLOW,
                reason="No policy loaded (passthrough mode).",
            )
        return self._policy_engine.evaluate(tool_name, arguments)
