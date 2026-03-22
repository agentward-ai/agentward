"""MCP stdio proxy server.

Sits between an MCP client and a real MCP server, forwarding JSON-RPC 2.0
messages bidirectionally over stdio. Intercepts tools/call requests for
policy evaluation.

Architecture:
  Client (Claude Desktop, Cursor, etc.)
    ↕ stdin/stdout (this process's stdio)
  AgentWard StdioProxy
    ↕ stdin/stdout (subprocess pipes)
  Real MCP Server (spawned as subprocess)

Three concurrent async tasks:
  1. client→server: reads from own stdin, evaluates policy, forwards to subprocess
  2. server→client: reads from subprocess stdout, forwards to own stdout
  3. server stderr: reads subprocess stderr, logs to our stderr
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from sys import platform as _platform
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentward.proxy.judge import LlmJudge
    from agentward.session import SessionMonitor

from rich.console import Console

from agentward.audit.logger import AuditLogger
from agentward.inspect.classifier import ClassificationResult, classify_arguments, redact_arguments
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import PolicyDecision, SensitiveContentAction
from agentward.inspect.enforcer import BoundaryEnforcer
from agentward.inspect.role_cache import ToolRoleCache
from agentward.proxy.chaining import ChainTracker
from agentward.proxy.circuit_breaker import CircuitBreaker
from agentward.proxy.protocol import (
    APPROVAL_REQUIRED,
    POLICY_BLOCKED,
    JSONRPCRequest,
    JSONRPCResponse,
    ProtocolError,
    extract_tool_info,
    is_resources_read,
    is_tool_call,
    is_tool_call_notification,
    is_tools_list,
    is_tools_list_response,
    make_error_response,
    parse_message,
    serialize_message,
)

_console = Console(stderr=True)

# Timeout for graceful subprocess shutdown before SIGKILL
_SHUTDOWN_TIMEOUT_SECONDS = 5


class StdioProxy:
    """MCP proxy that intercepts tool calls over stdio transport.

    Spawns the real MCP server as a subprocess, then forwards all JSON-RPC
    messages bidirectionally. For tools/call requests, evaluates the policy
    engine and blocks/approves/logs accordingly.

    Args:
        server_command: The command to spawn the real MCP server
                        (e.g., ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]).
        policy_engine: The policy engine to evaluate tool calls against.
                       If None, operates in passthrough mode (all calls forwarded).
        audit_logger: The audit logger for structured event logging.
        server_env: Optional environment variables to pass to the subprocess.
        chain_tracker: Optional chain tracker for runtime skill chaining enforcement.
    """

    def __init__(
        self,
        server_command: list[str],
        policy_engine: PolicyEngine | None,
        audit_logger: AuditLogger,
        server_env: dict[str, str] | None = None,
        chain_tracker: ChainTracker | None = None,
        policy_path: Path | None = None,
        dry_run: bool = False,
        circuit_breaker: CircuitBreaker | None = None,
        boundary_enforcer: BoundaryEnforcer | None = None,
        role_cache: ToolRoleCache | None = None,
        llm_judge: LlmJudge | None = None,
        session_monitor: "SessionMonitor | None" = None,
    ) -> None:
        self._server_command = server_command
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._server_env = server_env
        self._chain_tracker = chain_tracker
        self._policy_path = policy_path
        self._dry_run = dry_run
        self._circuit_breaker = circuit_breaker
        self._boundary_enforcer = boundary_enforcer
        self._role_cache = role_cache
        self._llm_judge = llm_judge
        self._session_monitor = session_monitor
        # Stable session ID for the lifetime of this proxy process
        if session_monitor is not None:
            from agentward.session import SessionMonitor as _SM
            self._session_id = _SM.new_session_id("stdio")
        else:
            self._session_id = ""

        self._process: asyncio.subprocess.Process | None = None
        self._shutting_down = False

        # Track pending tool call requests so we can log responses
        # Maps request_id → tool_name
        self._pending_tool_calls: dict[int | str, str] = {}
        # Track pending tools/list request IDs for response logging
        self._pending_tools_list: set[int | str] = set()

    async def run(self) -> None:
        """Start the proxy: spawn subprocess, forward messages, handle shutdown.

        This is the main entry point. It runs until the client disconnects,
        the server exits, or a signal is received.
        """
        self._audit_logger.log_startup(
            self._server_command,
            self._policy_path,
        )

        # Build subprocess environment
        env = os.environ.copy()
        if self._server_env:
            env.update(self._server_env)

        try:
            self._process = await asyncio.create_subprocess_exec(
                *self._server_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            cmd = self._server_command[0]
            _console.print(
                f"[bold red]Error:[/bold red] Command not found: {cmd}\n\n"
                f"Make sure the MCP server command is installed and in your PATH.\n"
                f"Common fixes:\n"
                f"  • If using npx: npm install -g npx\n"
                f"  • If using a local binary: use the absolute path instead of '{cmd}'\n"
                f"  • Check your PATH: which {cmd}",
                highlight=False,
            )
            self._audit_logger.log_shutdown(
                f"Server command not found: {cmd}"
            )
            return
        except PermissionError:
            _console.print(
                f"[bold red]Error:[/bold red] Permission denied: {self._server_command[0]}\n"
                f"Check that the MCP server command is executable.",
                highlight=False,
            )
            self._audit_logger.log_shutdown(
                f"Permission denied for server command: {self._server_command[0]}"
            )
            return

        # Set up signal handlers for graceful shutdown
        # add_signal_handler is not supported on Windows
        loop = asyncio.get_running_loop()
        if _platform != "win32":
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self._handle_shutdown()))

        # Create the stdin reader for our own process
        client_reader = await _create_stdin_reader()

        # Run all three forwarding tasks concurrently
        tasks = [
            asyncio.create_task(
                self._forward_client_to_server(client_reader),
                name="client→server",
            ),
            asyncio.create_task(
                self._forward_server_to_client(),
                name="server→client",
            ),
            asyncio.create_task(
                self._forward_server_stderr(),
                name="server-stderr",
            ),
        ]

        try:
            # Wait for any task to complete (usually means connection closed)
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            # Check for exceptions in completed tasks
            for task in done:
                if task.exception() is not None:
                    _console.print(
                        f"[red]Task '{task.get_name()}' failed: {task.exception()}[/red]"
                    )
        finally:
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()

            # Wait for cancellation to complete
            await asyncio.gather(*tasks, return_exceptions=True)

            # Clean up subprocess
            await self._cleanup_subprocess()
            self._audit_logger.log_shutdown("Proxy stopped")
            self._audit_logger.close()

    async def _forward_client_to_server(
        self, client_reader: asyncio.StreamReader
    ) -> None:
        """Read from the client (our stdin), evaluate policy, forward to server.

        For tools/call requests:
          - Evaluate against policy engine
          - If BLOCK: send error response back to client, don't forward
          - If APPROVE: send error response asking for approval, don't forward
          - Otherwise: forward to server

        All other messages pass through unchanged.
        """
        if self._process is None or self._process.stdin is None:
            _console.print(
                "[bold red]Cannot forward to server: process not started[/bold red]",
            )
            return

        while not self._shutting_down:
            line = await client_reader.readline()
            if not line:
                # Client disconnected (EOF on stdin)
                break

            # Try to parse and evaluate.  For unparseable messages we normally
            # forward raw bytes so as not to break the protocol — except when
            # the raw line looks like a tools/call.  In that case, forwarding
            # would let a malformed-but-server-accepted call bypass policy.
            try:
                msg = parse_message(line)
            except ProtocolError:
                if b'"tools/call"' in line:
                    _console.print(
                        "[bold red]Dropped unparseable tools/call message "
                        "(cannot enforce policy on malformed request)[/bold red]",
                    )
                    continue
                # Non-tool-call messages: forward raw and move on
                self._process.stdin.write(line)
                await self._process.stdin.drain()
                continue

            if is_tool_call_notification(msg):
                # tools/call as a notification (no id) is invalid per MCP spec
                # and cannot be responded to. Drop it to prevent policy bypass.
                _console.print(
                    "[bold red]Dropped tools/call notification "
                    "(no id — cannot enforce policy)[/bold red]",
                )
                continue

            if is_tool_call(msg):
                if not isinstance(msg, JSONRPCRequest):
                    _console.print(
                        "[bold red]Dropped tools/call with unexpected message type[/bold red]",
                    )
                    continue
                try:
                    tool_name, arguments = extract_tool_info(msg)
                except ProtocolError:
                    # Malformed tools/call — block to prevent policy bypass
                    _console.print(
                        "[bold red]Blocked malformed tools/call "
                        "(could not extract tool info)[/bold red]",
                    )
                    error_resp = make_error_response(
                        msg.id,
                        POLICY_BLOCKED,
                        "AgentWard: malformed tools/call — could not extract tool name/arguments",
                    )
                    _write_to_stdout(serialize_message(error_resp))
                    continue

                # Circuit breaker — block runaway loops
                if self._circuit_breaker is not None:
                    if not self._circuit_breaker.check(tool_name, arguments):
                        cb_result = EvaluationResult(
                            decision=PolicyDecision.BLOCK,
                            reason=f"Circuit breaker tripped: tool '{tool_name}' "
                            f"called too frequently (>{self._circuit_breaker.config.max_calls} "
                            f"in {self._circuit_breaker.config.window_seconds}s).",
                        )
                        self._audit_logger.log_tool_call(tool_name, arguments, cb_result)
                        error_resp = make_error_response(
                            msg.id,
                            POLICY_BLOCKED,
                            f"AgentWard: {cb_result.reason}",
                        )
                        _write_to_stdout(serialize_message(error_resp))
                        continue

                result = self._evaluate_tool_call(tool_name, arguments)

                if result.decision == PolicyDecision.BLOCK:
                    if self._dry_run:
                        self._audit_logger.log_tool_call(
                            tool_name, arguments, result, dry_run=True,
                        )
                        # Dry-run: don't actually block — fall through to forward
                    else:
                        self._audit_logger.log_tool_call(tool_name, arguments, result)
                        error_resp = make_error_response(
                            msg.id,
                            POLICY_BLOCKED,
                            f"AgentWard policy blocked: {result.reason}",
                        )
                        _write_to_stdout(serialize_message(error_resp))
                        continue

                if result.decision == PolicyDecision.APPROVE:
                    if self._dry_run:
                        self._audit_logger.log_tool_call(
                            tool_name, arguments, result, dry_run=True,
                        )
                        # Dry-run: don't actually gate — fall through to forward
                    else:
                        self._audit_logger.log_tool_call(tool_name, arguments, result)
                        error_resp = make_error_response(
                            msg.id,
                            APPROVAL_REQUIRED,
                            f"AgentWard: Human approval required. {result.reason}",
                        )
                        _write_to_stdout(serialize_message(error_resp))
                        continue

                # LLM judge — semantic second opinion on ALLOW/LOG decisions
                if (
                    self._llm_judge is not None
                    and result.decision in self._llm_judge.judge_on_decisions
                ):
                    judge_override = await self._llm_judge.check(
                        tool_name, arguments, result
                    )
                    if judge_override is not None:
                        result = judge_override
                        if result.decision == PolicyDecision.BLOCK:
                            if self._dry_run:
                                self._audit_logger.log_tool_call(
                                    tool_name, arguments, result, dry_run=True,
                                )
                                # Dry-run: don't actually block
                            else:
                                self._audit_logger.log_tool_call(
                                    tool_name, arguments, result
                                )
                                error_resp = make_error_response(
                                    msg.id,
                                    POLICY_BLOCKED,
                                    f"AgentWard LLM judge blocked: {result.reason}",
                                )
                                _write_to_stdout(serialize_message(error_resp))
                                continue

                # ALLOW or LOG — check sensitive content before chaining
                sensitive = self._classify_tool_args(arguments)
                if sensitive.has_sensitive_data:
                    action = self._sensitive_content_action()
                    if action == SensitiveContentAction.REDACT:
                        # Redact mode: mask sensitive fields and rewrite the message
                        arguments = redact_arguments(arguments, sensitive.findings)
                        # Rewrite the JSON-RPC message with redacted arguments
                        import json as _json
                        raw_msg = _json.loads(line)
                        raw_msg["params"]["arguments"] = arguments
                        line = (_json.dumps(raw_msg) + "\n").encode()
                        self._audit_logger.log_tool_call(
                            tool_name, arguments,
                            EvaluationResult(
                                decision=PolicyDecision.REDACT,
                                reason=f"Sensitive data redacted: "
                                f"{', '.join(f.finding_type.value for f in sensitive.findings)}",
                            ),
                        )
                    elif self._dry_run:
                        self._audit_logger.log_sensitive_block(
                            tool_name, arguments, sensitive.findings,
                        )
                        # Dry-run: don't actually block
                    else:
                        self._audit_logger.log_sensitive_block(
                            tool_name, arguments, sensitive.findings,
                        )
                        error_resp = make_error_response(
                            msg.id,
                            POLICY_BLOCKED,
                            f"AgentWard: Sensitive data detected in tool arguments. "
                            f"Findings: {', '.join(f.finding_type.value for f in sensitive.findings)}",
                        )
                        _write_to_stdout(serialize_message(error_resp))
                        continue

                # Check chaining rules before forwarding
                if self._chain_tracker is not None:
                    chain_result = self._chain_tracker.check_before_call(
                        tool_name, arguments
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
                            error_resp = make_error_response(
                                msg.id,
                                POLICY_BLOCKED,
                                f"AgentWard chain blocked: {chain_result.reason}",
                            )
                            _write_to_stdout(serialize_message(error_resp))
                            continue
                    self._chain_tracker.record_call(
                        tool_name, arguments, request_id=msg.id
                    )

                # Check data boundary rules before forwarding
                if self._boundary_enforcer is not None:
                    skill_for_boundary = (
                        self._policy_engine.resolve_skill(tool_name)
                        if self._policy_engine else None
                    )
                    boundary_result = self._boundary_enforcer.check_tool_call(
                        tool_name, skill_for_boundary, arguments
                    )
                    if boundary_result is not None:
                        if boundary_result.decision == PolicyDecision.BLOCK:
                            if self._dry_run:
                                self._audit_logger.log_tool_call(
                                    tool_name, arguments, boundary_result, dry_run=True,
                                )
                            else:
                                self._audit_logger.log_tool_call(
                                    tool_name, arguments, boundary_result,
                                )
                                error_resp = make_error_response(
                                    msg.id,
                                    POLICY_BLOCKED,
                                    f"AgentWard boundary: {boundary_result.reason}",
                                )
                                _write_to_stdout(serialize_message(error_resp))
                                continue
                        elif boundary_result.decision == PolicyDecision.LOG:
                            # LOG_ONLY: log the violation but allow the call
                            self._audit_logger.log_tool_call(
                                tool_name, arguments, boundary_result,
                            )

                # Log ALLOW/LOG only after passing all checks (policy + chaining + boundary)
                self._audit_logger.log_tool_call(tool_name, arguments, result)

                # Session-level evasion detection — runs after per-call decision.
                # Never blocks a call on its own; only acts when the full sequence
                # triggers a session-level verdict.
                if self._session_monitor is not None:
                    _session_result = self._session_monitor.record_and_check(
                        self._session_id,
                        tool_name,
                        arguments,
                        result.decision,
                    )
                    if _session_result.verdict.value != "CLEAN":
                        self._audit_logger.log_session_event(
                            session_id=self._session_id,
                            tool_name=tool_name,
                            verdict=_session_result.verdict.value,
                            aggregate_score=_session_result.aggregate_score,
                            triggering_pattern=_session_result.triggering_pattern,
                            pattern_results=[
                                {
                                    "pattern": r.pattern_name,
                                    "score": r.score,
                                    "reason": r.reason,
                                }
                                for r in _session_result.pattern_results
                                if r.score > 0
                            ],
                            dry_run=self._dry_run,
                        )
                        if self._session_monitor.should_pause_session(_session_result):
                            self._session_monitor.pause_session(self._session_id)
                        if (
                            self._session_monitor.should_block(_session_result)
                            and not self._dry_run
                        ):
                            error_resp = make_error_response(
                                msg.id,
                                POLICY_BLOCKED,
                                f"AgentWard session monitor: "
                                f"{_session_result.triggering_pattern} detected "
                                f"(score={_session_result.aggregate_score:.2f}).",
                            )
                            _write_to_stdout(serialize_message(error_resp))
                            continue

                self._pending_tool_calls[msg.id] = tool_name

                # Record for circuit breaker after all checks pass
                if self._circuit_breaker is not None:
                    self._circuit_breaker.record(tool_name, arguments)

            # Track tools/list requests so we can log the response
            if is_tools_list(msg) and isinstance(msg, JSONRPCRequest):
                self._pending_tools_list.add(msg.id)

            # Log resources/read requests for audit trail
            if is_resources_read(msg) and isinstance(msg, JSONRPCRequest):
                uri = msg.params.get("uri", "") if msg.params else ""
                _console.print(
                    f"  [dim]resources/read {uri}[/dim]",
                    highlight=False,
                )

            # Forward message to server
            self._process.stdin.write(line)
            await self._process.stdin.drain()

    async def _forward_server_to_client(self) -> None:
        """Read from server subprocess stdout, forward to our stdout (the client).

        Also logs tool call responses for audit purposes.
        """
        if self._process is None or self._process.stdout is None:
            _console.print(
                "[bold red]Cannot read from server: process not started[/bold red]",
            )
            return

        while not self._shutting_down:
            line = await self._process.stdout.readline()
            if not line:
                # Server process closed stdout (exited)
                break

            # Try to parse for audit logging, but always forward regardless
            try:
                msg = parse_message(line)
                # Check if this is a response to a tracked tool call
                if hasattr(msg, "id") and msg.id in self._pending_tool_calls:  # type: ignore[union-attr]
                    tool_name = self._pending_tool_calls.pop(msg.id)  # type: ignore[union-attr]
                    from agentward.proxy.protocol import JSONRPCError as _JSONRPCError
                    from agentward.proxy.protocol import JSONRPCResponse as _JSONRPCResponse

                    is_error = isinstance(msg, _JSONRPCError)
                    self._audit_logger.log_tool_result(tool_name, msg.id, is_error)  # type: ignore[union-attr]

                    # Record response content for chaining detection
                    if self._chain_tracker is not None and isinstance(msg, _JSONRPCResponse):
                        self._chain_tracker.record_response(
                            tool_name, msg.result, request_id=msg.id
                        )

                    # Record response for boundary taint tracking
                    if self._boundary_enforcer is not None and isinstance(msg, _JSONRPCResponse):
                        skill_for_boundary = (
                            self._policy_engine.resolve_skill(tool_name)
                            if self._policy_engine else None
                        )
                        self._boundary_enforcer.record_response(
                            tool_name, skill_for_boundary, msg.result
                        )

                    # Scan tool response for sensitive data (response inspection)
                    if isinstance(msg, _JSONRPCResponse) and msg.result:
                        self._inspect_tool_response(tool_name, msg.result)

                # Log tools/list responses (audit: what tools the server exposes)
                if is_tools_list_response(msg, self._pending_tools_list):
                    self._pending_tools_list.discard(msg.id)  # type: ignore[union-attr]
                    if isinstance(msg, JSONRPCResponse) and isinstance(msg.result, dict):
                        tools = msg.result.get("tools", [])
                        if isinstance(tools, list):
                            tool_names = [
                                t.get("name", "?") for t in tools
                                if isinstance(t, dict)
                            ]
                            _console.print(
                                f"  [dim]Server exposes {len(tool_names)} tools: "
                                f"{', '.join(tool_names[:10])}"
                                f"{'...' if len(tool_names) > 10 else ''}[/dim]",
                                highlight=False,
                            )
                            # Populate role cache from tool schemas
                            if self._role_cache is not None:
                                for t in tools:
                                    if isinstance(t, dict) and "name" in t:
                                        self._role_cache.register_tool(
                                            t["name"],
                                            t.get("inputSchema", {}),
                                            t.get("annotations"),
                                        )
                            # Register tool descriptions with the LLM judge
                            if self._llm_judge is not None:
                                for t in tools:
                                    if isinstance(t, dict) and "name" in t:
                                        self._llm_judge.register_tool(
                                            t["name"],
                                            t.get("inputSchema", {}),
                                            t.get("description"),
                                        )
            except ProtocolError:
                pass  # Can't parse — that's fine, still forward it

            _write_to_stdout(line)

    def _inspect_tool_response(
        self, tool_name: str, result: Any
    ) -> None:
        """Scan a tool response for sensitive data (response-side inspection).

        This catches sensitive data flowing OUT of tools (e.g., a database
        query returning SSNs). Currently logs only — does not block the
        response (it has already been forwarded by the time we parse it
        from the server's stdout stream).

        Args:
            tool_name: The tool that produced the response.
            result: The JSON-RPC result value from the server.
        """
        if self._policy_engine is None:
            return
        config = self._policy_engine.policy.sensitive_content
        if not config.enabled:
            return

        # Extract text content from MCP tool result format
        # MCP responses use: {content: [{type: "text", text: "..."}]}
        text_parts: list[str] = []
        if isinstance(result, dict):
            content = result.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block.get("text", "")
                        if isinstance(text, str) and text:
                            text_parts.append(text)

        if not text_parts:
            return

        classification = classify_arguments(
            {"_response": " ".join(text_parts)},
            enabled_patterns=config.patterns,
        )
        if classification.has_sensitive_data:
            _console.print(
                f"  [bold #ffcc00]SENSITIVE RESPONSE[/bold #ffcc00] {tool_name}: "
                f"{', '.join(f.finding_type.value for f in classification.findings)}",
                highlight=False,
            )
            self._audit_logger.log_sensitive_block(
                tool_name, {"_response_scan": True}, classification.findings,
            )

    async def _forward_server_stderr(self) -> None:
        """Read server subprocess stderr and log it.

        Server stderr is diagnostic output — never goes to our stdout
        (which is reserved for MCP protocol messages).
        """
        if self._process is None or self._process.stderr is None:
            _console.print(
                "[bold red]Cannot read server stderr: process not started[/bold red]",
            )
            return

        while not self._shutting_down:
            line = await self._process.stderr.readline()
            if not line:
                break
            # Write server stderr to our stderr
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    async def _handle_shutdown(self) -> None:
        """Handle graceful shutdown on signal."""
        self._shutting_down = True

    async def _cleanup_subprocess(self) -> None:
        """Terminate the subprocess gracefully, then force-kill if needed."""
        if self._process is None:
            return

        if self._process.returncode is not None:
            # Already exited
            return

        # Try graceful termination
        try:
            self._process.terminate()
            await asyncio.wait_for(
                self._process.wait(),
                timeout=_SHUTDOWN_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            # Force kill
            self._process.kill()
            await self._process.wait()

    def _evaluate_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> EvaluationResult:
        """Evaluate a tool call against the policy engine.

        If no policy engine is loaded (passthrough mode), returns ALLOW.

        Args:
            tool_name: The MCP tool name.
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

    def _sensitive_content_action(self) -> SensitiveContentAction:
        """Return the configured action for sensitive content detection.

        Defaults to BLOCK if no policy is loaded.
        """
        if self._policy_engine is None:
            return SensitiveContentAction.BLOCK
        return self._policy_engine.policy.sensitive_content.on_detection

    def _classify_tool_args(
        self, arguments: dict[str, Any]
    ) -> ClassificationResult:
        """Run the sensitive content classifier on tool call arguments.

        Reads enabled patterns from the policy config. If no policy is loaded
        or the classifier is disabled, returns a clean result.

        Args:
            arguments: The tool call arguments dict.

        Returns:
            A ClassificationResult.
        """
        if self._policy_engine is None:
            return ClassificationResult(has_sensitive_data=False)

        config = self._policy_engine.policy.sensitive_content
        if not config.enabled:
            return ClassificationResult(has_sensitive_data=False)

        return classify_arguments(arguments, enabled_patterns=config.patterns)


async def _create_stdin_reader() -> asyncio.StreamReader:
    """Create an asyncio StreamReader for the process's stdin.

    Returns:
        An asyncio.StreamReader connected to sys.stdin.
    """
    loop = asyncio.get_running_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)
    return reader


def _write_to_stdout(data: bytes) -> None:
    """Write bytes to stdout and flush immediately.

    This is the only path for MCP protocol messages going to the client.
    Must flush after every write to avoid buffering delays.

    Args:
        data: The raw bytes to write (should be newline-terminated JSON).
    """
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
