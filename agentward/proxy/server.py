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
from typing import Any

from rich.console import Console

from agentward.audit.logger import AuditLogger
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import PolicyDecision
from agentward.proxy.chaining import ChainTracker
from agentward.proxy.protocol import (
    APPROVAL_REQUIRED,
    POLICY_BLOCKED,
    JSONRPCRequest,
    ProtocolError,
    extract_tool_info,
    is_tool_call,
    is_tool_call_notification,
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
    ) -> None:
        self._server_command = server_command
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._server_env = server_env
        self._chain_tracker = chain_tracker
        self._policy_path = policy_path

        self._process: asyncio.subprocess.Process | None = None
        self._shutting_down = False

        # Track pending tool call requests so we can log responses
        # Maps request_id → tool_name
        self._pending_tool_calls: dict[int | str, str] = {}

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
        assert self._process is not None
        assert self._process.stdin is not None

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
                assert isinstance(msg, JSONRPCRequest)
                try:
                    tool_name, arguments = extract_tool_info(msg)
                except ProtocolError:
                    # Malformed tools/call — forward as-is, let server handle it
                    self._process.stdin.write(line)
                    await self._process.stdin.drain()
                    continue

                result = self._evaluate_tool_call(tool_name, arguments)

                if result.decision == PolicyDecision.BLOCK:
                    self._audit_logger.log_tool_call(tool_name, arguments, result)
                    error_resp = make_error_response(
                        msg.id,
                        POLICY_BLOCKED,
                        f"AgentWard policy blocked: {result.reason}",
                    )
                    _write_to_stdout(serialize_message(error_resp))
                    continue

                if result.decision == PolicyDecision.APPROVE:
                    self._audit_logger.log_tool_call(tool_name, arguments, result)
                    error_resp = make_error_response(
                        msg.id,
                        APPROVAL_REQUIRED,
                        f"AgentWard: Human approval required. {result.reason}",
                    )
                    _write_to_stdout(serialize_message(error_resp))
                    continue

                # ALLOW or LOG — check chaining rules before forwarding
                if self._chain_tracker is not None:
                    chain_result = self._chain_tracker.check_before_call(
                        tool_name, arguments
                    )
                    if chain_result is not None and chain_result.decision == PolicyDecision.BLOCK:
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

                # Log ALLOW/LOG only after passing all checks (policy + chaining)
                self._audit_logger.log_tool_call(tool_name, arguments, result)
                self._pending_tool_calls[msg.id] = tool_name

            # Forward message to server
            self._process.stdin.write(line)
            await self._process.stdin.drain()

    async def _forward_server_to_client(self) -> None:
        """Read from server subprocess stdout, forward to our stdout (the client).

        Also logs tool call responses for audit purposes.
        """
        assert self._process is not None
        assert self._process.stdout is not None

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
            except ProtocolError:
                pass  # Can't parse — that's fine, still forward it

            _write_to_stdout(line)

    async def _forward_server_stderr(self) -> None:
        """Read server subprocess stderr and log it.

        Server stderr is diagnostic output — never goes to our stdout
        (which is reserved for MCP protocol messages).
        """
        assert self._process is not None
        assert self._process.stderr is not None

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
