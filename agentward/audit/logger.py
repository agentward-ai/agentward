"""Structured audit logging for AgentWard.

Logs every policy decision as structured JSON. Writes to stderr (via rich)
for human-readable output, and optionally to a JSON Lines file for machine
consumption and SIEM ingestion.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from rich.console import Console

from agentward.policy.engine import EvaluationResult
from agentward.policy.schema import PolicyDecision

# All CLI/log output goes to stderr — stdout is reserved for MCP protocol messages
_console = Console(stderr=True)


class AuditLogger:
    """Logs tool call decisions and proxy lifecycle events.

    Attributes:
        log_file: Optional open file handle for JSON Lines output.
    """

    def __init__(self, log_path: Path | None = None) -> None:
        """Initialize the audit logger.

        Args:
            log_path: Optional path to write structured JSON Lines audit log.
                      If None, only logs to stderr via rich console.
        """
        self._log_file: IO[str] | None = None
        self._log_path = log_path
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(log_path, "a", encoding="utf-8")  # noqa: SIM115

    def close(self) -> None:
        """Flush and close the log file if open."""
        if self._log_file is not None:
            self._log_file.flush()
            self._log_file.close()
            self._log_file = None

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: EvaluationResult,
        chain_violation: bool = False,
    ) -> None:
        """Log a tool call and its policy decision.

        Args:
            tool_name: The MCP tool name.
            arguments: The tool call arguments.
            result: The evaluation result from the policy engine.
            chain_violation: Whether this was blocked due to a chaining rule.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "tool_call",
            "tool": tool_name,
            "decision": result.decision.value,
            "reason": result.reason,
            "skill": result.skill,
            "resource": result.resource,
        }
        if chain_violation:
            entry["chain_violation"] = True
        self._write_entry(entry)

        # Human-readable stderr output
        if chain_violation and result.decision == PolicyDecision.BLOCK:
            _console.print(
                f"  [bold red]✗ CHAIN BLOCK[/bold red] {tool_name}",
                highlight=False,
            )
            _console.print(f"    [dim]{result.reason}[/dim]", highlight=False)
        elif result.decision == PolicyDecision.BLOCK:
            _console.print(
                f"  [bold red]✗ BLOCK[/bold red] {tool_name}",
                highlight=False,
            )
            _console.print(f"    [dim]{result.reason}[/dim]", highlight=False)
        elif result.decision == PolicyDecision.ALLOW:
            _console.print(
                f"  [#00ff88]✓ ALLOW[/#00ff88] {tool_name}",
                highlight=False,
            )
        else:
            decision_style = _decision_style(result.decision)
            _console.print(
                f"  [{decision_style}]{result.decision.value}[/{decision_style}] {tool_name}",
                highlight=False,
            )
            _console.print(f"    [dim]{result.reason}[/dim]", highlight=False)

    def log_tool_result(
        self,
        tool_name: str,
        request_id: int | str,
        is_error: bool,
    ) -> None:
        """Log a tool call response.

        Args:
            tool_name: The MCP tool name that was called.
            request_id: The JSON-RPC request ID.
            is_error: Whether the response was an error.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "tool_result",
            "tool": tool_name,
            "request_id": request_id,
            "is_error": is_error,
        }
        self._write_entry(entry)

    def log_startup(
        self, server_command: list[str], policy_path: Path | None
    ) -> None:
        """Log proxy startup.

        Args:
            server_command: The MCP server command being proxied.
            policy_path: Path to the loaded policy, or None if passthrough mode.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "startup",
            "server_command": server_command,
            "policy_path": str(policy_path) if policy_path else None,
            "mode": "enforce" if policy_path else "passthrough",
        }
        self._write_entry(entry)

        _console.print("[bold #00ff88]AgentWard proxy started[/bold #00ff88]")
        _console.print(f"  Server: {' '.join(server_command)}")
        if policy_path:
            _console.print(f"  Policy: {policy_path}")
        else:
            _console.print("  Mode: [#ffcc00]passthrough[/#ffcc00] (no policy loaded)")

    def log_http_request(
        self,
        method: str,
        path: str,
        status: int,
        *,
        is_websocket: bool = False,
        stderr: bool = True,
    ) -> None:
        """Log a proxied HTTP request (non-tool-invoke traffic).

        Uses dim styling so tool call decisions remain visually prominent.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: Request path.
            status: Response status code.
            is_websocket: Whether this was a WebSocket upgrade.
            stderr: Whether to print to stderr.  Set to False for high-frequency
                    paths (e.g., LLM API calls) that would drown out tool decisions.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "http_request",
            "method": method,
            "path": path,
            "status": status,
        }
        if is_websocket:
            entry["websocket"] = True
        self._write_entry(entry)

        if not stderr:
            return

        if is_websocket:
            _console.print(
                f"  [dim]WS  {path} → upgraded[/dim]",
                highlight=False,
            )
        else:
            # Color status code: green for 2xx, yellow for 3xx, red for 4xx/5xx
            if 200 <= status < 300:
                status_style = "#00ff88"
            elif 300 <= status < 400:
                status_style = "#ffcc00"
            else:
                status_style = "red"
            _console.print(
                f"  [dim]{method:4s} {path} → [{status_style}]{status}[/{status_style}][/dim]",
                highlight=False,
            )

    def log_websocket_disconnect(self, path: str) -> None:
        """Log a WebSocket disconnection.

        Args:
            path: The WebSocket path that disconnected.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "websocket_disconnect",
            "path": path,
        }
        self._write_entry(entry)
        _console.print(
            f"  [dim]WS  {path} → closed[/dim]",
            highlight=False,
        )

    def log_http_startup(
        self,
        listen_port: int,
        backend_url: str,
        policy_path: Path | None,
    ) -> None:
        """Log HTTP proxy startup.

        Args:
            listen_port: The port the proxy is listening on.
            backend_url: The backend URL being proxied.
            policy_path: Path to the loaded policy, or None if passthrough mode.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "http_proxy_startup",
            "listen_port": listen_port,
            "backend_url": backend_url,
            "policy_path": str(policy_path) if policy_path else None,
            "mode": "enforce" if policy_path else "passthrough",
        }
        self._write_entry(entry)

        _console.print("[bold #00ff88]AgentWard HTTP proxy started[/bold #00ff88]")
        _console.print(f"  Backend: {backend_url}")
        if policy_path:
            _console.print(f"  Policy:  {policy_path}")
        else:
            _console.print("  Mode: [#ffcc00]passthrough[/#ffcc00] (no policy loaded)")

    def log_llm_startup(
        self,
        listen_port: int,
        provider_urls: dict[str, str],
        policy_path: Path | None,
    ) -> None:
        """Log LLM proxy startup.

        Args:
            listen_port: The port the LLM proxy is listening on.
            provider_urls: Mapping of model key to real provider base URL.
            policy_path: Path to the loaded policy, or None if passthrough mode.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "llm_proxy_startup",
            "listen_port": listen_port,
            "provider_urls": provider_urls,
            "policy_path": str(policy_path) if policy_path else None,
            "mode": "enforce" if policy_path else "passthrough",
        }
        self._write_entry(entry)

    def log_shutdown(self, reason: str) -> None:
        """Log proxy shutdown.

        Args:
            reason: Why the proxy is shutting down.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "shutdown",
            "reason": reason,
        }
        self._write_entry(entry)
        _console.print(f"[bold]AgentWard proxy stopped:[/bold] {reason}")

    def _write_entry(self, entry: dict[str, Any]) -> None:
        """Write a structured JSON entry to the log file.

        If the write fails (disk full, permission error, etc.), logs the
        failure to stderr and continues — the proxy must not crash due to
        audit I/O errors.

        Args:
            entry: The log entry as a dictionary.
        """
        if self._log_file is not None:
            try:
                self._log_file.write(json.dumps(entry, default=str) + "\n")
                self._log_file.flush()
            except (OSError, ValueError) as e:
                # OSError: disk full, permission denied, etc.
                # ValueError: I/O operation on closed file
                _console.print(
                    f"[bold red]Audit log write failed:[/bold red] {e}",
                    highlight=False,
                )
                # Close the broken file handle to avoid repeated failures
                try:
                    self._log_file.close()
                except (OSError, ValueError):
                    pass
                self._log_file = None


def _now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _decision_style(decision: PolicyDecision) -> str:
    """Map a policy decision to a rich style for console output."""
    styles = {
        PolicyDecision.ALLOW: "#00ff88",
        PolicyDecision.BLOCK: "bold red",
        PolicyDecision.REDACT: "#ffcc00",
        PolicyDecision.APPROVE: "bold #ffcc00",
        PolicyDecision.LOG: "#5eead4",
    }
    return styles.get(decision, "white")
