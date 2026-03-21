"""Structured audit logging for AgentWard.

Logs every policy decision as structured JSON. Writes to stderr (via rich)
for human-readable output, and optionally to a JSON Lines file and an RFC 5424
syslog file for machine consumption and SIEM ingestion.

When a log_path is provided both JSONL and syslog files are always written
simultaneously — the syslog path defaults to the JSONL path with a .syslog
extension but can be overridden via the policy's ``audit.syslog_path`` setting.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from agentward.audit.syslog_formatter import format_rfc5424

from rich.console import Console

from agentward.inspect.classifier import classify_arguments, redact_arguments
from agentward.policy.engine import EvaluationResult
from agentward.policy.schema import PolicyDecision

# All CLI/log output goes to stderr — stdout is reserved for MCP protocol messages
_console = Console(stderr=True)


class AuditLogger:
    """Logs tool call decisions and proxy lifecycle events.

    Attributes:
        log_file: Optional open file handle for JSON Lines output.
    """

    def __init__(
        self,
        log_path: Path | None = None,
        syslog_path: Path | None = None,
    ) -> None:
        """Initialize the audit logger.

        Args:
            log_path: Optional path to write structured JSON Lines audit log.
                      If None, only logs to stderr via rich console.
            syslog_path: Optional path for the RFC 5424 syslog output file.
                         When log_path is set and syslog_path is None, the
                         syslog file is written alongside the JSONL file with
                         a ``.syslog`` extension.  Ignored when log_path is None.
        """
        self._log_file: IO[str] | None = None
        self._log_path = log_path
        self._syslog_file: IO[str] | None = None

        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._log_file = open(log_path, "a", encoding="utf-8")  # noqa: SIM115

            # Always open syslog file alongside the JSONL file.
            effective_syslog = (
                syslog_path if syslog_path is not None else log_path.with_suffix(".syslog")
            )
            effective_syslog.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._syslog_file = open(effective_syslog, "a", encoding="utf-8")  # noqa: SIM115
            except OSError as e:
                _console.print(
                    f"[bold red]Syslog file open failed:[/bold red] {e}",
                    highlight=False,
                )

    def close(self) -> None:
        """Flush and close both log files if open."""
        if self._log_file is not None:
            self._log_file.flush()
            self._log_file.close()
            self._log_file = None
        if self._syslog_file is not None:
            self._syslog_file.flush()
            self._syslog_file.close()
            self._syslog_file = None

    def log_tool_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        result: EvaluationResult,
        chain_violation: bool = False,
        dry_run: bool = False,
    ) -> None:
        """Log a tool call and its policy decision.

        Args:
            tool_name: The MCP tool name.
            arguments: The tool call arguments.
            result: The evaluation result from the policy engine.
            chain_violation: Whether this was blocked due to a chaining rule.
            dry_run: If True, the decision was observed but not enforced.
        """
        # Redact sensitive data from arguments before writing to audit log.
        # Always runs regardless of policy — audit logs must never contain raw PII.
        safe_arguments = _redact_for_audit(arguments)

        entry = {
            "timestamp": _now_iso(),
            "event": "tool_call",
            "tool": tool_name,
            "arguments": safe_arguments,
            "decision": result.decision.value,
            "reason": result.reason,
            "skill": result.skill,
            "resource": result.resource,
        }
        if chain_violation:
            entry["chain_violation"] = True
        if dry_run:
            entry["dry_run"] = True
        self._write_entry(entry)

        # Human-readable stderr output
        dry_tag = " [bold #5eead4](dry-run)[/bold #5eead4]" if dry_run else ""
        if chain_violation and result.decision == PolicyDecision.BLOCK:
            _console.print(
                f"  [bold red]✗ CHAIN BLOCK[/bold red]{dry_tag} {tool_name}",
                highlight=False,
            )
            _console.print(f"    [dim]{result.reason}[/dim]", highlight=False)
        elif result.decision == PolicyDecision.BLOCK:
            _console.print(
                f"  [bold red]✗ BLOCK[/bold red]{dry_tag} {tool_name}",
                highlight=False,
            )
            _console.print(f"    [dim]{result.reason}[/dim]", highlight=False)
        elif result.decision == PolicyDecision.APPROVE and dry_run:
            _console.print(
                f"  [bold #ffcc00]⚠ APPROVE[/bold #ffcc00]{dry_tag} {tool_name}",
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
                f"  [{decision_style}]{result.decision.value}[/{decision_style}]{dry_tag} {tool_name}",
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

    def log_approval_dialog(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        decision: str,
        elapsed_ms: int,
    ) -> None:
        """Log an approval dialog interaction.

        Args:
            tool_name: The tool that required approval.
            arguments: The tool call arguments.
            decision: The outcome (allow_once, allow_session, deny, timeout).
            elapsed_ms: How long the dialog was open in milliseconds.
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "approval_dialog",
            "tool": tool_name,
            "decision": decision,
            "elapsed_ms": elapsed_ms,
        }
        self._write_entry(entry)

    def log_sensitive_block(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        findings: list[Any],
    ) -> None:
        """Log a tool call blocked due to sensitive data in arguments.

        Args:
            tool_name: The tool that was blocked.
            arguments: The tool call arguments (not logged raw — contains sensitive data).
            findings: List of Finding objects from the classifier.
        """
        finding_summaries = [
            f"{f.finding_type.value} ({f.matched_text})" if hasattr(f, "matched_text") else str(f)
            for f in findings
        ]
        entry = {
            "timestamp": _now_iso(),
            "event": "sensitive_data_blocked",
            "tool": tool_name,
            "findings": [
                {"type": f.finding_type.value, "redacted": f.matched_text, "path": f.field_path}
                for f in findings
                if hasattr(f, "finding_type")
            ],
        }
        self._write_entry(entry)

        summary = ", ".join(finding_summaries)
        _console.print(
            f"  [bold red]\u2717 SENSITIVE DATA BLOCKED[/bold red] {tool_name}",
            highlight=False,
        )
        _console.print(
            f"    [dim]Detected: {summary}[/dim]",
            highlight=False,
        )

    def log_boundary_violation(
        self,
        tool_name: str,
        zone_name: str,
        classification: str,
        source_tool: str,
        matched_content: str,
        action: str,
    ) -> None:
        """Log a data boundary violation.

        Args:
            tool_name: The tool that violated the boundary.
            zone_name: The boundary zone that was violated.
            classification: The data classification (e.g., "phi", "financial").
            source_tool: The tool whose response contained the tainted data.
            matched_content: The content string that matched.
            action: "block" or "log_only".
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "boundary_violation",
            "tool": tool_name,
            "zone": zone_name,
            "classification": classification,
            "source_tool": source_tool,
            "matched_content": matched_content[:200],  # Truncate for safety
            "action": action,
        }
        self._write_entry(entry)

        if action == "block":
            _console.print(
                f"  [bold red]\u2717 BOUNDARY BLOCK[/bold red] {tool_name}",
                highlight=False,
            )
        else:
            _console.print(
                f"  [#ffcc00]\u26a0 BOUNDARY LOG[/#ffcc00] {tool_name}",
                highlight=False,
            )
        _console.print(
            f"    [dim]{classification} data from {source_tool} "
            f"(zone: {zone_name})[/dim]",
            highlight=False,
        )

    def log_judge_decision(
        self,
        tool_name: str,
        verdict: str,
        risk_score: float,
        reasoning: str,
        elapsed_ms: int,
        cached: bool = False,
    ) -> None:
        """Log an LLM judge decision.

        Records the structured judge result for audit trail and SIEM ingestion.
        The human-readable verdict is also printed to stderr by the judge module
        itself, so this method only writes to the JSON Lines file.

        Args:
            tool_name: The tool that was judged.
            verdict: The judge's verdict: "allow", "flag", or "block".
            risk_score: Risk score 0.0–1.0 from the judge LLM.
            reasoning: One-sentence explanation from the judge LLM.
            elapsed_ms: Time the judge LLM call took in milliseconds.
            cached: Whether this result was served from cache (no LLM call made).
        """
        entry = {
            "timestamp": _now_iso(),
            "event": "judge_decision",
            "tool": tool_name,
            "verdict": verdict,
            "risk_score": risk_score,
            "reasoning": reasoning,
            "elapsed_ms": elapsed_ms,
            "cached": cached,
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
        """Write a structured JSON entry to both log files.

        If a write fails (disk full, permission error, etc.), logs the
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

        if self._syslog_file is not None:
            try:
                self._syslog_file.write(format_rfc5424(entry) + "\n")
                self._syslog_file.flush()
            except (OSError, ValueError) as e:
                _console.print(
                    f"[bold red]Syslog write failed:[/bold red] {e}",
                    highlight=False,
                )
                try:
                    self._syslog_file.close()
                except (OSError, ValueError):
                    pass
                self._syslog_file = None


def _redact_for_audit(arguments: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive data from tool arguments before writing to audit log.

    Always runs the full classifier (all patterns) regardless of policy
    configuration. Audit logs must never contain raw PII/credentials,
    even when the proxy's sensitive_content config is disabled.

    Args:
        arguments: The raw tool call arguments.

    Returns:
        A copy with sensitive values replaced by "[REDACTED:<type>]",
        or the original dict if nothing was found.
    """
    if not arguments:
        return arguments
    result = classify_arguments(arguments)
    if not result.has_sensitive_data:
        return arguments
    return redact_arguments(arguments, result.findings)


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
