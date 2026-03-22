"""RFC 5424 syslog formatter for AgentWard audit events.

Converts structured audit log entries to RFC 5424 syslog messages suitable
for consumption by standard log shippers (Splunk UF, Filebeat, Fluentd, rsyslog).

Format: <PRI>VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP [SD] SP MSG
"""

from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from typing import Any

# LOG_USER facility (1) — standard for user-space applications
_FACILITY = 1

# RFC 5424 severity levels
_SEV_ALERT = 1       # Alert: action must be taken immediately
_SEV_ERROR = 3       # Error: error conditions
_SEV_WARNING = 4     # Warning: warning conditions
_SEV_NOTICE = 5      # Notice: normal but significant conditions
_SEV_INFO = 6        # Informational: informational messages

# Fixed per-process values (resolved once at import time)
_HOSTNAME = socket.gethostname()[:255] or "-"
_APP_NAME = "agentward"
_PROCID = str(os.getpid())

# SD-ID for AgentWard structured data elements.
# The @0 suffix marks this as a private/custom SD-ID per RFC 5424 §6.3.2.
_SD_ID = "agentward@0"


def _pri(severity: int) -> str:
    """Compute the RFC 5424 PRI field string."""
    return f"<{_FACILITY * 8 + severity}>"


def _escape_sd_value(value: str) -> str:
    """Escape a structured data param value per RFC 5424 §6.3.3.

    The characters ``\\``, ``"``, and ``]`` must be escaped.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _sd_element(params: dict[str, Any]) -> str:
    """Render one SD-ELEMENT, or ``-`` (NILVALUE) if params is empty."""
    if not params:
        return "-"
    parts = [_SD_ID]
    for key, val in params.items():
        escaped = _escape_sd_value(str(val)[:255])
        parts.append(f'{key}="{escaped}"')
    return "[" + " ".join(parts) + "]"


def _severity_for_entry(entry: dict[str, Any]) -> int:
    """Map an audit entry to the appropriate RFC 5424 severity level."""
    event = entry.get("event", "")

    if event == "tool_call":
        decision = entry.get("decision", "")
        if decision == "BLOCK":
            # Chain violations are slightly more severe — they indicate an
            # attempt to bridge two skill zones, not just a policy mismatch.
            return _SEV_ERROR if entry.get("chain_violation") else _SEV_WARNING
        if decision in ("REDACT", "APPROVE"):
            return _SEV_NOTICE
        # ALLOW, LOG
        return _SEV_INFO

    if event == "judge_decision":
        verdict = entry.get("verdict", "")
        if verdict in ("block", "flag"):
            return _SEV_WARNING
        return _SEV_INFO

    if event == "approval_dialog":
        # Human approval interactions are notable but not alarming
        return _SEV_NOTICE

    if event in ("sensitive_data_blocked", "boundary_violation"):
        action = entry.get("action", "block")
        return _SEV_WARNING if action == "block" else _SEV_NOTICE

    if event == "circuit_breaker":
        return _SEV_ALERT

    # startup, shutdown, http_request, tool_result, websocket_disconnect, etc.
    return _SEV_INFO


def _sd_params_for_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Extract the most useful fields for the SD-ELEMENT from an audit entry."""
    event = entry.get("event", "")
    params: dict[str, Any] = {"event": event}

    if event == "tool_call":
        for key in ("tool", "decision", "skill", "resource", "reason"):
            if entry.get(key) is not None:
                params[key] = str(entry[key])[:255]
        if entry.get("chain_violation"):
            params["chain_violation"] = "true"
        if entry.get("dry_run"):
            params["dry_run"] = "true"

    elif event == "judge_decision":
        for key in ("tool", "verdict", "risk_score", "reasoning"):
            if entry.get(key) is not None:
                params[key] = str(entry[key])[:255]
        if entry.get("cached"):
            params["cached"] = "true"

    elif event == "approval_dialog":
        for key in ("tool", "decision", "elapsed_ms"):
            if entry.get(key) is not None:
                params[key] = str(entry[key])

    elif event == "sensitive_data_blocked":
        if entry.get("tool"):
            params["tool"] = str(entry["tool"])
        findings = entry.get("findings", [])
        params["finding_count"] = str(len(findings))

    elif event == "boundary_violation":
        for key in ("tool", "zone", "classification", "source_tool", "action"):
            if entry.get(key) is not None:
                params[key] = str(entry[key])

    elif event == "startup":
        if entry.get("mode"):
            params["mode"] = str(entry["mode"])
        if entry.get("policy_path"):
            params["policy_path"] = str(entry["policy_path"])[:255]

    elif event in ("http_proxy_startup", "llm_proxy_startup"):
        if entry.get("mode"):
            params["mode"] = str(entry["mode"])
        if entry.get("listen_port") is not None:
            params["listen_port"] = str(entry["listen_port"])

    elif event == "shutdown":
        if entry.get("reason"):
            params["reason"] = str(entry["reason"])[:255]

    elif event == "http_request":
        for key in ("method", "path", "status"):
            if entry.get(key) is not None:
                params[key] = str(entry[key])

    elif event == "tool_result":
        for key in ("tool", "request_id", "is_error"):
            if entry.get(key) is not None:
                params[key] = str(entry[key])

    return params


def _msg_for_entry(entry: dict[str, Any]) -> str:
    """Build the human-readable MSG portion of the syslog line."""
    event = entry.get("event", "unknown")

    if event == "tool_call":
        tool = entry.get("tool", "?")
        decision = entry.get("decision", "?")
        reason = entry.get("reason", "")
        chain = " (chain violation)" if entry.get("chain_violation") else ""
        dry = " [dry-run]" if entry.get("dry_run") else ""
        return f"{decision}{chain}{dry} {tool}: {reason}"

    if event == "judge_decision":
        tool = entry.get("tool", "?")
        verdict = str(entry.get("verdict", "?")).upper()
        risk = entry.get("risk_score", "?")
        reasoning = entry.get("reasoning", "")
        cached = " (cached)" if entry.get("cached") else ""
        return f"Judge {verdict}{cached} {tool} risk={risk}: {reasoning}"

    if event == "approval_dialog":
        tool = entry.get("tool", "?")
        decision = entry.get("decision", "?")
        elapsed = entry.get("elapsed_ms", "?")
        return f"Approval {decision} for {tool} after {elapsed}ms"

    if event == "sensitive_data_blocked":
        tool = entry.get("tool", "?")
        findings = entry.get("findings", [])
        return f"Sensitive data blocked: {tool} ({len(findings)} finding(s))"

    if event == "boundary_violation":
        tool = entry.get("tool", "?")
        zone = entry.get("zone", "?")
        classification = entry.get("classification", "?")
        action = entry.get("action", "?")
        return f"Boundary {action}: {tool} in zone {zone} ({classification} data)"

    if event == "startup":
        mode = entry.get("mode", "?")
        return f"AgentWard proxy started (mode={mode})"

    if event == "http_proxy_startup":
        port = entry.get("listen_port", "?")
        backend = entry.get("backend_url", "?")
        return f"AgentWard HTTP proxy started on port {port} -> {backend}"

    if event == "llm_proxy_startup":
        port = entry.get("listen_port", "?")
        return f"AgentWard LLM proxy started on port {port}"

    if event == "shutdown":
        reason = entry.get("reason", "?")
        return f"AgentWard proxy stopped: {reason}"

    if event == "http_request":
        method = entry.get("method", "?")
        path = entry.get("path", "?")
        status = entry.get("status", "?")
        return f"{method} {path} {status}"

    if event == "tool_result":
        tool = entry.get("tool", "?")
        is_error = entry.get("is_error", False)
        outcome = "error" if is_error else "ok"
        return f"Tool result: {tool} ({outcome})"

    if event == "websocket_disconnect":
        path = entry.get("path", "?")
        return f"WebSocket disconnected: {path}"

    return f"AgentWard event: {event}"


def format_rfc5424(entry: dict[str, Any]) -> str:
    """Format an audit log entry as an RFC 5424 syslog message.

    Returns a complete syslog line without a trailing newline.

    Args:
        entry: A structured audit log entry dict (as written to the JSONL file).

    Returns:
        An RFC 5424 syslog line string.
    """
    severity = _severity_for_entry(entry)
    pri = _pri(severity)

    # Use the entry's own timestamp if present; fall back to now.
    timestamp = entry.get("timestamp") or datetime.now(timezone.utc).isoformat()

    # MSGID: event type, max 32 chars, no spaces (replace with underscore).
    msgid = str(entry.get("event", "-"))[:32].replace(" ", "_") or "-"

    sd = _sd_element(_sd_params_for_entry(entry))
    msg = _msg_for_entry(entry)

    return f"{pri}1 {timestamp} {_HOSTNAME} {_APP_NAME} {_PROCID} {msgid} {sd} {msg}"
