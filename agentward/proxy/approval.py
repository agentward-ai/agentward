"""macOS native approval dialogs for APPROVE policy decisions.

Shows a native macOS dialog via ``osascript`` when a tool call requires
human approval.  The user sees the tool name, argument preview, risk
level, and policy reason — enough to make an informed Allow/Deny decision.

Features:
  - Session-level caching ("Allow for Interaction" skips future dialogs for that tool)
  - Concurrency serialization (macOS shows one dialog at a time)
  - Configurable timeout (default 60s, auto-deny on expiry)
  - Non-macOS graceful degradation (default deny)
  - Credential redaction in argument previews
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from enum import Enum
from typing import Any

from rich.console import Console

_console = Console(stderr=True)

# Credential-like argument keys — values are redacted in the dialog.
_SENSITIVE_KEYS = frozenset({
    "token", "api_key", "apikey", "password", "secret",
    "credentials", "auth", "authorization", "private_key",
    "access_token", "refresh_token", "session_token",
})


class ApprovalDecision(str, Enum):
    """Outcome of an approval dialog."""

    ALLOW_ONCE = "allow_once"
    ALLOW_SESSION = "allow_session"
    DENY = "deny"
    TIMEOUT = "timeout"


class ApprovalHandler:
    """Manages approval dialogs for the proxy.

    Serializes concurrent dialog requests via an ``asyncio.Lock``
    (macOS only shows one dialog at a time).  "Allow for Interaction" grants a
    blanket approval that covers all tools until ``clear_cache()``
    is called (typically at the start of each new LLM request).

    Args:
        timeout: Seconds before the dialog auto-dismisses (deny).
    """

    def __init__(self, timeout: int = 60) -> None:
        self._timeout = timeout
        self._session_approved: bool = False
        self._dialog_lock = asyncio.Lock()
        self._is_macos: bool = sys.platform == "darwin"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def request_approval(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
    ) -> ApprovalDecision:
        """Show an approval dialog and return the user's decision.

        Checks the session cache first.  If the tool was previously
        allowed for the session, returns ``ALLOW_SESSION`` immediately.
        Otherwise shows a macOS native dialog.

        On non-macOS platforms, returns ``DENY`` (fail-secure).

        Args:
            tool_name: The tool being invoked (e.g. ``web_fetch``).
            arguments: The tool call arguments dict.
            reason: The policy reason string from ``EvaluationResult``.

        Returns:
            The user's decision.
        """
        # Session cache — skip dialog if session-wide approval was granted
        if self._session_approved:
            return ApprovalDecision.ALLOW_SESSION

        if not self._is_macos:
            _console.print(
                f"  [bold red]DENY[/bold red] {tool_name} "
                "(approval dialogs require macOS)",
                highlight=False,
            )
            return ApprovalDecision.DENY

        message = _format_dialog_message(tool_name, arguments, reason)

        # Serialize — macOS shows one dialog at a time
        async with self._dialog_lock:
            # Re-check cache (another request may have approved while waiting)
            if self._session_approved:
                return ApprovalDecision.ALLOW_SESSION

            start = time.monotonic()
            decision = await self._show_dialog(message)
            elapsed_ms = int((time.monotonic() - start) * 1000)

        # Update session cache — session-wide, covers all tools
        if decision == ApprovalDecision.ALLOW_SESSION:
            self._session_approved = True

        # Log to stderr
        _log_decision(tool_name, decision, elapsed_ms)

        return decision

    def clear_cache(self) -> None:
        """Clear the session approval cache."""
        self._session_approved = False

    # ------------------------------------------------------------------
    # Dialog execution
    # ------------------------------------------------------------------

    async def _show_dialog(self, message: str) -> ApprovalDecision:
        """Execute ``osascript`` in a thread pool and parse the result.

        Args:
            message: The formatted dialog message text.

        Returns:
            The parsed decision.
        """
        cmd = _build_osascript_command(message, self._timeout)
        loop = asyncio.get_running_loop()

        try:
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(  # noqa: S603, S607
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout + 10,  # buffer beyond dialog timeout
                ),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            _console.print(
                f"  [bold red]Dialog error:[/bold red] {exc}",
                highlight=False,
            )
            return ApprovalDecision.DENY

        if result.returncode != 0:
            # osascript error (no GUI session, syntax error, etc.)
            return ApprovalDecision.DENY

        return _parse_osascript_output(result.stdout)


# ----------------------------------------------------------------------
# Dialog message formatting
# ----------------------------------------------------------------------


def _format_dialog_message(
    tool_name: str,
    arguments: dict[str, Any],
    reason: str,
) -> str:
    """Format the dialog message with tool info, args preview, and risk.

    Args:
        tool_name: The tool name.
        arguments: The tool call arguments.
        reason: The policy reason string.

    Returns:
        A human-readable message string for the dialog.
    """
    from agentward.scan.enumerator import ToolInfo
    from agentward.scan.permissions import analyze_tool

    # Risk analysis
    perm = analyze_tool(ToolInfo(name=tool_name))
    risk_label = perm.risk_level.value
    access_types = [a.type.value for a in perm.data_access if a.type.value != "unknown"]
    risk_detail = ", ".join(perm.risk_reasons) if perm.risk_reasons else "No specific risk detected"

    # Build message parts
    parts: list[str] = []
    parts.append(f"Tool: {tool_name}")

    # Action line — derived from data access types
    if access_types:
        parts.append(f"Access: {', '.join(access_types)}")

    # Arguments preview
    args_preview = _format_args_preview(arguments)
    if args_preview:
        parts.append(f"Args: {args_preview}")

    parts.append("")  # blank line
    parts.append(f"Risk: {risk_label} — {risk_detail}")
    parts.append(f"Policy: {reason}")

    return "\n".join(parts)


def _format_args_preview(
    arguments: dict[str, Any],
    max_pairs: int = 3,
    max_value_len: int = 80,
) -> str:
    """Format a preview of tool arguments for the dialog.

    Redacts sensitive values, truncates long values, limits the number
    of key-value pairs shown.

    Args:
        arguments: The tool call arguments dict.
        max_pairs: Maximum number of key-value pairs to show.
        max_value_len: Maximum character length per value.

    Returns:
        A formatted string like ``key1=value1, key2=value2, ... and 3 more``.
    """
    if not arguments:
        return ""

    pairs: list[str] = []
    items = list(arguments.items())

    for key, value in items[:max_pairs]:
        if key.lower() in _SENSITIVE_KEYS:
            pairs.append(f"{key}=<redacted>")
        else:
            val_str = str(value)
            if len(val_str) > max_value_len:
                val_str = val_str[:max_value_len] + "..."
            pairs.append(f"{key}={val_str}")

    result = ", ".join(pairs)
    remaining = len(items) - max_pairs
    if remaining > 0:
        result += f" ... and {remaining} more"

    return result


# ----------------------------------------------------------------------
# osascript command building and parsing
# ----------------------------------------------------------------------


def _escape_for_osascript(text: str) -> str:
    """Escape text for safe embedding in AppleScript double-quoted strings.

    Args:
        text: The raw text.

    Returns:
        Text safe for use inside ``"..."`` in AppleScript.
    """
    # AppleScript uses \" for literal quotes and \\ for backslashes
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _build_osascript_command(message: str, timeout: int) -> list[str]:
    """Build the osascript command for an approval dialog.

    Args:
        message: The dialog message (will be escaped).
        timeout: Auto-dismiss timeout in seconds.

    Returns:
        The command as a list of strings for subprocess.run.
    """
    safe_message = _escape_for_osascript(message)
    script = (
        f'display dialog "{safe_message}" '
        f'buttons {{"Deny", "Allow Once", "Allow for Interaction"}} '
        f'default button "Deny" '
        f'giving up after {timeout} '
        f'with title "AgentWard: Approval Required"'
    )
    return ["osascript", "-e", script]


def _parse_osascript_output(stdout: str) -> ApprovalDecision:
    """Parse osascript output to an ``ApprovalDecision``.

    Args:
        stdout: The stdout from osascript.

    Returns:
        The parsed decision.
    """
    output = stdout.strip()

    if "gave up:true" in output:
        return ApprovalDecision.TIMEOUT

    if "button returned:Allow for Interaction" in output:
        return ApprovalDecision.ALLOW_SESSION

    if "button returned:Allow Once" in output:
        return ApprovalDecision.ALLOW_ONCE

    if "button returned:Deny" in output:
        return ApprovalDecision.DENY

    # Unknown output — fail-secure
    return ApprovalDecision.DENY


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------


def _log_decision(
    tool_name: str,
    decision: ApprovalDecision,
    elapsed_ms: int,
) -> None:
    """Log an approval decision to stderr."""
    if decision in (ApprovalDecision.ALLOW_ONCE, ApprovalDecision.ALLOW_SESSION):
        suffix = " (session)" if decision == ApprovalDecision.ALLOW_SESSION else ""
        _console.print(
            f"  [bold #00ff88]APPROVED[/bold #00ff88] {tool_name}{suffix}",
            highlight=False,
        )
    elif decision == ApprovalDecision.TIMEOUT:
        _console.print(
            f"  [bold #ffcc00]TIMEOUT[/bold #ffcc00] {tool_name} "
            f"(denied after {elapsed_ms}ms)",
            highlight=False,
        )
    else:
        _console.print(
            f"  [bold red]DENIED[/bold red] {tool_name}",
            highlight=False,
        )
