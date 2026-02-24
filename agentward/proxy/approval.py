"""Approval dialogs for APPROVE policy decisions.

Supports two channels that race in parallel (first response wins):

1. **macOS terminal dialog** — native ``osascript`` dialog on the local machine.
2. **Telegram bot** — remote inline-keyboard message via the Telegram API
   proxy (intercepts OpenClaw's ``getUpdates`` responses).

Features:
  - Session-level caching ("Allow for Interaction" skips future dialogs)
  - Concurrency serialization (one approval at a time)
  - Configurable timeout (default 60s, auto-deny on expiry)
  - Race: terminal + Telegram simultaneously, first response wins
  - Non-macOS + no Telegram → fail-secure deny
  - Credential redaction in argument previews
"""

from __future__ import annotations

import asyncio
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

    Serializes concurrent dialog requests via an ``asyncio.Lock``.
    "Allow for Interaction" grants a blanket approval that covers all
    tools until ``clear_cache()`` is called.

    When a ``TelegramApprovalBot`` is provided, both macOS terminal and
    Telegram channels race in parallel — first response wins.

    Args:
        timeout: Seconds before the dialog auto-dismisses (deny).
        telegram_bot: Optional Telegram bot for remote approvals.
    """

    def __init__(
        self,
        timeout: int = 60,
        telegram_bot: Any = None,
    ) -> None:
        self._timeout = timeout
        self._session_approved: bool = False
        self._dialog_lock = asyncio.Lock()
        self._is_macos: bool = sys.platform == "darwin"
        self._telegram_bot = telegram_bot
        self._osascript_proc: asyncio.subprocess.Process | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def request_approval(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
    ) -> ApprovalDecision:
        """Show approval dialog(s) and return the user's decision.

        Checks the session cache first.  Then races all available
        channels (macOS terminal + Telegram) in parallel — first
        response wins.

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

        has_telegram = (
            self._telegram_bot is not None
            and self._telegram_bot.is_paired
        )

        if not self._is_macos and not has_telegram:
            _console.print(
                f"  [bold red]DENY[/bold red] {tool_name} "
                "(no approval channel available)",
                highlight=False,
            )
            return ApprovalDecision.DENY

        message = _format_dialog_message(tool_name, arguments, reason)

        # Serialize — one approval at a time
        async with self._dialog_lock:
            # Re-check cache (another request may have approved while waiting)
            if self._session_approved:
                return ApprovalDecision.ALLOW_SESSION

            start = time.monotonic()
            decision = await self._race_approval(
                tool_name, arguments, reason, message,
            )
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
    # Race logic
    # ------------------------------------------------------------------

    async def _race_approval(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
        message: str,
    ) -> ApprovalDecision:
        """Race all available approval channels.  First response wins.

        Args:
            tool_name: The tool name (for Telegram message).
            arguments: The tool call arguments (for Telegram message).
            reason: The policy reason (for Telegram message).
            message: The pre-formatted macOS dialog text.

        Returns:
            The winning decision.
        """
        tasks: list[asyncio.Task[ApprovalDecision]] = []

        if self._is_macos:
            tasks.append(
                asyncio.create_task(self._show_dialog(message), name="terminal")
            )

        if self._telegram_bot is not None and self._telegram_bot.is_paired:
            tasks.append(
                asyncio.create_task(
                    self._telegram_request(tool_name, arguments, reason),
                    name="telegram",
                )
            )

        if not tasks:
            return ApprovalDecision.DENY

        if len(tasks) == 1:
            return await tasks[0]

        # Race — first to complete wins
        done, pending = await asyncio.wait(
            tasks, return_when=asyncio.FIRST_COMPLETED,
        )

        # Cancel losers
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

        # Get the winner's result
        winner = done.pop()
        try:
            return winner.result()
        except Exception:
            # If winner raised, check remaining done tasks
            for task in done:
                try:
                    return task.result()
                except Exception:
                    continue
            return ApprovalDecision.DENY

    async def _telegram_request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
    ) -> ApprovalDecision:
        """Wrapper for Telegram approval that falls back on failure.

        If the Telegram bot returns None (send failure), this raises
        so the race falls through to the terminal dialog.
        """
        result = await self._telegram_bot.request_approval(
            tool_name, arguments, reason, timeout=self._timeout,
        )
        if result is None:
            raise RuntimeError("Telegram send failed")
        return result

    # ------------------------------------------------------------------
    # macOS dialog execution
    # ------------------------------------------------------------------

    async def _show_dialog(self, message: str) -> ApprovalDecision:
        """Execute ``osascript`` as an async subprocess and parse the result.

        Uses ``asyncio.create_subprocess_exec`` so the process can be
        killed cleanly when the Telegram channel wins the race.

        Args:
            message: The formatted dialog message text.

        Returns:
            The parsed decision.
        """
        cmd = _build_osascript_command(message, self._timeout)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._osascript_proc = proc
            stdout, _ = await asyncio.wait_for(
                proc.communicate(),
                timeout=self._timeout + 10,
            )
        except asyncio.CancelledError:
            # Race lost — kill the dialog
            if self._osascript_proc is not None:
                try:
                    self._osascript_proc.kill()
                except ProcessLookupError:
                    pass
            raise
        except (asyncio.TimeoutError, FileNotFoundError, OSError) as exc:
            _console.print(
                f"  [bold red]Dialog error:[/bold red] {exc}",
                highlight=False,
            )
            return ApprovalDecision.DENY
        finally:
            self._osascript_proc = None

        if proc.returncode != 0:
            return ApprovalDecision.DENY

        return _parse_osascript_output(stdout.decode())


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
        The command as a list of strings for asyncio.create_subprocess_exec.
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
