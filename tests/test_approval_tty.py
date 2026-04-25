"""Tests for the TTY (stdin) approval channel — Linux fallback.

The TTY channel runs ``input()``-style prompts on the controlling
terminal so APPROVE policy decisions don't fail-deny on Linux when no
Telegram bot is configured. These tests cover detection, parsing, and
race integration without requiring an actual TTY.
"""

from __future__ import annotations

import asyncio
import io
import sys
from unittest.mock import patch

import pytest

from agentward.proxy.approval import (
    ApprovalDecision,
    ApprovalHandler,
    _detect_tty_support,
)


# ---------------------------------------------------------------------------
# TTY detection
# ---------------------------------------------------------------------------


class TestDetectTtySupport:
    def test_disabled_via_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTWARD_DISABLE_TTY_APPROVAL", "1")
        # Even if isatty is True, the env var wins
        with patch.object(sys.stdin, "isatty", return_value=True), \
             patch.object(sys.stderr, "isatty", return_value=True):
            assert _detect_tty_support() is False

    def test_false_when_stdin_not_tty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTWARD_DISABLE_TTY_APPROVAL", raising=False)
        with patch.object(sys.stdin, "isatty", return_value=False), \
             patch.object(sys.stderr, "isatty", return_value=True):
            assert _detect_tty_support() is False

    def test_false_when_stderr_not_tty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTWARD_DISABLE_TTY_APPROVAL", raising=False)
        with patch.object(sys.stdin, "isatty", return_value=True), \
             patch.object(sys.stderr, "isatty", return_value=False):
            assert _detect_tty_support() is False

    def test_true_when_both_tty_and_no_env_var(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTWARD_DISABLE_TTY_APPROVAL", raising=False)
        with patch.object(sys.stdin, "isatty", return_value=True), \
             patch.object(sys.stderr, "isatty", return_value=True):
            assert _detect_tty_support() is True

    def test_handles_oserror_gracefully(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTWARD_DISABLE_TTY_APPROVAL", raising=False)
        with patch.object(sys.stdin, "isatty", side_effect=OSError("closed")):
            assert _detect_tty_support() is False


# ---------------------------------------------------------------------------
# TTY prompt parsing — simulate stdin input via a mock
# ---------------------------------------------------------------------------


def _handler_with_tty(monkeypatch: pytest.MonkeyPatch) -> ApprovalHandler:
    """Build a handler with TTY enabled, regardless of the test environment."""
    handler = ApprovalHandler(timeout=5)
    # Force TTY mode on; tests don't actually have a real TTY
    handler._can_use_tty = True
    handler._is_macos = False  # Force the Linux path
    return handler


@pytest.mark.asyncio
class TestTtyPromptParsing:
    async def test_a_returns_allow_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handler = _handler_with_tty(monkeypatch)
        with patch("sys.stdin.readline", return_value="a\n"):
            decision = await handler._tty_prompt("test message")
        assert decision == ApprovalDecision.ALLOW_ONCE

    async def test_s_returns_allow_session(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handler = _handler_with_tty(monkeypatch)
        with patch("sys.stdin.readline", return_value="s\n"):
            decision = await handler._tty_prompt("test message")
        assert decision == ApprovalDecision.ALLOW_SESSION

    async def test_d_returns_deny(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handler = _handler_with_tty(monkeypatch)
        with patch("sys.stdin.readline", return_value="d\n"):
            decision = await handler._tty_prompt("test message")
        assert decision == ApprovalDecision.DENY

    async def test_capital_letter_works(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handler = _handler_with_tty(monkeypatch)
        with patch("sys.stdin.readline", return_value="A\n"):
            decision = await handler._tty_prompt("test message")
        assert decision == ApprovalDecision.ALLOW_ONCE

    async def test_unknown_input_denies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handler = _handler_with_tty(monkeypatch)
        with patch("sys.stdin.readline", return_value="garbage\n"):
            decision = await handler._tty_prompt("test message")
        assert decision == ApprovalDecision.DENY

    async def test_empty_line_denies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        handler = _handler_with_tty(monkeypatch)
        with patch("sys.stdin.readline", return_value="\n"):
            decision = await handler._tty_prompt("test message")
        assert decision == ApprovalDecision.DENY

    async def test_eof_denies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # readline returns "" on EOF
        handler = _handler_with_tty(monkeypatch)
        with patch("sys.stdin.readline", return_value=""):
            decision = await handler._tty_prompt("test message")
        assert decision == ApprovalDecision.DENY


# ---------------------------------------------------------------------------
# Integration: race fallback when no other channel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestApprovalRaceWithTty:
    async def test_linux_no_telegram_uses_tty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """On Linux without Telegram, TTY path should produce an answer
        rather than fail-deny.
        """
        handler = ApprovalHandler(timeout=5)
        handler._is_macos = False
        handler._telegram_bot = None
        handler._can_use_tty = True

        with patch("sys.stdin.readline", return_value="a\n"):
            decision = await handler.request_approval(
                tool_name="read_file",
                arguments={"path": "/tmp/x"},
                reason="test",
            )
        assert decision == ApprovalDecision.ALLOW_ONCE

    async def test_linux_no_channels_still_fails_deny(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When TTY is also disabled, fail-deny is preserved (the prior
        Linux behavior with no Telegram).
        """
        handler = ApprovalHandler(timeout=5)
        handler._is_macos = False
        handler._telegram_bot = None
        handler._can_use_tty = False

        decision = await handler.request_approval(
            tool_name="read_file",
            arguments={"path": "/tmp/x"},
            reason="test",
        )
        assert decision == ApprovalDecision.DENY
