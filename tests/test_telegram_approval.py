"""Tests for the Telegram approval bot module (API proxy approach).

Covers:
  - TelegramApprovalBot: construction, pairing, state file persistence
  - Callback data parsing and filtering
  - Message formatting
  - getUpdates response filtering (the core proxy logic)
  - try_create_bot factory: various config states
  - ApprovalHandler race logic: both channels, single channel, no channels
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentward.proxy.approval import ApprovalDecision, ApprovalHandler
from agentward.proxy.telegram_approval import (
    TelegramApprovalBot,
    _CALLBACK_PREFIX,
    _decision_label,
    _format_telegram_message,
    _parse_callback_decision,
    try_create_bot,
)


# -----------------------------------------------------------------------
# Callback data parsing
# -----------------------------------------------------------------------


class TestParseCallbackDecision:
    """Tests for _parse_callback_decision."""

    def test_allow_once(self) -> None:
        assert _parse_callback_decision("allow_once") == ApprovalDecision.ALLOW_ONCE

    def test_allow_session(self) -> None:
        assert _parse_callback_decision("allow_session") == ApprovalDecision.ALLOW_SESSION

    def test_deny(self) -> None:
        assert _parse_callback_decision("deny") == ApprovalDecision.DENY

    def test_unknown_returns_none(self) -> None:
        assert _parse_callback_decision("unknown") is None

    def test_empty_returns_none(self) -> None:
        assert _parse_callback_decision("") is None


# -----------------------------------------------------------------------
# Decision labels
# -----------------------------------------------------------------------


class TestDecisionLabel:
    """Tests for _decision_label."""

    def test_allow_session(self) -> None:
        assert "Approved" in _decision_label(ApprovalDecision.ALLOW_SESSION)

    def test_allow_once(self) -> None:
        assert "Approved" in _decision_label(ApprovalDecision.ALLOW_ONCE)

    def test_deny(self) -> None:
        assert "Denied" in _decision_label(ApprovalDecision.DENY)

    def test_timeout(self) -> None:
        assert "Timed out" in _decision_label(ApprovalDecision.TIMEOUT)


# -----------------------------------------------------------------------
# Telegram message formatting
# -----------------------------------------------------------------------


class TestFormatTelegramMessage:
    """Tests for _format_telegram_message."""

    def test_contains_tool_name(self) -> None:
        msg = _format_telegram_message("web_fetch", {"url": "https://example.com"}, "reason")
        assert "web_fetch" in msg

    def test_contains_header(self) -> None:
        msg = _format_telegram_message("exec", {}, "test reason")
        assert "Approval Required" in msg

    def test_contains_args(self) -> None:
        msg = _format_telegram_message("tool", {"key": "value"}, "reason")
        assert "key=value" in msg


# -----------------------------------------------------------------------
# TelegramApprovalBot
# -----------------------------------------------------------------------


class TestTelegramApprovalBot:
    """Tests for TelegramApprovalBot construction and state."""

    def test_not_paired_when_no_chat_id(self, tmp_path: Path) -> None:
        bot = TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=None,
            state_file=tmp_path / "state.json",
        )
        assert not bot.is_paired

    def test_paired_when_chat_id_set(self, tmp_path: Path) -> None:
        bot = TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=12345,
            state_file=tmp_path / "state.json",
        )
        assert bot.is_paired

    def test_save_chat_id(self, tmp_path: Path) -> None:
        state_file = tmp_path / "telegram" / "agentward-chat-id.json"
        bot = TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=99999,
            state_file=state_file,
        )
        bot._save_chat_id()
        assert state_file.exists()
        data = json.loads(state_file.read_text())
        assert data["chat_id"] == 99999

    def test_request_approval_returns_none_when_not_paired(self, tmp_path: Path) -> None:
        bot = TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=None,
            state_file=tmp_path / "state.json",
        )

        async def _run() -> ApprovalDecision | None:
            return await bot.request_approval("tool", {}, "reason")

        result = asyncio.run(_run())
        assert result is None

    def test_proxy_port_default(self, tmp_path: Path) -> None:
        bot = TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=None,
            state_file=tmp_path / "state.json",
        )
        assert bot.proxy_port == 18901

    def test_proxy_port_custom(self, tmp_path: Path) -> None:
        bot = TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=None,
            state_file=tmp_path / "state.json",
            proxy_port=19000,
        )
        assert bot.proxy_port == 19000


# -----------------------------------------------------------------------
# getUpdates response filtering
# -----------------------------------------------------------------------


class TestFilterUpdates:
    """Tests for _filter_updates — the core proxy interception logic."""

    def _make_bot(self, tmp_path: Path) -> TelegramApprovalBot:
        return TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=12345,
            state_file=tmp_path / "state.json",
        )

    def test_passes_through_non_json(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)
        body = b"not json"
        assert bot._filter_updates(body) == body

    def test_passes_through_non_ok_response(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)
        body = json.dumps({"ok": False, "result": []}).encode()
        assert bot._filter_updates(body) == body

    def test_passes_through_normal_updates(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)
        updates = {
            "ok": True,
            "result": [
                {"update_id": 1, "message": {"text": "hello", "chat": {"id": 123}}},
                {"update_id": 2, "message": {"text": "world", "chat": {"id": 123}}},
            ],
        }
        body = json.dumps(updates).encode()
        result = json.loads(bot._filter_updates(body))
        assert len(result["result"]) == 2

    def test_strips_agentward_callback(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)

        # Set up a pending future
        loop = asyncio.new_event_loop()
        future: asyncio.Future[ApprovalDecision] = loop.create_future()
        bot._pending["abc123"] = future

        updates = {
            "ok": True,
            "result": [
                {"update_id": 1, "message": {"text": "hello", "chat": {"id": 123}}},
                {
                    "update_id": 2,
                    "callback_query": {
                        "id": "cb1",
                        "data": f"{_CALLBACK_PREFIX}abc123:allow_once",
                        "from": {"id": 123},
                    },
                },
                {"update_id": 3, "message": {"text": "world", "chat": {"id": 123}}},
            ],
        }
        body = json.dumps(updates).encode()
        result = json.loads(bot._filter_updates(body))

        # AgentWard callback stripped, other updates preserved
        assert len(result["result"]) == 2
        assert result["result"][0]["update_id"] == 1
        assert result["result"][1]["update_id"] == 3

        # Future should be resolved
        assert future.done()
        assert future.result() == ApprovalDecision.ALLOW_ONCE

        loop.close()

    def test_passes_through_non_agentward_callback(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)
        updates = {
            "ok": True,
            "result": [
                {
                    "update_id": 1,
                    "callback_query": {
                        "id": "cb1",
                        "data": "some_openclaw_data",
                        "from": {"id": 123},
                    },
                },
            ],
        }
        body = json.dumps(updates).encode()
        result = json.loads(bot._filter_updates(body))
        # Non-AgentWard callback passes through
        assert len(result["result"]) == 1

    def test_handles_start_pairing(self, tmp_path: Path) -> None:
        bot = TelegramApprovalBot(
            bot_token="fake-token",
            chat_id=None,
            state_file=tmp_path / "telegram" / "state.json",
        )
        updates = {
            "ok": True,
            "result": [
                {
                    "update_id": 1,
                    "message": {"text": "/start", "chat": {"id": 42}},
                },
            ],
        }
        body = json.dumps(updates).encode()
        result = json.loads(bot._filter_updates(body))

        # /start still passes through to OpenClaw
        assert len(result["result"]) == 1
        # But bot is now paired
        assert bot.is_paired
        assert bot._chat_id == 42
        # State file persisted
        assert (tmp_path / "telegram" / "state.json").exists()

    def test_strips_multiple_agentward_callbacks(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)

        loop = asyncio.new_event_loop()
        f1: asyncio.Future[ApprovalDecision] = loop.create_future()
        f2: asyncio.Future[ApprovalDecision] = loop.create_future()
        bot._pending["req1"] = f1
        bot._pending["req2"] = f2

        updates = {
            "ok": True,
            "result": [
                {
                    "update_id": 1,
                    "callback_query": {
                        "id": "cb1",
                        "data": f"{_CALLBACK_PREFIX}req1:allow_once",
                    },
                },
                {"update_id": 2, "message": {"text": "hi", "chat": {"id": 1}}},
                {
                    "update_id": 3,
                    "callback_query": {
                        "id": "cb2",
                        "data": f"{_CALLBACK_PREFIX}req2:deny",
                    },
                },
            ],
        }
        body = json.dumps(updates).encode()
        result = json.loads(bot._filter_updates(body))

        assert len(result["result"]) == 1
        assert result["result"][0]["update_id"] == 2
        assert f1.result() == ApprovalDecision.ALLOW_ONCE
        assert f2.result() == ApprovalDecision.DENY

        loop.close()

    def test_ignores_callback_with_unknown_request_id(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)
        # No pending futures set up — callback data has our prefix but unknown ID
        updates = {
            "ok": True,
            "result": [
                {
                    "update_id": 1,
                    "callback_query": {
                        "id": "cb1",
                        "data": f"{_CALLBACK_PREFIX}unknown_id:allow_once",
                    },
                },
            ],
        }
        body = json.dumps(updates).encode()
        result = json.loads(bot._filter_updates(body))
        # Still stripped (it's ours, just stale) — don't leak to OpenClaw
        assert len(result["result"]) == 0

    def test_empty_result_list(self, tmp_path: Path) -> None:
        bot = self._make_bot(tmp_path)
        body = json.dumps({"ok": True, "result": []}).encode()
        assert bot._filter_updates(body) == body


# -----------------------------------------------------------------------
# try_create_bot factory
# -----------------------------------------------------------------------


class TestTryCreateBot:
    """Tests for the try_create_bot factory function."""

    def test_returns_none_when_telegram_not_enabled(self, tmp_path: Path) -> None:
        config = tmp_path / "clawdbot.json"
        config.write_text(json.dumps({
            "channels": {"telegram": {"enabled": False, "botToken": "tok"}},
        }))
        result = try_create_bot(config)
        assert result is None

    def test_returns_none_when_no_bot_token(self, tmp_path: Path) -> None:
        config = tmp_path / "clawdbot.json"
        config.write_text(json.dumps({
            "channels": {"telegram": {"enabled": True}},
        }))
        result = try_create_bot(config)
        assert result is None

    def test_returns_none_when_no_telegram_section(self, tmp_path: Path) -> None:
        config = tmp_path / "clawdbot.json"
        config.write_text(json.dumps({"channels": {}}))
        result = try_create_bot(config)
        assert result is None

    def test_returns_none_when_config_missing(self, tmp_path: Path) -> None:
        result = try_create_bot(tmp_path / "nonexistent.json")
        assert result is None

    def test_returns_bot_when_valid(self, tmp_path: Path) -> None:
        config = tmp_path / "clawdbot.json"
        config.write_text(json.dumps({
            "channels": {"telegram": {"enabled": True, "botToken": "tok123"}},
        }))
        result = try_create_bot(config)
        assert result is not None
        assert isinstance(result, TelegramApprovalBot)
        assert not result.is_paired  # no chat_id yet

    def test_loads_chat_id_from_state_file(self, tmp_path: Path) -> None:
        config = tmp_path / "clawdbot.json"
        config.write_text(json.dumps({
            "channels": {"telegram": {"enabled": True, "botToken": "tok123"}},
        }))
        # Create state file
        state_dir = tmp_path / "telegram"
        state_dir.mkdir()
        (state_dir / "agentward-chat-id.json").write_text(
            json.dumps({"chat_id": 42}),
        )
        result = try_create_bot(config)
        assert result is not None
        assert result.is_paired

    def test_custom_proxy_port(self, tmp_path: Path) -> None:
        config = tmp_path / "clawdbot.json"
        config.write_text(json.dumps({
            "channels": {"telegram": {"enabled": True, "botToken": "tok123"}},
        }))
        result = try_create_bot(config, proxy_port=19999)
        assert result is not None
        assert result.proxy_port == 19999


# -----------------------------------------------------------------------
# ApprovalHandler race logic
# -----------------------------------------------------------------------


class TestApprovalHandlerRace:
    """Tests for the race logic in ApprovalHandler."""

    @pytest.mark.asyncio
    async def test_no_channels_returns_deny(self) -> None:
        """Non-macOS + no Telegram -> deny."""
        handler = ApprovalHandler(timeout=5)
        with patch.object(handler, "_is_macos", False):
            result = await handler.request_approval("tool", {}, "reason")
        assert result == ApprovalDecision.DENY

    @pytest.mark.asyncio
    async def test_session_cache_skips_dialog(self) -> None:
        """Session cache hit -> immediate ALLOW_SESSION."""
        handler = ApprovalHandler(timeout=5)
        handler._session_approved = True
        result = await handler.request_approval("tool", {}, "reason")
        assert result == ApprovalDecision.ALLOW_SESSION

    @pytest.mark.asyncio
    async def test_telegram_only_race(self) -> None:
        """Non-macOS with Telegram bot -> Telegram only."""
        mock_bot = MagicMock()
        mock_bot.is_paired = True
        mock_bot.request_approval = AsyncMock(
            return_value=ApprovalDecision.ALLOW_ONCE,
        )
        handler = ApprovalHandler(timeout=5, telegram_bot=mock_bot)
        with patch.object(handler, "_is_macos", False):
            result = await handler.request_approval("tool", {}, "reason")
        assert result == ApprovalDecision.ALLOW_ONCE
        mock_bot.request_approval.assert_called_once()

    @pytest.mark.asyncio
    async def test_terminal_only_race(self) -> None:
        """macOS with no Telegram bot -> terminal only."""
        handler = ApprovalHandler(timeout=5)
        with (
            patch.object(handler, "_is_macos", True),
            patch.object(
                handler,
                "_show_dialog",
                new_callable=AsyncMock,
                return_value=ApprovalDecision.ALLOW_ONCE,
            ),
        ):
            result = await handler.request_approval("tool", {}, "reason")
        assert result == ApprovalDecision.ALLOW_ONCE

    @pytest.mark.asyncio
    async def test_race_telegram_wins(self) -> None:
        """Both channels race, Telegram responds first."""
        mock_bot = MagicMock()
        mock_bot.is_paired = True
        mock_bot.request_approval = AsyncMock(
            return_value=ApprovalDecision.ALLOW_SESSION,
        )
        handler = ApprovalHandler(timeout=5, telegram_bot=mock_bot)

        # Terminal takes forever (simulate with sleep)
        async def slow_dialog(message: str) -> ApprovalDecision:
            await asyncio.sleep(100)
            return ApprovalDecision.DENY

        with (
            patch.object(handler, "_is_macos", True),
            patch.object(handler, "_show_dialog", side_effect=slow_dialog),
        ):
            result = await handler.request_approval("tool", {}, "reason")

        assert result == ApprovalDecision.ALLOW_SESSION
        # Session should be cached
        assert handler._session_approved is True

    @pytest.mark.asyncio
    async def test_race_terminal_wins(self) -> None:
        """Both channels race, terminal responds first."""
        mock_bot = MagicMock()
        mock_bot.is_paired = True

        # Telegram takes forever
        async def slow_telegram(
            tool_name: str,
            arguments: dict[str, Any],
            reason: str,
            timeout: int = 60,
        ) -> ApprovalDecision:
            await asyncio.sleep(100)
            return ApprovalDecision.DENY

        mock_bot.request_approval = slow_telegram

        handler = ApprovalHandler(timeout=5, telegram_bot=mock_bot)

        with (
            patch.object(handler, "_is_macos", True),
            patch.object(
                handler,
                "_show_dialog",
                new_callable=AsyncMock,
                return_value=ApprovalDecision.ALLOW_ONCE,
            ),
        ):
            result = await handler.request_approval("tool", {}, "reason")

        assert result == ApprovalDecision.ALLOW_ONCE

    @pytest.mark.asyncio
    async def test_telegram_send_failure_falls_through(self) -> None:
        """Telegram returns None (send failure) -> terminal wins by default."""
        mock_bot = MagicMock()
        mock_bot.is_paired = True
        mock_bot.request_approval = AsyncMock(return_value=None)

        handler = ApprovalHandler(timeout=5, telegram_bot=mock_bot)

        with (
            patch.object(handler, "_is_macos", True),
            patch.object(
                handler,
                "_show_dialog",
                new_callable=AsyncMock,
                return_value=ApprovalDecision.ALLOW_ONCE,
            ),
        ):
            result = await handler.request_approval("tool", {}, "reason")

        assert result == ApprovalDecision.ALLOW_ONCE

    @pytest.mark.asyncio
    async def test_unpaired_telegram_ignored(self) -> None:
        """Unpaired Telegram bot -> terminal only."""
        mock_bot = MagicMock()
        mock_bot.is_paired = False

        handler = ApprovalHandler(timeout=5, telegram_bot=mock_bot)

        with (
            patch.object(handler, "_is_macos", True),
            patch.object(
                handler,
                "_show_dialog",
                new_callable=AsyncMock,
                return_value=ApprovalDecision.DENY,
            ),
        ):
            result = await handler.request_approval("tool", {}, "reason")

        assert result == ApprovalDecision.DENY
        # Telegram should not have been called
        mock_bot.request_approval.assert_not_called()


# -----------------------------------------------------------------------
# Setup: Telegram proxy patching
# -----------------------------------------------------------------------


class TestTelegramProxySetup:
    """Tests for setup.py Telegram proxy patching."""

    def test_patch_adds_proxy_to_config(self, tmp_path: Path) -> None:
        from agentward.setup import _patch_telegram_proxy

        config: dict[str, Any] = {
            "channels": {"telegram": {"enabled": True, "botToken": "tok"}},
        }
        sidecar: dict[str, Any] = {}
        original = _patch_telegram_proxy(config, sidecar)
        assert config["channels"]["telegram"]["proxy"] == "http://127.0.0.1:18901"
        assert original is None  # was not set before

    def test_patch_preserves_existing_proxy(self, tmp_path: Path) -> None:
        from agentward.setup import _patch_telegram_proxy

        config: dict[str, Any] = {
            "channels": {
                "telegram": {
                    "enabled": True,
                    "botToken": "tok",
                    "proxy": "http://existing:8080",
                },
            },
        }
        sidecar: dict[str, Any] = {}
        original = _patch_telegram_proxy(config, sidecar)
        assert original == "http://existing:8080"
        assert config["channels"]["telegram"]["proxy"] == "http://127.0.0.1:18901"

    def test_patch_skips_when_telegram_disabled(self) -> None:
        from agentward.setup import _patch_telegram_proxy

        config: dict[str, Any] = {
            "channels": {"telegram": {"enabled": False, "botToken": "tok"}},
        }
        sidecar: dict[str, Any] = {}
        result = _patch_telegram_proxy(config, sidecar)
        assert result is None
        assert "proxy" not in config["channels"]["telegram"]

    def test_patch_skips_when_no_bot_token(self) -> None:
        from agentward.setup import _patch_telegram_proxy

        config: dict[str, Any] = {
            "channels": {"telegram": {"enabled": True}},
        }
        sidecar: dict[str, Any] = {}
        result = _patch_telegram_proxy(config, sidecar)
        assert result is None

    def test_restore_removes_proxy(self) -> None:
        from agentward.setup import _restore_telegram_proxy

        config: dict[str, Any] = {
            "channels": {
                "telegram": {
                    "enabled": True,
                    "botToken": "tok",
                    "proxy": "http://127.0.0.1:18901",
                },
            },
        }
        _restore_telegram_proxy(config, None)
        assert "proxy" not in config["channels"]["telegram"]

    def test_restore_sets_original_proxy(self) -> None:
        from agentward.setup import _restore_telegram_proxy

        config: dict[str, Any] = {
            "channels": {
                "telegram": {
                    "enabled": True,
                    "botToken": "tok",
                    "proxy": "http://127.0.0.1:18901",
                },
            },
        }
        _restore_telegram_proxy(config, "http://original:8080")
        assert config["channels"]["telegram"]["proxy"] == "http://original:8080"

    def test_get_telegram_proxy_port_from_sidecar(self, tmp_path: Path) -> None:
        from agentward.setup import get_clawdbot_telegram_proxy_port

        config = tmp_path / "clawdbot.json"
        config.write_text("{}")
        sidecar = tmp_path / ".agentward-gateway.json"
        sidecar.write_text(json.dumps({
            "original_port": 18789,
            "telegram_proxy_port": 18901,
        }))
        result = get_clawdbot_telegram_proxy_port(config)
        assert result == 18901

    def test_get_telegram_proxy_port_none_without_sidecar(self, tmp_path: Path) -> None:
        from agentward.setup import get_clawdbot_telegram_proxy_port

        config = tmp_path / "clawdbot.json"
        config.write_text("{}")
        result = get_clawdbot_telegram_proxy_port(config)
        assert result is None
