"""Tests for agentward status module.

Covers:
  - Proxy process detection from PID files
  - Audit log reading for current session stats
  - Edge cases (no PID files, stale PID, no audit log, empty log)
  - Duration formatting
  - Status rendering (smoke tests)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from rich.console import Console

from agentward.status import (
    ProxyInfo,
    ProxyStatus,
    _format_duration,
    _is_process_alive,
    _read_current_session_stats,
    find_running_proxies,
    get_status,
    render_status,
)


# ---------------------------------------------------------------------------
# _format_duration
# ---------------------------------------------------------------------------


class TestFormatDuration:
    def test_seconds(self) -> None:
        assert _format_duration(42) == "42s"

    def test_minutes(self) -> None:
        assert _format_duration(130) == "2m 10s"

    def test_hours(self) -> None:
        assert _format_duration(3700) == "1h 1m"

    def test_zero(self) -> None:
        assert _format_duration(0) == "0s"

    def test_just_under_minute(self) -> None:
        assert _format_duration(59) == "59s"

    def test_exactly_one_hour(self) -> None:
        assert _format_duration(3600) == "1h 0m"


# ---------------------------------------------------------------------------
# _is_process_alive
# ---------------------------------------------------------------------------


class TestIsProcessAlive:
    def test_current_process_alive(self) -> None:
        assert _is_process_alive(os.getpid()) is True

    def test_nonexistent_pid(self) -> None:
        # PID 99999999 is almost certainly not running
        assert _is_process_alive(99999999) is False


# ---------------------------------------------------------------------------
# find_running_proxies
# ---------------------------------------------------------------------------


class TestFindRunningProxies:
    def test_no_agentward_dir(self, tmp_path: Path) -> None:
        with patch("agentward.status._AGENTWARD_DIR", tmp_path / "nonexistent"):
            result = find_running_proxies()
        assert result == []

    def test_empty_dir(self, tmp_path: Path) -> None:
        with patch("agentward.status._AGENTWARD_DIR", tmp_path):
            result = find_running_proxies()
        assert result == []

    def test_detects_pid_file(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "proxy-18789.pid"
        pid_file.write_text(str(os.getpid()))

        with patch("agentward.status._AGENTWARD_DIR", tmp_path):
            result = find_running_proxies()

        assert len(result) == 1
        assert result[0].port == 18789
        assert result[0].pid == os.getpid()
        assert result[0].alive is True

    def test_stale_pid(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "proxy-18789.pid"
        pid_file.write_text("99999999")

        with patch("agentward.status._AGENTWARD_DIR", tmp_path):
            result = find_running_proxies()

        assert len(result) == 1
        assert result[0].alive is False

    def test_multiple_pid_files(self, tmp_path: Path) -> None:
        (tmp_path / "proxy-18789.pid").write_text(str(os.getpid()))
        (tmp_path / "proxy-18900.pid").write_text("99999999")

        with patch("agentward.status._AGENTWARD_DIR", tmp_path):
            result = find_running_proxies()

        assert len(result) == 2
        ports = [p.port for p in result]
        assert 18789 in ports
        assert 18900 in ports

    def test_invalid_pid_file_content(self, tmp_path: Path) -> None:
        (tmp_path / "proxy-18789.pid").write_text("not-a-pid")

        with patch("agentward.status._AGENTWARD_DIR", tmp_path):
            result = find_running_proxies()

        assert result == []

    def test_malformed_filename(self, tmp_path: Path) -> None:
        (tmp_path / "proxy-.pid").write_text("12345")

        with patch("agentward.status._AGENTWARD_DIR", tmp_path):
            result = find_running_proxies()

        assert result == []

    def test_non_pid_files_ignored(self, tmp_path: Path) -> None:
        (tmp_path / "something-else.json").write_text("{}")

        with patch("agentward.status._AGENTWARD_DIR", tmp_path):
            result = find_running_proxies()

        assert result == []


# ---------------------------------------------------------------------------
# _read_current_session_stats
# ---------------------------------------------------------------------------


def _make_log(*entries: dict) -> str:
    """Create a JSON Lines string from entries."""
    return "\n".join(json.dumps(e) for e in entries)


class TestReadCurrentSessionStats:
    def test_nonexistent_file(self, tmp_path: Path) -> None:
        result = _read_current_session_stats(tmp_path / "nope.jsonl")
        assert result == {}

    def test_empty_file(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text("")
        result = _read_current_session_stats(log)
        assert result == {}

    def test_single_tool_call(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {
                "event": "tool_call",
                "tool": "browser",
                "decision": "ALLOW",
                "timestamp": "2026-02-24T10:00:05+00:00",
            },
        ))
        result = _read_current_session_stats(log)
        assert result["total_calls"] == 1
        assert result["decisions"] == {"ALLOW": 1}

    def test_only_counts_current_session(self, tmp_path: Path) -> None:
        """Old session events should not be counted."""
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            # Old session
            {"event": "startup", "timestamp": "2026-02-24T08:00:00+00:00"},
            {"event": "tool_call", "tool": "old_tool", "decision": "BLOCK", "timestamp": "2026-02-24T08:00:01+00:00"},
            {"event": "tool_call", "tool": "old_tool", "decision": "BLOCK", "timestamp": "2026-02-24T08:00:02+00:00"},
            # Current session
            {"event": "http_proxy_startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {"event": "tool_call", "tool": "browser", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:05+00:00"},
        ))
        result = _read_current_session_stats(log)
        assert result["total_calls"] == 1
        assert result["decisions"] == {"ALLOW": 1}
        assert result["blocked_tools"] == {}

    def test_blocked_tools(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {"event": "tool_call", "tool": "shell", "decision": "BLOCK", "timestamp": "2026-02-24T10:00:01+00:00"},
            {"event": "tool_call", "tool": "shell", "decision": "BLOCK", "timestamp": "2026-02-24T10:00:02+00:00"},
            {"event": "tool_call", "tool": "browser", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:03+00:00"},
        ))
        result = _read_current_session_stats(log)
        assert result["total_calls"] == 3
        assert result["blocked_tools"] == {"shell": 2}
        assert result["decisions"]["BLOCK"] == 2
        assert result["decisions"]["ALLOW"] == 1

    def test_chain_violations(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {
                "event": "tool_call",
                "tool": "email_send",
                "decision": "BLOCK",
                "chain_violation": True,
                "timestamp": "2026-02-24T10:00:01+00:00",
            },
        ))
        result = _read_current_session_stats(log)
        assert result["chain_violations"] == 1

    def test_dry_run_count(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {"event": "tool_call", "tool": "x", "decision": "BLOCK", "dry_run": True, "timestamp": "2026-02-24T10:00:01+00:00"},
            {"event": "tool_call", "tool": "y", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:02+00:00"},
        ))
        result = _read_current_session_stats(log)
        assert result["dry_run_count"] == 1

    def test_approval_and_sensitive_events(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {"event": "approval_dialog", "tool": "gmail_send", "timestamp": "2026-02-24T10:00:01+00:00"},
            {"event": "sensitive_data_blocked", "tool": "api", "timestamp": "2026-02-24T10:00:02+00:00"},
        ))
        result = _read_current_session_stats(log)
        assert result["approvals"] == 1
        assert result["sensitive_blocks"] == 1

    def test_timestamps_tracked(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {"event": "tool_call", "tool": "a", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:05+00:00"},
            {"event": "tool_call", "tool": "b", "decision": "ALLOW", "timestamp": "2026-02-24T10:30:00+00:00"},
        ))
        result = _read_current_session_stats(log)
        assert result["session_start"] == "2026-02-24T10:00:00+00:00"
        assert result["last_event"] == "2026-02-24T10:30:00+00:00"

    def test_malformed_json_lines_skipped(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(
            '{"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"}\n'
            "not valid json\n"
            '{"event": "tool_call", "tool": "x", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:01+00:00"}\n'
        )
        result = _read_current_session_stats(log)
        assert result["total_calls"] == 1

    def test_no_startup_counts_all(self, tmp_path: Path) -> None:
        """Log with no startup event should count all entries."""
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "tool_call", "tool": "a", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:01+00:00"},
            {"event": "tool_call", "tool": "b", "decision": "BLOCK", "timestamp": "2026-02-24T10:00:02+00:00"},
        ))
        result = _read_current_session_stats(log)
        assert result["total_calls"] == 2

    def test_llm_proxy_startup_recognized(self, tmp_path: Path) -> None:
        """llm_proxy_startup is also a session boundary."""
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "tool_call", "tool": "old", "decision": "ALLOW", "timestamp": "2026-02-24T08:00:00+00:00"},
            {"event": "llm_proxy_startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {"event": "tool_call", "tool": "new", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:01+00:00"},
        ))
        result = _read_current_session_stats(log)
        assert result["total_calls"] == 1


# ---------------------------------------------------------------------------
# get_status
# ---------------------------------------------------------------------------


class TestGetStatus:
    def test_no_audit_log(self, tmp_path: Path) -> None:
        status = get_status(audit_log=tmp_path / "nonexistent.jsonl")
        assert status.audit_exists is False
        assert status.total_calls == 0

    def test_with_audit_log(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
            {"event": "tool_call", "tool": "x", "decision": "ALLOW", "timestamp": "2026-02-24T10:00:01+00:00"},
        ))
        status = get_status(audit_log=log)
        assert status.audit_exists is True
        assert status.total_calls == 1
        assert status.decisions == {"ALLOW": 1}

    def test_uptime_computed(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        log.write_text(_make_log(
            {"event": "startup", "timestamp": "2026-02-24T10:00:00+00:00"},
        ))
        status = get_status(audit_log=log)
        assert status.uptime_seconds is not None
        assert status.uptime_seconds > 0


# ---------------------------------------------------------------------------
# render_status (smoke tests)
# ---------------------------------------------------------------------------


class TestRenderStatus:
    def _capture(self, status: ProxyStatus) -> str:
        console = Console(file=None, force_terminal=False, no_color=True, width=100)
        with console.capture() as cap:
            render_status(status, console)
        return cap.get()

    def test_no_proxy_no_audit(self) -> None:
        output = self._capture(ProxyStatus())
        assert "No proxy detected" in output
        assert "No audit log found" in output

    def test_running_proxy(self) -> None:
        status = ProxyStatus(
            proxies=[ProxyInfo(port=18789, pid=12345, alive=True, pid_file=Path("/tmp/x"))],
        )
        output = self._capture(status)
        assert "18789" in output
        assert "12345" in output

    def test_stale_proxy(self) -> None:
        status = ProxyStatus(
            proxies=[ProxyInfo(port=18789, pid=99999, alive=False, pid_file=Path("/tmp/x"))],
        )
        output = self._capture(status)
        assert "not running" in output

    def test_with_tool_calls(self) -> None:
        status = ProxyStatus(
            audit_exists=True,
            total_calls=10,
            decisions={"ALLOW": 8, "BLOCK": 2},
            blocked_tools={"shell": 2},
            session_start="2026-02-24T10:00:00+00:00",
            last_event="2026-02-24T10:30:00+00:00",
            uptime_seconds=1800,
        )
        output = self._capture(status)
        assert "ALLOW" in output
        assert "BLOCK" in output
        assert "shell" in output
        assert "Total: 10" in output

    def test_with_chain_violations(self) -> None:
        status = ProxyStatus(
            audit_exists=True,
            total_calls=5,
            decisions={"BLOCK": 5},
            chain_violations=3,
        )
        output = self._capture(status)
        assert "Chain violations: 3" in output

    def test_with_dry_run(self) -> None:
        status = ProxyStatus(
            audit_exists=True,
            total_calls=5,
            decisions={"ALLOW": 5},
            dry_run_count=5,
        )
        output = self._capture(status)
        assert "dry-run" in output

    def test_audit_exists_but_no_calls(self) -> None:
        status = ProxyStatus(audit_exists=True)
        output = self._capture(status)
        assert "No tool calls" in output
