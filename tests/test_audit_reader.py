"""Tests for the audit log reader and dashboard.

Covers:
  - Reading and parsing JSON Lines audit logs
  - Aggregation of statistics (decisions, tools, chain violations)
  - Filtering by decision, tool, and last N
  - Edge cases (empty file, malformed lines, missing file)
  - Dashboard rendering (smoke test — no assertion on output content)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from agentward.audit.reader import AuditStats, read_audit_log, render_dashboard


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_log(path: Path, entries: list[dict]) -> None:
    """Write a list of dicts as JSON Lines to a file."""
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry) + "\n")


def _sample_entries() -> list[dict]:
    """Return a realistic set of audit log entries."""
    return [
        {
            "timestamp": "2026-02-24T10:00:00+00:00",
            "event": "http_proxy_startup",
            "listen_port": 18789,
            "backend_url": "http://127.0.0.1:18790",
            "policy_path": "agentward.yaml",
            "mode": "enforce",
        },
        {
            "timestamp": "2026-02-24T10:00:01+00:00",
            "event": "tool_call",
            "tool": "gmail_read",
            "decision": "ALLOW",
            "reason": "Action 'read' allowed.",
            "skill": "email-manager",
            "resource": "gmail",
        },
        {
            "timestamp": "2026-02-24T10:00:02+00:00",
            "event": "tool_call",
            "tool": "gmail_send",
            "decision": "BLOCK",
            "reason": "Action 'send' is denied.",
            "skill": "email-manager",
            "resource": "gmail",
        },
        {
            "timestamp": "2026-02-24T10:00:03+00:00",
            "event": "tool_call",
            "tool": "gmail_read",
            "decision": "ALLOW",
            "reason": "Action 'read' allowed.",
            "skill": "email-manager",
            "resource": "gmail",
        },
        {
            "timestamp": "2026-02-24T10:00:04+00:00",
            "event": "tool_call",
            "tool": "browser_open",
            "decision": "BLOCK",
            "reason": "Chain blocked.",
            "skill": None,
            "resource": None,
            "chain_violation": True,
        },
        {
            "timestamp": "2026-02-24T10:00:05+00:00",
            "event": "tool_call",
            "tool": "shell_exec",
            "decision": "APPROVE",
            "reason": "Requires approval.",
            "skill": None,
            "resource": None,
        },
        {
            "timestamp": "2026-02-24T10:00:06+00:00",
            "event": "approval_dialog",
            "tool": "shell_exec",
            "decision": "allow_once",
            "elapsed_ms": 3200,
        },
        {
            "timestamp": "2026-02-24T10:00:07+00:00",
            "event": "tool_call",
            "tool": "gmail_draft",
            "decision": "ALLOW",
            "reason": "Allowed.",
            "skill": "email-manager",
            "resource": "gmail",
            "dry_run": True,
        },
        {
            "timestamp": "2026-02-24T10:00:08+00:00",
            "event": "shutdown",
            "reason": "Proxy stopped",
        },
    ]


# ---------------------------------------------------------------------------
# Reading and aggregation
# ---------------------------------------------------------------------------


class TestReadAuditLog:
    """Test reading and aggregating audit log files."""

    def test_basic_stats(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path)

        assert stats.total_events == 9
        assert stats.tool_calls == 6
        assert stats.sessions == 1
        assert stats.decisions["ALLOW"] == 3
        assert stats.decisions["BLOCK"] == 2
        assert stats.decisions["APPROVE"] == 1
        assert stats.chain_violations == 1
        assert stats.dry_run_count == 1
        assert stats.approvals == 1

    def test_tools_counter(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path)

        assert stats.tools["gmail_read"] == 2
        assert stats.tools["gmail_send"] == 1
        assert stats.tools["browser_open"] == 1

    def test_blocked_tools(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path)

        assert stats.blocked_tools["gmail_send"] == 1
        assert stats.blocked_tools["browser_open"] == 1
        assert "gmail_read" not in stats.blocked_tools

    def test_time_range(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path)

        assert stats.first_timestamp == "2026-02-24T10:00:00+00:00"
        assert stats.last_timestamp == "2026-02-24T10:00:08+00:00"


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


class TestFiltering:
    """Test decision, tool, and last-N filters."""

    def test_filter_by_decision(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path, decision_filter="BLOCK")

        # Only BLOCK tool_call events + non-tool-call events
        assert stats.decisions["BLOCK"] == 2
        assert "ALLOW" not in stats.decisions
        assert "APPROVE" not in stats.decisions

    def test_filter_by_decision_case_insensitive(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path, decision_filter="block")

        assert stats.decisions["BLOCK"] == 2

    def test_filter_by_tool(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path, tool_filter="gmail")

        # gmail_read x2, gmail_send, gmail_draft = 4 tool_call events
        assert stats.tool_calls == 4

    def test_filter_by_tool_substring(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path, tool_filter="browser")

        assert stats.tool_calls == 1
        assert stats.tools["browser_open"] == 1

    def test_last_n(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())

        stats = read_audit_log(log_path, last_n=3)

        # Last 3 lines: dry_run tool_call, shutdown, (and the one before)
        assert stats.total_events == 3


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases for the audit reader."""

    def test_empty_file(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("")

        stats = read_audit_log(log_path)

        assert stats.total_events == 0
        assert stats.tool_calls == 0

    def test_malformed_lines_skipped(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(
            'not json\n'
            '{"event": "tool_call", "tool": "test", "decision": "ALLOW", "timestamp": "2026-01-01T00:00:00Z"}\n'
            'also not json\n'
        )

        stats = read_audit_log(log_path)

        assert stats.total_events == 1
        assert stats.tool_calls == 1

    def test_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="Audit log not found"):
            read_audit_log(tmp_path / "nonexistent.jsonl")

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(
            '\n\n'
            '{"event": "tool_call", "tool": "test", "decision": "ALLOW", "timestamp": "2026-01-01T00:00:00Z"}\n'
            '\n'
        )

        stats = read_audit_log(log_path)

        assert stats.total_events == 1


# ---------------------------------------------------------------------------
# Dashboard rendering (smoke test)
# ---------------------------------------------------------------------------


class TestRenderDashboard:
    """Smoke tests for dashboard rendering — verifies no crashes."""

    def test_render_with_stats(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())
        stats = read_audit_log(log_path)

        console = Console(file=open(tmp_path / "output.txt", "w"), width=120)
        render_dashboard(stats, console)
        console.file.close()

        output = (tmp_path / "output.txt").read_text()
        assert "Audit Summary" in output
        assert "Decisions" in output

    def test_render_with_timeline(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        _write_log(log_path, _sample_entries())
        stats = read_audit_log(log_path)

        console = Console(file=open(tmp_path / "output.txt", "w"), width=120)
        render_dashboard(stats, console, show_timeline=True)
        console.file.close()

        output = (tmp_path / "output.txt").read_text()
        assert "Event Timeline" in output

    def test_render_empty_stats(self, tmp_path: Path) -> None:
        stats = AuditStats()

        console = Console(file=open(tmp_path / "output.txt", "w"), width=120)
        render_dashboard(stats, console)
        console.file.close()

        output = (tmp_path / "output.txt").read_text()
        assert "No events found" in output
