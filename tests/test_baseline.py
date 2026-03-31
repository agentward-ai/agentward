"""Tests for behavioral baseline tracking and anomaly detection."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from agentward.baseline import (
    AnomalyDetail,
    AnomalyDetector,
    AnomalyResult,
    BaselineTracker,
    ServerBaseline,
    ToolBaseline,
)
from agentward.baseline.tracker import (
    BaselineTracker,
    _baseline_from_dict,
    _baseline_to_dict,
)


# ---------------------------------------------------------------------------
# TestArgumentClassification
# ---------------------------------------------------------------------------


class TestArgumentClassification:
    def test_file_path_unix_absolute(self) -> None:
        assert BaselineTracker._classify_arg_value("/etc/passwd") == "file_path"

    def test_file_path_tilde(self) -> None:
        assert BaselineTracker._classify_arg_value("~/documents") == "file_path"

    def test_file_path_windows(self) -> None:
        assert BaselineTracker._classify_arg_value("C:\\Users\\foo") == "file_path"

    def test_url_http(self) -> None:
        assert BaselineTracker._classify_arg_value("http://example.com") == "url"

    def test_url_https(self) -> None:
        assert BaselineTracker._classify_arg_value("https://api.github.com") == "url"

    def test_url_ftp(self) -> None:
        assert BaselineTracker._classify_arg_value("ftp://files.example.com") == "url"

    def test_ip_address_v4(self) -> None:
        assert BaselineTracker._classify_arg_value("192.168.1.1") == "ip_address"

    def test_email(self) -> None:
        assert BaselineTracker._classify_arg_value("user@example.com") == "email"

    def test_numeric_int(self) -> None:
        assert BaselineTracker._classify_arg_value(42) == "numeric"

    def test_numeric_float(self) -> None:
        assert BaselineTracker._classify_arg_value(3.14) == "numeric"

    def test_boolean_true(self) -> None:
        assert BaselineTracker._classify_arg_value(True) == "boolean"

    def test_boolean_false(self) -> None:
        assert BaselineTracker._classify_arg_value(False) == "boolean"

    def test_json_string_object(self) -> None:
        assert BaselineTracker._classify_arg_value('{"key": "value"}') == "json_string"

    def test_json_string_array(self) -> None:
        assert BaselineTracker._classify_arg_value('[1, 2, 3]') == "json_string"

    def test_short_string(self) -> None:
        assert BaselineTracker._classify_arg_value("hello world") == "short_string"

    def test_long_string(self) -> None:
        assert BaselineTracker._classify_arg_value("x" * 101) == "long_string"

    def test_empty_string(self) -> None:
        assert BaselineTracker._classify_arg_value("") == "empty"

    def test_none_value(self) -> None:
        assert BaselineTracker._classify_arg_value(None) == "empty"

    def test_dict_value(self) -> None:
        result = BaselineTracker._classify_arg_value({"key": "val"})
        assert result == "json_string"


# ---------------------------------------------------------------------------
# TestBaselineTracker
# ---------------------------------------------------------------------------


class TestBaselineTracker:
    def test_record_call_adds_to_baseline(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        baseline = tracker.get_baseline("myserver")
        assert baseline is not None
        assert baseline.total_calls == 1

    def test_record_multiple_calls(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        for _ in range(5):
            tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        baseline = tracker.get_baseline("myserver")
        assert baseline.total_calls == 5

    def test_record_call_creates_tool_baseline(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        baseline = tracker.get_baseline("myserver")
        assert "read_file" in baseline.tools

    def test_tool_call_count_incremented(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/a"})
        tracker.record_call("myserver", "read_file", {"path": "/tmp/b"})
        baseline = tracker.get_baseline("myserver")
        assert baseline.tools["read_file"].call_count == 2

    def test_arg_patterns_tracked(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        baseline = tracker.get_baseline("myserver")
        dist = baseline.tools["read_file"].arg_pattern_distributions
        assert "path" in dist
        assert "file_path" in dist["path"]

    def test_hourly_distribution_tracked(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        baseline = tracker.get_baseline("myserver")
        assert len(baseline.tools["read_file"].hourly_distribution) > 0

    def test_arg_name_sets_tracked(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test", "encoding": "utf-8"})
        baseline = tracker.get_baseline("myserver")
        tb = baseline.tools["read_file"]
        sets = tb.get_frozensets()
        assert frozenset({"path", "encoding"}) in sets

    def test_none_arguments_handled(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "ping", None)
        baseline = tracker.get_baseline("myserver")
        assert baseline.tools["ping"].call_count == 1

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        path = tracker.save_baseline("myserver")
        assert path.exists()
        loaded = tracker.load_baseline("myserver")
        assert loaded is not None
        assert loaded.total_calls == 1

    def test_load_nonexistent_returns_none(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        assert tracker.load_baseline("nonexistent") is None

    def test_clear_baseline_removes_file(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp"})
        tracker.save_baseline("myserver")
        tracker.clear_baseline("myserver")
        assert tracker.load_baseline("myserver") is None

    def test_list_baselines_returns_saved(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("server1", "tool1", {})
        tracker.record_call("server2", "tool2", {})
        tracker.save_baseline("server1")
        tracker.save_baseline("server2")
        names = tracker.list_baselines()
        assert "server1" in names
        assert "server2" in names

    def test_list_baselines_empty_when_none_saved(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        assert tracker.list_baselines() == []

    def test_get_baseline_falls_back_to_disk(self, tmp_path: Path) -> None:
        tracker1 = BaselineTracker(storage_dir=tmp_path)
        tracker1.record_call("myserver", "tool", {"x": 1})
        tracker1.save_baseline("myserver")
        # New tracker instance — no in-memory data
        tracker2 = BaselineTracker(storage_dir=tmp_path)
        baseline = tracker2.get_baseline("myserver")
        assert baseline is not None
        assert baseline.total_calls == 1

    def test_multiple_tools_tracked(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "tool_a", {"x": 1})
        tracker.record_call("myserver", "tool_b", {"y": "hello"})
        baseline = tracker.get_baseline("myserver")
        assert "tool_a" in baseline.tools
        assert "tool_b" in baseline.tools


# ---------------------------------------------------------------------------
# TestAnomalyDetector
# ---------------------------------------------------------------------------


class TestAnomalyDetector:
    def test_no_baseline_returns_zero_score(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        detector = AnomalyDetector(tracker)
        result = detector.score("unknown_server", "some_tool", {})
        assert result.score == 0.0
        assert not result.baseline_exists

    def test_no_baseline_not_anomalous(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        detector = AnomalyDetector(tracker)
        result = detector.score("unknown_server", "some_tool", {})
        assert not result.is_anomalous

    def test_known_tool_known_args_low_score(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        # Build a baseline with many calls
        for _ in range(10):
            tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "read_file", {"path": "/tmp/other"})
        assert result.baseline_exists
        # Same arg name and same pattern (file_path) — should be low anomaly
        assert result.score < 0.3

    def test_new_tool_gives_high_score(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "totally_new_tool", {"x": 1})
        assert result.score >= 0.8

    def test_new_tool_flagged_as_anomalous(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "rm_rf", {})
        assert result.is_anomalous

    def test_new_arg_name_increases_score(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "read_file", {"path": "/tmp/x", "new_arg": "val"})
        assert result.score > 0.0

    def test_new_arg_pattern_increases_score(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        # Baseline: path is always a file_path
        for _ in range(5):
            tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        # Now call with URL in path — pattern drift
        result = detector.score("myserver", "read_file", {"path": "http://evil.com/thing"})
        # "path" seen before but as file_path; now it's url → anomaly
        assert result.score > 0.0

    def test_time_anomaly_outside_normal_hours(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        # Set hourly distribution to only contain hour 9
        baseline = tracker.get_baseline("myserver")
        baseline.tools["read_file"].hourly_distribution = {9: 10}
        # Score at hour 3 (unusual)
        unusual_ts = _timestamp_at_hour(3)
        result = detector.score("myserver", "read_file", {"path": "/tmp/x"}, timestamp=unusual_ts)
        assert any(d.type == "time_anomaly" for d in result.details)

    def test_time_anomaly_within_normal_hours_no_flag(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        baseline = tracker.get_baseline("myserver")
        # Set hour 9 as normal
        baseline.tools["read_file"].hourly_distribution = {9: 10}
        ts = _timestamp_at_hour(9)
        result = detector.score("myserver", "read_file", {"path": "/tmp/x"}, timestamp=ts)
        assert not any(d.type == "time_anomaly" for d in result.details)

    def test_score_clamped_to_1(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "known_tool", {"x": 1})
        detector = AnomalyDetector(tracker)
        # Score for a new tool should be at most 1.0
        result = detector.score("myserver", "evil_new_tool", {"a": "b", "c": "d", "e": "f"})
        assert result.score <= 1.0

    def test_anomaly_details_populated(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "evil_tool", {})
        assert len(result.details) > 0

    def test_new_tool_detail_type(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "evil_tool", {})
        assert any(d.type == "new_tool" for d in result.details)

    def test_warn_threshold_respected(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker, warn_threshold=0.5)
        result = detector.score("myserver", "new_tool", {})
        # new_tool score = 0.8 >= 0.5 → anomalous
        assert result.is_anomalous

    def test_block_threshold_accessible(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        detector = AnomalyDetector(tracker, block_threshold=0.9)
        assert detector.block_threshold == 0.9

    def test_clean_normal_call_not_anomalous(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        for _ in range(20):
            tracker.record_call("myserver", "query", {"sql": "SELECT 1"})
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "query", {"sql": "SELECT 2"})
        # Same tool, same arg name (sql), same pattern (short_string), same-ish hour
        assert result.score < 0.5  # Might have minor time anomaly but overall low

    def test_no_args_baseline_with_no_args(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "ping", None)
        detector = AnomalyDetector(tracker)
        result = detector.score("myserver", "ping", None)
        # Known tool, no args — should be normal
        assert result.baseline_exists
        assert result.score < 0.5

    def test_multiple_new_args_score_capped(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("myserver", "read_file", {"path": "/tmp/test"})
        detector = AnomalyDetector(tracker)
        # 5 new args — score contribution capped at 0.8
        new_args = {f"arg{i}": "val" for i in range(5)}
        new_args["path"] = "/tmp/x"  # known arg
        result = detector.score("myserver", "read_file", new_args)
        # new arg contribution = min(0.8, 5*0.4)=0.8 plus possible time anomaly
        assert result.score <= 1.0

    def test_arg_value_drift_detail(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        for _ in range(5):
            tracker.record_call("myserver", "fetch", {"url": "https://api.com"})
        detector = AnomalyDetector(tracker)
        # url arg now has a file_path — different pattern
        result = detector.score("myserver", "fetch", {"url": "/etc/passwd"})
        assert any(d.type == "arg_value_drift" for d in result.details)


# ---------------------------------------------------------------------------
# TestBaselinePersistence
# ---------------------------------------------------------------------------


class TestBaselinePersistence:
    def test_save_creates_json_file(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("srv", "tool", {"x": "hello"})
        path = tracker.save_baseline("srv")
        assert path.suffix == ".json"
        assert path.exists()

    def test_saved_json_is_valid(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("srv", "tool", {"x": "hello"})
        path = tracker.save_baseline("srv")
        data = json.loads(path.read_text())
        assert data["server_name"] == "srv"
        assert data["total_calls"] == 1

    def test_load_from_disk_correct_calls(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("srv", "tool", {"x": "hello"})
        tracker.record_call("srv", "tool", {"x": "world"})
        tracker.save_baseline("srv")
        tracker2 = BaselineTracker(storage_dir=tmp_path)
        bl = tracker2.load_baseline("srv")
        assert bl.total_calls == 2

    def test_roundtrip_preserves_tool_data(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("srv", "read_file", {"path": "/tmp/a"})
        tracker.save_baseline("srv")
        bl = tracker.load_baseline("srv")
        assert "read_file" in bl.tools
        assert bl.tools["read_file"].call_count == 1

    def test_baseline_to_dict_roundtrip(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("srv", "t", {"a": "b"})
        baseline = tracker.get_baseline("srv")
        d = _baseline_to_dict(baseline)
        restored = _baseline_from_dict(d)
        assert restored.server_name == "srv"
        assert restored.total_calls == 1

    def test_clear_also_removes_in_memory(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("srv", "tool", {})
        tracker.save_baseline("srv")
        tracker.clear_baseline("srv")
        # In-memory should also be gone
        assert "srv" not in tracker._baselines

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        deep = tmp_path / "a" / "b" / "c"
        tracker = BaselineTracker(storage_dir=deep)
        tracker.record_call("srv", "tool", {})
        path = tracker.save_baseline("srv")
        assert path.exists()

    def test_corrupted_json_returns_none(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text("{ invalid json }", encoding="utf-8")
        tracker = BaselineTracker(storage_dir=tmp_path)
        bl = tracker.load_baseline("broken")
        assert bl is None

    def test_list_baselines_sorted(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        for name in ["zebra", "alpha", "middle"]:
            tracker.record_call(name, "t", {})
            tracker.save_baseline(name)
        names = tracker.list_baselines()
        assert names == sorted(names)

    def test_version_field_saved(self, tmp_path: Path) -> None:
        tracker = BaselineTracker(storage_dir=tmp_path)
        tracker.record_call("srv", "t", {})
        path = tracker.save_baseline("srv")
        data = json.loads(path.read_text())
        assert data["version"] == "1.0"


# ---------------------------------------------------------------------------
# TestBaselineCLI
# ---------------------------------------------------------------------------


class TestBaselineCLI:
    def test_baseline_list_empty(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        monkeypatch.chdir(tmp_path)
        runner = CliRunner()
        result = runner.invoke(app, ["baseline", "list"])
        assert result.exit_code == 0

    def test_baseline_reset_nonexistent(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app
        from agentward.baseline import BaselineTracker

        runner = CliRunner()
        # Resetting a non-existent baseline should not crash
        result = runner.invoke(app, ["baseline", "reset", "nonexistent-server-xyz"])
        assert result.exit_code == 0

    def test_baseline_show_not_found(self) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["baseline", "show", "nonexistent-server-xyz"])
        assert result.exit_code == 1

    def test_baseline_check_no_baseline(self) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["baseline", "check", "nonexistent-server-xyz", "--tool", "foo"])
        assert result.exit_code == 0

    def test_schema_has_baseline_fields(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy.model_validate({"version": "1.0"})
        assert hasattr(policy, "baseline_check")
        assert hasattr(policy, "baseline_warn_threshold")
        assert hasattr(policy, "baseline_block_threshold")
        assert policy.baseline_check is False
        assert policy.baseline_warn_threshold == 0.3
        assert policy.baseline_block_threshold == 0.8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _timestamp_at_hour(hour: int) -> float:
    """Return a Unix timestamp for today at the given UTC hour."""
    from datetime import datetime, timezone

    now = datetime.now(tz=timezone.utc)
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    return target.timestamp()
