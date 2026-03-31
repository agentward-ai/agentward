"""Behavioral baseline tracker — records tool calls and builds baselines."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentward.baseline.models import (
    ArgumentPattern,
    ServerBaseline,
    ToolBaseline,
    ToolCallRecord,
)

_DEFAULT_STORAGE = Path.home() / ".agentward" / "baselines"

# Patterns for argument classification
_URL_RE = re.compile(r"^(?:https?|ftp)://", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]{2,39}(?::[0-9a-fA-F]{1,4})*$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_FILE_PATH_RE = re.compile(r"^(?:/|~|[A-Za-z]:\\)")


class BaselineTracker:
    """Records tool calls and builds behavioral baselines per server.

    Baselines are stored as JSON files in ``~/.agentward/baselines/<name>.json``.
    In-memory records are accumulated and merged on :meth:`save_baseline`.

    Args:
        storage_dir: Directory to store baseline files.
                     Defaults to ``~/.agentward/baselines/``.
    """

    def __init__(self, storage_dir: Path | None = None) -> None:
        self._storage_dir = storage_dir or _DEFAULT_STORAGE
        # In-memory records: server_name → list of ToolCallRecord
        self._records: dict[str, list[ToolCallRecord]] = {}
        # In-memory baselines (merged from records + loaded from disk)
        self._baselines: dict[str, ServerBaseline] = {}

    def record_call(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any] | None,
    ) -> None:
        """Record a tool call to the in-memory buffer.

        Extracts argument names and classifies each value into a pattern type.

        Args:
            server_name: The MCP server name.
            tool_name: The tool name.
            arguments: The tool call arguments dict (may be None).
        """
        args = arguments or {}
        arg_names = list(args.keys())
        arg_patterns: dict[str, ArgumentPattern] = {
            name: self._classify_arg_value(val) for name, val in args.items()
        }

        now = datetime.now(tz=timezone.utc)
        record = ToolCallRecord(
            server_name=server_name,
            tool_name=tool_name,
            arg_names=arg_names,
            arg_patterns=arg_patterns,
            timestamp=time.time(),
            hour_of_day=now.hour,
            day_of_week=now.weekday(),  # 0=Monday
        )

        self._records.setdefault(server_name, []).append(record)
        # Update in-memory baseline immediately
        self._update_baseline_from_record(server_name, record)

    def _update_baseline_from_record(
        self, server_name: str, record: ToolCallRecord
    ) -> None:
        """Merge a single record into the in-memory baseline."""
        if server_name not in self._baselines:
            self._baselines[server_name] = ServerBaseline(
                server_name=server_name,
                recorded_at=record.timestamp,
            )
        baseline = self._baselines[server_name]
        baseline.total_calls += 1

        tool_bl = baseline.tools.setdefault(
            record.tool_name, ToolBaseline(tool_name=record.tool_name)
        )
        tool_bl.call_count += 1

        # Track arg name sets (deduplicated by frozenset equality)
        arg_set = frozenset(record.arg_names)
        existing_sets = tool_bl.get_frozensets()
        if arg_set not in existing_sets:
            tool_bl.arg_name_sets.append(record.arg_names)

        # Update pattern distributions
        for arg_name, pattern in record.arg_patterns.items():
            dist = tool_bl.arg_pattern_distributions.setdefault(arg_name, {})
            dist[pattern] = dist.get(pattern, 0) + 1

        # Update time distributions
        tool_bl.hourly_distribution[record.hour_of_day] = (
            tool_bl.hourly_distribution.get(record.hour_of_day, 0) + 1
        )
        tool_bl.daily_distribution[record.day_of_week] = (
            tool_bl.daily_distribution.get(record.day_of_week, 0) + 1
        )

    def save_baseline(self, server_name: str) -> Path:
        """Flush in-memory baseline to disk as a JSON file.

        Creates the storage directory if it does not exist.

        Args:
            server_name: The server name to save.

        Returns:
            Path to the saved JSON file.
        """
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        path = self._storage_dir / f"{server_name}.json"

        baseline = self._baselines.get(server_name)
        if baseline is None:
            baseline = ServerBaseline(server_name=server_name, recorded_at=time.time())

        # Serialise to JSON-safe dict
        data = _baseline_to_dict(baseline)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def load_baseline(self, server_name: str) -> ServerBaseline | None:
        """Load a baseline from disk.

        Args:
            server_name: The server name to load.

        Returns:
            A :class:`ServerBaseline` or None if no file exists.
        """
        path = self._storage_dir / f"{server_name}.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return _baseline_from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def get_baseline(self, server_name: str) -> ServerBaseline | None:
        """Return in-memory baseline if available, otherwise load from disk.

        Args:
            server_name: The server name.

        Returns:
            A :class:`ServerBaseline` or None.
        """
        if server_name in self._baselines:
            return self._baselines[server_name]
        loaded = self.load_baseline(server_name)
        if loaded is not None:
            self._baselines[server_name] = loaded
        return loaded

    def clear_baseline(self, server_name: str) -> None:
        """Delete the baseline file and remove in-memory data.

        Args:
            server_name: The server name to clear.
        """
        path = self._storage_dir / f"{server_name}.json"
        if path.exists():
            path.unlink()
        self._baselines.pop(server_name, None)
        self._records.pop(server_name, None)

    def list_baselines(self) -> list[str]:
        """List all server names with saved baselines on disk.

        Returns:
            Sorted list of server names (without the ``.json`` extension).
        """
        if not self._storage_dir.exists():
            return []
        return sorted(p.stem for p in self._storage_dir.glob("*.json"))

    @staticmethod
    def _classify_arg_value(value: Any) -> ArgumentPattern:
        """Classify a single argument value into an :data:`ArgumentPattern`.

        Args:
            value: The argument value to classify.

        Returns:
            One of the :data:`ArgumentPattern` literals.
        """
        if value is None or value == "" or (isinstance(value, str) and not value.strip()):
            return "empty"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
            return "numeric"
        if isinstance(value, str):
            if _URL_RE.match(value):
                return "url"
            if _FILE_PATH_RE.match(value):
                return "file_path"
            if _IPV4_RE.match(value) or _IPV6_RE.match(value):
                return "ip_address"
            if _EMAIL_RE.match(value):
                return "email"
            # JSON object/array check
            stripped = value.strip()
            if (stripped.startswith("{") and stripped.endswith("}")) or (
                stripped.startswith("[") and stripped.endswith("]")
            ):
                try:
                    import json as _json
                    parsed = _json.loads(stripped)
                    if isinstance(parsed, (dict, list)):
                        return "json_string"
                except (ValueError, TypeError):
                    pass
            if len(value) > 100:
                return "long_string"
            return "short_string"
        # Fallback for other types (dict, list, etc.)
        return "json_string"


# ---------------------------------------------------------------------------
# JSON serialisation helpers
# ---------------------------------------------------------------------------


def _baseline_to_dict(baseline: ServerBaseline) -> dict:
    """Serialise a :class:`ServerBaseline` to a JSON-safe dict."""
    tools = {}
    for tool_name, tb in baseline.tools.items():
        tools[tool_name] = {
            "tool_name": tb.tool_name,
            "call_count": tb.call_count,
            "arg_name_sets": [list(s) for s in tb.arg_name_sets],
            "arg_pattern_distributions": tb.arg_pattern_distributions,
            "hourly_distribution": {str(k): v for k, v in tb.hourly_distribution.items()},
            "daily_distribution": {str(k): v for k, v in tb.daily_distribution.items()},
        }
    return {
        "server_name": baseline.server_name,
        "recorded_at": baseline.recorded_at,
        "total_calls": baseline.total_calls,
        "tools": tools,
        "version": baseline.version,
    }


def _baseline_from_dict(data: dict) -> ServerBaseline:
    """Deserialise a :class:`ServerBaseline` from a JSON dict."""
    tools: dict[str, ToolBaseline] = {}
    for tool_name, td in data.get("tools", {}).items():
        tb = ToolBaseline(
            tool_name=td["tool_name"],
            call_count=td.get("call_count", 0),
            arg_name_sets=td.get("arg_name_sets", []),
            arg_pattern_distributions=td.get("arg_pattern_distributions", {}),
            hourly_distribution={
                int(k): v for k, v in td.get("hourly_distribution", {}).items()
            },
            daily_distribution={
                int(k): v for k, v in td.get("daily_distribution", {}).items()
            },
        )
        tools[tool_name] = tb

    return ServerBaseline(
        server_name=data["server_name"],
        recorded_at=data.get("recorded_at", 0.0),
        total_calls=data.get("total_calls", 0),
        tools=tools,
        version=data.get("version", "1.0"),
    )
