"""Runtime data boundary enforcement via taint tracking.

Tracks tool response content from skills in data boundary zones and
blocks cross-zone data flow when tainted content appears in subsequent
tool call arguments.

Design:
  Phase 1 — Taint on response: When a tool from a boundary zone skill
            returns a response, extract content and mark the session
            as tainted with that zone's classification.
  Phase 2 — Check on call: When a subsequent tool call targets a skill
            NOT in the same zone, check if tainted content appears in
            the arguments. Block per the zone's on_violation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    PolicyDecision,
    ViolationAction,
)
from agentward.proxy.content import ExtractedContent, extract_content


@dataclass
class TaintEntry:
    """A record of tainted content from a data boundary zone response."""

    zone_name: str
    classification: str
    skill_name: str
    tool_name: str
    extracted: ExtractedContent
    text_snippets: list[str]
    on_violation: ViolationAction


# Minimum snippet length to match — prevents false positives on common words.
_MIN_SNIPPET_LENGTH = 20

# Maximum text fields to extract snippets from per response.
_MAX_TEXT_FIELDS = 10


class BoundaryEnforcer:
    """Runtime data boundary enforcement via session-level taint tracking.

    Created at proxy startup from `policy.data_boundaries`. Passed to
    both StdioProxy and HttpProxy alongside the ChainTracker.

    Args:
        policy: The loaded AgentWard policy.
        policy_engine: For skill name resolution.
        max_taint_entries: Bound on taint entries to prevent unbounded memory.
        snippet_max_length: Maximum characters extracted per text field.
    """

    def __init__(
        self,
        policy: AgentWardPolicy,
        policy_engine: PolicyEngine,
        max_taint_entries: int = 200,
        snippet_max_length: int = 100,
    ) -> None:
        self._policy = policy
        self._engine = policy_engine
        self._max_taint_entries = max_taint_entries
        self._snippet_max_length = snippet_max_length
        self._taint_entries: list[TaintEntry] = []

        # Precompute: skill_name → list of (zone_name, classification, on_violation)
        self._skill_to_zones: dict[str, list[tuple[str, str, ViolationAction]]] = {}
        for zone_name, boundary in policy.data_boundaries.items():
            for skill in boundary.skills:
                if skill not in self._skill_to_zones:
                    self._skill_to_zones[skill] = []
                self._skill_to_zones[skill].append(
                    (zone_name, boundary.classification, boundary.on_violation)
                )

    @property
    def taint_count(self) -> int:
        """Number of active taint entries."""
        return len(self._taint_entries)

    def record_response(
        self,
        tool_name: str,
        skill_name: str | None,
        response_data: Any,
    ) -> None:
        """Record a tool response and taint the session if the skill is in a boundary zone.

        Args:
            tool_name: The MCP tool name.
            skill_name: The resolved skill name (or None if unknown).
            response_data: The raw response payload.
        """
        if skill_name is None:
            return
        zones = self._skill_to_zones.get(skill_name)
        if not zones:
            return

        # Extract content: URLs, file paths, and text snippets
        extracted = extract_content(response_data)
        snippets = self._extract_text_snippets(response_data)

        # Nothing to track if no content was extracted
        if extracted.is_empty and not snippets:
            return

        for zone_name, classification, on_violation in zones:
            self._taint_entries.append(TaintEntry(
                zone_name=zone_name,
                classification=classification,
                skill_name=skill_name,
                tool_name=tool_name,
                extracted=extracted,
                text_snippets=snippets,
                on_violation=on_violation,
            ))

        # Evict oldest entries to bound memory
        if len(self._taint_entries) > self._max_taint_entries:
            self._taint_entries = self._taint_entries[-self._max_taint_entries:]

    def check_tool_call(
        self,
        tool_name: str,
        skill_name: str | None,
        arguments: dict[str, Any],
    ) -> EvaluationResult | None:
        """Check if a tool call violates data boundary rules.

        Returns an EvaluationResult with BLOCK if a violation is detected,
        or None if the call is allowed. LOG_ONLY violations return None
        (the caller should log separately).

        Args:
            tool_name: The MCP tool name being called.
            skill_name: The resolved skill name (or None if unknown).
            arguments: The tool call arguments.

        Returns:
            EvaluationResult(BLOCK) if violation detected, None otherwise.
        """
        if not self._taint_entries or not arguments:
            return None
        if skill_name is None:
            return None  # Can't boundary-check unknown skills

        for entry in self._taint_entries:
            # Same-zone calls are always allowed
            if self._skill_in_zone(skill_name, entry.zone_name):
                continue

            # Check if tainted content flows into these arguments
            matched = self._content_flows_into_arguments(entry, arguments)
            if matched is None:
                continue

            # Violation detected
            if entry.on_violation == ViolationAction.LOG_ONLY:
                # LOG_ONLY: return a special result that the proxy can detect
                # (decision=LOG instead of BLOCK)
                return EvaluationResult(
                    decision=PolicyDecision.LOG,
                    reason=(
                        f"Data boundary violation (log-only): '{entry.classification}' "
                        f"data from '{entry.tool_name}' ({entry.skill_name}) in zone "
                        f"'{entry.zone_name}' flows into '{tool_name}' which is outside "
                        f"the zone. Matched: {matched!r}"
                    ),
                    skill=skill_name,
                )

            return EvaluationResult(
                decision=PolicyDecision.BLOCK,
                reason=(
                    f"Data boundary violation: '{entry.classification}' data from "
                    f"'{entry.tool_name}' ({entry.skill_name}) in zone "
                    f"'{entry.zone_name}' flows into '{tool_name}' which is outside "
                    f"the zone. Matched: {matched!r}"
                ),
                skill=skill_name,
            )

        return None

    def _skill_in_zone(self, skill_name: str, zone_name: str) -> bool:
        """Check if a skill belongs to a specific boundary zone."""
        zones = self._skill_to_zones.get(skill_name, [])
        return any(z == zone_name for z, _cls, _vio in zones)

    def _extract_text_snippets(self, response_data: Any) -> list[str]:
        """Extract text snippets from response data for substring matching.

        Walks the response structure, extracts the first `snippet_max_length`
        characters from each string field that's at least `_MIN_SNIPPET_LENGTH`
        characters long. Caps at `_MAX_TEXT_FIELDS` fields.

        Args:
            response_data: The raw response payload.

        Returns:
            List of text snippets.
        """
        snippets: list[str] = []
        self._walk_for_snippets(response_data, snippets)
        return snippets

    def _walk_for_snippets(self, data: Any, snippets: list[str]) -> None:
        """Recursively extract text snippets from a data structure."""
        if len(snippets) >= _MAX_TEXT_FIELDS:
            return

        if isinstance(data, str):
            if len(data) >= _MIN_SNIPPET_LENGTH:
                snippets.append(data[: self._snippet_max_length])
        elif isinstance(data, dict):
            for value in data.values():
                if len(snippets) >= _MAX_TEXT_FIELDS:
                    return
                self._walk_for_snippets(value, snippets)
        elif isinstance(data, (list, tuple)):
            for item in data:
                if len(snippets) >= _MAX_TEXT_FIELDS:
                    return
                self._walk_for_snippets(item, snippets)

    def _content_flows_into_arguments(
        self,
        entry: TaintEntry,
        arguments: dict[str, Any],
    ) -> str | None:
        """Check if tainted content appears in the tool call arguments.

        Serializes arguments to a JSON string and checks for substring
        matches against extracted URLs, file paths, and text snippets.

        Args:
            entry: The taint entry to check against.
            arguments: The tool call arguments.

        Returns:
            The matched content string, or None if no match.
        """
        try:
            args_str = json.dumps(arguments, default=str)
        except (TypeError, ValueError):
            return None

        # Check URLs
        for url in entry.extracted.urls:
            if url in args_str:
                return url

        # Check file paths
        for path in entry.extracted.file_paths:
            if path in args_str:
                return path

        # Check text snippets
        for snippet in entry.text_snippets:
            if snippet in args_str:
                return snippet

        return None
