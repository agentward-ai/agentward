"""Runtime skill chaining enforcement.

Tracks tool call history within a proxy session and enforces skill_chaining
policy rules by detecting when data flows from one skill's tool to another.

Two enforcement modes:
  - CONTENT (default): Inspects tool response content and blocks only when
    data from a prior response appears in the current tool call's arguments.
  - BLANKET: Blocks all calls to a target skill after the source skill has
    been called, regardless of argument content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import ChainingMode, PolicyDecision
from agentward.proxy.content import (
    ExtractedContent,
    content_matches_arguments,
    extract_content,
)


@dataclass
class SessionToolCall:
    """Record of a tool call in the current session."""

    tool_name: str
    skill_name: str | None
    arguments: dict[str, Any]
    request_id: str | int | None = None
    response_content: ExtractedContent | None = None


class ChainTracker:
    """Tracks tool call history and enforces chaining rules at runtime.

    Used by both StdioProxy and HttpProxy. Maintains a bounded session
    history and checks each incoming tool call against prior calls using
    the configured enforcement mode.

    Args:
        policy_engine: The loaded policy engine (for skill resolution
                       and chaining rule evaluation).
        mode: Enforcement mode (CONTENT or BLANKET).
        max_history: Maximum number of tool calls to retain in history.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        mode: ChainingMode = ChainingMode.CONTENT,
        max_history: int = 100,
    ) -> None:
        self._engine = policy_engine
        self._mode = mode
        self._max_history = max_history
        self._history: list[SessionToolCall] = []
        self._called_skills: set[str] = set()

    @property
    def mode(self) -> ChainingMode:
        """The active chaining enforcement mode."""
        return self._mode

    def check_before_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> EvaluationResult | None:
        """Check if a tool call should be blocked due to chaining rules.

        This is the main entry point called by the proxy before forwarding
        a tool call to the backend/server.

        Checks both:
          1. Individual chaining rules (A cannot trigger B).
          2. Global ``skill_chain_depth`` limit — consecutive skill-to-skill
             handoffs exceeding this depth are blocked regardless of rules.

        Args:
            tool_name: The tool being called.
            arguments: The tool call arguments.

        Returns:
            An EvaluationResult with BLOCK if a chain violation is detected,
            or None if the call is allowed.
        """
        target_skill = self._engine.resolve_skill(tool_name)
        if target_skill is None:
            return None  # Unknown tool — can't enforce chaining

        # Check global depth limit
        depth_result = self._check_depth(target_skill)
        if depth_result is not None:
            return depth_result

        # Check individual chaining rules
        if not self._engine.policy.skill_chaining:
            return None  # No chaining rules configured

        if self._mode == ChainingMode.BLANKET:
            return self._check_blanket(target_skill)
        return self._check_content(target_skill, arguments)

    def record_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str | int | None = None,
    ) -> None:
        """Record that a tool call was made (before the response is known).

        Call this after the tool call has been forwarded to the backend
        (i.e., after it passed the chaining check).

        Args:
            tool_name: The tool that was called.
            arguments: The tool call arguments.
            request_id: Optional JSON-RPC request ID for matching responses
                        to calls when multiple calls may be in-flight.
        """
        skill = self._engine.resolve_skill(tool_name)
        entry = SessionToolCall(
            tool_name=tool_name,
            skill_name=skill,
            arguments=arguments,
            request_id=request_id,
        )
        self._history.append(entry)
        if skill is not None:
            self._called_skills.add(skill)

        # Evict old entries to bound memory
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

    def record_response(
        self,
        tool_name: str,
        response_data: Any,
        request_id: str | int | None = None,
    ) -> None:
        """Record the response content for a completed tool call.

        Extracts URLs, file paths, etc. from the response for content-mode
        chain detection. Only processes data in CONTENT mode.

        When request_id is provided, matches against the specific call with
        that ID. Otherwise falls back to LIFO matching by tool_name.

        Args:
            tool_name: The tool that returned the response.
            response_data: The response payload (typically a dict from JSON).
            request_id: Optional request ID for precise call-response matching.
        """
        if self._mode != ChainingMode.CONTENT:
            return  # Blanket mode doesn't need response content

        # If request_id is provided, use it for precise matching
        if request_id is not None:
            for entry in reversed(self._history):
                if entry.request_id == request_id and entry.response_content is None:
                    entry.response_content = extract_content(response_data)
                    return

        # Fallback: match by tool_name (LIFO) — existing behavior
        for entry in reversed(self._history):
            if entry.tool_name == tool_name and entry.response_content is None:
                entry.response_content = extract_content(response_data)
                break

    def _check_depth(self, target_skill: str) -> EvaluationResult | None:
        """Check the global skill_chain_depth limit.

        Counts consecutive skill-to-skill transitions in recent history.
        A "transition" is when the current call's skill differs from the
        previous call's skill. If the running count of transitions reaches
        the configured depth limit, the call is blocked.

        Returns:
            An EvaluationResult with BLOCK if depth is exceeded, else None.
        """
        max_depth = self._engine.policy.skill_chain_depth
        if max_depth is None:
            return None  # No depth limit configured

        # Count consecutive skill transitions in history
        depth = 0
        prev_skill: str | None = None
        for entry in self._history:
            if entry.skill_name is None:
                continue
            if prev_skill is not None and entry.skill_name != prev_skill:
                depth += 1
            prev_skill = entry.skill_name

        # The upcoming call would add another transition if skill differs
        if prev_skill is not None and target_skill != prev_skill:
            depth += 1

        if depth > max_depth:
            return EvaluationResult(
                decision=PolicyDecision.BLOCK,
                reason=(
                    f"Skill chain depth exceeded: {depth} transitions "
                    f"(limit: {max_depth}). Current chain involves "
                    f"{len(self._called_skills)} skill(s)."
                ),
                skill=target_skill,
            )

        return None

    def _check_blanket(self, target_skill: str) -> EvaluationResult | None:
        """Blanket mode: block if any prior skill triggers a chaining rule.

        Checks every skill that has been called in this session against
        the target skill using the policy engine's chaining rules.
        """
        for source_skill in self._called_skills:
            result = self._engine.evaluate_chaining(source_skill, target_skill)
            if result.decision == PolicyDecision.BLOCK:
                return result
        return None

    def _check_content(
        self,
        target_skill: str,
        arguments: dict[str, Any],
    ) -> EvaluationResult | None:
        """Content mode: block only when prior response data flows into arguments.

        Iterates history in reverse, checking each entry where a chaining rule
        applies. If the entry's response content matches the current arguments,
        the chain is blocked.
        """
        for entry in reversed(self._history):
            if entry.skill_name is None or entry.response_content is None:
                continue

            # Check if a chaining rule blocks this source → target pair
            chain_result = self._engine.evaluate_chaining(
                entry.skill_name, target_skill
            )
            if chain_result.decision != PolicyDecision.BLOCK:
                continue

            # There IS a chaining rule. Check if content actually flows.
            matches = content_matches_arguments(
                entry.response_content, arguments
            )
            if matches:
                return EvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    reason=(
                        f"Chain detected: '{entry.tool_name}' ({entry.skill_name}) "
                        f"response content flows into this call's arguments "
                        f"(matched: {matches[0]!r}). Policy rule: "
                        f"'{entry.skill_name} cannot trigger {target_skill}'."
                    ),
                    skill=target_skill,
                )

        return None
