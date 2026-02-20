"""Policy evaluation engine.

Takes a tool call (name + arguments) and a loaded policy, and returns a decision:
ALLOW, BLOCK, REDACT, APPROVE, or LOG.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentward.policy.schema import AgentWardPolicy, PolicyDecision, ResourcePermissions


@dataclass(frozen=True)
class EvaluationResult:
    """Result of evaluating a tool call against the policy.

    Attributes:
        decision: The policy decision (ALLOW, BLOCK, APPROVE, etc.).
        reason: Human-readable explanation of why this decision was made.
        skill: The skill name that matched, if any.
        resource: The resource name that matched, if any.
    """

    decision: PolicyDecision
    reason: str
    skill: str | None = None
    resource: str | None = None


class PolicyEngine:
    """Evaluates tool calls against an AgentWard policy.

    Tool name matching strategy:
      MCP tool names are flat strings (e.g., "gmail_send", "read_file").
      Policy defines a hierarchy: skill → resource → action.

      We match by checking if the tool name starts with or contains
      the resource name. If a resource match is found, we extract the
      remaining part as the action name.

      Example: tool "gmail_send" with resource "gmail" → action "send"

    If no policy rule matches a tool, the default is ALLOW (passthrough).
    """

    def __init__(self, policy: AgentWardPolicy) -> None:
        self._policy = policy
        # Pre-build a lookup: (skill_name, resource_name) → ResourcePermissions
        self._resource_lookup: dict[tuple[str, str], ResourcePermissions] = {}
        for skill_name, resources in policy.skills.items():
            for resource_name, permissions in resources.items():
                self._resource_lookup[(skill_name, resource_name)] = permissions

    @property
    def policy(self) -> AgentWardPolicy:
        """The loaded policy."""
        return self._policy

    def evaluate(self, tool_name: str, arguments: dict[str, Any] | None = None) -> EvaluationResult:
        """Evaluate a tool call against the policy.

        Args:
            tool_name: The MCP tool name (e.g., "gmail_send", "read_file").
            arguments: The tool call arguments (currently used for logging context,
                       will be used for data classification in the future).

        Returns:
            An EvaluationResult with the decision and reasoning.
        """
        # Check require_approval first — takes priority over resource-level permissions
        if tool_name in self._policy.require_approval:
            return EvaluationResult(
                decision=PolicyDecision.APPROVE,
                reason=f"Tool '{tool_name}' requires human approval before execution.",
            )

        # Try to match tool name against skill/resource/action hierarchy
        match = self._match_tool(tool_name)
        if match is not None:
            skill_name, resource_name, action, permissions = match
            return self._evaluate_permissions(
                tool_name, skill_name, resource_name, action, permissions
            )

        # No match — default to ALLOW (passthrough for unknown tools)
        return EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason=f"No policy rule matches tool '{tool_name}'. Allowing by default.",
        )

    def evaluate_chaining(self, source_skill: str, target_skill: str) -> EvaluationResult:
        """Check if a skill-to-skill chain is allowed.

        Args:
            source_skill: The skill initiating the chain.
            target_skill: The skill being triggered.

        Returns:
            BLOCK if any chaining rule prohibits this chain, ALLOW otherwise.
        """
        for rule in self._policy.skill_chaining:
            if rule.blocks(source_skill, target_skill):
                return EvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    reason=(
                        f"Chaining blocked: '{source_skill}' cannot trigger "
                        f"'{target_skill}' (policy rule: "
                        f"'{rule.source_skill} cannot trigger {rule.target_skill}')."
                    ),
                    skill=source_skill,
                )

        return EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason=f"No chaining rule blocks '{source_skill}' → '{target_skill}'.",
            skill=source_skill,
        )

    def _match_tool(
        self, tool_name: str
    ) -> tuple[str, str, str | None, ResourcePermissions] | None:
        """Match a flat MCP tool name to a skill/resource/action in the policy.

        Matching strategy:
          1. Check if tool_name starts with resource_name + separator ("_" or "-")
             → extract the remainder as the action
          2. Check if tool_name exactly equals resource_name
             → action is None (resource-level check only)

        Returns:
            Tuple of (skill_name, resource_name, action_or_none, permissions),
            or None if no match found.
        """
        best_match: tuple[str, str, str | None, ResourcePermissions] | None = None
        best_resource_len = 0

        for (skill_name, resource_name), permissions in self._resource_lookup.items():
            # Exact match: tool name IS the resource name
            if tool_name == resource_name:
                if len(resource_name) > best_resource_len:
                    best_match = (skill_name, resource_name, None, permissions)
                    best_resource_len = len(resource_name)
                continue

            # Prefix match with separator: "gmail_send" matches resource "gmail"
            for sep in ("_", "-", "."):
                prefix = resource_name + sep
                if tool_name.startswith(prefix):
                    action = tool_name[len(prefix):]
                    if action and len(resource_name) > best_resource_len:
                        best_match = (skill_name, resource_name, action, permissions)
                        best_resource_len = len(resource_name)

        return best_match

    def _evaluate_permissions(
        self,
        tool_name: str,
        skill_name: str,
        resource_name: str,
        action: str | None,
        permissions: ResourcePermissions,
    ) -> EvaluationResult:
        """Evaluate a matched tool call against resource permissions.

        Args:
            tool_name: The original MCP tool name.
            skill_name: The matched skill.
            resource_name: The matched resource.
            action: The extracted action (e.g., "send"), or None if no action extracted.
            permissions: The resource permissions to check against.

        Returns:
            The evaluation result.
        """
        # Denied resources block everything
        if permissions.denied:
            return EvaluationResult(
                decision=PolicyDecision.BLOCK,
                reason=(
                    f"Resource '{resource_name}' is denied for skill '{skill_name}'. "
                    f"Tool '{tool_name}' blocked."
                ),
                skill=skill_name,
                resource=resource_name,
            )

        # If we have a specific action, check it
        if action is not None:
            allowed = permissions.is_action_allowed(action)
            if allowed is True:
                return EvaluationResult(
                    decision=PolicyDecision.ALLOW,
                    reason=(
                        f"Action '{action}' on resource '{resource_name}' "
                        f"is allowed for skill '{skill_name}'."
                    ),
                    skill=skill_name,
                    resource=resource_name,
                )
            elif allowed is False:
                return EvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    reason=(
                        f"Action '{action}' on resource '{resource_name}' "
                        f"is denied for skill '{skill_name}'. Tool '{tool_name}' blocked."
                    ),
                    skill=skill_name,
                    resource=resource_name,
                )
            # allowed is None — action not mentioned in policy, fall through

        # Resource matched but no specific action rule — ALLOW by default
        # (resource exists in policy but this particular action isn't listed)
        return EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason=(
                f"Resource '{resource_name}' matched for skill '{skill_name}', "
                f"but no explicit rule for action '{action}'. Allowing by default."
            ),
            skill=skill_name,
            resource=resource_name,
        )
