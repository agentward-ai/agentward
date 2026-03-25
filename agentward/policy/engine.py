"""Policy evaluation engine.

Takes a tool call (name + arguments) and a loaded policy, and returns a decision:
ALLOW, BLOCK, REDACT, APPROVE, or LOG.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


 
from agentward.policy.constraints import (
    ConstraintViolation,
    evaluate_argument_constraints,
    evaluate_capabilities,
)
from agentward.policy.protected_paths import check_arguments as _check_protected_paths
from agentward.policy.schema import (
    AgentWardPolicy,
    DefaultAction,
    PolicyDecision,
    ResourcePermissions,
)

# Import is deferred at runtime to avoid circular dependencies;
# the type is only used for isinstance checks in _check_role_filters.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentward.inspect.role_cache import ToolRoleCache


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


def _format_constraint_violations(
    tool_name: str,
    violations: list[ConstraintViolation],
) -> str:
    """Format constraint violations into a concise, actionable block reason.

    Args:
        tool_name: The tool name (used in the first violation message).
        violations: Non-empty list of constraint violations.

    Returns:
        A human-readable string suitable for audit logs and operator dashboards.
    """
    if not violations:
        return f"Tool '{tool_name}' blocked by capability constraints."
    # Violations already contain BLOCKED: prefixed messages.
    return " ".join(v.message for v in violations)


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

    def __init__(
        self,
        policy: AgentWardPolicy,
        skill_context: str | None = None,
        role_cache: "ToolRoleCache | None" = None,
    ) -> None:
        self._policy = policy
        self._skill_context = skill_context
        self._role_cache = role_cache
        # Pre-build a lookup: (skill_name, resource_name) → ResourcePermissions
        self._resource_lookup: dict[tuple[str, str], ResourcePermissions] = {}
        for skill_name, resources in policy.skills.items():
            for resource_name, permissions in resources.items():
                self._resource_lookup[(skill_name, resource_name)] = permissions

    @property
    def policy(self) -> AgentWardPolicy:
        """The loaded policy."""
        return self._policy

    def resolve_skill(self, tool_name: str) -> str | None:
        """Resolve a tool name to its skill (server) name.

        Uses the policy's skill/resource hierarchy to map flat MCP tool
        names back to the skill that owns them. This is the bridge between
        tool-level proxy interception and skill-level chaining rules.

        Args:
            tool_name: The MCP tool name (e.g., "gmail_send", "read_file").

        Returns:
            The skill name if the tool matches a policy rule, None otherwise.
        """
        match = self._match_tool(tool_name)
        if match is not None:
            return match[0]  # skill_name
        return None

    def evaluate(self, tool_name: str, arguments: dict[str, Any] | None = None) -> EvaluationResult:
        """Evaluate a tool call against the policy.

        Args:
            tool_name: The MCP tool name (e.g., "gmail_send", "read_file").
            arguments: The tool call arguments (currently used for logging context,
                       will be used for data classification in the future).

        Returns:
            An EvaluationResult with the decision and reasoning.
        """
        # Protected path invariants — non-overridable safety floor.
        # Blocks access to ~/.ssh, ~/.gnupg, ~/.aws, etc. regardless of policy.
        # This check CANNOT be bypassed by any policy configuration.
        protected_reason = _check_protected_paths(arguments)
        if protected_reason is not None:
            return EvaluationResult(
                decision=PolicyDecision.BLOCK,
                reason=protected_reason,
            )

        # Check require_approval — takes priority over resource-level permissions
        for rule in self._policy.require_approval:
            if rule.matches(tool_name, arguments):
                if rule.conditional is not None and rule.conditional.when:
                    # Conditional rule matched — include condition info in reason
                    conditions = ", ".join(
                        f"{k}: {v.contains or v.not_contains or v.equals or v.matches}"
                        for k, v in rule.conditional.when.items()
                    )
                    reason = (
                        f"Tool '{tool_name}' requires human approval "
                        f"(condition matched: {conditions})."
                    )
                else:
                    reason = f"Tool '{tool_name}' requires human approval before execution."
                return EvaluationResult(
                    decision=PolicyDecision.APPROVE,
                    reason=reason,
                )

        # Try to match tool name against skill/resource/action hierarchy
        match = self._match_tool(tool_name, skill_filter=self._skill_context)
        if match is not None:
            skill_name, resource_name, action, permissions = match
            result = self._evaluate_permissions(
                tool_name, skill_name, resource_name, action, permissions, arguments
            )
            return self._apply_capabilities(tool_name, arguments, result)

        # No match — use the configured default action
        if self._policy.default_action == DefaultAction.BLOCK:
            return EvaluationResult(
                decision=PolicyDecision.BLOCK,
                reason=f"No policy rule matches tool '{tool_name}'. "
                f"Blocked by default (default_action: block).",
            )
        default_allow = EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason=f"No policy rule matches tool '{tool_name}'. Allowing by default.",
        )
        return self._apply_capabilities(tool_name, arguments, default_allow)

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
        self,
        tool_name: str,
        skill_filter: str | None = None,
    ) -> tuple[str, str, str | None, ResourcePermissions] | None:
        """Match a flat MCP tool name to a skill/resource/action in the policy.

        Matching strategy (longest resource name wins across all strategies):
          1. Exact match: tool_name equals resource_name
             → action is None (resource-level check only)
          2. Prefix match: tool_name starts with resource_name + separator
             → remainder is the action (e.g., "gmail_send" → action "send")
          3. Suffix match: tool_name ends with separator + resource_name
             → prefix is the action (e.g., "read_file" → action "read")

        Separators: "_", "-", "."

        Args:
            tool_name: The MCP tool name to match.
            skill_filter: When set, only match resources belonging to this
                          skill. Used to disambiguate when multiple skills
                          define the same resource name.

        Returns:
            Tuple of (skill_name, resource_name, action_or_none, permissions),
            or None if no match found.
        """
        best_match: tuple[str, str, str | None, ResourcePermissions] | None = None
        best_resource_len = 0

        for (skill_name, resource_name), permissions in self._resource_lookup.items():
            # When skill_filter is set, only match resources from that skill
            if skill_filter is not None and skill_name != skill_filter:
                continue
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

            # Suffix match with separator: "read_file" matches resource "file"
            for sep in ("_", "-", "."):
                suffix = sep + resource_name
                if tool_name.endswith(suffix):
                    action = tool_name[: len(tool_name) - len(suffix)]
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
        arguments: dict[str, Any] | None = None,
    ) -> EvaluationResult:
        """Evaluate a matched tool call against resource permissions.

        Args:
            tool_name: The original MCP tool name.
            skill_name: The matched skill.
            resource_name: The matched resource.
            action: The extracted action (e.g., "send"), or None if no action extracted.
            permissions: The resource permissions to check against.
            arguments: The tool call arguments (for filter enforcement).

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
                # Action allowed — check filters then capability constraints.
                filter_result = self._check_filters(
                    tool_name, skill_name, resource_name, permissions, arguments
                )
                if filter_result is not None:
                    return filter_result
                cap_result = self._check_capabilities(
                    tool_name, skill_name, resource_name, permissions, arguments
                )
                if cap_result is not None:
                    return cap_result
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

        # Resource matched but no specific action rule.
        # If the resource has ONLY deny rules (no allow rules), block:
        # this covers generated rules like `url: {outbound: false}` where
        # the action token extracted from the tool name ("fetch") will never
        # match the permission key ("outbound").
        if permissions.actions and not any(permissions.actions.values()):
            return EvaluationResult(
                decision=PolicyDecision.BLOCK,
                reason=(
                    f"Resource '{resource_name}' is restricted for skill '{skill_name}' "
                    f"(all listed actions are denied). Tool '{tool_name}' blocked."
                ),
                skill=skill_name,
                resource=resource_name,
            )

        # Resource matched but action isn't listed.
        # Respect default_action: in block mode, unlisted actions are denied
        # (zero-trust — only explicitly allowed actions pass).
        # In allow mode, unlisted actions pass through.
        if self._policy.default_action == DefaultAction.BLOCK:
            return EvaluationResult(
                decision=PolicyDecision.BLOCK,
                reason=(
                    f"Action '{action}' on resource '{resource_name}' "
                    f"is not explicitly allowed for skill '{skill_name}'. "
                    f"Blocked by default (default_action: block)."
                ),
                skill=skill_name,
                resource=resource_name,
            )

        # Final ALLOW — check filters then capability constraints.
        filter_result = self._check_filters(
            tool_name, skill_name, resource_name, permissions, arguments
        )
        if filter_result is not None:
            return filter_result

        cap_result = self._check_capabilities(
            tool_name, skill_name, resource_name, permissions, arguments
        )
        if cap_result is not None:
            return cap_result

        return EvaluationResult(
            decision=PolicyDecision.ALLOW,
            reason=(
                f"Resource '{resource_name}' matched for skill '{skill_name}', "
                f"but no explicit rule for action '{action}'. Allowing by default."
            ),
            skill=skill_name,
            resource=resource_name,
        )

    def _check_filters(
        self,
        tool_name: str,
        skill_name: str,
        resource_name: str,
        permissions: ResourcePermissions,
        arguments: dict[str, Any] | None,
    ) -> EvaluationResult | None:
        """Check resource filters against tool call arguments.

        Enforces two filter types:
          - only_from: At least one argument value must contain one of the
            allowed values (allowlist).
          - exclude_labels: No argument value may contain any of the
            excluded values (denylist).

        Args:
            tool_name: The original MCP tool name.
            skill_name: The matched skill.
            resource_name: The matched resource.
            permissions: The resource permissions with filters.
            arguments: The tool call arguments.

        Returns:
            A BLOCK result if a filter is violated, None if all filters pass.
        """
        if not permissions.filters or not arguments:
            return None

        # Collect all string argument values for matching
        arg_values: list[str] = []
        for v in arguments.values():
            if isinstance(v, str):
                arg_values.append(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, str):
                        arg_values.append(item)

        # only_from: at least one arg must contain an allowed value
        only_from = permissions.filters.get("only_from")
        if only_from and arg_values:
            if not any(
                any(allowed in val for allowed in only_from)
                for val in arg_values
            ):
                return EvaluationResult(
                    decision=PolicyDecision.BLOCK,
                    reason=(
                        f"Filter 'only_from' violated for resource '{resource_name}' "
                        f"in skill '{skill_name}'. Allowed sources: {only_from}. "
                        f"Tool '{tool_name}' blocked."
                    ),
                    skill=skill_name,
                    resource=resource_name,
                )

        # exclude_labels: no arg may contain an excluded value
        exclude_labels = permissions.filters.get("exclude_labels")
        if exclude_labels and arg_values:
            for val in arg_values:
                for excluded in exclude_labels:
                    if excluded.lower() in val.lower():
                        return EvaluationResult(
                            decision=PolicyDecision.BLOCK,
                            reason=(
                                f"Filter 'exclude_labels' violated for resource "
                                f"'{resource_name}' in skill '{skill_name}'. "
                                f"Excluded label '{excluded}' found in arguments. "
                                f"Tool '{tool_name}' blocked."
                            ),
                            skill=skill_name,
                            resource=resource_name,
                        )

        # Role-aware filters (only active when role_cache is populated)
        role_result = self._check_role_filters(
            tool_name, skill_name, resource_name, permissions, arguments,
        )
        if role_result is not None:
            return role_result

        return None

    def _check_capabilities(
        self,
        tool_name: str,
        skill_name: str,
        resource_name: str,
        permissions: ResourcePermissions,
        arguments: dict[str, Any] | None,
    ) -> EvaluationResult | None:
        """Check argument constraints from the capabilities block.

        This is the last gate before ALLOW — runs after action-level and
        filter-level checks have already passed.

        Args:
            tool_name: The full MCP tool name (used to look up capability constraints).
            skill_name: The matched skill (for EvaluationResult context).
            resource_name: The matched resource (for EvaluationResult context).
            permissions: Resource permissions, which may carry ``capabilities``.
            arguments: Tool call arguments to evaluate.

        Returns:
            A BLOCK EvaluationResult if any constraint fails, None if all pass
            or if no capability constraints are defined for this tool.
        """
        if not permissions.capabilities:
            return None

        tool_caps = permissions.capabilities.get(tool_name)
        if not tool_caps:
            return None

        result = evaluate_argument_constraints(arguments, tool_caps)
        if result.passed:
            return None

        reason = _format_constraint_violations(tool_name, result.violations)
        return EvaluationResult(
            decision=PolicyDecision.BLOCK,
            reason=reason,
            skill=skill_name,
            resource=resource_name,
        )

    def _check_role_filters(
        self,
        tool_name: str,
        skill_name: str,
        resource_name: str,
        permissions: ResourcePermissions,
        arguments: dict[str, Any] | None,
    ) -> EvaluationResult | None:
        """Check role-aware filters against tool call arguments.

        Supports two filter types:
          - ``block_write_paths``: Block if any WRITE_PATH parameter value
            matches a pattern in the list (substring match).
          - ``allow_read_paths``: If set, READ_PATH parameter values must
            match at least one pattern (allowlist).

        Only activates when the role_cache has roles for this tool.

        Args:
            tool_name: The MCP tool name.
            skill_name: The matched skill.
            resource_name: The matched resource.
            permissions: The resource permissions with filters.
            arguments: The tool call arguments.

        Returns:
            A BLOCK result if a role filter is violated, None otherwise.
        """
        if self._role_cache is None or not arguments or not permissions.filters:
            return None

        from agentward.inspect.role_cache import ToolRoleCache
        from agentward.inspect.roles import ArgumentRole

        roles = self._role_cache.get_roles(tool_name)
        if roles is None:
            return None

        # block_write_paths: block if WRITE_PATH args match any pattern
        block_write = permissions.filters.get("block_write_paths")
        if block_write:
            write_params = [
                name for name, role in roles.items()
                if role == ArgumentRole.WRITE_PATH
            ]
            for param in write_params:
                val = arguments.get(param)
                if isinstance(val, str):
                    for pattern in block_write:
                        if pattern in val:
                            return EvaluationResult(
                                decision=PolicyDecision.BLOCK,
                                reason=(
                                    f"Filter 'block_write_paths' violated: parameter "
                                    f"'{param}' (role: WRITE_PATH) contains '{pattern}'. "
                                    f"Tool '{tool_name}' blocked."
                                ),
                                skill=skill_name,
                                resource=resource_name,
                            )

        # allow_read_paths: READ_PATH args must match at least one pattern
        allow_read = permissions.filters.get("allow_read_paths")
        if allow_read:
            read_params = [
                name for name, role in roles.items()
                if role == ArgumentRole.READ_PATH
            ]
            for param in read_params:
                val = arguments.get(param)
                if isinstance(val, str):
                    if not any(pattern in val for pattern in allow_read):
                        return EvaluationResult(
                            decision=PolicyDecision.BLOCK,
                            reason=(
                                f"Filter 'allow_read_paths' violated: parameter "
                                f"'{param}' (role: READ_PATH) value '{val}' does not "
                                f"match any allowed pattern: {allow_read}. "
                                f"Tool '{tool_name}' blocked."
                            ),
                            skill=skill_name,
                            resource=resource_name,
                        )

        return None

    def _apply_capabilities(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None,
        base_result: EvaluationResult,
    ) -> EvaluationResult:
        """Apply capability constraints on top of a base evaluation result.

        Only runs capability checks when the base result is ALLOW or LOG —
        if the action is already blocked, there is nothing to further restrict.

        Args:
            tool_name: The MCP tool name.
            arguments: The tool call arguments.
            base_result: The result from action-level permission evaluation.

        Returns:
            The base result unchanged if it is not ALLOW/LOG, or a BLOCK result
            if any capability constraint is violated.
        """
        if base_result.decision not in (PolicyDecision.ALLOW, PolicyDecision.LOG):
            return base_result

        if not self._policy.capabilities:
            return base_result

        violations = evaluate_capabilities(tool_name, arguments, self._policy.capabilities)
        if not violations:
            return base_result

        # Build a message that lists ALL violations (not just the first)
        violation_lines = "; ".join(v.reason for v in violations)
        return EvaluationResult(
            decision=PolicyDecision.BLOCK,
            reason=(
                f"Capability constraint violated for tool '{tool_name}': "
                f"{violation_lines}"
            ),
            skill=base_result.skill,
            resource=base_result.resource,
        )
