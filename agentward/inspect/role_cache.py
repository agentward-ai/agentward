"""Cache for tool parameter role classifications.

Populated from ``tools/list`` responses during proxy initialization.
Queried by the policy engine for role-aware filter evaluation.
"""

from __future__ import annotations

from typing import Any

from agentward.inspect.roles import ArgumentRole, classify_tool_schema


class ToolRoleCache:
    """Maps tool names to their classified parameter roles.

    Thread-safe for concurrent reads; writes happen only during tools/list
    processing (single writer, no lock needed for dict).
    """

    def __init__(self) -> None:
        # tool_name → {param_name → ArgumentRole}
        self._cache: dict[str, dict[str, ArgumentRole]] = {}

    def register_tool(
        self,
        tool_name: str,
        input_schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> None:
        """Classify and cache parameter roles for a tool.

        Args:
            tool_name: The MCP tool name.
            input_schema: The tool's JSON Schema ``inputSchema``.
            annotations: Optional MCP tool annotations.
        """
        roles = classify_tool_schema(tool_name, input_schema, annotations)
        self._cache[tool_name] = roles

    def get_roles(self, tool_name: str) -> dict[str, ArgumentRole] | None:
        """Get all parameter roles for a tool.

        Args:
            tool_name: The MCP tool name.

        Returns:
            Mapping of param_name → role, or None if tool not registered.
        """
        return self._cache.get(tool_name)

    def get_role(self, tool_name: str, param_name: str) -> ArgumentRole | None:
        """Get the role for a specific parameter.

        Args:
            tool_name: The MCP tool name.
            param_name: The parameter name.

        Returns:
            The parameter's role, or None if not found.
        """
        roles = self._cache.get(tool_name)
        if roles is None:
            return None
        return roles.get(param_name)

    def has_tool(self, tool_name: str) -> bool:
        """Check if a tool has been registered."""
        return tool_name in self._cache

    def tool_has_role(self, tool_name: str, role: ArgumentRole) -> bool:
        """Check if any parameter of a tool has the given role.

        Args:
            tool_name: The MCP tool name.
            role: The role to check for.

        Returns:
            True if any parameter has this role.
        """
        roles = self._cache.get(tool_name)
        if roles is None:
            return False
        return role in roles.values()

    def get_params_with_role(
        self, tool_name: str, role: ArgumentRole
    ) -> list[str]:
        """Get all parameter names with a specific role.

        Args:
            tool_name: The MCP tool name.
            role: The role to filter by.

        Returns:
            List of parameter names with this role.
        """
        roles = self._cache.get(tool_name)
        if roles is None:
            return []
        return [name for name, r in roles.items() if r == role]

    @property
    def registered_count(self) -> int:
        """Number of tools registered in the cache."""
        return len(self._cache)
