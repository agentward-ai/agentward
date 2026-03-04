"""Tests for argument-role classification (roles.py + role_cache.py).

Covers parameter name matching, JSON Schema format hints, annotation
overrides, tool name disambiguation, cache operations, and role-aware
filter integration with the policy engine.
"""

from __future__ import annotations

import pytest

from agentward.inspect.role_cache import ToolRoleCache
from agentward.inspect.roles import ArgumentRole, classify_tool_schema
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    PolicyDecision,
    ResourcePermissions,
)


# ---------------------------------------------------------------------------
# classify_tool_schema — Name matching
# ---------------------------------------------------------------------------


class TestNameMatching:
    """Classify parameters by their names."""

    def test_read_path_names(self) -> None:
        schema = {"properties": {"source_path": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["source_path"] == ArgumentRole.READ_PATH

    def test_write_path_names(self) -> None:
        schema = {"properties": {"dest_file": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["dest_file"] == ArgumentRole.WRITE_PATH

    def test_url_names(self) -> None:
        schema = {"properties": {"endpoint": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["endpoint"] == ArgumentRole.URL

    def test_recipient_names(self) -> None:
        schema = {"properties": {"recipient": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["recipient"] == ArgumentRole.RECIPIENT

    def test_content_body_names(self) -> None:
        schema = {"properties": {"body": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["body"] == ArgumentRole.CONTENT_BODY

    def test_credential_names(self) -> None:
        schema = {"properties": {"api_key": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["api_key"] == ArgumentRole.CREDENTIAL

    def test_unknown_parameter(self) -> None:
        schema = {"properties": {"foobar": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["foobar"] == ArgumentRole.UNKNOWN


class TestSubstringMatching:
    """Name matching uses substring, not just exact match."""

    def test_substring_read_path(self) -> None:
        schema = {"properties": {"my_source_path_here": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["my_source_path_here"] == ArgumentRole.READ_PATH

    def test_substring_credential(self) -> None:
        schema = {"properties": {"github_api_token_v2": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["github_api_token_v2"] == ArgumentRole.CREDENTIAL


# ---------------------------------------------------------------------------
# JSON Schema format hints
# ---------------------------------------------------------------------------


class TestSchemaFormatHints:
    """JSON Schema format: "uri" → URL, format: "email" → RECIPIENT."""

    def test_uri_format(self) -> None:
        schema = {"properties": {"callback": {"type": "string", "format": "uri"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["callback"] == ArgumentRole.URL

    def test_email_format(self) -> None:
        schema = {"properties": {"contact": {"type": "string", "format": "email"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["contact"] == ArgumentRole.RECIPIENT

    def test_format_takes_priority_over_name(self) -> None:
        """format: "uri" should win even if the name suggests something else."""
        schema = {"properties": {"body": {"type": "string", "format": "uri"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["body"] == ArgumentRole.URL


# ---------------------------------------------------------------------------
# Annotation overrides
# ---------------------------------------------------------------------------


class TestAnnotationOverrides:
    """MCP annotations override name-based classification."""

    def test_read_only_hint_overrides_write_path(self) -> None:
        """readOnlyHint=True + write-path name → READ_PATH."""
        schema = {"properties": {"dest_file": {"type": "string"}}}
        roles = classify_tool_schema(
            "safe_copy", schema, annotations={"readOnlyHint": True}
        )
        assert roles["dest_file"] == ArgumentRole.READ_PATH

    def test_destructive_hint_overrides_read_path(self) -> None:
        """destructiveHint=True + read-path name → WRITE_PATH."""
        schema = {"properties": {"source_file": {"type": "string"}}}
        roles = classify_tool_schema(
            "shred_file", schema, annotations={"destructiveHint": True}
        )
        assert roles["source_file"] == ArgumentRole.WRITE_PATH


# ---------------------------------------------------------------------------
# Tool name disambiguation
# ---------------------------------------------------------------------------


class TestToolNameDisambiguation:
    """Ambiguous path names resolved using tool name."""

    def test_read_tool_disambiguates_to_read_path(self) -> None:
        schema = {"properties": {"path": {"type": "string"}}}
        roles = classify_tool_schema("read_file", schema)
        assert roles["path"] == ArgumentRole.READ_PATH

    def test_write_tool_disambiguates_to_write_path(self) -> None:
        schema = {"properties": {"path": {"type": "string"}}}
        roles = classify_tool_schema("write_file", schema)
        assert roles["path"] == ArgumentRole.WRITE_PATH

    def test_delete_tool_disambiguates_to_write_path(self) -> None:
        schema = {"properties": {"file": {"type": "string"}}}
        roles = classify_tool_schema("delete_file", schema)
        assert roles["file"] == ArgumentRole.WRITE_PATH

    def test_list_tool_disambiguates_to_read_path(self) -> None:
        schema = {"properties": {"directory": {"type": "string"}}}
        roles = classify_tool_schema("list_directory", schema)
        assert roles["directory"] == ArgumentRole.READ_PATH

    def test_ambiguous_tool_defaults_to_read_path(self) -> None:
        """No annotation, no read/write hint in tool name → default READ_PATH."""
        schema = {"properties": {"path": {"type": "string"}}}
        roles = classify_tool_schema("process_data", schema)
        assert roles["path"] == ArgumentRole.READ_PATH

    def test_tool_with_underscore_prefix(self) -> None:
        """Tool name with read/write keyword after underscore."""
        schema = {"properties": {"file_path": {"type": "string"}}}
        roles = classify_tool_schema("fs_delete", schema)
        assert roles["file_path"] == ArgumentRole.WRITE_PATH


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases in schema classification."""

    def test_empty_schema(self) -> None:
        roles = classify_tool_schema("some_tool", {})
        assert roles == {}

    def test_no_properties(self) -> None:
        roles = classify_tool_schema("some_tool", {"type": "object"})
        assert roles == {}

    def test_non_dict_property(self) -> None:
        """Non-dict property schema should classify as UNKNOWN."""
        schema = {"properties": {"weird": "not_a_dict"}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["weird"] == ArgumentRole.UNKNOWN

    def test_multiple_params_classified(self) -> None:
        schema = {
            "properties": {
                "source_path": {"type": "string"},
                "dest_file": {"type": "string"},
                "api_key": {"type": "string"},
                "url": {"type": "string"},
                "body": {"type": "string"},
            }
        }
        roles = classify_tool_schema("some_tool", schema)
        assert roles["source_path"] == ArgumentRole.READ_PATH
        assert roles["dest_file"] == ArgumentRole.WRITE_PATH
        assert roles["api_key"] == ArgumentRole.CREDENTIAL
        assert roles["url"] == ArgumentRole.URL
        assert roles["body"] == ArgumentRole.CONTENT_BODY

    def test_credential_priority_over_path(self) -> None:
        """Credential names should take priority even if they contain path-like substrings."""
        schema = {"properties": {"secret_key": {"type": "string"}}}
        roles = classify_tool_schema("some_tool", schema)
        assert roles["secret_key"] == ArgumentRole.CREDENTIAL


# ---------------------------------------------------------------------------
# ToolRoleCache
# ---------------------------------------------------------------------------


class TestToolRoleCache:
    """Tests for the ToolRoleCache."""

    def test_register_and_get_roles(self) -> None:
        cache = ToolRoleCache()
        schema = {"properties": {"path": {"type": "string"}, "body": {"type": "string"}}}
        cache.register_tool("read_file", schema)

        roles = cache.get_roles("read_file")
        assert roles is not None
        assert roles["path"] == ArgumentRole.READ_PATH
        assert roles["body"] == ArgumentRole.CONTENT_BODY

    def test_get_role_single(self) -> None:
        cache = ToolRoleCache()
        cache.register_tool("read_file", {"properties": {"path": {"type": "string"}}})
        assert cache.get_role("read_file", "path") == ArgumentRole.READ_PATH

    def test_get_role_missing_tool(self) -> None:
        cache = ToolRoleCache()
        assert cache.get_role("nonexistent", "path") is None

    def test_get_role_missing_param(self) -> None:
        cache = ToolRoleCache()
        cache.register_tool("read_file", {"properties": {"path": {"type": "string"}}})
        assert cache.get_role("read_file", "nonexistent") is None

    def test_has_tool(self) -> None:
        cache = ToolRoleCache()
        assert not cache.has_tool("read_file")
        cache.register_tool("read_file", {"properties": {}})
        assert cache.has_tool("read_file")

    def test_tool_has_role(self) -> None:
        cache = ToolRoleCache()
        cache.register_tool("read_file", {"properties": {"path": {"type": "string"}}})
        assert cache.tool_has_role("read_file", ArgumentRole.READ_PATH)
        assert not cache.tool_has_role("read_file", ArgumentRole.WRITE_PATH)

    def test_get_params_with_role(self) -> None:
        cache = ToolRoleCache()
        schema = {
            "properties": {
                "src": {"type": "string"},  # UNKNOWN
                "source_path": {"type": "string"},  # READ_PATH
                "input_file": {"type": "string"},  # READ_PATH
            }
        }
        cache.register_tool("copy_tool", schema)
        read_params = cache.get_params_with_role("copy_tool", ArgumentRole.READ_PATH)
        assert "source_path" in read_params
        assert "input_file" in read_params
        assert "src" not in read_params

    def test_registered_count(self) -> None:
        cache = ToolRoleCache()
        assert cache.registered_count == 0
        cache.register_tool("a", {"properties": {}})
        cache.register_tool("b", {"properties": {}})
        assert cache.registered_count == 2

    def test_annotations_passed_through(self) -> None:
        cache = ToolRoleCache()
        cache.register_tool(
            "delete_file",
            {"properties": {"path": {"type": "string"}}},
            annotations={"destructiveHint": True},
        )
        assert cache.get_role("delete_file", "path") == ArgumentRole.WRITE_PATH


# ---------------------------------------------------------------------------
# Role-aware filter integration with PolicyEngine
# ---------------------------------------------------------------------------


class TestRoleAwareFilters:
    """Tests for block_write_paths and allow_read_paths filters."""

    def _make_policy_with_filters(
        self, filters: dict[str, list[str]]
    ) -> tuple[AgentWardPolicy, PolicyEngine, ToolRoleCache]:
        """Build a policy with a filesystem resource that has role-aware filters."""
        skills = {
            "file-manager": {
                "filesystem": ResourcePermissions.model_construct(
                    denied=False,
                    actions={"read": True, "write": True},
                    filters=filters,
                ),
            },
        }
        policy = AgentWardPolicy(
            version="1.0",
            skills=skills,
            skill_chaining=[],
            require_approval=[],
        )
        cache = ToolRoleCache()
        engine = PolicyEngine(policy, role_cache=cache)

        # Register tool schemas in cache
        cache.register_tool(
            "filesystem_write",
            {
                "properties": {
                    "dest_file": {"type": "string"},
                    "content": {"type": "string"},
                },
            },
        )
        cache.register_tool(
            "filesystem_read",
            {
                "properties": {
                    "source_path": {"type": "string"},
                },
            },
        )
        return policy, engine, cache

    def test_block_write_paths_blocks(self) -> None:
        """block_write_paths blocks write to /etc."""
        _, engine, _ = self._make_policy_with_filters(
            {"block_write_paths": ["/etc"]},
        )
        result = engine.evaluate(
            "filesystem_write", {"dest_file": "/etc/passwd", "content": "bad"}
        )
        assert result.decision == PolicyDecision.BLOCK
        assert "block_write_paths" in result.reason

    def test_block_write_paths_allows_safe_path(self) -> None:
        """block_write_paths allows write to /tmp."""
        _, engine, _ = self._make_policy_with_filters(
            {"block_write_paths": ["/etc"]},
        )
        result = engine.evaluate(
            "filesystem_write", {"dest_file": "/tmp/output.txt", "content": "ok"}
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_allow_read_paths_blocks(self) -> None:
        """allow_read_paths blocks read from outside allowed paths."""
        _, engine, _ = self._make_policy_with_filters(
            {"allow_read_paths": ["/home/user/docs"]},
        )
        result = engine.evaluate(
            "filesystem_read", {"source_path": "/etc/shadow"}
        )
        assert result.decision == PolicyDecision.BLOCK
        assert "allow_read_paths" in result.reason

    def test_allow_read_paths_allows_matching(self) -> None:
        """allow_read_paths allows read from allowed path."""
        _, engine, _ = self._make_policy_with_filters(
            {"allow_read_paths": ["/home/user/docs"]},
        )
        result = engine.evaluate(
            "filesystem_read", {"source_path": "/home/user/docs/report.pdf"}
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_no_role_cache_skips_role_filters(self) -> None:
        """Without a role cache, role-aware filters are skipped."""
        skills = {
            "file-manager": {
                "filesystem": ResourcePermissions.model_construct(
                    denied=False,
                    actions={"write": True},
                    filters={"block_write_paths": ["/etc"]},
                ),
            },
        }
        policy = AgentWardPolicy(
            version="1.0",
            skills=skills,
            skill_chaining=[],
            require_approval=[],
        )
        engine = PolicyEngine(policy)  # No role_cache

        # Should ALLOW because role filters are skipped without cache
        result = engine.evaluate(
            "filesystem_write", {"dest_file": "/etc/passwd"}
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_unregistered_tool_skips_role_filters(self) -> None:
        """If tool isn't in the cache, role filters are skipped."""
        _, engine, _ = self._make_policy_with_filters(
            {"block_write_paths": ["/etc"]},
        )
        # Use a tool name that matches the resource but isn't registered in cache
        result = engine.evaluate(
            "filesystem_delete", {"path": "/etc/important"}
        )
        # Tool matches resource "filesystem" but isn't in role cache
        assert result.decision == PolicyDecision.ALLOW
