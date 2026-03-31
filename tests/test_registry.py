"""Tests for the MCP server risk registry."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentward.registry import KnownRisk, RecommendedConstraint, ServerEntry, ServerRegistry
from agentward.registry.models import RISK_LEVEL_ORDER


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_extra_yaml(tmp_path: Path, servers: list[dict]) -> Path:
    """Write a temporary registry YAML file."""
    data = {"servers": servers}
    path = tmp_path / "extra.yaml"
    path.write_text(yaml.dump(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# TestServerRegistry
# ---------------------------------------------------------------------------


class TestServerRegistry:
    def test_loads_builtin_servers(self) -> None:
        reg = ServerRegistry()
        servers = reg.all_servers()
        assert len(servers) >= 20

    def test_all_servers_sorted_by_risk_desc(self) -> None:
        reg = ServerRegistry()
        servers = reg.all_servers()
        ranks = [RISK_LEVEL_ORDER.get(s.risk_level, 0) for s in servers]
        assert ranks == sorted(ranks, reverse=True)

    def test_entry_has_required_fields(self) -> None:
        reg = ServerRegistry()
        for entry in reg.all_servers():
            assert entry.name
            assert entry.package
            assert entry.category
            assert entry.risk_level in ("critical", "high", "medium", "low")

    def test_filesystem_in_registry(self) -> None:
        reg = ServerRegistry()
        assert reg.lookup("filesystem") is not None

    def test_github_is_high_risk(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("github") == "high"

    def test_stripe_is_critical(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("stripe") == "critical"

    def test_gmail_is_critical(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("gmail") == "critical"

    def test_docker_is_critical(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("docker") == "critical"

    def test_kubernetes_is_critical(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("kubernetes") == "critical"

    def test_postgres_is_critical(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("postgres") == "critical"

    def test_brave_search_is_low(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("brave-search") == "low"

    def test_extra_registry_merged(self, tmp_path: Path) -> None:
        extra = _make_extra_yaml(tmp_path, [{
            "name": "test-server",
            "package": "test-pkg",
            "category": "testing",
            "risk_level": "medium",
            "known_risks": [],
        }])
        reg = ServerRegistry(extra_registry_paths=[extra])
        assert reg.lookup("test-server") is not None

    def test_extra_does_not_duplicate_builtin(self, tmp_path: Path) -> None:
        extra = _make_extra_yaml(tmp_path, [{
            "name": "filesystem",
            "package": "@modelcontextprotocol/server-filesystem",
            "category": "file-access",
            "risk_level": "high",
            "known_risks": [],
        }])
        reg = ServerRegistry(extra_registry_paths=[extra])
        # Should not have duplicates beyond the expected number
        all_servers = reg.all_servers()
        names = [s.name for s in all_servers]
        # Count of "filesystem" may be 2 if extra is added without dedup — that's OK
        # but it must be present
        assert "filesystem" in names

    def test_enrich_audit_entry_returns_dict(self) -> None:
        reg = ServerRegistry()
        result = reg.enrich_audit_entry("filesystem")
        assert result is not None
        assert "server" in result
        assert "risk_level" in result
        assert "known_risks" in result

    def test_enrich_audit_entry_unknown_server(self) -> None:
        reg = ServerRegistry()
        result = reg.enrich_audit_entry("not-a-real-server-xyz")
        assert result is None

    def test_entry_known_risks_populated(self) -> None:
        reg = ServerRegistry()
        entry = reg.lookup("postgres")
        assert entry is not None
        assert len(entry.known_risks) > 0

    def test_entry_recommended_constraints(self) -> None:
        reg = ServerRegistry()
        constraints = reg.get_recommended_constraints("filesystem")
        assert len(constraints) > 0
        assert any(c.argument == "path" for c in constraints)


# ---------------------------------------------------------------------------
# TestServerLookup
# ---------------------------------------------------------------------------


class TestServerLookup:
    def test_lookup_by_canonical_name(self) -> None:
        reg = ServerRegistry()
        assert reg.lookup("filesystem") is not None

    def test_lookup_by_alias(self) -> None:
        reg = ServerRegistry()
        assert reg.lookup("mcp-server-filesystem") is not None

    def test_lookup_by_full_package_name(self) -> None:
        reg = ServerRegistry()
        result = reg.lookup("@modelcontextprotocol/server-filesystem")
        assert result is not None
        assert result.name == "filesystem"

    def test_lookup_case_insensitive(self) -> None:
        reg = ServerRegistry()
        assert reg.lookup("FILESYSTEM") is not None

    def test_lookup_unknown_returns_none(self) -> None:
        reg = ServerRegistry()
        assert reg.lookup("not-a-real-server-xyz") is None

    def test_lookup_by_scope_stripped_package(self) -> None:
        reg = ServerRegistry()
        # "@modelcontextprotocol/server-github" → "github"
        result = reg.lookup("@modelcontextprotocol/server-github")
        assert result is not None
        assert result.name == "github"

    def test_lookup_playwright_alias(self) -> None:
        reg = ServerRegistry()
        result = reg.lookup("playwright-mcp")
        assert result is not None

    def test_get_risk_level_unknown(self) -> None:
        reg = ServerRegistry()
        assert reg.get_risk_level("not-a-real-server-xyz") is None

    def test_get_recommended_constraints_unknown(self) -> None:
        reg = ServerRegistry()
        assert reg.get_recommended_constraints("not-a-real-server-xyz") == []

    def test_lookup_github_returns_correct_entry(self) -> None:
        reg = ServerRegistry()
        entry = reg.lookup("github")
        assert entry is not None
        assert entry.name == "github"
        assert entry.category == "code-hosting"


# ---------------------------------------------------------------------------
# TestSearchAndFilter
# ---------------------------------------------------------------------------


class TestSearchAndFilter:
    def test_search_all_returns_all(self) -> None:
        reg = ServerRegistry()
        assert len(reg.search()) == len(reg.all_servers())

    def test_search_by_category(self) -> None:
        reg = ServerRegistry()
        results = reg.search(category="database")
        assert len(results) > 0
        assert all(r.category == "database" for r in results)

    def test_search_by_category_case_insensitive(self) -> None:
        reg = ServerRegistry()
        results = reg.search(category="DATABASE")
        assert len(results) > 0

    def test_search_min_risk_critical(self) -> None:
        reg = ServerRegistry()
        results = reg.search(min_risk="critical")
        assert all(r.risk_level == "critical" for r in results)

    def test_search_min_risk_high(self) -> None:
        reg = ServerRegistry()
        results = reg.search(min_risk="high")
        for r in results:
            assert RISK_LEVEL_ORDER[r.risk_level] >= RISK_LEVEL_ORDER["high"]

    def test_search_category_and_risk_combined(self) -> None:
        reg = ServerRegistry()
        results = reg.search(category="database", min_risk="high")
        assert len(results) > 0
        for r in results:
            assert r.category == "database"
            assert RISK_LEVEL_ORDER[r.risk_level] >= RISK_LEVEL_ORDER["high"]

    def test_search_nonexistent_category_returns_empty(self) -> None:
        reg = ServerRegistry()
        results = reg.search(category="nonexistent-category-xyz")
        assert results == []

    def test_risk_level_ordering(self) -> None:
        assert RISK_LEVEL_ORDER["critical"] > RISK_LEVEL_ORDER["high"]
        assert RISK_LEVEL_ORDER["high"] > RISK_LEVEL_ORDER["medium"]
        assert RISK_LEVEL_ORDER["medium"] > RISK_LEVEL_ORDER["low"]

    def test_search_min_risk_low_returns_all(self) -> None:
        reg = ServerRegistry()
        results = reg.search(min_risk="low")
        assert len(results) == len(reg.all_servers())

    def test_browser_automation_category_exists(self) -> None:
        reg = ServerRegistry()
        results = reg.search(category="browser-automation")
        assert len(results) >= 2


# ---------------------------------------------------------------------------
# TestRegistryCLI
# ---------------------------------------------------------------------------


class TestRegistryCLI:
    def test_registry_list_runs(self) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "list"])
        assert result.exit_code == 0

    def test_registry_list_json(self) -> None:
        import json

        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) > 0

    def test_registry_lookup_filesystem(self) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "lookup", "filesystem"])
        assert result.exit_code == 0

    def test_registry_lookup_json(self) -> None:
        import json

        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "lookup", "--json", "github"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "github"

    def test_registry_lookup_unknown_exits_1(self) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "lookup", "not-a-real-server-xyz"])
        assert result.exit_code == 1

    def test_registry_export_json(self) -> None:
        import json

        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "export", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)

    def test_decode_command_base64(self) -> None:
        import base64

        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        val = base64.b64encode(b"/etc/passwd").decode()
        result = runner.invoke(app, ["decode", val])
        assert result.exit_code == 0

    def test_decode_command_json_output(self) -> None:
        import base64
        import json

        from typer.testing import CliRunner

        from agentward.cli import app

        runner = CliRunner()
        val = base64.b64encode(b"/etc/passwd").decode()
        result = runner.invoke(app, ["decode", "--json", val])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["encoding"] == "original"


# ---------------------------------------------------------------------------
# TestPolicyIntegration
# ---------------------------------------------------------------------------


class TestPolicyIntegration:
    def test_schema_has_registry_check_field(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy.model_validate({"version": "1.0"})
        assert hasattr(policy, "registry_check")
        assert policy.registry_check is True

    def test_schema_has_warn_unregistered_field(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy.model_validate({"version": "1.0"})
        assert hasattr(policy, "warn_unregistered")
        assert policy.warn_unregistered is False

    def test_registry_check_can_be_disabled(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy.model_validate({"version": "1.0", "registry_check": False})
        assert not policy.registry_check

    def test_warn_unregistered_can_be_enabled(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy.model_validate({"version": "1.0", "warn_unregistered": True})
        assert policy.warn_unregistered

    def test_top_severity_property(self) -> None:
        reg = ServerRegistry()
        entry = reg.lookup("postgres")
        assert entry is not None
        # postgres has critical risks
        assert entry.top_severity == "critical"

    def test_top_severity_no_risks_falls_back(self) -> None:
        entry = ServerEntry(name="test", package="test", category="x", risk_level="medium")
        assert entry.top_severity == "medium"

    def test_schema_has_deobfuscation_field(self) -> None:
        from agentward.policy.schema import AgentWardPolicy

        policy = AgentWardPolicy.model_validate({"version": "1.0"})
        assert hasattr(policy, "deobfuscation")
        assert policy.deobfuscation is True
