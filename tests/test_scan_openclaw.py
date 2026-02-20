"""Tests for the OpenClaw/ClawdBot skill scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentward.scan.config import TransportType
from agentward.scan.openclaw import (
    ClawdBotConfig,
    SkillDefinition,
    SkillRequirements,
    config_to_enumeration_result,
    parse_clawdbot_config,
    parse_skill_md,
    scan_openclaw_directory,
    scan_skill_directory,
    skills_to_enumeration_results,
    _parse_frontmatter,
    _skill_to_tool_info,
)
from agentward.scan.permissions import (
    DataAccessType,
    RiskLevel,
    build_permission_map,
)
from agentward.scan.recommendations import generate_recommendations

FIXTURES = Path(__file__).parent / "fixtures" / "openclaw_skills"


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------


class TestParseFrontmatter:
    """Test YAML frontmatter parsing from SKILL.md files."""

    def test_basic_frontmatter(self) -> None:
        text = "---\nname: test\ndescription: A test skill\n---\n# Body\nHello"
        fm, body = _parse_frontmatter(text)
        assert fm["name"] == "test"
        assert fm["description"] == "A test skill"
        assert "Hello" in body

    def test_no_frontmatter_raises(self) -> None:
        with pytest.raises(ValueError, match="No YAML frontmatter"):
            _parse_frontmatter("# Just markdown\nNo frontmatter here")

    def test_unclosed_frontmatter_raises(self) -> None:
        with pytest.raises(ValueError, match="No closing ---"):
            _parse_frontmatter("---\nname: test\nstill going")

    def test_bom_stripped(self) -> None:
        text = "\ufeff---\nname: bom-test\n---\nBody"
        fm, body = _parse_frontmatter(text)
        assert fm["name"] == "bom-test"

    def test_empty_body(self) -> None:
        text = "---\nname: empty\n---\n"
        fm, body = _parse_frontmatter(text)
        assert fm["name"] == "empty"
        assert body == ""


# ---------------------------------------------------------------------------
# SKILL.md parsing
# ---------------------------------------------------------------------------


class TestParseSkillMd:
    """Test parsing individual SKILL.md files."""

    def test_email_manager(self) -> None:
        skill = parse_skill_md(FIXTURES / "email-manager" / "SKILL.md")
        assert skill.name == "email-manager"
        assert "himalaya" in (skill.description or "")
        assert skill.homepage == "https://github.com/pimalaya/himalaya"
        assert skill.requirements.bins == ["himalaya"]
        assert skill.requirements.env == ["IMAP_PASSWORD"]
        assert skill.primary_env == "IMAP_PASSWORD"
        assert "darwin" in skill.os_platforms
        assert "linux" in skill.os_platforms

    def test_shell_runner(self) -> None:
        skill = parse_skill_md(FIXTURES / "shell-runner" / "SKILL.md")
        assert skill.name == "shell-runner"
        assert "bash" in skill.requirements.bins
        assert "curl" in skill.requirements.bins

    def test_api_client(self) -> None:
        skill = parse_skill_md(FIXTURES / "api-client" / "SKILL.md")
        assert skill.name == "api-client"
        assert "API_KEY" in skill.requirements.env
        assert "API_SECRET" in skill.requirements.env
        assert skill.primary_env == "API_KEY"
        assert "win32" in skill.os_platforms

    def test_minimal_skill(self) -> None:
        skill = parse_skill_md(FIXTURES / "minimal-skill" / "SKILL.md")
        assert skill.name == "minimal-skill"
        assert skill.requirements.bins == []
        assert skill.requirements.env == []

    def test_coding_agent_any_bins(self) -> None:
        skill = parse_skill_md(FIXTURES / "coding-agent" / "SKILL.md")
        assert skill.name == "coding-agent"
        assert "claude" in skill.requirements.any_bins
        assert "codex" in skill.requirements.any_bins

    def test_no_frontmatter_raises(self) -> None:
        with pytest.raises(ValueError, match="No YAML frontmatter"):
            parse_skill_md(FIXTURES / "no-frontmatter" / "SKILL.md")

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_skill_md(FIXTURES / "nonexistent" / "SKILL.md")

    def test_install_steps_parsed(self) -> None:
        skill = parse_skill_md(FIXTURES / "email-manager" / "SKILL.md")
        assert len(skill.install_steps) == 1
        assert skill.install_steps[0]["kind"] == "brew"
        assert skill.install_steps[0]["formula"] == "himalaya"


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------


class TestScanSkillDirectory:
    """Test scanning a directory of skills."""

    def test_scan_fixtures(self) -> None:
        skills = scan_skill_directory(FIXTURES)
        # Should find all valid skills (not no-frontmatter)
        names = {s.name for s in skills}
        assert "email-manager" in names
        assert "shell-runner" in names
        assert "api-client" in names
        assert "minimal-skill" in names
        assert "coding-agent" in names
        # no-frontmatter should be skipped (ValueError during parsing)

    def test_scan_nonexistent_directory(self) -> None:
        result = scan_skill_directory(Path("/nonexistent/path"))
        assert result == []

    def test_skill_count(self) -> None:
        skills = scan_skill_directory(FIXTURES)
        assert len(skills) == 5  # 5 valid skills, 1 invalid (no-frontmatter)


# ---------------------------------------------------------------------------
# Tool info conversion
# ---------------------------------------------------------------------------


class TestSkillToToolInfo:
    """Test converting SkillDefinition to ToolInfo."""

    def test_email_manager_tool_info(self) -> None:
        skill = parse_skill_md(FIXTURES / "email-manager" / "SKILL.md")
        tool = _skill_to_tool_info(skill)
        assert tool.name == "email-manager"
        assert tool.description is not None
        assert "himalaya" in tool.description

    def test_shell_runner_has_shell_signals(self) -> None:
        skill = parse_skill_md(FIXTURES / "shell-runner" / "SKILL.md")
        tool = _skill_to_tool_info(skill)
        # bash binary should create a shell signal in the schema
        props = tool.input_schema.get("properties", {})
        shell_keys = [k for k in props if "shell" in k]
        assert len(shell_keys) > 0, "Expected shell signal in schema properties"

    def test_api_client_has_credential_signals(self) -> None:
        skill = parse_skill_md(FIXTURES / "api-client" / "SKILL.md")
        tool = _skill_to_tool_info(skill)
        # API_KEY should create a credential signal
        desc = tool.description or ""
        assert "API_KEY" in desc

    def test_minimal_skill_empty_schema(self) -> None:
        skill = parse_skill_md(FIXTURES / "minimal-skill" / "SKILL.md")
        tool = _skill_to_tool_info(skill)
        assert tool.input_schema == {}

    def test_coding_agent_shell_signals(self) -> None:
        skill = parse_skill_md(FIXTURES / "coding-agent" / "SKILL.md")
        tool = _skill_to_tool_info(skill)
        # anyBins with claude/codex should create shell signals
        props = tool.input_schema.get("properties", {})
        shell_keys = [k for k in props if "shell" in k]
        assert len(shell_keys) > 0


# ---------------------------------------------------------------------------
# Enumeration results bridge
# ---------------------------------------------------------------------------


class TestSkillsToEnumerationResults:
    """Test converting skills to EnumerationResult objects."""

    def test_basic_conversion(self) -> None:
        skills = scan_skill_directory(FIXTURES)
        results = skills_to_enumeration_results(skills, "test")
        assert len(results) >= 1
        # All should use OPENCLAW transport
        for r in results:
            assert r.server.transport == TransportType.OPENCLAW

    def test_tools_populated(self) -> None:
        skills = scan_skill_directory(FIXTURES)
        results = skills_to_enumeration_results(skills, "test")
        total_tools = sum(len(r.tools) for r in results)
        assert total_tools == 5  # 5 valid skills

    def test_enumeration_method(self) -> None:
        skills = scan_skill_directory(FIXTURES)
        results = skills_to_enumeration_results(skills, "test")
        for r in results:
            assert r.enumeration_method.startswith("skill_md:")

    def test_empty_skills(self) -> None:
        results = skills_to_enumeration_results([], "test")
        assert results == []


# ---------------------------------------------------------------------------
# clawdbot.json parsing
# ---------------------------------------------------------------------------


class TestParseClawdBotConfig:
    """Test parsing clawdbot.json files."""

    def test_full_config(self) -> None:
        config = parse_clawdbot_config(FIXTURES / "clawdbot.json")
        assert "anthropic" in config.auth_profiles
        assert "github" in config.auth_profiles
        assert "whatsapp" in config.channels
        assert "telegram" in config.channels
        assert config.gateway_enabled is True
        assert config.gateway_port == 18789
        assert config.gateway_has_auth is True
        assert "session-memory" in config.enabled_hooks
        assert "auto-reply" in config.enabled_plugins

    def test_no_auth_gateway(self) -> None:
        config = parse_clawdbot_config(FIXTURES / "clawdbot_no_auth_gateway.json")
        assert config.auth_profiles == []
        assert config.channels == []
        assert config.gateway_enabled is True
        assert config.gateway_port == 8080
        assert config.gateway_has_auth is False

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_clawdbot_config(Path("/nonexistent/clawdbot.json"))


# ---------------------------------------------------------------------------
# Config to EnumerationResult
# ---------------------------------------------------------------------------


class TestConfigToEnumerationResult:
    """Test converting clawdbot.json to EnumerationResult."""

    def test_full_config_result(self) -> None:
        config = parse_clawdbot_config(FIXTURES / "clawdbot.json")
        result = config_to_enumeration_result(config)
        assert result is not None
        assert result.server.transport == TransportType.OPENCLAW
        # Should have tools for auth profiles, channels, and gateway
        tool_names = {t.name for t in result.tools}
        assert "auth:anthropic" in tool_names
        assert "auth:github" in tool_names
        assert "channel:whatsapp" in tool_names
        assert "channel:telegram" in tool_names
        assert "gateway" in tool_names

    def test_no_auth_gateway_result(self) -> None:
        config = parse_clawdbot_config(FIXTURES / "clawdbot_no_auth_gateway.json")
        result = config_to_enumeration_result(config)
        assert result is not None
        tool_names = {t.name for t in result.tools}
        assert "gateway" in tool_names
        # Gateway without auth should note it
        gateway_tool = next(t for t in result.tools if t.name == "gateway")
        assert "NO AUTH" in (gateway_tool.description or "")

    def test_empty_config_returns_none(self) -> None:
        config = ClawdBotConfig(
            source_file=Path("/tmp/empty.json"),
            auth_profiles=[],
            channels=[],
            gateway_enabled=False,
        )
        result = config_to_enumeration_result(config)
        assert result is None


# ---------------------------------------------------------------------------
# End-to-end: OpenClaw → permission map → risk analysis
# ---------------------------------------------------------------------------


class TestEndToEndPipeline:
    """Test that OpenClaw skills flow through the full scan pipeline."""

    def test_shell_runner_is_critical(self) -> None:
        """Shell-runner skill should be rated CRITICAL due to bash binary."""
        skills = [parse_skill_md(FIXTURES / "shell-runner" / "SKILL.md")]
        results = skills_to_enumeration_results(skills, "test")
        scan_result = build_permission_map(results)

        assert len(scan_result.servers) == 1
        server_map = scan_result.servers[0]

        # Find the shell-runner tool
        shell_tool = next(
            (t for t in server_map.tools if t.tool.name == "shell-runner"),
            None,
        )
        assert shell_tool is not None
        assert shell_tool.risk_level == RiskLevel.CRITICAL

    def test_api_client_has_credentials_access(self) -> None:
        """api-client skill should detect credential access from env vars."""
        skills = [parse_skill_md(FIXTURES / "api-client" / "SKILL.md")]
        results = skills_to_enumeration_results(skills, "test")
        scan_result = build_permission_map(results)

        server_map = scan_result.servers[0]
        api_tool = next(
            (t for t in server_map.tools if t.tool.name == "api-client"),
            None,
        )
        assert api_tool is not None
        access_types = {a.type for a in api_tool.data_access}
        assert DataAccessType.CREDENTIALS in access_types

    def test_email_manager_has_email_access(self) -> None:
        """email-manager skill should detect email access from himalaya binary."""
        skills = [parse_skill_md(FIXTURES / "email-manager" / "SKILL.md")]
        results = skills_to_enumeration_results(skills, "test")
        scan_result = build_permission_map(results)

        server_map = scan_result.servers[0]
        email_tool = next(
            (t for t in server_map.tools if t.tool.name == "email-manager"),
            None,
        )
        assert email_tool is not None
        access_types = {a.type for a in email_tool.data_access}
        assert DataAccessType.EMAIL in access_types

    def test_coding_agent_is_critical(self) -> None:
        """coding-agent with claude/codex binaries should be CRITICAL."""
        skills = [parse_skill_md(FIXTURES / "coding-agent" / "SKILL.md")]
        results = skills_to_enumeration_results(skills, "test")
        scan_result = build_permission_map(results)

        server_map = scan_result.servers[0]
        agent_tool = next(
            (t for t in server_map.tools if t.tool.name == "coding-agent"),
            None,
        )
        assert agent_tool is not None
        assert agent_tool.risk_level == RiskLevel.CRITICAL

    def test_minimal_skill_is_low_risk(self) -> None:
        """minimal-skill with no requirements should be LOW risk."""
        skills = [parse_skill_md(FIXTURES / "minimal-skill" / "SKILL.md")]
        results = skills_to_enumeration_results(skills, "test")
        scan_result = build_permission_map(results)

        server_map = scan_result.servers[0]
        minimal_tool = next(
            (t for t in server_map.tools if t.tool.name == "minimal-skill"),
            None,
        )
        assert minimal_tool is not None
        assert minimal_tool.risk_level == RiskLevel.LOW

    def test_recommendations_generated(self) -> None:
        """Shell and credential tools should trigger recommendations."""
        skills = scan_skill_directory(FIXTURES)
        results = skills_to_enumeration_results(skills, "test")
        scan_result = build_permission_map(results)
        recs = generate_recommendations(scan_result)
        # Shell-runner should trigger a CRITICAL shell recommendation
        critical_recs = [r for r in recs if r.severity.value == "CRITICAL"]
        assert len(critical_recs) > 0

    def test_directory_scan_function(self) -> None:
        """scan_openclaw_directory should work end-to-end."""
        results = scan_openclaw_directory(FIXTURES)
        assert len(results) >= 1
        total_tools = sum(len(r.tools) for r in results)
        assert total_tools == 5

    def test_clawdbot_config_flows_through_pipeline(self) -> None:
        """clawdbot.json analysis should flow through the permission pipeline."""
        config = parse_clawdbot_config(FIXTURES / "clawdbot.json")
        result = config_to_enumeration_result(config)
        assert result is not None

        scan_result = build_permission_map([result])
        assert len(scan_result.servers) == 1

        # Auth tools should have credential access
        server_map = scan_result.servers[0]
        auth_tools = [t for t in server_map.tools if t.tool.name.startswith("auth:")]
        assert len(auth_tools) >= 2
        for auth_tool in auth_tools:
            access_types = {a.type for a in auth_tool.data_access}
            assert DataAccessType.CREDENTIALS in access_types
