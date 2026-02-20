"""Tests for Python agent skill/tool scanning via AST analysis."""

from pathlib import Path

import pytest

from agentward.scan.config import TransportType
from agentward.scan.skills import (
    AgentFramework,
    ParameterInfo,
    ToolDefinition,
    _params_to_input_schema,
    scan_directory,
    scan_python_file,
    tools_to_enumeration_results,
)

FIXTURES = Path(__file__).parent / "fixtures" / "python_tools"


class TestScanOpenAI:
    """Tests for OpenAI Agents SDK @function_tool detection."""

    def test_simple_decorator(self) -> None:
        tools = scan_python_file(FIXTURES / "openai_tools.py")
        weather = next(t for t in tools if t.name == "get_weather")
        assert weather.framework == AgentFramework.OPENAI
        assert weather.kind == "function"
        assert weather.description == "Get the current weather for a location."
        assert len(weather.parameters) == 2

    def test_decorator_with_overrides(self) -> None:
        tools = scan_python_file(FIXTURES / "openai_tools.py")
        search = next(t for t in tools if t.name == "search_web")
        assert search.description == "Search the web for information"
        assert search.framework == AgentFramework.OPENAI

    def test_parameter_extraction(self) -> None:
        tools = scan_python_file(FIXTURES / "openai_tools.py")
        weather = next(t for t in tools if t.name == "get_weather")
        location = next(p for p in weather.parameters if p.name == "location")
        assert location.type_annotation == "str"
        assert location.is_required is True
        unit = next(p for p in weather.parameters if p.name == "unit")
        assert unit.is_required is False

    def test_tool_count(self) -> None:
        tools = scan_python_file(FIXTURES / "openai_tools.py")
        assert len(tools) == 2


class TestScanLangChain:
    """Tests for LangChain @tool and BaseTool detection."""

    def test_tool_decorator(self) -> None:
        tools = scan_python_file(FIXTURES / "langchain_tools.py")
        search = next(t for t in tools if t.name == "search_database")
        assert search.framework == AgentFramework.LANGCHAIN
        assert search.kind == "function"
        assert "database" in search.description.lower()

    def test_base_tool_subclass(self) -> None:
        tools = scan_python_file(FIXTURES / "langchain_tools.py")
        reader = next(t for t in tools if t.name == "read_file")
        assert reader.kind == "class"
        assert "Read contents" in reader.description
        assert len(reader.parameters) == 1
        assert reader.parameters[0].name == "file_path"

    def test_tool_count(self) -> None:
        tools = scan_python_file(FIXTURES / "langchain_tools.py")
        assert len(tools) == 2


class TestScanCrewAI:
    """Tests for CrewAI @tool and BaseTool detection."""

    def test_tool_with_string_name(self) -> None:
        tools = scan_python_file(FIXTURES / "crewai_tools.py")
        email = next(t for t in tools if t.name == "Send Email")
        assert email.framework == AgentFramework.CREWAI
        assert email.kind == "function"
        assert len(email.parameters) == 3

    def test_base_tool_subclass(self) -> None:
        tools = scan_python_file(FIXTURES / "crewai_tools.py")
        shell = next(t for t in tools if t.name == "execute_shell")
        assert shell.kind == "class"
        assert shell.parameters[0].name == "command"

    def test_tool_count(self) -> None:
        tools = scan_python_file(FIXTURES / "crewai_tools.py")
        assert len(tools) == 2


class TestScanAnthropic:
    """Tests for Anthropic @beta_tool detection."""

    def test_beta_tool(self) -> None:
        tools = scan_python_file(FIXTURES / "anthropic_tools.py")
        assert len(tools) == 1
        fetch = tools[0]
        assert fetch.name == "fetch_url"
        assert fetch.framework == AgentFramework.ANTHROPIC
        assert any(p.name == "url" for p in fetch.parameters)

    def test_optional_param(self) -> None:
        tools = scan_python_file(FIXTURES / "anthropic_tools.py")
        fetch = tools[0]
        headers = next(p for p in fetch.parameters if p.name == "headers")
        assert headers.is_required is False
        assert headers.type_annotation is not None
        assert "None" in headers.type_annotation or "dict" in headers.type_annotation


class TestNoTools:
    """Files with no tool definitions should return empty list."""

    def test_regular_python_file(self) -> None:
        tools = scan_python_file(FIXTURES / "mixed_no_tools.py")
        assert tools == []


class TestErrorHandling:
    """Tests for error handling in the scanner."""

    def test_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            scan_python_file(Path("/nonexistent/file.py"))

    def test_syntax_error_in_scan_file(self) -> None:
        with pytest.raises(SyntaxError):
            scan_python_file(FIXTURES / "syntax_error.py")

    def test_syntax_error_in_directory_scan_is_skipped(self) -> None:
        """Directory scanning should skip files with syntax errors."""
        tools = scan_directory(FIXTURES)
        # Should still find tools from valid files
        assert len(tools) > 0


class TestParamsToInputSchema:
    """Tests for parameter-to-JSON-schema conversion."""

    def test_simple_string_param(self) -> None:
        params = [ParameterInfo(name="query", type_annotation="str", is_required=True)]
        schema = _params_to_input_schema(params)
        assert schema["properties"]["query"]["type"] == "string"
        assert "query" in schema["required"]

    def test_optional_param_not_required(self) -> None:
        params = [
            ParameterInfo(name="limit", type_annotation="int", default="10", is_required=False),
        ]
        schema = _params_to_input_schema(params)
        assert schema["properties"]["limit"]["type"] == "integer"
        assert "limit" not in schema.get("required", [])

    def test_empty_params(self) -> None:
        schema = _params_to_input_schema([])
        assert schema == {}

    def test_multiple_types(self) -> None:
        params = [
            ParameterInfo(name="name", type_annotation="str", is_required=True),
            ParameterInfo(name="count", type_annotation="int", is_required=True),
            ParameterInfo(name="active", type_annotation="bool", is_required=True),
        ]
        schema = _params_to_input_schema(params)
        assert schema["properties"]["name"]["type"] == "string"
        assert schema["properties"]["count"]["type"] == "integer"
        assert schema["properties"]["active"]["type"] == "boolean"
        assert len(schema["required"]) == 3

    def test_optional_type_stripped(self) -> None:
        params = [ParameterInfo(name="x", type_annotation="Optional[str]", is_required=False)]
        schema = _params_to_input_schema(params)
        assert schema["properties"]["x"]["type"] == "string"

    def test_union_none_stripped(self) -> None:
        params = [ParameterInfo(name="x", type_annotation="dict | None", is_required=False)]
        schema = _params_to_input_schema(params)
        assert schema["properties"]["x"]["type"] == "object"


class TestDirectoryScan:
    """Tests for recursive directory scanning."""

    def test_finds_tools_across_files(self) -> None:
        tools = scan_directory(FIXTURES)
        frameworks = {t.framework for t in tools}
        # Should find tools from at least OpenAI, LangChain, CrewAI, Anthropic
        assert AgentFramework.OPENAI in frameworks
        assert AgentFramework.LANGCHAIN in frameworks
        assert AgentFramework.CREWAI in frameworks
        assert AgentFramework.ANTHROPIC in frameworks

    def test_total_tool_count(self) -> None:
        tools = scan_directory(FIXTURES)
        # openai: 2, langchain: 2, crewai: 2, anthropic: 1 = 7 total
        assert len(tools) == 7

    def test_skips_excluded_dirs(self) -> None:
        # Scanning from the project root with default excludes
        # should not include files from .venv, __pycache__, etc.
        tools = scan_directory(FIXTURES, exclude_dirs=frozenset({"nonexistent_dir"}))
        assert len(tools) >= 7  # should still find fixture tools


class TestToolsToEnumerationResults:
    """Tests for conversion to pipeline-compatible EnumerationResult."""

    def test_groups_by_source_file(self) -> None:
        tools = scan_directory(FIXTURES)
        results = tools_to_enumeration_results(tools)
        # Should have one result per source file with tools
        source_files = {r.server.source_file for r in results}
        assert len(source_files) == len(results)

    def test_server_config_has_python_transport(self) -> None:
        tools = scan_python_file(FIXTURES / "openai_tools.py")
        results = tools_to_enumeration_results(tools)
        assert len(results) == 1
        assert results[0].server.transport == TransportType.PYTHON

    def test_tool_info_has_input_schema(self) -> None:
        tools = scan_python_file(FIXTURES / "openai_tools.py")
        results = tools_to_enumeration_results(tools)
        weather_info = next(t for t in results[0].tools if t.name == "get_weather")
        assert "properties" in weather_info.input_schema
        assert "location" in weather_info.input_schema["properties"]

    def test_enumeration_method_includes_framework(self) -> None:
        tools = scan_python_file(FIXTURES / "openai_tools.py")
        results = tools_to_enumeration_results(tools)
        assert results[0].enumeration_method.startswith("ast_analysis:")

    def test_client_includes_framework(self) -> None:
        tools = scan_python_file(FIXTURES / "crewai_tools.py")
        results = tools_to_enumeration_results(tools)
        assert "python:crewai" in results[0].server.client


class TestEndToEndPipeline:
    """Tests that Python tool results flow through the full permission pipeline."""

    def test_python_tools_get_risk_ratings(self) -> None:
        from agentward.scan.permissions import RiskLevel, build_permission_map

        tools = scan_python_file(FIXTURES / "crewai_tools.py")
        results = tools_to_enumeration_results(tools)
        scan_result = build_permission_map(results)

        assert len(scan_result.servers) > 0
        # execute_shell should be CRITICAL risk (shell access)
        for server_map in scan_result.servers:
            for tool_perm in server_map.tools:
                if tool_perm.tool.name == "execute_shell":
                    assert tool_perm.risk_level == RiskLevel.CRITICAL
                    assert tool_perm.is_read_only is False

    def test_send_email_gets_email_access(self) -> None:
        from agentward.scan.permissions import DataAccessType, build_permission_map

        tools = scan_python_file(FIXTURES / "crewai_tools.py")
        results = tools_to_enumeration_results(tools)
        scan_result = build_permission_map(results)

        for server_map in scan_result.servers:
            for tool_perm in server_map.tools:
                if tool_perm.tool.name == "Send Email":
                    access_types = {a.type for a in tool_perm.data_access}
                    assert DataAccessType.EMAIL in access_types

    def test_python_tools_get_recommendations(self) -> None:
        from agentward.scan.permissions import build_permission_map
        from agentward.scan.recommendations import generate_recommendations

        tools = scan_python_file(FIXTURES / "crewai_tools.py")
        results = tools_to_enumeration_results(tools)
        scan_result = build_permission_map(results)
        recs = generate_recommendations(scan_result)

        # Shell execution tool should trigger recommendations
        assert any(
            "shell" in r.message.lower() or "execute" in r.message.lower()
            for r in recs
        )
