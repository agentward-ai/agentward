"""Python agent tool/skill scanner via AST analysis.

Parses Python source files to find tool definitions from major agent frameworks:
  - OpenAI Agents SDK: @function_tool
  - LangChain/LangGraph: @tool, BaseTool subclass
  - CrewAI: @tool("Name"), BaseTool subclass
  - Anthropic Claude SDK: @beta_tool

Safety: This module NEVER imports or executes user code. All analysis uses
ast.parse() only — the Python file is read as text and parsed into an AST
without any code execution.

Limitations:
  - Dynamic tool registration (StructuredTool.from_function(), runtime construction)
    is not detectable from static analysis.
  - Pydantic model resolution for args_schema references requires imports and is
    not performed. The scanner extracts what's visible in the AST.
  - Complex type annotations (Annotated[str, Field(...)]) are captured as strings
    but not fully resolved.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from agentward.scan.config import ServerConfig, TransportType
from agentward.scan.enumerator import EnumerationResult, ToolInfo


class AgentFramework(str, Enum):
    """Agent framework that a tool definition belongs to."""

    OPENAI = "openai"
    LANGCHAIN = "langchain"
    CREWAI = "crewai"
    ANTHROPIC = "anthropic"
    UNKNOWN = "unknown"


@dataclass
class ParameterInfo:
    """A single parameter extracted from a function signature."""

    name: str
    type_annotation: str | None = None
    default: str | None = None
    is_required: bool = True


@dataclass
class ToolDefinition:
    """A tool definition extracted from a Python source file via AST."""

    name: str
    description: str | None = None
    parameters: list[ParameterInfo] = field(default_factory=list)
    framework: AgentFramework = AgentFramework.UNKNOWN
    source_file: Path = field(default_factory=lambda: Path("."))
    line_number: int = 0
    kind: str = "function"  # "function" or "class"


# ---------------------------------------------------------------------------
# Decorator → framework mapping
# ---------------------------------------------------------------------------

_DECORATOR_FRAMEWORKS: dict[str, AgentFramework] = {
    "function_tool": AgentFramework.OPENAI,
    "tool": AgentFramework.LANGCHAIN,  # also CrewAI — disambiguated via imports
    "beta_tool": AgentFramework.ANTHROPIC,
}

_BASE_TOOL_CLASSES: frozenset[str] = frozenset({"BaseTool"})

# Directories to skip during recursive scanning
_EXCLUDED_DIRS: frozenset[str] = frozenset({
    "__pycache__", ".git", ".venv", "venv", "env", ".env",
    "node_modules", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "dist", "build", ".eggs", "site-packages",
})

# ---------------------------------------------------------------------------
# Type hint → JSON Schema mapping
# ---------------------------------------------------------------------------

_TYPE_TO_JSON_SCHEMA: dict[str, dict[str, Any]] = {
    "str": {"type": "string"},
    "int": {"type": "integer"},
    "float": {"type": "number"},
    "bool": {"type": "boolean"},
    "list": {"type": "array"},
    "dict": {"type": "object"},
    "bytes": {"type": "string", "format": "binary"},
    "Any": {},
}


# ---------------------------------------------------------------------------
# AST helper functions
# ---------------------------------------------------------------------------


def _annotation_to_str(node: ast.expr | None) -> str | None:
    """Convert an AST annotation node to a human-readable type string.

    Args:
        node: An AST expression node representing a type annotation.

    Returns:
        A string like "str", "list[int]", "str | None", or None.
    """
    if node is None:
        return None
    # Python 3.9+ has ast.unparse which handles everything
    try:
        return ast.unparse(node)
    except Exception:
        return None


def _extract_decorator_name(node: ast.expr) -> str | None:
    """Extract the base name from a decorator node.

    Handles: @tool, @tool(...), @module.tool, @module.tool(...)

    Args:
        node: A decorator AST node.

    Returns:
        The decorator name (e.g., "tool", "function_tool"), or None.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _extract_decorator_name(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _extract_decorator_args(node: ast.expr) -> dict[str, str]:
    """Extract keyword arguments from a decorator call.

    Handles patterns like:
      @function_tool(name_override="x", description_override="y")
      @tool("Tool Name")  — positional string arg treated as name

    Args:
        node: A decorator AST node.

    Returns:
        Dict of extracted string arguments.
    """
    if not isinstance(node, ast.Call):
        return {}

    overrides: dict[str, str] = {}

    # Positional string arg → treat as name (CrewAI pattern: @tool("Name"))
    if node.args:
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            overrides["name"] = first.value

    # Keyword string args
    for kw in node.keywords:
        if kw.arg and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            overrides[kw.arg] = kw.value.value

    return overrides


def _extract_function_params(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ParameterInfo]:
    """Extract parameters from a function definition, skipping self/cls.

    Args:
        node: A function definition AST node.

    Returns:
        List of ParameterInfo for each meaningful parameter.
    """
    params: list[ParameterInfo] = []
    args = node.args

    # Defaults align to the END of the args list
    num_defaults = len(args.defaults)
    num_args = len(args.args)

    for i, arg in enumerate(args.args):
        if arg.arg in ("self", "cls"):
            continue

        type_str = _annotation_to_str(arg.annotation)

        # Check if this arg has a default
        default_index = i - (num_args - num_defaults)
        has_default = default_index >= 0
        default_str = None
        if has_default:
            default_node = args.defaults[default_index]
            try:
                default_str = ast.unparse(default_node)
            except Exception:
                default_str = "..."

        params.append(ParameterInfo(
            name=arg.arg,
            type_annotation=type_str,
            default=default_str,
            is_required=not has_default,
        ))

    return params


def _extract_class_attribute(node: ast.ClassDef, attr_name: str) -> str | None:
    """Extract a string class attribute value from a class body.

    Handles:
      name: str = "my_tool"
      name = "my_tool"

    Args:
        node: A class definition AST node.
        attr_name: The attribute name to look for.

    Returns:
        The string value, or None if not found.
    """
    for stmt in node.body:
        # Annotated assignment: name: str = "my_tool"
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            if stmt.target.id == attr_name and stmt.value:
                if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                    return stmt.value.value
        # Plain assignment: name = "my_tool"
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == attr_name:
                    if isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                        return stmt.value.value
    return None


def _extract_run_method_params(node: ast.ClassDef) -> list[ParameterInfo]:
    """Extract parameters from the _run method of a BaseTool subclass.

    Args:
        node: A class definition AST node.

    Returns:
        Parameters from _run (excluding self), or empty list.
    """
    for stmt in node.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name == "_run":
                return _extract_function_params(stmt)
    return []


def _inherits_base_tool(node: ast.ClassDef) -> bool:
    """Check if a class inherits from BaseTool.

    Args:
        node: A class definition AST node.

    Returns:
        True if any base class is named BaseTool.
    """
    for base in node.bases:
        if isinstance(base, ast.Name) and base.id in _BASE_TOOL_CLASSES:
            return True
        if isinstance(base, ast.Attribute) and base.attr in _BASE_TOOL_CLASSES:
            return True
    return False


def _params_to_input_schema(params: list[ParameterInfo]) -> dict[str, Any]:
    """Convert extracted parameters to a JSON Schema-like input_schema dict.

    This produces the same format as MCP tools/list responses, so the
    downstream permission analysis pipeline works identically.

    Args:
        params: List of parameters extracted from a function/method.

    Returns:
        A JSON Schema dict, or empty dict if no params.
    """
    if not params:
        return {}

    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in params:
        prop: dict[str, Any] = {}

        if param.type_annotation:
            type_str = param.type_annotation

            # Strip Optional[...] wrapper
            if type_str.startswith("Optional[") and type_str.endswith("]"):
                type_str = type_str[9:-1]

            # Strip ... | None unions
            if " | None" in type_str:
                type_str = type_str.replace(" | None", "").strip()
            elif "None | " in type_str:
                type_str = type_str.replace("None | ", "").strip()

            # Get the base type (e.g., list[str] → list)
            base_type = type_str.split("[")[0].strip()
            schema_type = _TYPE_TO_JSON_SCHEMA.get(base_type, {})
            prop.update(schema_type)

        properties[param.name] = prop

        if param.is_required:
            required.append(param.name)

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
    }
    if required:
        schema["required"] = required

    return schema


# ---------------------------------------------------------------------------
# AST Visitor
# ---------------------------------------------------------------------------


class ToolDefinitionVisitor(ast.NodeVisitor):
    """AST visitor that finds tool definitions across agent frameworks.

    Tracks import statements to disambiguate the @tool decorator
    (used by both LangChain and CrewAI).
    """

    def __init__(self, source_file: Path) -> None:
        self.source_file = source_file
        self.tools: list[ToolDefinition] = []
        self._imports: dict[str, str] = {}  # imported_name → module path

    def visit_Import(self, node: ast.Import) -> None:
        """Track plain import statements."""
        for alias in node.names:
            name = alias.asname or alias.name
            self._imports[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-import statements for framework disambiguation."""
        if node.module and node.names:
            for alias in node.names:
                imported_name = alias.asname or alias.name
                self._imports[imported_name] = node.module
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definitions for tool decorators."""
        self._check_function_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Check async function definitions for tool decorators."""
        self._check_function_decorators(node)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Check class definitions for BaseTool subclasses."""
        if _inherits_base_tool(node):
            framework = self._resolve_class_framework()
            name = _extract_class_attribute(node, "name") or node.name
            description = _extract_class_attribute(node, "description") or ast.get_docstring(node)
            params = _extract_run_method_params(node)

            self.tools.append(ToolDefinition(
                name=name,
                description=description,
                parameters=params,
                framework=framework,
                source_file=self.source_file,
                line_number=node.lineno,
                kind="class",
            ))
        self.generic_visit(node)

    def _check_function_decorators(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Check if a function has a known tool decorator."""
        for decorator in node.decorator_list:
            decorator_name = _extract_decorator_name(decorator)
            if decorator_name and decorator_name in _DECORATOR_FRAMEWORKS:
                framework = self._resolve_framework(decorator_name)
                overrides = _extract_decorator_args(decorator)

                name = (
                    overrides.get("name")
                    or overrides.get("name_override")
                    or node.name
                )
                description = (
                    overrides.get("description")
                    or overrides.get("description_override")
                    or ast.get_docstring(node)
                )
                params = _extract_function_params(node)

                self.tools.append(ToolDefinition(
                    name=name,
                    description=description,
                    parameters=params,
                    framework=framework,
                    source_file=self.source_file,
                    line_number=node.lineno,
                    kind="function",
                ))
                return  # Only match first decorator

    def _resolve_framework(self, decorator_name: str) -> AgentFramework:
        """Resolve which framework a decorator belongs to using import context."""
        if decorator_name == "function_tool":
            return AgentFramework.OPENAI
        if decorator_name == "beta_tool":
            return AgentFramework.ANTHROPIC
        if decorator_name == "tool":
            module = self._imports.get("tool", "")
            if "crewai" in module:
                return AgentFramework.CREWAI
            if "langchain" in module:
                return AgentFramework.LANGCHAIN
            # Default to langchain if ambiguous (more common)
            return AgentFramework.LANGCHAIN
        return AgentFramework.UNKNOWN

    def _resolve_class_framework(self) -> AgentFramework:
        """Resolve which framework a BaseTool subclass belongs to."""
        module = self._imports.get("BaseTool", "")
        if "crewai" in module:
            return AgentFramework.CREWAI
        if "langchain" in module:
            return AgentFramework.LANGCHAIN
        # Default to langchain
        return AgentFramework.LANGCHAIN


# ---------------------------------------------------------------------------
# Public scanning functions
# ---------------------------------------------------------------------------


def scan_python_file(path: Path) -> list[ToolDefinition]:
    """Parse a single Python file and extract all tool definitions.

    Uses AST parsing only — never imports or executes the file.

    Args:
        path: Path to a .py file.

    Returns:
        List of ToolDefinition objects found in the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        SyntaxError: If the file contains invalid Python syntax.
    """
    if not path.exists():
        raise FileNotFoundError(f"Python file not found: {path}")

    source = path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        raise SyntaxError(
            f"Failed to parse {path}: {e.msg} (line {e.lineno})"
        ) from e

    visitor = ToolDefinitionVisitor(source_file=path)
    visitor.visit(tree)
    return visitor.tools


def scan_directory(
    directory: Path,
    exclude_dirs: frozenset[str] | None = None,
) -> list[ToolDefinition]:
    """Recursively scan a directory for Python files with tool definitions.

    Skips common non-source directories (__pycache__, .venv, .git, etc.).
    Files with syntax errors are silently skipped.

    Args:
        directory: Root directory to scan.
        exclude_dirs: Directory names to skip. Defaults to common non-source dirs.

    Returns:
        All tool definitions found across all Python files.
    """
    if exclude_dirs is None:
        exclude_dirs = _EXCLUDED_DIRS

    all_tools: list[ToolDefinition] = []

    for py_file in directory.rglob("*.py"):
        # Skip excluded directories
        if any(part in exclude_dirs for part in py_file.parts):
            continue

        try:
            tools = scan_python_file(py_file)
            all_tools.extend(tools)
        except (SyntaxError, UnicodeDecodeError) as e:
            from rich.console import Console as _Console
            _warn_console = _Console(stderr=True)
            _warn_console.print(
                f"  [#ffcc00]⚠[/#ffcc00] Skipping {py_file}: {e}",
                highlight=False,
            )
            continue

    return all_tools


def tools_to_enumeration_results(
    tools: list[ToolDefinition],
) -> list[EnumerationResult]:
    """Convert Python tool definitions into EnumerationResults.

    Groups tools by source file, creating one EnumerationResult per file.
    Each file is represented as a "virtual server" using ServerConfig
    with transport=PYTHON.

    This produces the same data structure as MCP server enumeration,
    so the downstream permission/risk pipeline works identically.

    Args:
        tools: Tool definitions extracted from Python files.

    Returns:
        A list of EnumerationResult objects, one per source file.
    """
    # Group by source file
    by_file: dict[Path, list[ToolDefinition]] = defaultdict(list)
    for tool_def in tools:
        by_file[tool_def.source_file].append(tool_def)

    results: list[EnumerationResult] = []
    for source_file, file_tools in by_file.items():
        # Determine the dominant framework for this file
        framework = file_tools[0].framework

        # Create a "virtual server" representing this Python file
        server = ServerConfig(
            name=source_file.stem,
            transport=TransportType.PYTHON,
            source_file=source_file,
            client=f"python:{framework.value}",
        )

        tool_infos = [
            ToolInfo(
                name=td.name,
                description=td.description,
                input_schema=_params_to_input_schema(td.parameters),
            )
            for td in file_tools
        ]

        results.append(EnumerationResult(
            server=server,
            tools=tool_infos,
            capabilities=None,
            enumeration_method=f"ast_analysis:{framework.value}",
        ))

    return results
