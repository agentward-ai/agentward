"""Argument-role classification for tool parameters.

Classifies tool input parameters into semantic roles (READ_PATH, WRITE_PATH,
URL, RECIPIENT, CONTENT_BODY, CREDENTIAL, UNKNOWN) based on:
  1. MCP tool annotations (readOnlyHint, destructiveHint)
  2. JSON Schema hints (format: "uri", format: "email")
  3. Parameter name heuristics (e.g., "file_path", "recipient", "api_key")
  4. Tool name disambiguation (e.g., tool name contains "read" → READ_PATH)
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class ArgumentRole(str, Enum):
    """Semantic role of a tool parameter."""

    READ_PATH = "read_path"
    WRITE_PATH = "write_path"
    URL = "url"
    RECIPIENT = "recipient"
    CONTENT_BODY = "content_body"
    CREDENTIAL = "credential"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Heuristic tables — substring matching on lowercased parameter names
# ---------------------------------------------------------------------------

_READ_PATH_NAMES: tuple[str, ...] = (
    "read_path", "source_path", "source_file", "input_path", "input_file",
    "src_path", "src_file", "file_to_read", "read_file",
)

_WRITE_PATH_NAMES: tuple[str, ...] = (
    "write_path", "dest_path", "dest_file", "output_path", "output_file",
    "target_path", "target_file", "file_to_write", "write_file", "save_path",
    "save_file", "destination",
)

_AMBIGUOUS_PATH_NAMES: tuple[str, ...] = (
    "path", "file", "file_path", "filepath", "filename", "directory", "dir",
    "folder", "location",
)

_URL_NAMES: tuple[str, ...] = (
    "url", "uri", "href", "link", "endpoint", "base_url", "baseurl",
    "callback_url", "webhook_url", "redirect_url",
)

_RECIPIENT_NAMES: tuple[str, ...] = (
    "to", "recipient", "recipients", "email", "email_address", "cc", "bcc",
    "send_to", "notify", "address",
)

_CONTENT_BODY_NAMES: tuple[str, ...] = (
    "body", "content", "text", "message", "html", "markdown", "data",
    "payload", "subject", "description", "comment", "note",
)

_CREDENTIAL_NAMES: tuple[str, ...] = (
    "api_key", "apikey", "api_token", "token", "secret", "password",
    "credentials", "auth_token", "access_token", "refresh_token",
    "private_key", "secret_key",
)

# Tool name substrings that disambiguate read vs write for path parameters
_READ_TOOL_PREFIXES: tuple[str, ...] = (
    "read", "get", "list", "fetch", "search", "find", "show", "cat",
    "head", "tail", "view", "open",
)
_WRITE_TOOL_PREFIXES: tuple[str, ...] = (
    "write", "create", "delete", "remove", "update", "put", "post",
    "set", "modify", "save", "append", "overwrite", "move", "rename",
)


def classify_tool_schema(
    tool_name: str,
    input_schema: dict[str, Any],
    annotations: dict[str, Any] | None = None,
) -> dict[str, ArgumentRole]:
    """Classify each parameter in a tool's input schema into a semantic role.

    Args:
        tool_name: The MCP tool name (used for disambiguation).
        input_schema: The tool's JSON Schema ``inputSchema``.
        annotations: Optional MCP tool annotations dict with keys like
                     ``readOnlyHint``, ``destructiveHint``.

    Returns:
        Mapping of parameter name → ArgumentRole.
    """
    properties = input_schema.get("properties", {})
    if not properties or not isinstance(properties, dict):
        return {}

    # Pre-compute tool-level hints
    is_read_only = (annotations or {}).get("readOnlyHint") is True
    is_destructive = (annotations or {}).get("destructiveHint") is True
    tool_suggests_read = _tool_name_suggests_read(tool_name)
    tool_suggests_write = _tool_name_suggests_write(tool_name)

    roles: dict[str, ArgumentRole] = {}

    for param_name, param_schema in properties.items():
        if not isinstance(param_schema, dict):
            roles[param_name] = ArgumentRole.UNKNOWN
            continue

        role = _classify_single_param(
            param_name,
            param_schema,
            is_read_only=is_read_only,
            is_destructive=is_destructive,
            tool_suggests_read=tool_suggests_read,
            tool_suggests_write=tool_suggests_write,
        )
        roles[param_name] = role

    return roles


def _classify_single_param(
    param_name: str,
    param_schema: dict[str, Any],
    *,
    is_read_only: bool,
    is_destructive: bool,
    tool_suggests_read: bool,
    tool_suggests_write: bool,
) -> ArgumentRole:
    """Classify a single parameter using layered heuristics.

    Priority:
      1. JSON Schema format hints (format: "uri", "email")
      2. Credential name match (always a credential regardless of context)
      3. Explicit read/write path name match
      4. Ambiguous path → disambiguate via annotation + tool name
      5. URL / recipient / content body name match
      6. UNKNOWN fallback
    """
    name_lower = param_name.lower()
    schema_format = param_schema.get("format", "")

    # 1. JSON Schema format hints
    if schema_format == "uri":
        return ArgumentRole.URL
    if schema_format == "email":
        return ArgumentRole.RECIPIENT

    # 2. Credential names (highest priority after format — always sensitive)
    if _matches_any(name_lower, _CREDENTIAL_NAMES):
        return ArgumentRole.CREDENTIAL

    # 3. Explicit read-path names
    if _matches_any(name_lower, _READ_PATH_NAMES):
        # Annotation override: destructive_hint=True → WRITE_PATH
        if is_destructive:
            return ArgumentRole.WRITE_PATH
        return ArgumentRole.READ_PATH

    # 4. Explicit write-path names
    if _matches_any(name_lower, _WRITE_PATH_NAMES):
        # Annotation override: read_only_hint=True → READ_PATH
        if is_read_only:
            return ArgumentRole.READ_PATH
        return ArgumentRole.WRITE_PATH

    # 5. Ambiguous path names → disambiguate
    if _matches_any(name_lower, _AMBIGUOUS_PATH_NAMES):
        return _disambiguate_path(
            is_read_only=is_read_only,
            is_destructive=is_destructive,
            tool_suggests_read=tool_suggests_read,
            tool_suggests_write=tool_suggests_write,
        )

    # 6. URL names
    if _matches_any(name_lower, _URL_NAMES):
        return ArgumentRole.URL

    # 7. Recipient names
    if _matches_any(name_lower, _RECIPIENT_NAMES):
        return ArgumentRole.RECIPIENT

    # 8. Content body names
    if _matches_any(name_lower, _CONTENT_BODY_NAMES):
        return ArgumentRole.CONTENT_BODY

    return ArgumentRole.UNKNOWN


def _disambiguate_path(
    *,
    is_read_only: bool,
    is_destructive: bool,
    tool_suggests_read: bool,
    tool_suggests_write: bool,
) -> ArgumentRole:
    """Resolve an ambiguous path parameter using context signals.

    Priority: annotation > tool name > default READ_PATH (safer assumption).
    """
    # Annotations win
    if is_read_only:
        return ArgumentRole.READ_PATH
    if is_destructive:
        return ArgumentRole.WRITE_PATH

    # Tool name hint
    if tool_suggests_write and not tool_suggests_read:
        return ArgumentRole.WRITE_PATH
    if tool_suggests_read and not tool_suggests_write:
        return ArgumentRole.READ_PATH

    # Default: READ_PATH (conservative — reads are safer than writes)
    return ArgumentRole.READ_PATH


def _matches_any(name: str, patterns: tuple[str, ...]) -> bool:
    """Check if a parameter name matches any pattern (exact or substring)."""
    for pattern in patterns:
        if name == pattern or pattern in name:
            return True
    return False


def _tool_name_suggests_read(tool_name: str) -> bool:
    """Check if the tool name suggests read-like behavior."""
    lower = tool_name.lower()
    return any(
        lower.startswith(p) or f"_{p}" in lower or f"-{p}" in lower
        for p in _READ_TOOL_PREFIXES
    )


def _tool_name_suggests_write(tool_name: str) -> bool:
    """Check if the tool name suggests write-like behavior."""
    lower = tool_name.lower()
    return any(
        lower.startswith(p) or f"_{p}" in lower or f"-{p}" in lower
        for p in _WRITE_TOOL_PREFIXES
    )
