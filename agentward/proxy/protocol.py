"""JSON-RPC 2.0 message parsing and serialization for the MCP protocol.

MCP uses JSON-RPC 2.0 over stdio with newline-delimited JSON.
Each message is a single JSON object on one line, terminated by \\n.

Message types are distinguished by field presence:
  - Request:      has "id" AND "method"
  - Notification: has "method" but NO "id"
  - Response:     has "id" AND "result"
  - Error:        has "id" (or null) AND "error"
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ErrorData:
    """JSON-RPC 2.0 error object."""

    code: int
    message: str
    data: Any | None = None


@dataclass(frozen=True)
class JSONRPCRequest:
    """A JSON-RPC 2.0 request (expects a response)."""

    id: int | str
    method: str
    params: dict[str, Any] | None = None


@dataclass(frozen=True)
class JSONRPCNotification:
    """A JSON-RPC 2.0 notification (no response expected)."""

    method: str
    params: dict[str, Any] | None = None


@dataclass(frozen=True)
class JSONRPCResponse:
    """A JSON-RPC 2.0 successful response."""

    id: int | str
    result: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class JSONRPCError:
    """A JSON-RPC 2.0 error response."""

    id: int | str | None
    error: ErrorData = field(default_factory=lambda: ErrorData(code=-32603, message="Internal error"))


JSONRPCMessage = JSONRPCRequest | JSONRPCNotification | JSONRPCResponse | JSONRPCError


class ProtocolError(Exception):
    """Raised when a JSON-RPC message cannot be parsed."""


def parse_message(line: bytes) -> JSONRPCMessage:
    """Parse a single line of newline-delimited JSON into a typed message.

    Args:
        line: Raw bytes of a single JSON-RPC message (may include trailing newline).

    Returns:
        The parsed message as the appropriate type.

    Raises:
        ProtocolError: If the line is not valid JSON or not a valid JSON-RPC 2.0 message.
    """
    stripped = line.strip()
    if not stripped:
        raise ProtocolError("Empty message line")

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as e:
        raise ProtocolError(f"Invalid JSON: {e}") from e

    if not isinstance(data, dict):
        raise ProtocolError(f"JSON-RPC message must be an object, got {type(data).__name__}")

    # Validate jsonrpc version field
    if data.get("jsonrpc") != "2.0":
        raise ProtocolError(
            f"Expected jsonrpc version '2.0', got {data.get('jsonrpc')!r}"
        )

    has_id = "id" in data
    has_method = "method" in data
    has_result = "result" in data
    has_error = "error" in data

    if has_error:
        # Error response
        error_obj = data["error"]
        if not isinstance(error_obj, dict):
            raise ProtocolError("'error' field must be an object")
        return JSONRPCError(
            id=data.get("id"),
            error=ErrorData(
                code=error_obj.get("code", -32603),
                message=error_obj.get("message", "Unknown error"),
                data=error_obj.get("data"),
            ),
        )

    if has_result:
        # Successful response
        if not has_id:
            raise ProtocolError("Response with 'result' must have an 'id' field")
        return JSONRPCResponse(
            id=data["id"],
            result=data["result"] if isinstance(data["result"], dict) else {"value": data["result"]},
        )

    if has_method:
        method = data["method"]
        if not isinstance(method, str):
            raise ProtocolError(f"'method' must be a string, got {type(method).__name__}")
        params = data.get("params")
        if params is not None and not isinstance(params, dict):
            # JSON-RPC allows array params, but MCP uses only object params
            if isinstance(params, list):
                raise ProtocolError("MCP uses named parameters (objects), not positional (arrays)")
            raise ProtocolError(f"'params' must be an object or null, got {type(params).__name__}")

        if has_id:
            # Request (expects response)
            return JSONRPCRequest(id=data["id"], method=method, params=params)
        else:
            # Notification (no response)
            return JSONRPCNotification(method=method, params=params)

    raise ProtocolError(
        "Cannot determine message type: must have 'method' (request/notification), "
        "'result' (response), or 'error' (error response)"
    )


def serialize_message(msg: JSONRPCMessage) -> bytes:
    """Serialize a JSON-RPC message to newline-terminated bytes.

    Args:
        msg: The message to serialize.

    Returns:
        UTF-8 encoded JSON bytes with a trailing newline.
    """
    data: dict[str, Any] = {"jsonrpc": "2.0"}

    if isinstance(msg, JSONRPCRequest):
        data["id"] = msg.id
        data["method"] = msg.method
        if msg.params is not None:
            data["params"] = msg.params
    elif isinstance(msg, JSONRPCNotification):
        data["method"] = msg.method
        if msg.params is not None:
            data["params"] = msg.params
    elif isinstance(msg, JSONRPCResponse):
        data["id"] = msg.id
        data["result"] = msg.result
    elif isinstance(msg, JSONRPCError):
        data["id"] = msg.id
        data["error"] = {
            "code": msg.error.code,
            "message": msg.error.message,
        }
        if msg.error.data is not None:
            data["error"]["data"] = msg.error.data

    return json.dumps(data, separators=(",", ":")).encode("utf-8") + b"\n"


def is_tool_call(msg: JSONRPCMessage) -> bool:
    """Check if a message is a tools/call request.

    Args:
        msg: The parsed JSON-RPC message.

    Returns:
        True if this is a request with method "tools/call".
    """
    return isinstance(msg, JSONRPCRequest) and msg.method == "tools/call"


def is_tool_call_notification(msg: JSONRPCMessage) -> bool:
    """Check if a message is a tools/call notification (no id).

    MCP does not define tools/call as a notification method, so a
    well-behaved client should never send one. If we see one, it's
    likely a protocol violation or an attempt to bypass policy
    enforcement (since notifications have no id to send an error
    response to).

    Args:
        msg: The parsed JSON-RPC message.

    Returns:
        True if this is a notification with method "tools/call".
    """
    return isinstance(msg, JSONRPCNotification) and msg.method == "tools/call"


def extract_tool_info(msg: JSONRPCRequest) -> tuple[str, dict[str, Any]]:
    """Extract tool name and arguments from a tools/call request.

    Args:
        msg: A JSONRPCRequest with method "tools/call".

    Returns:
        A tuple of (tool_name, arguments).

    Raises:
        ProtocolError: If the request doesn't have the expected params structure.
    """
    if msg.method != "tools/call":
        raise ProtocolError(f"Expected method 'tools/call', got '{msg.method}'")

    if msg.params is None:
        raise ProtocolError("tools/call request has no params")

    name = msg.params.get("name")
    if not isinstance(name, str):
        raise ProtocolError(
            f"tools/call params must have a string 'name' field, got {type(name).__name__}"
        )

    arguments = msg.params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ProtocolError(
            f"tools/call 'arguments' must be an object, got {type(arguments).__name__}"
        )

    return name, arguments


def make_error_response(request_id: int | str, code: int, message: str) -> JSONRPCError:
    """Create a JSON-RPC error response.

    Args:
        request_id: The id from the original request.
        code: JSON-RPC error code (e.g., -32602 for invalid params).
        message: Human-readable error message.

    Returns:
        A JSONRPCError ready to serialize and send back to the client.
    """
    return JSONRPCError(
        id=request_id,
        error=ErrorData(code=code, message=message),
    )


# Standard JSON-RPC error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# AgentWard-specific error codes (in the -32000 to -32099 range)
POLICY_BLOCKED = -32050
APPROVAL_REQUIRED = -32051
