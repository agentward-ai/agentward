"""Tests for JSON-RPC 2.0 protocol parsing and serialization."""

import json

import pytest

from agentward.proxy.protocol import (
    JSONRPCError,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    ProtocolError,
    extract_tool_info,
    is_tool_call,
    is_tool_call_notification,
    make_error_response,
    parse_message,
    serialize_message,
)
from tests.fixtures.mcp_messages import (
    EMPTY_LINE,
    INITIALIZE_REQUEST,
    INITIALIZE_RESPONSE,
    INITIALIZED_NOTIFICATION,
    MINIMAL_REQUEST,
    MISSING_JSONRPC,
    NO_TYPE_FIELDS,
    NOT_JSON,
    NOT_OBJECT,
    NULL_ID_ERROR,
    NULL_PARAMS_REQUEST,
    SCALAR_RESULT_RESPONSE,
    TOOLS_CALL_READ,
    TOOLS_CALL_RESPONSE_ERROR,
    TOOLS_CALL_RESPONSE_SUCCESS,
    TOOLS_CALL_SEND,
    TOOLS_LIST_CHANGED,
    TOOLS_LIST_REQUEST,
    TOOLS_LIST_RESPONSE,
    WRONG_JSONRPC,
)


class TestParseRequest:
    """Tests for parsing JSON-RPC requests."""

    def test_initialize_request(self) -> None:
        msg = parse_message(INITIALIZE_REQUEST)
        assert isinstance(msg, JSONRPCRequest)
        assert msg.id == 1
        assert msg.method == "initialize"
        assert msg.params is not None
        assert msg.params["protocolVersion"] == "2025-11-25"

    def test_tools_list_request(self) -> None:
        msg = parse_message(TOOLS_LIST_REQUEST)
        assert isinstance(msg, JSONRPCRequest)
        assert msg.method == "tools/list"

    def test_tools_call_request(self) -> None:
        msg = parse_message(TOOLS_CALL_READ)
        assert isinstance(msg, JSONRPCRequest)
        assert msg.method == "tools/call"
        assert msg.params is not None
        assert msg.params["name"] == "gmail_read"

    def test_minimal_request(self) -> None:
        msg = parse_message(MINIMAL_REQUEST)
        assert isinstance(msg, JSONRPCRequest)
        assert msg.id == 99
        assert msg.method == "ping"
        assert msg.params is None

    def test_null_params(self) -> None:
        msg = parse_message(NULL_PARAMS_REQUEST)
        assert isinstance(msg, JSONRPCRequest)
        assert msg.params is None


class TestParseResponse:
    """Tests for parsing JSON-RPC responses."""

    def test_initialize_response(self) -> None:
        msg = parse_message(INITIALIZE_RESPONSE)
        assert isinstance(msg, JSONRPCResponse)
        assert msg.id == 1
        assert msg.result["protocolVersion"] == "2025-11-25"

    def test_tools_list_response(self) -> None:
        msg = parse_message(TOOLS_LIST_RESPONSE)
        assert isinstance(msg, JSONRPCResponse)
        assert msg.id == 2
        assert "tools" in msg.result
        assert len(msg.result["tools"]) == 3

    def test_tools_call_success_response(self) -> None:
        msg = parse_message(TOOLS_CALL_RESPONSE_SUCCESS)
        assert isinstance(msg, JSONRPCResponse)
        assert msg.id == 3
        assert msg.result["isError"] is False

    def test_scalar_result_wrapped(self) -> None:
        msg = parse_message(SCALAR_RESULT_RESPONSE)
        assert isinstance(msg, JSONRPCResponse)
        assert msg.result == {"value": "ok"}


class TestParseNotification:
    """Tests for parsing JSON-RPC notifications."""

    def test_initialized_notification(self) -> None:
        msg = parse_message(INITIALIZED_NOTIFICATION)
        assert isinstance(msg, JSONRPCNotification)
        assert msg.method == "notifications/initialized"
        assert msg.params is None

    def test_tools_list_changed(self) -> None:
        msg = parse_message(TOOLS_LIST_CHANGED)
        assert isinstance(msg, JSONRPCNotification)
        assert msg.method == "notifications/tools/list_changed"


class TestParseError:
    """Tests for parsing JSON-RPC error responses."""

    def test_tool_call_error(self) -> None:
        msg = parse_message(TOOLS_CALL_RESPONSE_ERROR)
        assert isinstance(msg, JSONRPCError)
        assert msg.id == 5
        assert msg.error.code == -32602
        assert "File not found" in msg.error.message

    def test_null_id_error(self) -> None:
        msg = parse_message(NULL_ID_ERROR)
        assert isinstance(msg, JSONRPCError)
        assert msg.id is None
        assert msg.error.code == -32700


class TestParseInvalid:
    """Tests for invalid message handling."""

    def test_empty_line(self) -> None:
        with pytest.raises(ProtocolError, match="Empty message"):
            parse_message(EMPTY_LINE)

    def test_not_json(self) -> None:
        with pytest.raises(ProtocolError, match="Invalid JSON"):
            parse_message(NOT_JSON)

    def test_not_object(self) -> None:
        with pytest.raises(ProtocolError, match="must be an object"):
            parse_message(NOT_OBJECT)

    def test_missing_jsonrpc(self) -> None:
        with pytest.raises(ProtocolError, match="Expected jsonrpc version"):
            parse_message(MISSING_JSONRPC)

    def test_wrong_jsonrpc_version(self) -> None:
        with pytest.raises(ProtocolError, match="Expected jsonrpc version"):
            parse_message(WRONG_JSONRPC)

    def test_no_type_fields(self) -> None:
        with pytest.raises(ProtocolError, match="Cannot determine message type"):
            parse_message(NO_TYPE_FIELDS)


class TestIsToolCall:
    """Tests for the is_tool_call helper."""

    def test_tools_call_request(self) -> None:
        msg = parse_message(TOOLS_CALL_READ)
        assert is_tool_call(msg) is True

    def test_tools_list_request(self) -> None:
        msg = parse_message(TOOLS_LIST_REQUEST)
        assert is_tool_call(msg) is False

    def test_notification(self) -> None:
        msg = parse_message(INITIALIZED_NOTIFICATION)
        assert is_tool_call(msg) is False

    def test_response(self) -> None:
        msg = parse_message(TOOLS_CALL_RESPONSE_SUCCESS)
        assert is_tool_call(msg) is False


class TestIsToolCallNotification:
    """Tests for the is_tool_call_notification helper."""

    def test_tools_call_notification_detected(self) -> None:
        """A tools/call notification (no id) is detected."""
        line = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"evil","arguments":{}}}\n'
        msg = parse_message(line)
        assert is_tool_call_notification(msg) is True
        # And is NOT a regular tool call (it's a notification, no id)
        assert is_tool_call(msg) is False

    def test_regular_notification_not_flagged(self) -> None:
        msg = parse_message(INITIALIZED_NOTIFICATION)
        assert is_tool_call_notification(msg) is False

    def test_regular_tool_call_not_flagged(self) -> None:
        msg = parse_message(TOOLS_CALL_READ)
        assert is_tool_call_notification(msg) is False

    def test_response_not_flagged(self) -> None:
        msg = parse_message(TOOLS_CALL_RESPONSE_SUCCESS)
        assert is_tool_call_notification(msg) is False


class TestExtractToolInfo:
    """Tests for extracting tool name and arguments."""

    def test_extract_read(self) -> None:
        msg = parse_message(TOOLS_CALL_READ)
        assert isinstance(msg, JSONRPCRequest)
        name, args = extract_tool_info(msg)
        assert name == "gmail_read"
        assert args == {"query": "from:alice@example.com"}

    def test_extract_send(self) -> None:
        msg = parse_message(TOOLS_CALL_SEND)
        assert isinstance(msg, JSONRPCRequest)
        name, args = extract_tool_info(msg)
        assert name == "gmail_send"
        assert args["to"] == "bob@example.com"

    def test_wrong_method(self) -> None:
        msg = parse_message(TOOLS_LIST_REQUEST)
        assert isinstance(msg, JSONRPCRequest)
        with pytest.raises(ProtocolError, match="Expected method"):
            extract_tool_info(msg)


class TestSerialize:
    """Tests for message serialization."""

    def test_roundtrip_request(self) -> None:
        original = parse_message(TOOLS_CALL_READ)
        serialized = serialize_message(original)
        reparsed = parse_message(serialized)
        assert isinstance(reparsed, JSONRPCRequest)
        assert reparsed.id == original.id  # type: ignore[union-attr]
        assert reparsed.method == original.method  # type: ignore[union-attr]

    def test_roundtrip_notification(self) -> None:
        original = parse_message(INITIALIZED_NOTIFICATION)
        serialized = serialize_message(original)
        reparsed = parse_message(serialized)
        assert isinstance(reparsed, JSONRPCNotification)
        assert reparsed.method == original.method  # type: ignore[union-attr]

    def test_roundtrip_response(self) -> None:
        original = parse_message(TOOLS_CALL_RESPONSE_SUCCESS)
        serialized = serialize_message(original)
        reparsed = parse_message(serialized)
        assert isinstance(reparsed, JSONRPCResponse)
        assert reparsed.id == original.id  # type: ignore[union-attr]

    def test_serialized_ends_with_newline(self) -> None:
        msg = JSONRPCRequest(id=1, method="test")
        data = serialize_message(msg)
        assert data.endswith(b"\n")

    def test_serialized_is_compact_json(self) -> None:
        msg = JSONRPCRequest(id=1, method="test", params={"key": "value"})
        data = serialize_message(msg)
        # Compact JSON means no spaces after separators
        text = data.decode("utf-8").strip()
        assert " " not in text or text == json.dumps(json.loads(text), separators=(",", ":"))


class TestMakeErrorResponse:
    """Tests for creating error responses."""

    def test_make_error(self) -> None:
        resp = make_error_response(42, -32050, "Policy blocked this call")
        assert isinstance(resp, JSONRPCError)
        assert resp.id == 42
        assert resp.error.code == -32050
        assert resp.error.message == "Policy blocked this call"

    def test_error_serializes(self) -> None:
        resp = make_error_response(1, -32050, "Blocked")
        data = serialize_message(resp)
        parsed = json.loads(data)
        assert parsed["error"]["code"] == -32050
        assert parsed["id"] == 1
