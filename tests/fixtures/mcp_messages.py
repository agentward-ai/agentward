"""Real MCP JSON-RPC 2.0 message samples for testing.

These are actual message formats exchanged between MCP clients and servers
over the stdio transport. Each message is a newline-terminated JSON bytes object.
"""

# --- Initialization Handshake ---

INITIALIZE_REQUEST = (
    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
    b'{"protocolVersion":"2025-11-25","capabilities":{"sampling":{}},'
    b'"clientInfo":{"name":"test-client","version":"1.0.0"}}}\n'
)

INITIALIZE_RESPONSE = (
    b'{"jsonrpc":"2.0","id":1,"result":'
    b'{"protocolVersion":"2025-11-25",'
    b'"capabilities":{"tools":{"listChanged":true}},'
    b'"serverInfo":{"name":"test-server","version":"0.1.0"}}}\n'
)

INITIALIZED_NOTIFICATION = (
    b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
)


# --- Tools ---

TOOLS_LIST_REQUEST = (
    b'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
)

TOOLS_LIST_RESPONSE = (
    b'{"jsonrpc":"2.0","id":2,"result":{"tools":['
    b'{"name":"gmail_read","description":"Read emails from Gmail",'
    b'"inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}},'
    b'{"name":"gmail_send","description":"Send an email via Gmail",'
    b'"inputSchema":{"type":"object","required":["to","subject","body"],'
    b'"properties":{"to":{"type":"string"},"subject":{"type":"string"},"body":{"type":"string"}}}},'
    b'{"name":"filesystem_read","description":"Read a file",'
    b'"inputSchema":{"type":"object","required":["path"],'
    b'"properties":{"path":{"type":"string"}}}}'
    b']}}\n'
)

TOOLS_CALL_READ = (
    b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":'
    b'{"name":"gmail_read","arguments":{"query":"from:alice@example.com"}}}\n'
)

TOOLS_CALL_SEND = (
    b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":'
    b'{"name":"gmail_send","arguments":'
    b'{"to":"bob@example.com","subject":"Hello","body":"Hi Bob"}}}\n'
)

TOOLS_CALL_FILESYSTEM = (
    b'{"jsonrpc":"2.0","id":5,"method":"tools/call","params":'
    b'{"name":"filesystem_read","arguments":{"path":"/tmp/test.txt"}}}\n'
)

TOOLS_CALL_RESPONSE_SUCCESS = (
    b'{"jsonrpc":"2.0","id":3,"result":{"content":'
    b'[{"type":"text","text":"Email from Alice: Meeting at 3pm"}],"isError":false}}\n'
)

TOOLS_CALL_RESPONSE_ERROR = (
    b'{"jsonrpc":"2.0","id":5,"error":{"code":-32602,"message":"File not found: /tmp/test.txt"}}\n'
)


# --- Notifications ---

TOOLS_LIST_CHANGED = (
    b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n'
)


# --- Edge Cases ---

# Minimal valid request
MINIMAL_REQUEST = b'{"jsonrpc":"2.0","id":99,"method":"ping"}\n'

# Request with null params
NULL_PARAMS_REQUEST = b'{"jsonrpc":"2.0","id":100,"method":"test","params":null}\n'

# Non-dict result (should be wrapped)
SCALAR_RESULT_RESPONSE = b'{"jsonrpc":"2.0","id":101,"result":"ok"}\n'

# Error with null id
NULL_ID_ERROR = b'{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}}\n'

# Invalid messages for error testing
EMPTY_LINE = b"\n"
NOT_JSON = b"this is not json\n"
NOT_OBJECT = b"[1, 2, 3]\n"
MISSING_JSONRPC = b'{"id":1,"method":"test"}\n'
WRONG_JSONRPC = b'{"jsonrpc":"1.0","id":1,"method":"test"}\n'
NO_TYPE_FIELDS = b'{"jsonrpc":"2.0","id":1}\n'
