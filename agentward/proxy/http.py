"""HTTP reverse proxy for gateway-based tool servers (e.g., ClawdBot).

Sits between HTTP clients and a backend gateway server, intercepting
POST /tools-invoke requests for policy evaluation. All other requests
— including WebSocket upgrades — are forwarded as-is.

Architecture:
  Clients (agents, tools, IDE, browser UI)
    ↕ HTTP + WebSocket (this proxy)
  AgentWard HttpProxy (listen_port)
    ↕ HTTP + WebSocket
  Backend Gateway (backend_url)

Policy enforcement only applies to POST /tools-invoke. Every other
request/response (including WebSocket traffic) passes through transparently.
"""

from __future__ import annotations

import asyncio
import itertools
import json as _json
import signal
from sys import platform as _platform
from pathlib import Path
from typing import Any

import aiohttp
from aiohttp import ClientError, ClientSession, ClientWebSocketResponse, web
from rich.console import Console

from agentward.audit.logger import AuditLogger
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import PolicyDecision
from agentward.proxy.chaining import ChainTracker

_console = Console(stderr=True)

# Headers that must not be forwarded on regular HTTP requests (hop-by-hop).
# Note: 'upgrade' and 'connection' are intentionally excluded here — they
# ARE forwarded for WebSocket upgrade requests (handled separately).
_HOP_BY_HOP_REQUEST = frozenset(
    {
        "transfer-encoding",
        "keep-alive",
        "te",
        "trailers",
        "host",
    }
)

# For responses we also skip content-length because web.Response sets its own.
_HOP_BY_HOP_RESPONSE = _HOP_BY_HOP_REQUEST | {"content-length"}

# The ClawdBot gateway tool invocation endpoint (hyphen, not slash).
_TOOL_INVOKE_PATH = "/tools-invoke"


class HttpProxy:
    """HTTP reverse proxy that intercepts tool invocations for policy enforcement.

    Receives all HTTP traffic, evaluates POST /tools-invoke against the loaded
    policy, forwards WebSocket upgrades transparently, and passes everything
    else unchanged to the backend.

    Args:
        backend_url: The URL of the real backend (e.g., "http://127.0.0.1:18790").
        listen_host: Host to bind to. Always "127.0.0.1" for security.
        listen_port: Port to listen on (e.g., 18789).
        policy_engine: Policy engine for tool call evaluation. None = passthrough.
        audit_logger: Structured audit logger.
        policy_path: Path to the loaded policy file (for logging only).
        chain_tracker: Optional chain tracker for runtime skill chaining enforcement.
    """

    def __init__(
        self,
        backend_url: str,
        listen_host: str,
        listen_port: int,
        policy_engine: PolicyEngine | None,
        audit_logger: AuditLogger,
        policy_path: Path | None = None,
        chain_tracker: ChainTracker | None = None,
    ) -> None:
        self._backend_url = backend_url.rstrip("/")
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._policy_engine = policy_engine
        self._audit_logger = audit_logger
        self._policy_path = policy_path
        self._chain_tracker = chain_tracker
        self._session: ClientSession | None = None
        # Monotonic counter for synthetic request IDs (HTTP has no JSON-RPC ids)
        self._request_counter = itertools.count(1)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the HTTP proxy server and block until shutdown."""
        self._audit_logger.log_http_startup(
            self._listen_port,
            self._backend_url,
            self._policy_path,
        )

        app = web.Application()
        # Catch-all routes — root path and everything under it
        app.router.add_route("*", "/", self._handle_request)
        app.router.add_route("*", "/{path_info:.+}", self._handle_request)

        runner = web.AppRunner(app)
        await runner.setup()

        site = web.TCPSite(runner, self._listen_host, self._listen_port)

        # Graceful shutdown on signals
        # add_signal_handler is not supported on Windows
        loop = asyncio.get_running_loop()
        shutdown_event = asyncio.Event()

        def _signal_handler() -> None:
            shutdown_event.set()

        if _platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, _signal_handler)

        try:
            await site.start()
            _console.print(
                f"[bold #00ff88]Listening on http://{self._listen_host}:{self._listen_port}[/bold #00ff88]",
            )
            _console.print(
                f"[dim]Forwarding to {self._backend_url}[/dim]",
            )
            _console.print("[dim]Press Ctrl+C to stop[/dim]")

            await shutdown_event.wait()
        finally:
            if self._session is not None:
                await self._session.close()
            await runner.cleanup()
            self._audit_logger.log_shutdown("signal received")

    async def _get_session(self) -> ClientSession:
        """Get or create the shared HTTP client session."""
        if self._session is None or self._session.closed:
            self._session = ClientSession()
        return self._session

    # ------------------------------------------------------------------
    # Request routing
    # ------------------------------------------------------------------

    async def _handle_request(self, request: web.Request) -> web.StreamResponse:
        """Route incoming requests.

        - WebSocket upgrade → bidirectional WebSocket proxy
        - POST /tools-invoke → policy-checked tool invocation
        - Everything else → transparent HTTP forward
        """
        # WebSocket upgrade detection
        # Connection header may contain multiple tokens (e.g., "Upgrade, keep-alive")
        connection_tokens = {
            t.strip()
            for t in request.headers.get("Connection", "").lower().split(",")
        }
        if (
            request.headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in connection_tokens
        ):
            return await self._handle_websocket(request)

        if request.method == "POST" and request.path == _TOOL_INVOKE_PATH:
            return await self._handle_tool_invoke(request)

        return await self._forward_request(request)

    # ------------------------------------------------------------------
    # WebSocket proxy
    # ------------------------------------------------------------------

    async def _handle_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Proxy a WebSocket connection bidirectionally.

        Accepts the incoming WebSocket from the client, opens a matching
        WebSocket to the backend, and relays messages in both directions.
        All WebSocket traffic passes through transparently — no policy
        evaluation (tool calls go through HTTP POST /tools-invoke, not WS).
        """
        # Build backend WebSocket URL
        backend_ws_url = self._backend_url.replace("http://", "ws://").replace(
            "https://", "wss://"
        )
        backend_ws_url = f"{backend_ws_url}{request.path_qs}"

        # Forward relevant headers to backend (auth, subprotocols, etc.)
        ws_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            lower = key.lower()
            # Skip hop-by-hop and websocket handshake headers (aiohttp handles those)
            if lower in {
                "host",
                "upgrade",
                "connection",
                "sec-websocket-key",
                "sec-websocket-version",
                "sec-websocket-extensions",
            }:
                continue
            ws_headers[key] = value

        # Accept incoming WebSocket from client
        client_ws = web.WebSocketResponse()
        await client_ws.prepare(request)

        session = await self._get_session()

        try:
            async with session.ws_connect(
                backend_ws_url,
                headers=ws_headers,
                max_msg_size=25 * 1024 * 1024,  # 25MB to match ClawdBot
            ) as backend_ws:
                # Relay in both directions concurrently
                await asyncio.gather(
                    self._relay_ws(client_ws, backend_ws, "client→backend"),
                    self._relay_ws(backend_ws, client_ws, "backend→client"),
                )
        except (ClientError, OSError) as e:
            _console.print(
                f"[dim]WebSocket backend connection failed: {e}[/dim]",
            )
            if not client_ws.closed:
                await client_ws.close(
                    code=aiohttp.WSCloseCode.GOING_AWAY,
                    message=b"Backend unavailable",
                )

        return client_ws

    @staticmethod
    async def _relay_ws(
        source: web.WebSocketResponse | ClientWebSocketResponse,
        dest: web.WebSocketResponse | ClientWebSocketResponse,
        direction: str,
    ) -> None:
        """Relay WebSocket messages from source to dest until one side closes."""
        async for msg in source:
            if msg.type == aiohttp.WSMsgType.TEXT:
                await dest.send_str(msg.data)
            elif msg.type == aiohttp.WSMsgType.BINARY:
                await dest.send_bytes(msg.data)
            elif msg.type in (
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSING,
                aiohttp.WSMsgType.CLOSED,
            ):
                break
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break

        # When source closes, close dest too
        if not dest.closed:
            await dest.close()

    # ------------------------------------------------------------------
    # Tool invocation interception
    # ------------------------------------------------------------------

    async def _handle_tool_invoke(self, request: web.Request) -> web.StreamResponse:
        """Intercept a tool invocation, evaluate policy, forward or block.

        Parses the JSON body for ``tool`` and ``arguments``, runs policy
        evaluation, and either blocks with a JSON error response or forwards
        to the backend.

        The raw body is read once and cached so ``_forward_request`` can
        reuse it (aiohttp request bodies can only be read once).
        """
        # Read raw body once — we'll need it for both parsing and forwarding
        raw_body = await request.read()

        # Parse JSON body for policy evaluation.
        # If the body is unparseable or doesn't look like a tool invocation,
        # reject it — forwarding would let the backend accept a format this
        # proxy doesn't understand, bypassing policy enforcement.
        try:
            body = _json.loads(raw_body)
        except Exception:
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "bad_request",
                        "message": "AgentWard: /tools-invoke body must be valid JSON.",
                    },
                },
                status=400,
            )

        if not isinstance(body, dict) or "tool" not in body:
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "bad_request",
                        "message": "AgentWard: /tools-invoke body must be a JSON object with a 'tool' field.",
                    },
                },
                status=400,
            )

        tool_name = str(body["tool"])
        arguments = body.get("arguments", {})
        if not isinstance(arguments, dict):
            arguments = {}

        # Evaluate policy
        result = self._evaluate_tool_call(tool_name, arguments)

        if result.decision == PolicyDecision.BLOCK:
            self._audit_logger.log_tool_call(tool_name, arguments, result)
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "policy_blocked",
                        "message": f"AgentWard: {result.reason}",
                    },
                },
                status=403,
            )

        if result.decision == PolicyDecision.APPROVE:
            self._audit_logger.log_tool_call(tool_name, arguments, result)
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "approval_required",
                        "message": f"AgentWard: {result.reason}",
                    },
                },
                status=403,
            )

        # ALLOW or LOG — check chaining rules before forwarding
        request_id: int | None = None
        if self._chain_tracker is not None:
            chain_result = self._chain_tracker.check_before_call(
                tool_name, arguments,
            )
            if chain_result is not None and chain_result.decision == PolicyDecision.BLOCK:
                self._audit_logger.log_tool_call(
                    tool_name, arguments, chain_result, chain_violation=True,
                )
                return web.json_response(
                    {
                        "ok": False,
                        "error": {
                            "type": "chain_blocked",
                            "message": f"AgentWard: {chain_result.reason}",
                        },
                    },
                    status=403,
                )
            request_id = next(self._request_counter)
            self._chain_tracker.record_call(
                tool_name, arguments, request_id=request_id,
            )

        # Log ALLOW/LOG only after passing all checks (policy + chaining)
        self._audit_logger.log_tool_call(tool_name, arguments, result)

        # Forward to backend and capture response for chain tracking
        response = await self._forward_request(request, raw_body=raw_body)

        # Record response content for chaining detection
        if self._chain_tracker is not None and isinstance(response, web.Response):
            try:
                response_json = _json.loads(response.body)
                self._chain_tracker.record_response(
                    tool_name, response_json, request_id=request_id,
                )
            except Exception:
                pass  # Can't parse — skip chain recording

        return response

    # ------------------------------------------------------------------
    # HTTP forwarding
    # ------------------------------------------------------------------

    async def _forward_request(
        self,
        request: web.Request,
        raw_body: bytes | None = None,
    ) -> web.StreamResponse:
        """Forward an HTTP request to the backend and return the response.

        Copies method, path, query string, headers, and body.

        Args:
            request: The incoming aiohttp request.
            raw_body: Pre-read request body (avoids double-read issue).
                      If None, reads from the request directly.
        """
        session = await self._get_session()

        # Build backend URL
        target_url = f"{self._backend_url}{request.path_qs}"

        # Forward headers, skipping hop-by-hop
        forward_headers: dict[str, str] = {}
        for key, value in request.headers.items():
            if key.lower() not in _HOP_BY_HOP_REQUEST:
                forward_headers[key] = value

        # Use cached body if provided, otherwise read from request
        if raw_body is None:
            raw_body = await request.read()

        try:
            async with session.request(
                method=request.method,
                url=target_url,
                headers=forward_headers,
                data=raw_body if raw_body else None,
                allow_redirects=False,
            ) as backend_response:
                # Read the full backend response body first, then send as
                # a regular web.Response.  This avoids StreamResponse issues
                # with mismatched Content-Length / Transfer-Encoding headers.
                response_body = await backend_response.read()

                response = web.Response(
                    status=backend_response.status,
                    body=response_body,
                )

                # Copy response headers, skipping hop-by-hop + content-length
                # (web.Response sets its own content-length from the body)
                for key, value in backend_response.headers.items():
                    if key.lower() not in _HOP_BY_HOP_RESPONSE:
                        response.headers[key] = value

                return response

        except ClientError as e:
            return web.json_response(
                {
                    "ok": False,
                    "error": {
                        "type": "bad_gateway",
                        "message": f"AgentWard: Failed to reach backend at {self._backend_url}: {e}",
                    },
                },
                status=502,
            )

    # ------------------------------------------------------------------
    # Policy evaluation
    # ------------------------------------------------------------------

    def _evaluate_tool_call(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> EvaluationResult:
        """Evaluate a tool call against the policy engine.

        If no policy engine is loaded (passthrough mode), returns ALLOW.

        Args:
            tool_name: The tool name from the request body.
            arguments: The tool call arguments.

        Returns:
            The evaluation result.
        """
        if self._policy_engine is None:
            return EvaluationResult(
                decision=PolicyDecision.ALLOW,
                reason="No policy loaded (passthrough mode).",
            )
        return self._policy_engine.evaluate(tool_name, arguments)
