"""Tests for the HTTP reverse proxy."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, TestServer

from agentward.audit.logger import AuditLogger
from agentward.policy.engine import PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    ChainingMode,
    ChainingRule,
    ResourcePermissions,
)
from agentward.proxy.chaining import ChainTracker
from agentward.proxy.http import HttpProxy, _TOOL_LOG_RE


# ---------------------------------------------------------------------------
# Mock backend
# ---------------------------------------------------------------------------


def _create_mock_backend() -> web.Application:
    """Create a minimal mock backend that records requests."""
    app = web.Application()
    app["requests"] = []

    async def handle_tools_invoke(request: web.Request) -> web.Response:
        body = await request.json()
        app["requests"].append(
            {
                "method": request.method,
                "path": request.path,
                "headers": dict(request.headers),
                "body": body,
            }
        )
        return web.json_response(
            {"ok": True, "result": {"tool": body.get("tool"), "status": "executed"}}
        )

    async def handle_health(request: web.Request) -> web.Response:
        app["requests"].append(
            {"method": request.method, "path": request.path, "headers": dict(request.headers)}
        )
        return web.json_response({"status": "healthy"})

    async def handle_catch_all(request: web.Request) -> web.Response:
        app["requests"].append(
            {"method": request.method, "path": request.path, "headers": dict(request.headers)}
        )
        return web.json_response({"ok": True, "path": request.path})

    app.router.add_post("/tools-invoke", handle_tools_invoke)
    app.router.add_get("/health", handle_health)
    app.router.add_route("*", "/{path_info:.*}", handle_catch_all)

    return app


def _make_policy(
    blocked_tools: list[str] | None = None,
    approval_tools: list[str] | None = None,
) -> AgentWardPolicy:
    """Create a simple test policy."""
    skills: dict[str, dict[str, ResourcePermissions]] = {}

    if blocked_tools:
        for tool in blocked_tools:
            skills[tool] = {
                tool: ResourcePermissions.model_construct(
                    denied=True, actions={}, filters={}
                )
            }

    return AgentWardPolicy(
        version="1.0",
        skills=skills,
        skill_chaining=[],
        require_approval=approval_tools or [],
        data_boundaries={},
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def backend():
    """Start a mock backend server and return (app, url)."""
    app = _create_mock_backend()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)  # OS picks a free port
    await site.start()

    # Extract assigned port
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    url = f"http://127.0.0.1:{port}"

    yield app, url

    await runner.cleanup()


@pytest.fixture()
def audit_logger(tmp_path: Path) -> AuditLogger:
    """Create an audit logger writing to a temp file."""
    return AuditLogger(log_path=tmp_path / "audit.jsonl")


async def _start_proxy(
    backend_url: str,
    audit_logger: AuditLogger,
    policy_engine: PolicyEngine | None = None,
    chain_tracker: ChainTracker | None = None,
) -> tuple[HttpProxy, int, asyncio.Task[None]]:
    """Start the HTTP proxy on a free port and return (proxy, port, task)."""
    # Find a free port
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()

    proxy = HttpProxy(
        backend_url=backend_url,
        listen_host="127.0.0.1",
        listen_port=port,
        policy_engine=policy_engine,
        audit_logger=audit_logger,
        chain_tracker=chain_tracker,
    )

    # Run proxy in background task
    task = asyncio.create_task(proxy.run())
    # Give it a moment to start
    await asyncio.sleep(0.1)

    return proxy, port, task


async def _stop_proxy(proxy: HttpProxy, task: asyncio.Task[None]) -> None:
    """Stop the proxy by cancelling the task."""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    if proxy._session and not proxy._session.closed:
        await proxy._session.close()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHttpProxyPassthrough:
    """Tests for non-tool-invoke requests (passthrough)."""

    @pytest.mark.asyncio
    async def test_forwards_get_request(self, backend: tuple, audit_logger: AuditLogger) -> None:
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://127.0.0.1:{port}/health") as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["status"] == "healthy"

            # Verify backend received the request
            assert len(app["requests"]) == 1
            assert app["requests"][0]["path"] == "/health"
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_forwards_arbitrary_path(self, backend: tuple, audit_logger: AuditLogger) -> None:
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://127.0.0.1:{port}/some/other/path") as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["path"] == "/some/other/path"
        finally:
            await _stop_proxy(proxy, task)


class TestHttpProxyToolInvoke:
    """Tests for POST /tools-invoke with policy enforcement."""

    @pytest.mark.asyncio
    async def test_tool_invoke_allowed_no_policy(
        self, backend: tuple, audit_logger: AuditLogger
    ) -> None:
        """Passthrough mode: all tool calls forwarded."""
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"tool": "test-tool", "arguments": {"key": "value"}},
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["ok"] is True
                    assert data["result"]["tool"] == "test-tool"

            assert len(app["requests"]) == 1
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_tool_invoke_allowed_by_policy(
        self, backend: tuple, audit_logger: AuditLogger
    ) -> None:
        """Policy allows the tool — request forwarded."""
        app, backend_url = backend
        policy = _make_policy(blocked_tools=["bad-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"tool": "good-tool", "arguments": {}},
                ) as resp:
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["ok"] is True

            assert len(app["requests"]) == 1
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_tool_invoke_blocked(
        self, backend: tuple, audit_logger: AuditLogger
    ) -> None:
        """Policy blocks the tool — 403 returned, backend not called."""
        app, backend_url = backend
        policy = _make_policy(blocked_tools=["dangerous-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"tool": "dangerous-tool", "arguments": {}},
                ) as resp:
                    assert resp.status == 403
                    data = await resp.json()
                    assert data["ok"] is False
                    assert data["error"]["type"] == "policy_blocked"

            # Backend should NOT have received the request
            assert len(app["requests"]) == 0
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_tool_invoke_approval_required(
        self, backend: tuple, audit_logger: AuditLogger
    ) -> None:
        """Tool in require_approval — 403 returned."""
        app, backend_url = backend
        policy = _make_policy(approval_tools=["risky-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"tool": "risky-tool", "arguments": {}},
                ) as resp:
                    assert resp.status == 403
                    data = await resp.json()
                    assert data["ok"] is False
                    assert data["error"]["type"] == "approval_required"

            assert len(app["requests"]) == 0
        finally:
            await _stop_proxy(proxy, task)


class TestHttpProxyHeaders:
    """Tests for header forwarding."""

    @pytest.mark.asyncio
    async def test_auth_header_forwarded(
        self, backend: tuple, audit_logger: AuditLogger
    ) -> None:
        """Authorization header is passed through to backend."""
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{port}/health",
                    headers={"Authorization": "Bearer test-token-123"},
                ) as resp:
                    assert resp.status == 200

            assert len(app["requests"]) == 1
            received_auth = app["requests"][0]["headers"].get("Authorization")
            assert received_auth == "Bearer test-token-123"
        finally:
            await _stop_proxy(proxy, task)


class TestHttpProxyEdgeCases:
    """Edge case tests."""

    @pytest.mark.asyncio
    async def test_malformed_json_body_forwarded(
        self, backend: tuple, audit_logger: AuditLogger
    ) -> None:
        """POST /tools-invoke with non-JSON body is forwarded to backend."""
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    data=b"not-json",
                    headers={"Content-Type": "text/plain"},
                ) as resp:
                    # Should be forwarded to backend (which may return an error)
                    # The key assertion is that the proxy doesn't crash
                    assert resp.status in (200, 400, 500)
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_missing_tool_field_forwarded(
        self, backend: tuple, audit_logger: AuditLogger
    ) -> None:
        """POST /tools-invoke without 'tool' field is forwarded as-is."""
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"arguments": {"key": "value"}},
                ) as resp:
                    # Forwarded to backend — backend handles it
                    assert resp.status in (200, 400)
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_backend_down_returns_502(self, audit_logger: AuditLogger) -> None:
        """When backend is unreachable, proxy returns 502."""
        # Point proxy at a port nothing is listening on
        proxy, port, task = await _start_proxy(
            "http://127.0.0.1:1", audit_logger  # port 1 — nothing there
        )

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://127.0.0.1:{port}/health") as resp:
                    assert resp.status == 502
                    data = await resp.json()
                    assert data["ok"] is False
                    assert data["error"]["type"] == "bad_gateway"
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_audit_log_written(
        self, backend: tuple, audit_logger: AuditLogger, tmp_path: Path
    ) -> None:
        """Tool calls are logged to the audit file."""
        app, backend_url = backend
        policy = _make_policy(blocked_tools=["blocked-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                # Make a blocked call
                await session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"tool": "blocked-tool", "arguments": {}},
                )
                # Make an allowed call
                await session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"tool": "allowed-tool", "arguments": {}},
                )
        finally:
            await _stop_proxy(proxy, task)

        # Read audit log
        log_path = tmp_path / "audit.jsonl"
        lines = log_path.read_text().strip().split("\n")
        events = [json.loads(line) for line in lines]

        # Find tool_call events
        tool_calls = [e for e in events if e.get("event") == "tool_call"]
        assert len(tool_calls) == 2

        blocked = tool_calls[0]
        assert blocked["tool"] == "blocked-tool"
        assert blocked["decision"] == "BLOCK"

        allowed = tool_calls[1]
        assert allowed["tool"] == "allowed-tool"
        assert allowed["decision"] == "ALLOW"


# ---------------------------------------------------------------------------
# Mock backend that returns URLs in responses (for chain testing)
# ---------------------------------------------------------------------------


def _create_chain_backend() -> web.Application:
    """Backend that returns tool responses containing extractable content."""
    app = web.Application()
    app["requests"] = []

    async def handle_tools_invoke(request: web.Request) -> web.Response:
        body = await request.json()
        app["requests"].append(body)
        tool = body.get("tool", "")

        # Email tools return responses with URLs
        if tool.startswith("gmail"):
            return web.json_response({
                "ok": True,
                "result": {
                    "content": [
                        {"text": "From: attacker@evil.com\nBody: Click https://evil.com/payload"}
                    ]
                },
            })

        return web.json_response({"ok": True, "result": {"status": "done"}})

    app.router.add_post("/tools-invoke", handle_tools_invoke)
    return app


def _make_chain_policy(
    mode: ChainingMode = ChainingMode.BLANKET,
) -> AgentWardPolicy:
    """Create a policy with email→browser chaining rule and skill→resource mappings."""
    return AgentWardPolicy(
        version="1.0",
        skills={
            "email-mgr": {
                "gmail": ResourcePermissions.model_construct(
                    denied=False, actions={"read": True, "send": True}, filters={},
                ),
            },
            "web-browser": {
                "browser": ResourcePermissions.model_construct(
                    denied=False, actions={"navigate": True}, filters={},
                ),
            },
        },
        skill_chaining=[
            ChainingRule(source_skill="email-mgr", target_skill="web-browser"),
        ],
        chaining_mode=mode,
        require_approval=[],
        data_boundaries={},
    )


# ---------------------------------------------------------------------------
# Chain enforcement integration tests
# ---------------------------------------------------------------------------


class TestHttpProxyChaining:
    """Integration tests for chain enforcement through the HTTP proxy."""

    @pytest.mark.asyncio
    async def test_chain_block_blanket_mode(
        self, audit_logger: AuditLogger,
    ) -> None:
        """Blanket mode: call email tool, then browser tool → blocked."""
        # Start chain backend
        chain_app = _create_chain_backend()
        runner = web.AppRunner(chain_app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        backend_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        backend_url = f"http://127.0.0.1:{backend_port}"

        try:
            policy = _make_chain_policy(mode=ChainingMode.BLANKET)
            engine = PolicyEngine(policy)
            tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

            proxy, port, task = await _start_proxy(
                backend_url, audit_logger, engine, tracker,
            )

            try:
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    # First: call email tool — should be allowed
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "gmail_read", "arguments": {"query": "inbox"}},
                    ) as resp:
                        assert resp.status == 200

                    # Second: call browser tool — should be chain-blocked
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "browser_navigate", "arguments": {"url": "https://safe.com"}},
                    ) as resp:
                        assert resp.status == 403
                        data = await resp.json()
                        assert data["error"]["type"] == "chain_blocked"
            finally:
                await _stop_proxy(proxy, task)
        finally:
            await runner.cleanup()

    @pytest.mark.asyncio
    async def test_chain_allow_content_mode_no_match(
        self, audit_logger: AuditLogger,
    ) -> None:
        """Content mode: email response URL doesn't match browser args → allowed."""
        chain_app = _create_chain_backend()
        runner = web.AppRunner(chain_app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        backend_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        backend_url = f"http://127.0.0.1:{backend_port}"

        try:
            policy = _make_chain_policy(mode=ChainingMode.CONTENT)
            engine = PolicyEngine(policy)
            tracker = ChainTracker(engine, mode=ChainingMode.CONTENT)

            proxy, port, task = await _start_proxy(
                backend_url, audit_logger, engine, tracker,
            )

            try:
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    # First: call email tool
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "gmail_read", "arguments": {"query": "inbox"}},
                    ) as resp:
                        assert resp.status == 200

                    # Second: call browser with DIFFERENT URL → content doesn't match → allowed
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "browser_navigate", "arguments": {"url": "https://totally-safe.com"}},
                    ) as resp:
                        assert resp.status == 200
            finally:
                await _stop_proxy(proxy, task)
        finally:
            await runner.cleanup()

    @pytest.mark.asyncio
    async def test_chain_block_content_mode_url_match(
        self, audit_logger: AuditLogger,
    ) -> None:
        """Content mode: email response URL flows into browser args → blocked."""
        chain_app = _create_chain_backend()
        runner = web.AppRunner(chain_app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        backend_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        backend_url = f"http://127.0.0.1:{backend_port}"

        try:
            policy = _make_chain_policy(mode=ChainingMode.CONTENT)
            engine = PolicyEngine(policy)
            tracker = ChainTracker(engine, mode=ChainingMode.CONTENT)

            proxy, port, task = await _start_proxy(
                backend_url, audit_logger, engine, tracker,
            )

            try:
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    # First: call email tool (response contains https://evil.com/payload)
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "gmail_read", "arguments": {"query": "inbox"}},
                    ) as resp:
                        assert resp.status == 200

                    # Second: call browser with the SAME URL from email response → blocked
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "browser_navigate", "arguments": {"url": "https://evil.com/payload"}},
                    ) as resp:
                        assert resp.status == 403
                        data = await resp.json()
                        assert data["error"]["type"] == "chain_blocked"
            finally:
                await _stop_proxy(proxy, task)
        finally:
            await runner.cleanup()


class TestHttpProxyAuditSingleLog:
    """Verify that chain-blocked calls produce exactly ONE audit log entry.

    Before the fix, the proxy logged the policy result (ALLOW) before checking
    chaining rules, then logged again (BLOCK) if chaining blocked — producing
    two entries per call. The fix defers logging until after all checks pass.
    """

    @pytest.mark.asyncio
    async def test_chain_blocked_produces_single_log_entry(
        self, audit_logger: AuditLogger, tmp_path: Path,
    ) -> None:
        """Call email tool, then browser tool (chain-blocked) → exactly one log per call."""
        chain_app = _create_chain_backend()
        runner = web.AppRunner(chain_app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        backend_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        backend_url = f"http://127.0.0.1:{backend_port}"

        try:
            policy = _make_chain_policy(mode=ChainingMode.BLANKET)
            engine = PolicyEngine(policy)
            tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

            proxy, port, task = await _start_proxy(
                backend_url, audit_logger, engine, tracker,
            )

            try:
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    # First: call email tool — allowed
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "gmail_read", "arguments": {"query": "inbox"}},
                    ) as resp:
                        assert resp.status == 200

                    # Second: call browser tool — chain-blocked
                    async with session.post(
                        f"http://127.0.0.1:{port}/tools-invoke",
                        json={"tool": "browser_navigate", "arguments": {"url": "https://x.com"}},
                    ) as resp:
                        assert resp.status == 403
            finally:
                await _stop_proxy(proxy, task)
        finally:
            await runner.cleanup()

        # Read audit log and count tool_call events
        log_path = tmp_path / "audit.jsonl"
        lines = log_path.read_text().strip().split("\n")
        events = [json.loads(line) for line in lines]
        tool_calls = [e for e in events if e.get("event") == "tool_call"]

        # Exactly 2 entries: one ALLOW for gmail_read, one BLOCK for browser_navigate
        assert len(tool_calls) == 2, f"Expected 2 tool_call entries, got {len(tool_calls)}: {tool_calls}"

        gmail_entry = tool_calls[0]
        assert gmail_entry["tool"] == "gmail_read"
        assert gmail_entry["decision"] == "ALLOW"
        assert gmail_entry.get("chain_violation") is not True

        browser_entry = tool_calls[1]
        assert browser_entry["tool"] == "browser_navigate"
        assert browser_entry["decision"] == "BLOCK"
        assert browser_entry["chain_violation"] is True


class TestWebSocketDetection:
    """Tests for WebSocket upgrade header detection.

    The proxy should detect WebSocket upgrade requests even when the
    Connection header contains multiple comma-separated tokens (e.g.,
    'Connection: Upgrade, keep-alive').
    """

    @pytest.mark.asyncio
    async def test_multi_value_connection_header_triggers_ws_handler(
        self, backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Request with 'Connection: Upgrade, keep-alive' goes to the WS handler.

        The WS handler will try to connect to the backend which doesn't support
        WS, so it will fail. But the proxy should have accepted the WS upgrade
        from the client before that failure — proving the detection logic works.
        """
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            # Send a WS upgrade with multi-value Connection header.
            # The proxy should accept the WS upgrade (proving detection works),
            # then fail when connecting to the non-WS backend.
            ws_accepted = False
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(
                        f"http://127.0.0.1:{port}/ws-test",
                        timeout=aiohttp.ClientWSTimeout(ws_close=1.0),
                    ) as ws:
                        ws_accepted = True
            except Exception:
                # The proxy accepted the WS upgrade from the client (good!)
                # but failed to connect to the backend (expected).
                # aiohttp may raise before ws_connect fully completes.
                pass

            # The backend should have received a request at /ws-test — this is
            # the proxy's WS handler trying to open a WS connection to the
            # backend. The key proof: it was a GET (WS handshake), not a
            # forwarded POST or regular HTTP request.
            ws_reqs = [r for r in app["requests"] if r.get("path") == "/ws-test"]
            assert len(ws_reqs) == 1
            assert ws_reqs[0]["method"] == "GET"  # WS handshake is always GET
        finally:
            await _stop_proxy(proxy, task)


class TestInvalidToolInvokeBody:
    """Verify /tools-invoke rejects malformed bodies instead of forwarding them."""

    @pytest.mark.asyncio
    async def test_non_json_body_returns_400(
        self, backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Non-JSON body to /tools-invoke should return 400, not forward."""
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    data=b"not json at all",
                    headers={"Content-Type": "application/json"},
                ) as resp:
                    assert resp.status == 400
                    data = await resp.json()
                    assert data["error"]["type"] == "bad_request"

            # Backend should NOT have received this request
            tool_reqs = [r for r in app["requests"] if r.get("path") == "/tools-invoke"]
            assert len(tool_reqs) == 0
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_missing_tool_field_returns_400(
        self, backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """JSON body without 'tool' field should return 400, not forward."""
        app, backend_url = backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"some_key": "some_value"},
                ) as resp:
                    assert resp.status == 400
                    data = await resp.json()
                    assert data["error"]["type"] == "bad_request"

            # Backend should NOT have received this request
            tool_reqs = [r for r in app["requests"] if r.get("path") == "/tools-invoke"]
            assert len(tool_reqs) == 0
        finally:
            await _stop_proxy(proxy, task)


class TestAuditLogWriteFailure:
    """Verify the proxy survives audit log write failures."""

    @pytest.mark.asyncio
    async def test_proxy_continues_after_log_write_failure(
        self, backend: tuple, tmp_path: Path,
    ) -> None:
        """Make the log file unwritable, then send a tool call — proxy must not crash."""
        app, backend_url = backend

        # Create a logger that will fail on write
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log_path)
        # Force-close the file handle to simulate I/O failure
        assert logger._log_file is not None
        logger._log_file.close()

        proxy, port, task = await _start_proxy(backend_url, logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                # This call triggers log_tool_call → _write_entry on a closed file.
                # Before the fix, this would raise ValueError and crash the proxy.
                async with session.post(
                    f"http://127.0.0.1:{port}/tools-invoke",
                    json={"tool": "test-tool", "arguments": {}},
                ) as resp:
                    # Proxy should still function — the tool call goes through
                    assert resp.status == 200
        finally:
            await _stop_proxy(proxy, task)


# ---------------------------------------------------------------------------
# WebSocket mock backend
# ---------------------------------------------------------------------------


def _create_ws_backend() -> web.Application:
    """Create a mock backend with WebSocket support for testing WS interception.

    The backend accepts WebSocket connections on any path. For ``node.invoke``
    request frames, it records the frame and replies with a success response.
    """
    app = web.Application()
    app["ws_received"] = []  # type: ignore[assignment]

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                app["ws_received"].append(msg.data)
                try:
                    parsed = json.loads(msg.data)
                    if isinstance(parsed, dict) and parsed.get("type") == "req":
                        response = json.dumps({
                            "type": "res",
                            "id": parsed["id"],
                            "ok": True,
                            "payload": {"result": "executed"},
                        })
                        await ws.send_str(response)
                except Exception:
                    pass
            elif msg.type == aiohttp.WSMsgType.BINARY:
                app["ws_received"].append(msg.data)
                await ws.send_bytes(msg.data)

        return ws

    app.router.add_get("/", ws_handler)
    app.router.add_get("/{path_info:.*}", ws_handler)

    return app


def _make_node_invoke_frame(
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    request_id: str = "test-id-1",
) -> str:
    """Build a ClawdBot ``node.invoke`` request frame."""
    return json.dumps({
        "type": "req",
        "id": request_id,
        "method": "node.invoke",
        "params": {
            "nodeId": "test-node",
            "command": tool_name,
            "params": arguments or {},
        },
    })


@pytest.fixture()
async def ws_backend():
    """Start a WebSocket mock backend and return (app, url)."""
    app = _create_ws_backend()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
    url = f"http://127.0.0.1:{port}"
    yield app, url
    await runner.cleanup()


# ---------------------------------------------------------------------------
# WebSocket interception tests
# ---------------------------------------------------------------------------


class TestWebSocketInterception:
    """Tests for node.invoke interception over WebSocket."""

    @pytest.mark.asyncio
    async def test_ws_node_invoke_allowed_no_policy(
        self, ws_backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Passthrough mode: node.invoke forwarded to backend."""
        app, backend_url = ws_backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    frame = _make_node_invoke_frame("test-tool", {"key": "val"})
                    await ws.send_str(frame)

                    resp = await asyncio.wait_for(ws.receive_str(), timeout=2.0)
                    data = json.loads(resp)
                    assert data["ok"] is True
                    assert data["id"] == "test-id-1"

            # Backend should have received the frame
            assert len(app["ws_received"]) == 1
            received = json.loads(app["ws_received"][0])
            assert received["method"] == "node.invoke"
            assert received["params"]["command"] == "test-tool"
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_ws_node_invoke_blocked_by_policy(
        self, ws_backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Policy blocks the tool — error frame sent back, backend NOT called."""
        app, backend_url = ws_backend
        policy = _make_policy(blocked_tools=["dangerous-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    frame = _make_node_invoke_frame("dangerous-tool", {}, "req-42")
                    await ws.send_str(frame)

                    resp = await asyncio.wait_for(ws.receive_str(), timeout=2.0)
                    data = json.loads(resp)
                    assert data["ok"] is False
                    assert data["id"] == "req-42"
                    assert data["payload"]["error"]["type"] == "policy_blocked"

            # Backend should NOT have received the frame
            assert len(app["ws_received"]) == 0
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_ws_node_invoke_approval_required(
        self, ws_backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Tool in require_approval — error frame with approval_required."""
        app, backend_url = ws_backend
        policy = _make_policy(approval_tools=["risky-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    frame = _make_node_invoke_frame("risky-tool", {}, "req-99")
                    await ws.send_str(frame)

                    resp = await asyncio.wait_for(ws.receive_str(), timeout=2.0)
                    data = json.loads(resp)
                    assert data["ok"] is False
                    assert data["id"] == "req-99"
                    assert data["payload"]["error"]["type"] == "approval_required"

            assert len(app["ws_received"]) == 0
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_ws_non_tool_messages_pass_through(
        self, ws_backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Non-node.invoke messages forwarded unchanged."""
        app, backend_url = ws_backend
        policy = _make_policy(blocked_tools=["dangerous-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    # Send a chat message (not node.invoke)
                    chat_msg = json.dumps({
                        "type": "req",
                        "id": "chat-1",
                        "method": "chat.send",
                        "params": {"text": "hello"},
                    })
                    await ws.send_str(chat_msg)

                    # Backend should receive and respond
                    resp = await asyncio.wait_for(ws.receive_str(), timeout=2.0)
                    data = json.loads(resp)
                    assert data["id"] == "chat-1"

            # Backend received the message
            assert len(app["ws_received"]) == 1
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_ws_binary_messages_pass_through(
        self, ws_backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Binary messages forwarded unchanged."""
        app, backend_url = ws_backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    await ws.send_bytes(b"\x00\x01\x02\x03")

                    resp = await asyncio.wait_for(ws.receive_bytes(), timeout=2.0)
                    assert resp == b"\x00\x01\x02\x03"

            assert len(app["ws_received"]) == 1
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_ws_malformed_json_with_node_invoke_forwarded(
        self, ws_backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """Malformed JSON containing 'node.invoke' is forwarded, not dropped."""
        app, backend_url = ws_backend
        proxy, port, task = await _start_proxy(backend_url, audit_logger)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    # Invalid JSON but contains the keyword
                    await ws.send_str('{"node.invoke": broken json')

                    # Give time for forwarding
                    await asyncio.sleep(0.3)

            # Backend should have received the raw message
            assert len(app["ws_received"]) == 1
            assert "node.invoke" in app["ws_received"][0]
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_ws_node_invoke_missing_command_forwarded(
        self, ws_backend: tuple, audit_logger: AuditLogger,
    ) -> None:
        """node.invoke frame without params.command is forwarded as-is."""
        app, backend_url = ws_backend
        policy = _make_policy(blocked_tools=["anything"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    # Valid node.invoke but no command field
                    frame = json.dumps({
                        "type": "req",
                        "id": "no-cmd",
                        "method": "node.invoke",
                        "params": {"nodeId": "test"},
                    })
                    await ws.send_str(frame)

                    resp = await asyncio.wait_for(ws.receive_str(), timeout=2.0)
                    data = json.loads(resp)
                    assert data["id"] == "no-cmd"

            # Backend should have received it (can't enforce without tool name)
            assert len(app["ws_received"]) == 1
        finally:
            await _stop_proxy(proxy, task)

    @pytest.mark.asyncio
    async def test_ws_audit_log_written(
        self, ws_backend: tuple, audit_logger: AuditLogger, tmp_path: Path,
    ) -> None:
        """Blocked WS tool call appears in audit log."""
        app, backend_url = ws_backend
        policy = _make_policy(blocked_tools=["bad-tool"])
        engine = PolicyEngine(policy)
        proxy, port, task = await _start_proxy(backend_url, audit_logger, engine)

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                    frame = _make_node_invoke_frame("bad-tool", {}, "audit-1")
                    await ws.send_str(frame)
                    await asyncio.wait_for(ws.receive_str(), timeout=2.0)
        finally:
            await _stop_proxy(proxy, task)

        log_path = tmp_path / "audit.jsonl"
        lines = log_path.read_text().strip().split("\n")
        events = [json.loads(line) for line in lines]
        tool_calls = [e for e in events if e.get("event") == "tool_call"]

        assert len(tool_calls) == 1
        assert tool_calls[0]["tool"] == "bad-tool"
        assert tool_calls[0]["decision"] == "BLOCK"

    @pytest.mark.asyncio
    async def test_ws_chain_block_blanket_mode(
        self, audit_logger: AuditLogger,
    ) -> None:
        """Blanket mode over WS: email tool then browser tool → chain blocked."""
        ws_app = _create_ws_backend()
        runner = web.AppRunner(ws_app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        backend_port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        backend_url = f"http://127.0.0.1:{backend_port}"

        try:
            policy = _make_chain_policy(mode=ChainingMode.BLANKET)
            engine = PolicyEngine(policy)
            tracker = ChainTracker(engine, mode=ChainingMode.BLANKET)

            proxy, port, task = await _start_proxy(
                backend_url, audit_logger, engine, tracker,
            )

            try:
                import aiohttp

                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(f"http://127.0.0.1:{port}/") as ws:
                        # First: email tool — should be allowed
                        frame1 = _make_node_invoke_frame("gmail_read", {"query": "inbox"}, "r1")
                        await ws.send_str(frame1)
                        resp1 = await asyncio.wait_for(ws.receive_str(), timeout=2.0)
                        data1 = json.loads(resp1)
                        assert data1["ok"] is True

                        # Second: browser tool — should be chain-blocked
                        frame2 = _make_node_invoke_frame("browser_navigate", {"url": "https://x.com"}, "r2")
                        await ws.send_str(frame2)
                        resp2 = await asyncio.wait_for(ws.receive_str(), timeout=2.0)
                        data2 = json.loads(resp2)
                        assert data2["ok"] is False
                        assert data2["payload"]["error"]["type"] == "chain_blocked"

                # Backend should only have received the first call
                assert len(ws_app["ws_received"]) == 1
            finally:
                await _stop_proxy(proxy, task)
        finally:
            await runner.cleanup()


# ---------------------------------------------------------------------------
# ClawdBot log tailer tests
# ---------------------------------------------------------------------------


class TestClawdBotLogTailer:
    """Tests for the log file tailer that surfaces tool invocations."""

    def test_tool_log_regex_matches_start(self) -> None:
        """Regex extracts tool start events."""
        line = "embedded run tool start: runId=af24974c-e854-444b-886f-2b41bfa6d7f9 tool=exec toolCallId=toolu_01PCFHQf9jsmqF9948TsRTL3"
        match = _TOOL_LOG_RE.search(line)
        assert match is not None
        assert match.group("phase") == "start"
        assert match.group("tool") == "exec"
        assert match.group("runId") == "af24974c-e854-444b-886f-2b41bfa6d7f9"
        assert match.group("toolCallId") == "toolu_01PCFHQf9jsmqF9948TsRTL3"

    def test_tool_log_regex_matches_end(self) -> None:
        """Regex extracts tool end events."""
        line = "embedded run tool end: runId=30bc85ef-baab-45fb-87b6-ce5e5c5d577c tool=exec toolCallId=toolu_01FFMLFC2BtGc6YvFEtpwUAk"
        match = _TOOL_LOG_RE.search(line)
        assert match is not None
        assert match.group("phase") == "end"
        assert match.group("tool") == "exec"

    def test_tool_log_regex_no_match_on_agent_start(self) -> None:
        """Regex does not match non-tool log lines."""
        line = "embedded run agent start: runId=30bc85ef-baab-45fb-87b6-ce5e5c5d577c"
        match = _TOOL_LOG_RE.search(line)
        assert match is None

    @pytest.mark.asyncio
    async def test_process_clawdbot_log_line_tool_start(
        self, audit_logger: AuditLogger, tmp_path: Path,
    ) -> None:
        """Tool start log line produces audit log entry."""
        proxy = HttpProxy(
            backend_url="http://127.0.0.1:9999",
            listen_host="127.0.0.1",
            listen_port=0,
            policy_engine=None,
            audit_logger=audit_logger,
        )

        log_entry = json.dumps({
            "0": '{"subsystem":"agent/embedded"}',
            "1": "embedded run tool start: runId=af24974c-e854-444b-886f-2b41bfa6d7f9 tool=exec toolCallId=toolu_01PCFHQf9jsmqF9948TsRTL3",
        })

        proxy._process_clawdbot_log_line(log_entry)

        # Check audit log was written
        log_path = tmp_path / "audit.jsonl"
        lines = log_path.read_text().strip().split("\n")
        events = [json.loads(line) for line in lines if line.strip()]
        tool_calls = [e for e in events if e.get("event") == "tool_call"]

        assert len(tool_calls) == 1
        assert tool_calls[0]["tool"] == "exec"
        assert tool_calls[0]["decision"] == "ALLOW"

    @pytest.mark.asyncio
    async def test_process_clawdbot_log_line_tool_end_no_audit(
        self, audit_logger: AuditLogger, tmp_path: Path,
    ) -> None:
        """Tool end log line does NOT produce an audit log entry."""
        proxy = HttpProxy(
            backend_url="http://127.0.0.1:9999",
            listen_host="127.0.0.1",
            listen_port=0,
            policy_engine=None,
            audit_logger=audit_logger,
        )

        log_entry = json.dumps({
            "0": '{"subsystem":"agent/embedded"}',
            "1": "embedded run tool end: runId=af24974c tool=exec toolCallId=toolu_01PCFHQf",
        })

        proxy._process_clawdbot_log_line(log_entry)

        # Tool end should NOT write to audit log
        log_path = tmp_path / "audit.jsonl"
        content = log_path.read_text().strip()
        tool_calls = [
            json.loads(line)
            for line in content.split("\n")
            if line.strip() and json.loads(line).get("event") == "tool_call"
        ]
        assert len(tool_calls) == 0

    def test_process_clawdbot_log_line_invalid_json(
        self, audit_logger: AuditLogger,
    ) -> None:
        """Invalid JSON lines are silently skipped."""
        proxy = HttpProxy(
            backend_url="http://127.0.0.1:9999",
            listen_host="127.0.0.1",
            listen_port=0,
            policy_engine=None,
            audit_logger=audit_logger,
        )
        # Should not raise
        proxy._process_clawdbot_log_line("not json at all")
        proxy._process_clawdbot_log_line("")

    def test_process_clawdbot_log_line_non_tool_entry(
        self, audit_logger: AuditLogger,
    ) -> None:
        """Non-tool log lines are silently skipped."""
        proxy = HttpProxy(
            backend_url="http://127.0.0.1:9999",
            listen_host="127.0.0.1",
            listen_port=0,
            policy_engine=None,
            audit_logger=audit_logger,
        )

        log_entry = json.dumps({
            "0": '{"subsystem":"diagnostic"}',
            "1": "session state: sessionId=abc prev=idle new=processing reason=run_started",
        })
        # Should not raise or log anything
        proxy._process_clawdbot_log_line(log_entry)
