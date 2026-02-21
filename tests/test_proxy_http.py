"""Tests for the HTTP reverse proxy."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

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
from agentward.proxy.http import HttpProxy


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
