"""Telegram approval for AgentWard — via CONNECT proxy with TLS interception.

AgentWard sits between OpenClaw and ``api.telegram.org`` as an HTTP CONNECT
proxy.  OpenClaw's config sets ``channels.telegram.proxy`` to point at this
proxy, and ``undici.ProxyAgent`` sends a ``CONNECT api.telegram.org:443``
request.

**How it works:**

1. OpenClaw sends ``CONNECT api.telegram.org:443`` to AgentWard.
2. AgentWard responds ``200 Connection Established`` and performs TLS
   termination with an auto-generated self-signed certificate.
3. Inside the decrypted tunnel, AgentWard sees plaintext HTTP requests
   (``getUpdates``, ``sendMessage``, etc.) and forwards them to the real
   ``api.telegram.org`` over TLS.
4. On ``getUpdates`` responses, AgentWard inspects the returned updates
   and strips ``callback_query`` updates whose ``data`` matches a pending
   AgentWard request ID.  These are resolved locally; all other updates
   pass through to OpenClaw unmodified.

Since the self-signed certificate is not trusted by Node.js,
``agentward setup`` sets ``NODE_TLS_REJECT_UNAUTHORIZED=0`` in the
LaunchAgent plist for the tunnel to work.  This only affects
localhost-to-localhost traffic.

The bot token is read from OpenClaw's config
(``channels.telegram.botToken``).  The user's ``chat_id`` is obtained via
a one-time ``/start`` pairing step and persisted to a state file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import tempfile
import uuid
from pathlib import Path
from typing import Any

import aiohttp
from rich.console import Console

from agentward.proxy.approval import ApprovalDecision, _format_dialog_message

_console = Console(stderr=True)

# All AgentWard callback data uses this prefix so we can identify our
# callbacks in the getUpdates response stream.
_CALLBACK_PREFIX = "aw:"

# Default port for the Telegram API proxy.
_DEFAULT_TELEGRAM_PROXY_PORT = 18901

_TELEGRAM_API_HOST = "https://api.telegram.org"
_TELEGRAM_HOST = "api.telegram.org"
_TELEGRAM_PORT = 443


def _generate_self_signed_cert() -> tuple[str, str]:
    """Generate a self-signed TLS certificate for api.telegram.org.

    Uses the ``cryptography`` library if available, otherwise falls back
    to a subprocess call to ``openssl``.

    Returns:
        Tuple of (cert_pem_path, key_pem_path) as temp file paths.
    """
    cert_path = Path(tempfile.mktemp(suffix=".pem", prefix="aw_tg_cert_"))
    key_path = Path(tempfile.mktemp(suffix=".pem", prefix="aw_tg_key_"))

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, _TELEGRAM_HOST),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(_TELEGRAM_HOST)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
    except ImportError:
        # Fallback to openssl CLI
        import subprocess

        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "365", "-nodes",
                "-subj", f"/CN={_TELEGRAM_HOST}",
                "-addext", f"subjectAltName=DNS:{_TELEGRAM_HOST}",
            ],
            check=True,
            capture_output=True,
        )

    return str(cert_path), str(key_path)


class TelegramApprovalBot:
    """Telegram approval bot backed by a CONNECT proxy with TLS MITM.

    Handles the ``CONNECT api.telegram.org:443`` request from undici's
    ``ProxyAgent``, terminates TLS with a self-signed cert, inspects
    plaintext HTTP traffic, and forwards to the real Telegram API.

    Lifecycle::

        bot = TelegramApprovalBot(token, chat_id, state_file, proxy_port)
        await bot.start()       # starts the CONNECT proxy server
        ...
        decision = await bot.request_approval(name, args, reason, timeout)
        ...
        await bot.stop()        # shuts down the proxy

    Args:
        bot_token: Telegram Bot API token.
        chat_id: The paired user's chat ID (None if not yet paired).
        state_file: Path to persist the chat_id after pairing.
        proxy_port: Local port for the CONNECT proxy.
    """

    def __init__(
        self,
        bot_token: str,
        chat_id: int | None,
        state_file: Path,
        proxy_port: int = _DEFAULT_TELEGRAM_PROXY_PORT,
    ) -> None:
        self._bot_token = bot_token
        self._chat_id = chat_id
        self._state_file = state_file
        self._proxy_port = proxy_port
        self._pending: dict[str, asyncio.Future[ApprovalDecision]] = {}
        self._server: asyncio.Server | None = None
        self._session: aiohttp.ClientSession | None = None
        self._ssl_ctx: ssl.SSLContext | None = None  # for outbound to Telegram
        self._mitm_ctx: ssl.SSLContext | None = None  # for inbound TLS termination
        self._cert_path: str | None = None
        self._key_path: str | None = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_paired(self) -> bool:
        """True if a chat_id is configured (user has sent /start)."""
        return self._chat_id is not None

    @property
    def proxy_port(self) -> int:
        """The local port the CONNECT proxy listens on."""
        return self._proxy_port

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the CONNECT proxy server with TLS MITM.

        Generates a self-signed certificate, starts listening for
        CONNECT requests, and creates an aiohttp session for outbound
        Telegram API calls.
        """
        # Suppress the noisy "returning true from eof_received() has no
        # effect when using ssl" warning that asyncio emits every time a
        # TLS connection is closed.  This is expected and harmless.
        logging.getLogger("asyncio").setLevel(logging.CRITICAL)

        # Generate self-signed cert for TLS MITM
        self._cert_path, self._key_path = _generate_self_signed_cert()

        self._mitm_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._mitm_ctx.load_cert_chain(self._cert_path, self._key_path)

        self._ssl_ctx = ssl.create_default_context()
        self._session = aiohttp.ClientSession()

        try:
            self._server = await asyncio.start_server(
                self._handle_connect,
                "127.0.0.1",
                self._proxy_port,
            )
        except OSError as exc:
            # Clean up session before propagating (e.g. address already in use)
            await self._session.close()
            self._session = None
            if exc.errno == 48:  # EADDRINUSE
                raise OSError(
                    exc.errno,
                    f"Telegram CONNECT proxy port {self._proxy_port} already in use. "
                    f"Kill the old process: lsof -i :{self._proxy_port}",
                ) from None
            raise

        _console.print(
            f"  [dim]Telegram CONNECT proxy on 127.0.0.1:{self._proxy_port}[/dim]",
            highlight=False,
        )

    async def stop(self) -> None:
        """Stop the proxy server and cancel pending futures."""
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        if self._session is not None:
            await self._session.close()
            self._session = None

        # Clean up temp cert files
        for path in (self._cert_path, self._key_path):
            if path is not None:
                try:
                    Path(path).unlink(missing_ok=True)
                except OSError:
                    pass

        # Cancel any pending futures
        for fut in self._pending.values():
            if not fut.done():
                fut.cancel()
        self._pending.clear()

    # ------------------------------------------------------------------
    # CONNECT proxy handler
    # ------------------------------------------------------------------

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an incoming TCP connection (expects CONNECT method).

        After the CONNECT handshake, we extract the raw socket, wrap it
        with ``asyncio.open_connection(ssl=...)`` for a proper TLS-upgraded
        stream pair, and hand off to ``_handle_tunnel``.
        """
        tls_reader: asyncio.StreamReader | None = None
        tls_writer: asyncio.StreamWriter | None = None
        try:
            # Read the initial HTTP request line
            request_line = await asyncio.wait_for(
                reader.readline(), timeout=30,
            )
            if not request_line:
                writer.close()
                return

            line = request_line.decode("utf-8", errors="replace").strip()

            # Read and discard headers until blank line
            while True:
                header_line = await reader.readline()
                if not header_line or header_line.strip() == b"":
                    break

            # Parse CONNECT request
            parts = line.split()
            if len(parts) < 2 or parts[0] != "CONNECT":
                # Not a CONNECT request — send 405
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            # Send 200 to establish tunnel
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            if self._mitm_ctx is None:
                writer.close()
                return

            # Upgrade to server-side TLS.  start_tls() wraps the underlying
            # transport and calls connection_lost/connection_made on the
            # protocol, so the original reader/writer keep working but now
            # carry decrypted data.
            loop = asyncio.get_running_loop()
            new_transport = await loop.start_tls(
                writer.transport,
                writer.transport.get_protocol(),
                self._mitm_ctx,
                server_side=True,
            )

            # After start_tls, the writer's transport reference is stale.
            # Replace it so writes go through the TLS layer.
            writer._transport = new_transport  # noqa: SLF001

            # The reader is fed by the protocol which start_tls reconnected
            # to the new transport, so it already receives decrypted data.
            tls_reader = reader
            tls_writer = writer

            # Handle plaintext HTTP inside the tunnel
            await self._handle_tunnel(tls_reader, tls_writer)

        except (ConnectionError, asyncio.TimeoutError, OSError):
            pass  # Client disconnected or tunnel closed
        except Exception as exc:
            _console.print(
                f"  [dim]Telegram proxy error: {type(exc).__name__}: {exc}[/dim]",
                highlight=False,
            )
        finally:
            for w in (tls_writer, writer):
                try:
                    if w is not None:
                        w.close()
                except Exception:
                    pass

    async def _handle_tunnel(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle plaintext HTTP requests inside the TLS tunnel.

        Reads HTTP requests, forwards them to ``api.telegram.org``,
        and for ``getUpdates`` responses, filters out AgentWard callbacks.
        """
        if self._session is None:
            return

        try:
            while True:
                # Read HTTP request line
                request_line = await asyncio.wait_for(
                    reader.readline(), timeout=120,
                )
                if not request_line:
                    break

                line = request_line.decode("utf-8", errors="replace").strip()
                if not line:
                    break

                parts = line.split(" ", 2)
                if len(parts) < 2:
                    break

                method = parts[0]
                path = parts[1]

                # Read headers
                headers: dict[str, str] = {}
                content_length = 0
                while True:
                    header_line = await reader.readline()
                    if not header_line or header_line.strip() == b"":
                        break
                    decoded = header_line.decode("utf-8", errors="replace").strip()
                    if ":" in decoded:
                        key, value = decoded.split(":", 1)
                        headers[key.strip()] = value.strip()
                        if key.strip().lower() == "content-length":
                            content_length = int(value.strip())

                # Read body
                body = b""
                if content_length > 0:
                    body = await asyncio.wait_for(
                        reader.readexactly(content_length), timeout=30,
                    )

                # Forward to Telegram
                upstream_url = f"{_TELEGRAM_API_HOST}{path}"
                fwd_headers = {
                    k: v for k, v in headers.items()
                    if k.lower() not in ("host", "content-length", "transfer-encoding")
                }

                try:
                    async with self._session.request(
                        method=method,
                        url=upstream_url,
                        headers=fwd_headers,
                        data=body if body else None,
                        ssl=self._ssl_ctx,
                    ) as resp:
                        resp_body = await resp.read()

                        # Filter getUpdates responses
                        if "/getUpdates" in path:
                            resp_body = self._filter_updates(resp_body)

                        # Build response
                        resp_line = f"HTTP/1.1 {resp.status} {resp.reason}\r\n"
                        writer.write(resp_line.encode())

                        for key, value in resp.headers.items():
                            if key.lower() in (
                                "content-length", "transfer-encoding",
                                "content-encoding",
                            ):
                                continue
                            writer.write(f"{key}: {value}\r\n".encode())

                        writer.write(f"Content-Length: {len(resp_body)}\r\n".encode())
                        writer.write(b"\r\n")
                        writer.write(resp_body)
                        await writer.drain()

                except Exception as exc:
                    # Send 502 back to client
                    error_body = str(exc).encode()
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\n")
                    writer.write(f"Content-Length: {len(error_body)}\r\n".encode())
                    writer.write(b"\r\n")
                    writer.write(error_body)
                    await writer.drain()

        except (ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass  # Tunnel closed

    def _filter_updates(self, body: bytes) -> bytes:
        """Inspect getUpdates response and extract AgentWard callbacks.

        - Strips ``callback_query`` updates whose ``data`` starts with
          the AgentWard prefix.
        - Detects ``/start`` messages for pairing.
        - Returns the modified response body for OpenClaw.
        """
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return body

        if not isinstance(data, dict) or not data.get("ok"):
            return body

        result = data.get("result")
        if not isinstance(result, list):
            return body

        filtered: list[dict[str, Any]] = []
        modified = False

        for update in result:
            if not isinstance(update, dict):
                filtered.append(update)
                continue

            # Check for AgentWard callback queries
            callback = update.get("callback_query")
            if callback and isinstance(callback, dict):
                cb_data = callback.get("data", "")
                if isinstance(cb_data, str) and cb_data.startswith(_CALLBACK_PREFIX):
                    # This is ours — resolve it and strip from response
                    self._resolve_callback(callback)
                    modified = True
                    continue  # Don't pass to OpenClaw

            # Check for /start pairing messages
            message = update.get("message")
            if message and isinstance(message, dict):
                text = message.get("text", "")
                if isinstance(text, str) and text.strip() == "/start":
                    chat = message.get("chat", {})
                    chat_id = chat.get("id") if isinstance(chat, dict) else None
                    if chat_id is not None:
                        self._handle_pairing(chat_id)
                        # Still pass /start through to OpenClaw

            filtered.append(update)

        if not modified:
            return body

        data["result"] = filtered
        return json.dumps(data).encode()

    def _resolve_callback(self, callback: dict[str, Any]) -> None:
        """Resolve a pending future from a callback query.

        Also answers the callback query to dismiss the loading spinner.

        Args:
            callback: The callback_query object from the update.
        """
        cb_data = callback.get("data", "")
        if not isinstance(cb_data, str):
            return

        # Strip prefix: "aw:{request_id}:{decision}"
        payload = cb_data[len(_CALLBACK_PREFIX):]
        parts = payload.split(":", 1)
        if len(parts) != 2:
            return

        request_id, decision_str = parts
        decision = _parse_callback_decision(decision_str)
        if decision is None:
            return

        future = self._pending.get(request_id)
        if future is not None and not future.done():
            future.set_result(decision)

        # Answer callback query to dismiss spinner (best-effort, fire-and-forget)
        callback_id = callback.get("id")
        if callback_id and self._session is not None:
            asyncio.create_task(self._answer_callback(callback_id))

    async def _answer_callback(self, callback_query_id: str) -> None:
        """Answer a callback query to dismiss the loading spinner."""
        if self._session is None:
            return
        url = f"{_TELEGRAM_API_HOST}/bot{self._bot_token}/answerCallbackQuery"
        try:
            async with self._session.post(
                url,
                json={"callback_query_id": callback_query_id},
                ssl=self._ssl_ctx,
            ):
                pass
        except Exception:
            pass  # Best-effort

    def _handle_pairing(self, chat_id: int) -> None:
        """Handle a /start pairing message.

        Saves the chat_id and sends a confirmation message (fire-and-forget).
        Only logs and sends confirmation on the first pairing or when the
        chat_id changes — not on every reconnect.
        """
        if self._chat_id == chat_id:
            return  # Already paired to this chat — skip noise

        self._chat_id = chat_id
        self._save_chat_id()

        _console.print(
            f"  [bold #00ff88]Telegram paired[/bold #00ff88] "
            f"(chat_id: {self._chat_id})",
            highlight=False,
        )

        # Send confirmation (best-effort)
        if self._session is not None:
            asyncio.create_task(self._send_pairing_confirmation())

    async def _send_pairing_confirmation(self) -> None:
        """Send a pairing confirmation message to the user."""
        if self._session is None or self._chat_id is None:
            return
        url = f"{_TELEGRAM_API_HOST}/bot{self._bot_token}/sendMessage"
        try:
            async with self._session.post(
                url,
                json={
                    "chat_id": self._chat_id,
                    "text": (
                        "\u2705 *AgentWard paired!*\n\n"
                        "You'll receive approval requests here when your agent "
                        "tries to use tools that require permission."
                    ),
                    "parse_mode": "Markdown",
                },
                ssl=self._ssl_ctx,
            ):
                pass
        except Exception:
            pass  # Best-effort

    # ------------------------------------------------------------------
    # Approval request
    # ------------------------------------------------------------------

    async def request_approval(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        reason: str,
        timeout: int = 60,
    ) -> ApprovalDecision | None:
        """Send an approval message and wait for the user's response.

        Args:
            tool_name: The tool being invoked.
            arguments: The tool call arguments.
            reason: The policy reason string.
            timeout: Seconds to wait before auto-denying.

        Returns:
            The user's decision, or None if not paired/not started.
        """
        if not self.is_paired or self._session is None:
            return None

        request_id = uuid.uuid4().hex[:12]
        message_text = _format_telegram_message(tool_name, arguments, reason)

        keyboard = {
            "inline_keyboard": [
                [
                    {
                        "text": "Allow Once",
                        "callback_data": f"{_CALLBACK_PREFIX}{request_id}:allow_once",
                    },
                    {
                        "text": "Allow Session",
                        "callback_data": f"{_CALLBACK_PREFIX}{request_id}:allow_session",
                    },
                ],
                [
                    {
                        "text": "Deny",
                        "callback_data": f"{_CALLBACK_PREFIX}{request_id}:deny",
                    },
                ],
            ],
        }

        # Send the message via Telegram Bot API
        url = f"{_TELEGRAM_API_HOST}/bot{self._bot_token}/sendMessage"
        try:
            async with self._session.post(
                url,
                json={
                    "chat_id": self._chat_id,
                    "text": message_text,
                    "reply_markup": keyboard,
                    "parse_mode": "Markdown",
                },
                ssl=self._ssl_ctx,
            ) as resp:
                resp_data = await resp.json()
        except Exception as exc:
            _console.print(
                f"  [bold red]Telegram send error:[/bold red] {exc}",
                highlight=False,
            )
            return None

        if not resp_data.get("ok"):
            _console.print(
                f"  [bold red]Telegram API error:[/bold red] "
                f"{resp_data.get('description', 'unknown')}",
                highlight=False,
            )
            return None

        message_id = resp_data.get("result", {}).get("message_id")

        # Create a future for this request
        loop = asyncio.get_running_loop()
        future: asyncio.Future[ApprovalDecision] = loop.create_future()
        self._pending[request_id] = future

        try:
            decision = await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            decision = ApprovalDecision.TIMEOUT
            if message_id:
                await self._edit_result(message_id, "\u23f1 Timed out (denied)")
        except asyncio.CancelledError:
            # Race lost to terminal — edit message to inform user
            if message_id:
                await self._edit_result(message_id, "\u21a9 Resolved from terminal")
            raise
        else:
            # Edit message to show result
            label = _decision_label(decision)
            if message_id:
                await self._edit_result(message_id, label)
        finally:
            self._pending.pop(request_id, None)

        return decision

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _edit_result(self, message_id: int, text: str) -> None:
        """Edit an approval message to show the result (best-effort)."""
        if self._session is None or self._chat_id is None:
            return
        url = f"{_TELEGRAM_API_HOST}/bot{self._bot_token}/editMessageText"
        try:
            async with self._session.post(
                url,
                json={
                    "chat_id": self._chat_id,
                    "message_id": message_id,
                    "text": text,
                },
                ssl=self._ssl_ctx,
            ):
                pass
        except Exception:
            pass  # Best-effort

    def _save_chat_id(self) -> None:
        """Persist the chat_id to the state file."""
        if self._chat_id is None:
            return
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        self._state_file.write_text(
            json.dumps({"chat_id": self._chat_id}),
        )


# -----------------------------------------------------------------------
# Message formatting
# -----------------------------------------------------------------------


def _format_telegram_message(
    tool_name: str,
    arguments: dict[str, Any],
    reason: str,
) -> str:
    """Format an approval request for Telegram.

    Reuses the same content as the macOS dialog but with Markdown
    formatting for Telegram's message renderer.

    Args:
        tool_name: The tool name.
        arguments: The tool call arguments.
        reason: The policy reason string.

    Returns:
        A Markdown-formatted message string.
    """
    body = _format_dialog_message(tool_name, arguments, reason)
    return f"\U0001f512 *AgentWard: Approval Required*\n\n```\n{body}\n```"


def _decision_label(decision: ApprovalDecision) -> str:
    """Human-readable label for an approval decision."""
    if decision == ApprovalDecision.ALLOW_SESSION:
        return "\u2705 Approved (session)"
    if decision == ApprovalDecision.ALLOW_ONCE:
        return "\u2705 Approved (once)"
    if decision == ApprovalDecision.TIMEOUT:
        return "\u23f1 Timed out (denied)"
    return "\u274c Denied"


def _parse_callback_decision(value: str) -> ApprovalDecision | None:
    """Parse a callback data decision string to an enum value."""
    mapping = {
        "allow_once": ApprovalDecision.ALLOW_ONCE,
        "allow_session": ApprovalDecision.ALLOW_SESSION,
        "deny": ApprovalDecision.DENY,
    }
    return mapping.get(value)


# -----------------------------------------------------------------------
# Factory
# -----------------------------------------------------------------------


def try_create_bot(
    config_path: Path,
    proxy_port: int = _DEFAULT_TELEGRAM_PROXY_PORT,
) -> TelegramApprovalBot | None:
    """Create a TelegramApprovalBot from OpenClaw config, or None.

    Returns None silently if:
    - No Telegram bot token in OpenClaw config
    - Telegram channel not enabled

    Args:
        config_path: Path to the OpenClaw/ClawdBot config JSON file.
        proxy_port: Port for the CONNECT proxy.

    Returns:
        A configured bot instance, or None.
    """
    try:
        config_data = json.loads(config_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    channels = config_data.get("channels", {})
    telegram_cfg = channels.get("telegram", {})

    if not telegram_cfg.get("enabled", False):
        return None

    bot_token = telegram_cfg.get("botToken")
    if not bot_token:
        return None

    # Load chat_id from state file
    state_dir = config_path.parent / "telegram"
    state_file = state_dir / "agentward-chat-id.json"
    chat_id: int | None = None

    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
            chat_id = state.get("chat_id")
        except (json.JSONDecodeError, OSError):
            pass

    paired = "paired" if chat_id else "not paired (send /start to bot)"
    _console.print(
        f"  [dim]Telegram approval: {paired}[/dim]",
        highlight=False,
    )

    return TelegramApprovalBot(
        bot_token=bot_token,
        chat_id=chat_id,
        state_file=state_file,
        proxy_port=proxy_port,
    )
