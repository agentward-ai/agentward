"""MCP config wrapping and gateway port swapping for AgentWard proxy setup.

Reads MCP config files, wraps each stdio server command with
``agentward inspect``, and writes the modified config back.
Also supports ClawdBot gateway port swapping for HTTP proxy mode.
Supports undo via embedded markers.
"""

from __future__ import annotations

import json
import platform
import plistlib
import shutil
from pathlib import Path
from typing import Any


# Marker keys embedded in wrapped server configs for undo support
_MARKER_ORIGINAL_COMMAND = "_agentward_original_command"
_MARKER_ORIGINAL_ARGS = "_agentward_original_args"
_MARKER_ORIGINAL_GATEWAY_PORT = "_agentward_original_gateway_port"

# Suffix for backup files
BACKUP_SUFFIX = ".agentward-backup"


def _find_servers_key(config: dict[str, Any]) -> str | None:
    """Detect which root key holds the server definitions.

    Supported formats:
      - ``mcpServers`` — Claude Desktop, Claude Code, Cursor, Windsurf
      - ``servers`` — VS Code

    Args:
        config: The parsed JSON config.

    Returns:
        The root key name, or None if no known key is found.
    """
    if "mcpServers" in config:
        return "mcpServers"
    if "servers" in config:
        return "servers"
    return None


def _is_stdio_server(server_def: dict[str, Any]) -> bool:
    """Check if a server definition uses stdio transport.

    A server is stdio if it has a ``command`` field and no ``url`` field,
    OR if ``type`` is explicitly ``"stdio"``.

    Args:
        server_def: A single server definition dict.

    Returns:
        True if this is a stdio server that can be wrapped.
    """
    if "url" in server_def:
        return False
    explicit_type = server_def.get("type", "")
    if explicit_type and explicit_type not in ("stdio",):
        return False
    return "command" in server_def


def _is_already_wrapped(server_def: dict[str, Any]) -> bool:
    """Check if a server is already wrapped with AgentWard.

    Detects either the marker keys or ``command == "agentward"``.

    Args:
        server_def: A single server definition dict.

    Returns:
        True if already wrapped.
    """
    if _MARKER_ORIGINAL_COMMAND in server_def:
        return True
    return server_def.get("command") == "agentward"


def wrap_config(
    config: dict[str, Any],
    policy_path: Path,
    log_path: Path | None = None,
) -> tuple[dict[str, Any], int]:
    """Wrap all stdio servers in an MCP config with agentward inspect.

    Creates a deep copy of the config with each stdio server's command
    rewritten to run through the AgentWard proxy.

    Args:
        config: The parsed MCP config dict.
        policy_path: Path to the agentward.yaml policy file (resolved to absolute).
        log_path: Optional path for audit log file.

    Returns:
        Tuple of (modified_config, count_of_wrapped_servers).

    Raises:
        ValueError: If no known servers key is found in the config.
    """
    servers_key = _find_servers_key(config)
    if servers_key is None:
        msg = (
            "No 'mcpServers' or 'servers' key found in config. "
            "Is this a valid MCP config file?"
        )
        raise ValueError(msg)

    # Deep copy to avoid mutating input
    result = json.loads(json.dumps(config))
    servers = result.get(servers_key, {})
    wrapped_count = 0

    abs_policy = str(policy_path.resolve())

    for name, server_def in servers.items():
        if not isinstance(server_def, dict):
            continue
        if not _is_stdio_server(server_def):
            continue
        if _is_already_wrapped(server_def):
            continue

        original_command = server_def["command"]
        original_args = server_def.get("args", [])

        # Build agentward inspect args
        agentward_args = ["inspect", "--policy", abs_policy]
        if log_path is not None:
            agentward_args.extend(["--log", str(log_path.resolve())])
        agentward_args.append("--")
        agentward_args.append(original_command)
        agentward_args.extend(original_args)

        # Rewrite the server definition
        server_def["command"] = "agentward"
        server_def["args"] = agentward_args

        # Store markers for undo
        server_def[_MARKER_ORIGINAL_COMMAND] = original_command
        server_def[_MARKER_ORIGINAL_ARGS] = original_args

        wrapped_count += 1

    return result, wrapped_count


def unwrap_config(config: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Restore original commands in a wrapped MCP config.

    Reads the embedded markers to recover the original command and args.

    Args:
        config: The wrapped MCP config dict.

    Returns:
        Tuple of (restored_config, count_of_unwrapped_servers).

    Raises:
        ValueError: If no known servers key is found.
    """
    servers_key = _find_servers_key(config)
    if servers_key is None:
        msg = (
            "No 'mcpServers' or 'servers' key found in config. "
            "Is this a valid MCP config file?"
        )
        raise ValueError(msg)

    result = json.loads(json.dumps(config))
    servers = result.get(servers_key, {})
    unwrapped_count = 0

    for name, server_def in servers.items():
        if not isinstance(server_def, dict):
            continue

        if _MARKER_ORIGINAL_COMMAND not in server_def:
            continue

        # Restore original command and args
        server_def["command"] = server_def.pop(_MARKER_ORIGINAL_COMMAND)
        server_def["args"] = server_def.pop(_MARKER_ORIGINAL_ARGS)
        unwrapped_count += 1

    return result, unwrapped_count


def read_config(config_path: Path) -> dict[str, Any]:
    """Read and parse an MCP config file.

    Args:
        config_path: Path to the JSON config file.

    Returns:
        The parsed config dict.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the file is not valid JSON.
    """
    if not config_path.exists():
        msg = f"Config file not found: {config_path}"
        raise FileNotFoundError(msg)

    text = config_path.read_text(encoding="utf-8")
    try:
        config = json.loads(text)
    except json.JSONDecodeError as e:
        msg = f"Invalid JSON in {config_path}: {e}"
        raise ValueError(msg) from e

    if not isinstance(config, dict):
        msg = f"Config must be a JSON object, got {type(config).__name__}"
        raise ValueError(msg)

    return config


def write_config(config_path: Path, config: dict[str, Any], backup: bool = True) -> Path | None:
    """Write an MCP config file, optionally backing up the original.

    Args:
        config_path: Path to write the config to.
        config: The config dict to write.
        backup: Whether to create a backup of the existing file.

    Returns:
        Path to the backup file if created, or None.
    """
    backup_path: Path | None = None

    if backup and config_path.exists():
        backup_path = config_path.with_suffix(config_path.suffix + BACKUP_SUFFIX)
        shutil.copy2(config_path, backup_path)

    try:
        config_path.write_text(
            json.dumps(config, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except PermissionError:
        raise PermissionError(
            f"Permission denied writing to {config_path}. "
            f"Check file permissions or run with appropriate privileges."
        ) from None

    return backup_path


def format_diff(
    original: dict[str, Any],
    wrapped: dict[str, Any],
) -> str:
    """Format a human-readable diff showing what changed.

    Args:
        original: The original config.
        wrapped: The wrapped config.

    Returns:
        A string showing the changes.
    """
    servers_key = _find_servers_key(wrapped)
    if servers_key is None:
        return "No servers found."

    orig_servers = original.get(servers_key, {})
    wrap_servers = wrapped.get(servers_key, {})
    lines: list[str] = []

    for name in wrap_servers:
        orig = orig_servers.get(name, {})
        wrap = wrap_servers.get(name, {})

        if not isinstance(orig, dict) or not isinstance(wrap, dict):
            continue

        orig_cmd = orig.get("command", "")
        wrap_cmd = wrap.get("command", "")

        if orig_cmd != wrap_cmd:
            orig_full = f"{orig_cmd} {' '.join(orig.get('args', []))}"
            wrap_full = f"{wrap_cmd} {' '.join(wrap.get('args', []))}"
            lines.append(f"  {name}:")
            lines.append(f"    - {orig_full}")
            lines.append(f"    + {wrap_full}")

    if not lines:
        return "  No changes."

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ClawdBot gateway port swapping
# ---------------------------------------------------------------------------

_DEFAULT_GATEWAY_PORT = 18789
_DEFAULT_LLM_PROXY_PORT = 18900
_DEFAULT_TELEGRAM_PROXY_PORT = 18901

# Default upstream URLs per provider prefix.
_PROVIDER_BASE_URLS: dict[str, str] = {
    "anthropic": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "openai-codex": "https://api.openai.com",
}

# Sidecar file stored next to the OpenClaw/ClawdBot config to track the
# original port. The config validates strictly and rejects unknown keys,
# so we cannot embed markers inside the config JSON itself.
_GATEWAY_SIDECAR_NAME = ".agentward-gateway.json"

# macOS LaunchAgent plist names — new OpenClaw first, then legacy ClawdBot.
# The plist hardcodes the port as a CLI arg (--port) and env var, so we must
# update it alongside the config JSON.
_LAUNCHAGENT_PLIST_NAMES = [
    "ai.openclaw.gateway.plist",    # OpenClaw (current)
    "bot.molt.gateway.plist",       # OpenClaw (older builds)
    "com.clawdbot.gateway.plist",   # ClawdBot (legacy)
]


def _launchagent_plist_path() -> Path | None:
    """Find the OpenClaw/ClawdBot LaunchAgent plist if it exists.

    Searches ``ai.openclaw.gateway.plist`` (current OpenClaw) first, then
    ``bot.molt.gateway.plist`` (older OpenClaw), then ``com.clawdbot.gateway.plist``
    (legacy ClawdBot).

    Returns:
        Path to the plist, or None if not found.
    """
    agents_dir = Path.home() / "Library" / "LaunchAgents"
    for name in _LAUNCHAGENT_PLIST_NAMES:
        plist_path = agents_dir / name
        if plist_path.exists():
            return plist_path
    return None


def _patch_plist_port(plist_path: Path, new_port: int) -> bool:
    """Update the gateway port in the LaunchAgent plist.

    Patches both the ``--port`` CLI argument in ``ProgramArguments``
    and the gateway port environment variable (``OPENCLAW_GATEWAY_PORT``
    or ``CLAWDBOT_GATEWAY_PORT``).

    Args:
        plist_path: Path to the .plist file.
        new_port: The new port value to set.

    Returns:
        True if the plist was modified, False if no port fields were found.
    """
    with plist_path.open("rb") as f:
        plist = plistlib.load(f)

    modified = False

    # Patch ProgramArguments: look for "--port" followed by a port string
    args = plist.get("ProgramArguments", [])
    for i, arg in enumerate(args):
        if arg == "--port" and i + 1 < len(args):
            args[i + 1] = str(new_port)
            modified = True
            break

    # Patch EnvironmentVariables — handle both new and legacy env var names
    env = plist.get("EnvironmentVariables", {})
    for env_key in ("OPENCLAW_GATEWAY_PORT", "CLAWDBOT_GATEWAY_PORT"):
        if env_key in env:
            env[env_key] = str(new_port)
            modified = True

    if modified:
        with plist_path.open("wb") as f:
            plistlib.dump(plist, f)

    return modified


def _patch_plist_auth(plist_path: Path, *, disable: bool) -> str | None:
    """Disable or restore gateway token auth in the LaunchAgent plist.

    The gateway reads ``OPENCLAW_GATEWAY_TOKEN`` from the plist env vars
    and enables token auth if set — regardless of the JSON config.  To
    truly disable auth we must clear this env var.

    Args:
        plist_path: Path to the .plist file.
        disable: True to clear the token (returns original token),
                 False has no effect (use ``_restore_plist_auth``).

    Returns:
        The original token value if it was cleared, or None.
    """
    if not disable:
        return None

    with plist_path.open("rb") as f:
        plist = plistlib.load(f)

    env = plist.get("EnvironmentVariables", {})
    original_token: str | None = None
    for token_key in ("OPENCLAW_GATEWAY_TOKEN", "CLAWDBOT_GATEWAY_TOKEN"):
        if token_key in env:
            original_token = env.pop(token_key)
            break  # Only need to clear one — gateway checks whichever is present

    if original_token is not None:
        with plist_path.open("wb") as f:
            plistlib.dump(plist, f)

    return original_token


def _restore_plist_auth(plist_path: Path, token: str) -> None:
    """Restore the gateway token in the LaunchAgent plist.

    Args:
        plist_path: Path to the .plist file.
        token: The original token value to restore.
    """
    with plist_path.open("rb") as f:
        plist = plistlib.load(f)

    env = plist.get("EnvironmentVariables", {})
    env["OPENCLAW_GATEWAY_TOKEN"] = token

    with plist_path.open("wb") as f:
        plistlib.dump(plist, f)


def _patch_plist_tls_reject(plist_path: Path, *, disable: bool) -> str | None:
    """Set NODE_TLS_REJECT_UNAUTHORIZED=0 in the LaunchAgent plist.

    Required for the Telegram CONNECT proxy — undici must accept the
    self-signed certificate that AgentWard presents during TLS MITM.
    Only affects localhost traffic.

    Args:
        plist_path: Path to the .plist file.
        disable: True to set NODE_TLS_REJECT_UNAUTHORIZED=0 (returns original value).

    Returns:
        The original value if it was set, or None.
    """
    if not disable:
        return None

    with plist_path.open("rb") as f:
        plist = plistlib.load(f)

    env = plist.get("EnvironmentVariables", {})
    original = env.get("NODE_TLS_REJECT_UNAUTHORIZED")
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
    plist["EnvironmentVariables"] = env

    with plist_path.open("wb") as f:
        plistlib.dump(plist, f)

    return original


def _restore_plist_tls_reject(plist_path: Path, original_value: str | None) -> None:
    """Restore NODE_TLS_REJECT_UNAUTHORIZED in the LaunchAgent plist.

    Args:
        plist_path: Path to the .plist file.
        original_value: The original value to restore, or None to remove the key.
    """
    with plist_path.open("rb") as f:
        plist = plistlib.load(f)

    env = plist.get("EnvironmentVariables", {})
    if original_value is None:
        env.pop("NODE_TLS_REJECT_UNAUTHORIZED", None)
    else:
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = original_value

    with plist_path.open("wb") as f:
        plistlib.dump(plist, f)


def _sidecar_path(config_path: Path) -> Path:
    """Return the sidecar file path for a given OpenClaw/ClawdBot config.

    Args:
        config_path: Path to the config file (openclaw.json or clawdbot.json).

    Returns:
        Path to the sidecar file in the same directory.
    """
    return config_path.parent / _GATEWAY_SIDECAR_NAME


def _patch_telegram_proxy(
    config: dict[str, Any],
    sidecar_data: dict[str, Any],
) -> str | None:
    """Patch Telegram channel proxy to route API calls through AgentWard.

    Sets ``channels.telegram.proxy`` to point at the AgentWard Telegram
    API proxy so that ``getUpdates`` responses can be intercepted for
    approval callback extraction.

    If ``sidecar_data`` already contains ``original_telegram_proxy``, that
    original is reused (idempotent re-wrap).

    Args:
        config: The ClawdBot config dict (mutated in place).
        sidecar_data: Existing sidecar data (may contain originals).

    Returns:
        The original proxy value (string, or None if not set).
    """
    channels = config.get("channels", {})
    telegram_cfg = channels.get("telegram", {})

    if not telegram_cfg.get("enabled", False):
        return None  # Telegram not enabled — nothing to patch

    if not telegram_cfg.get("botToken"):
        return None  # No bot token — nothing to patch

    proxy_port = sidecar_data.get("telegram_proxy_port", _DEFAULT_TELEGRAM_PROXY_PORT)
    proxy_url = f"http://127.0.0.1:{proxy_port}"

    # Determine original value
    if "original_telegram_proxy" in sidecar_data:
        original = sidecar_data["original_telegram_proxy"]
    else:
        original = telegram_cfg.get("proxy")

    # Patch — walk into nested accounts if present, else patch top-level
    # OpenClaw Telegram config can have per-account proxy settings under
    # channels.telegram.accounts.<id>.proxy, but the top-level
    # channels.telegram.proxy is the simpler (and documented) path.
    telegram_cfg["proxy"] = proxy_url

    return original


def _restore_telegram_proxy(
    config: dict[str, Any],
    original_proxy: str | None,
) -> None:
    """Restore the original Telegram proxy setting.

    Args:
        config: The ClawdBot config dict (mutated in place).
        original_proxy: The original proxy value (None to remove the key).
    """
    channels = config.get("channels", {})
    telegram_cfg = channels.get("telegram", {})

    if not isinstance(telegram_cfg, dict):
        return

    if original_proxy is None:
        telegram_cfg.pop("proxy", None)
    else:
        telegram_cfg["proxy"] = original_proxy


def _patch_model_base_urls(
    config: dict[str, Any],
    sidecar_data: dict[str, Any],
) -> dict[str, str]:
    """Patch provider baseUrl to route LLM calls through the AgentWard proxy.

    ClawdBot validates model entries with ``.strict()`` and only accepts
    ``alias`` and ``params`` — NOT ``baseUrl``.  The correct override point
    is ``models.providers[provider].baseUrl``.

    ClawdBot's zod ``ModelProviderSchema`` requires a ``models`` array
    (non-optional), so new provider entries must include ``"models": []``.
    The ``ensureClawdbotModelsJson()`` merge logic combines this empty
    array with the implicit provider's built-in models, and
    pi-coding-agent's ``ModelRegistry`` then treats the result as an
    "override-only" provider (applies ``baseUrl`` to all built-in models).

    Extracts unique provider prefixes from ``agents.defaults.models`` keys
    (e.g., ``anthropic/claude-opus-4-5`` → ``anthropic``), then adds or
    updates an entry in ``models.providers`` with ``baseUrl`` pointing to
    the AgentWard LLM proxy.

    If ``sidecar_data`` already contains ``original_base_urls``, those
    originals are reused (idempotent re-wrap).

    Args:
        config: The ClawdBot config dict (mutated in place).
        sidecar_data: Existing sidecar data (may contain ``original_base_urls``).

    Returns:
        Mapping of provider name → original base URL.
    """
    # Discover which providers are in use from model keys
    model_keys = (
        config.get("agents", {}).get("defaults", {}).get("models", {})
    )
    if not isinstance(model_keys, dict) or not model_keys:
        return {}

    # Collect unique provider prefixes
    providers_in_use: set[str] = set()
    for model_key in model_keys:
        if "/" in model_key:
            providers_in_use.add(model_key.split("/")[0])

    if not providers_in_use:
        return {}

    llm_port = sidecar_data.get("llm_proxy_port", _DEFAULT_LLM_PROXY_PORT)
    proxy_url = f"http://127.0.0.1:{llm_port}"

    # If sidecar already has originals, use those (idempotent)
    existing_originals: dict[str, str] = sidecar_data.get("original_base_urls", {})

    original_base_urls: dict[str, str] = {}

    # Ensure models.providers exists in config
    if "models" not in config:
        config["models"] = {}
    if "providers" not in config["models"]:
        config["models"]["providers"] = {}
    providers_cfg = config["models"]["providers"]

    for provider in sorted(providers_in_use):
        # Determine original base URL
        if provider in existing_originals:
            original_url = existing_originals[provider]
        elif provider in providers_cfg and "baseUrl" in providers_cfg[provider]:
            original_url = providers_cfg[provider]["baseUrl"]
        else:
            original_url = _PROVIDER_BASE_URLS.get(provider, "")

        if not original_url:
            continue  # Unknown provider — skip

        original_base_urls[provider] = original_url

        # Set or update the provider entry with proxy URL.
        # ClawdBot's zod schema requires `models` (non-optional array),
        # so new entries must include an empty array.
        if provider not in providers_cfg:
            providers_cfg[provider] = {"models": []}
        elif "models" not in providers_cfg[provider]:
            providers_cfg[provider]["models"] = []
        providers_cfg[provider]["baseUrl"] = proxy_url

    return original_base_urls


def _restore_model_base_urls(
    config: dict[str, Any],
    original_base_urls: dict[str, str],
) -> None:
    """Restore original provider baseUrl values.

    Args:
        config: The ClawdBot config dict (mutated in place).
        original_base_urls: Mapping of provider name → original base URL.
    """
    providers_cfg = config.get("models", {}).get("providers", {})
    if not isinstance(providers_cfg, dict):
        return

    for provider, original_url in original_base_urls.items():
        if provider not in providers_cfg:
            continue

        # If original was a well-known default, remove the provider entry
        # entirely (it didn't exist before we added it)
        default_url = _PROVIDER_BASE_URLS.get(provider, "")
        if original_url == default_url:
            del providers_cfg[provider]
        else:
            providers_cfg[provider]["baseUrl"] = original_url

    # Clean up empty models.providers / models sections
    if not providers_cfg and "providers" in config.get("models", {}):
        del config["models"]["providers"]
    if not config.get("models"):
        config.pop("models", None)


def wrap_clawdbot_gateway(
    config: dict[str, Any],
    config_path: Path,
    port_offset: int = 1,
) -> tuple[dict[str, Any], int, int]:
    """Swap the OpenClaw/ClawdBot gateway port so AgentWard can proxy in front.

    Changes ``gateway.port`` from the original to ``original + port_offset``,
    and stores the original port in a sidecar file next to the config JSON
    (the config rejects unknown keys, so we cannot embed markers in it).

    Args:
        config: The parsed config dict (openclaw.json or clawdbot.json).
        config_path: Path to the config file (for sidecar location).
        port_offset: How far to shift the gateway port (default 1).

    Returns:
        Tuple of (modified_config, original_port, new_backend_port).

    Raises:
        ValueError: If the config has no ``gateway`` section.
    """
    gateway = config.get("gateway")
    if not isinstance(gateway, dict):
        msg = (
            f"No 'gateway' section found in {config_path.name}. "
            "Is the OpenClaw gateway enabled?"
        )
        raise ValueError(msg)

    sidecar = _sidecar_path(config_path)

    # Already wrapped? Check sidecar file
    if sidecar.exists():
        sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
        original_port = sidecar_data.get("original_port", _DEFAULT_GATEWAY_PORT)
        # Deep copy — don't change anything, port is already swapped
        result = json.loads(json.dumps(config))
        backend_port = result["gateway"].get("port", original_port + port_offset)
        # Ensure baseUrl patching is still in place (idempotent)
        _patch_model_base_urls(result, sidecar_data)
        # Ensure Telegram proxy patching is still in place (idempotent)
        sidecar_changed = False
        original_telegram_proxy = _patch_telegram_proxy(result, sidecar_data)
        if "telegram_proxy_port" not in sidecar_data and (
            result.get("channels", {}).get("telegram", {}).get("proxy")
        ):
            sidecar_data["telegram_proxy_port"] = _DEFAULT_TELEGRAM_PROXY_PORT
            sidecar_data["original_telegram_proxy"] = original_telegram_proxy
            sidecar_changed = True
        # Ensure TLS reject patching is in place (for Telegram CONNECT proxy)
        plist_path_str = sidecar_data.get("plist_path")
        if plist_path_str and "original_tls_reject" not in sidecar_data:
            p = Path(plist_path_str)
            if p.exists():
                original_tls_reject = _patch_plist_tls_reject(p, disable=True)
                sidecar_data["original_tls_reject"] = original_tls_reject
                sidecar_changed = True
        if sidecar_changed:
            sidecar.write_text(
                json.dumps(sidecar_data, indent=2) + "\n", encoding="utf-8"
            )
        return result, original_port, backend_port

    # Deep copy to avoid mutating input
    result = json.loads(json.dumps(config))
    gw = result["gateway"]

    original_port = gw.get("port", _DEFAULT_GATEWAY_PORT)
    if not isinstance(original_port, int):
        original_port = _DEFAULT_GATEWAY_PORT

    backend_port = original_port + port_offset

    gw["port"] = backend_port

    # Disable gateway auth so the proxy can relay WebSocket connections
    # without needing to replicate the connect.challenge crypto handshake.
    # The original auth config is saved in the sidecar and restored on unwrap.
    original_auth = gw.get("auth")
    if isinstance(original_auth, dict) and original_auth.get("mode") != "none":
        gw["auth"] = {"mode": "none"}

    # Write sidecar with original port
    sidecar_data: dict[str, Any] = {"original_port": original_port}
    if original_auth is not None:
        sidecar_data["original_gateway_auth"] = original_auth

    # Patch model baseUrl entries to route through AgentWard LLM proxy
    original_base_urls = _patch_model_base_urls(result, sidecar_data)
    if original_base_urls:
        sidecar_data["llm_proxy_port"] = _DEFAULT_LLM_PROXY_PORT
        sidecar_data["original_base_urls"] = original_base_urls

    # Patch Telegram proxy to route API calls through AgentWard
    original_telegram_proxy = _patch_telegram_proxy(result, sidecar_data)
    if original_telegram_proxy is not None or (
        result.get("channels", {}).get("telegram", {}).get("proxy")
    ):
        sidecar_data["telegram_proxy_port"] = _DEFAULT_TELEGRAM_PROXY_PORT
        # Store original even if None (means "was not set")
        sidecar_data["original_telegram_proxy"] = original_telegram_proxy

    # Also patch the LaunchAgent plist (macOS) — the gateway hardcodes the
    # port as --port CLI arg and an env var in the plist, so editing the
    # config JSON alone is not enough.
    plist_path = _launchagent_plist_path()
    if plist_path is not None:
        _patch_plist_port(plist_path, backend_port)
        # Also clear the gateway token from the plist env vars — the gateway
        # reads OPENCLAW_GATEWAY_TOKEN from the plist and enables token auth
        # if set, regardless of the JSON config's auth.mode setting.
        original_plist_token = _patch_plist_auth(plist_path, disable=True)
        if original_plist_token is not None:
            sidecar_data["original_plist_token"] = original_plist_token
        # Disable TLS certificate verification so undici accepts our self-signed
        # cert for the Telegram CONNECT proxy (only affects localhost traffic).
        original_tls_reject = _patch_plist_tls_reject(plist_path, disable=True)
        sidecar_data["original_tls_reject"] = original_tls_reject
        sidecar_data["plist_path"] = str(plist_path)
    elif platform.system() == "Darwin":
        from rich.console import Console as _Console
        _warn_console = _Console(stderr=True)
        _warn_console.print(
            "[bold #ffcc00]Warning:[/bold #ffcc00] LaunchAgent plist not found.\n"
            f"Searched: {', '.join(_LAUNCHAGENT_PLIST_NAMES)}\n"
            "If OpenClaw uses a LaunchAgent, the gateway may ignore the port change.\n"
            f"Verify with: openclaw gateway restart && lsof -i :{backend_port}",
            highlight=False,
        )

    sidecar.write_text(
        json.dumps(sidecar_data, indent=2) + "\n", encoding="utf-8"
    )

    return result, original_port, backend_port


def unwrap_clawdbot_gateway(
    config: dict[str, Any],
    config_path: Path,
) -> tuple[dict[str, Any], bool]:
    """Restore the original OpenClaw/ClawdBot gateway port.

    Reads the sidecar file to recover the original port, then removes it.

    Args:
        config: The current config dict (openclaw.json or clawdbot.json).
        config_path: Path to the config file (for sidecar location).

    Returns:
        Tuple of (restored_config, was_wrapped).

    Raises:
        ValueError: If the config has no ``gateway`` section.
    """
    gateway = config.get("gateway")
    if not isinstance(gateway, dict):
        msg = (
            f"No 'gateway' section found in {config_path.name}. "
            "Is the OpenClaw gateway enabled?"
        )
        raise ValueError(msg)

    sidecar = _sidecar_path(config_path)

    if not sidecar.exists():
        return json.loads(json.dumps(config)), False

    sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
    original_port = sidecar_data.get("original_port", _DEFAULT_GATEWAY_PORT)

    result = json.loads(json.dumps(config))
    result["gateway"]["port"] = original_port

    # Restore gateway auth if we disabled it
    original_auth = sidecar_data.get("original_gateway_auth")
    if original_auth is not None:
        result["gateway"]["auth"] = original_auth

    # Restore model baseUrl values if we patched them
    original_base_urls = sidecar_data.get("original_base_urls", {})
    if original_base_urls:
        _restore_model_base_urls(result, original_base_urls)

    # Restore Telegram proxy if we patched it
    if "original_telegram_proxy" in sidecar_data:
        _restore_telegram_proxy(result, sidecar_data["original_telegram_proxy"])

    # Restore the LaunchAgent plist port and auth token if we patched them
    plist_str = sidecar_data.get("plist_path")
    if plist_str is not None:
        plist_path = Path(plist_str)
        if plist_path.exists():
            _patch_plist_port(plist_path, original_port)
            original_plist_token = sidecar_data.get("original_plist_token")
            if original_plist_token is not None:
                _restore_plist_auth(plist_path, original_plist_token)
            # Restore TLS certificate verification
            if "original_tls_reject" in sidecar_data:
                _restore_plist_tls_reject(plist_path, sidecar_data["original_tls_reject"])

    # Remove sidecar
    sidecar.unlink()

    return result, True


def is_clawdbot_gateway_wrapped(config_path: Path) -> bool:
    """Check if the OpenClaw/ClawdBot gateway has been wrapped by AgentWard.

    Args:
        config_path: Path to the OpenClaw/ClawdBot config file.

    Returns:
        True if the sidecar file exists (port has been swapped).
    """
    return _sidecar_path(config_path).exists()


def get_clawdbot_llm_proxy_config(
    config_path: Path,
) -> tuple[int, dict[str, str]] | None:
    """Get LLM proxy port and provider URL mapping from sidecar.

    Args:
        config_path: Path to the OpenClaw/ClawdBot config file.

    Returns:
        Tuple of (llm_proxy_port, provider_urls) if configured, None otherwise.
        provider_urls maps model key → real provider base URL.
    """
    sidecar = _sidecar_path(config_path)
    if not sidecar.exists():
        return None

    sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
    original_base_urls = sidecar_data.get("original_base_urls")
    if not original_base_urls:
        return None

    llm_port = sidecar_data.get("llm_proxy_port", _DEFAULT_LLM_PROXY_PORT)
    return llm_port, original_base_urls


def get_clawdbot_telegram_proxy_port(config_path: Path) -> int | None:
    """Get the Telegram API proxy port from sidecar, if configured.

    Args:
        config_path: Path to the OpenClaw/ClawdBot config file.

    Returns:
        The Telegram proxy port if configured, None otherwise.
    """
    sidecar = _sidecar_path(config_path)
    if not sidecar.exists():
        return None

    sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
    return sidecar_data.get("telegram_proxy_port")


def get_clawdbot_gateway_ports(config_path: Path) -> tuple[int, int] | None:
    """Get the listen and backend ports for a wrapped OpenClaw/ClawdBot gateway.

    Args:
        config_path: Path to the OpenClaw/ClawdBot config file.

    Returns:
        Tuple of (listen_port, backend_port) if wrapped, None otherwise.
    """
    sidecar = _sidecar_path(config_path)
    if not sidecar.exists():
        return None

    sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
    original_port = sidecar_data.get("original_port", _DEFAULT_GATEWAY_PORT)

    config = json.loads(config_path.read_text(encoding="utf-8"))
    backend_port = config.get("gateway", {}).get("port", original_port + 1)

    return original_port, backend_port
