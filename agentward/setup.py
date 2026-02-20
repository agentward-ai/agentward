"""MCP config wrapping and gateway port swapping for AgentWard proxy setup.

Reads MCP config files, wraps each stdio server command with
``agentward inspect``, and writes the modified config back.
Also supports ClawdBot gateway port swapping for HTTP proxy mode.
Supports undo via embedded markers.
"""

from __future__ import annotations

import json
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

    config_path.write_text(
        json.dumps(config, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

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

# Sidecar file stored next to clawdbot.json to track the original port.
# ClawdBot strictly validates its config and rejects unknown keys,
# so we cannot embed markers inside clawdbot.json itself.
_GATEWAY_SIDECAR_NAME = ".agentward-gateway.json"

# macOS LaunchAgent plist that ClawdBot uses to run the gateway as a service.
# The plist hardcodes the port as a CLI arg (--port) and env var
# (CLAWDBOT_GATEWAY_PORT), so we must update it alongside clawdbot.json.
_LAUNCHAGENT_PLIST_NAME = "com.clawdbot.gateway.plist"


def _launchagent_plist_path() -> Path | None:
    """Find the ClawdBot LaunchAgent plist if it exists.

    Returns:
        Path to the plist, or None if not found.
    """
    plist_path = Path.home() / "Library" / "LaunchAgents" / _LAUNCHAGENT_PLIST_NAME
    if plist_path.exists():
        return plist_path
    return None


def _patch_plist_port(plist_path: Path, new_port: int) -> bool:
    """Update the gateway port in the LaunchAgent plist.

    Patches both the ``--port`` CLI argument in ``ProgramArguments``
    and the ``CLAWDBOT_GATEWAY_PORT`` environment variable.

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

    # Patch EnvironmentVariables
    env = plist.get("EnvironmentVariables", {})
    if "CLAWDBOT_GATEWAY_PORT" in env:
        env["CLAWDBOT_GATEWAY_PORT"] = str(new_port)
        modified = True

    if modified:
        with plist_path.open("wb") as f:
            plistlib.dump(plist, f)

    return modified


def _sidecar_path(config_path: Path) -> Path:
    """Return the sidecar file path for a given clawdbot.json.

    Args:
        config_path: Path to the clawdbot.json file.

    Returns:
        Path to the sidecar file in the same directory.
    """
    return config_path.parent / _GATEWAY_SIDECAR_NAME


def wrap_clawdbot_gateway(
    config: dict[str, Any],
    config_path: Path,
    port_offset: int = 1,
) -> tuple[dict[str, Any], int, int]:
    """Swap the ClawdBot gateway port so AgentWard can proxy in front.

    Changes ``gateway.port`` from the original to ``original + port_offset``,
    and stores the original port in a sidecar file next to clawdbot.json
    (ClawdBot rejects unknown keys, so we cannot embed markers in the config).

    Args:
        config: The parsed clawdbot.json dict.
        config_path: Path to the clawdbot.json file (for sidecar location).
        port_offset: How far to shift the gateway port (default 1).

    Returns:
        Tuple of (modified_config, original_port, new_backend_port).

    Raises:
        ValueError: If the config has no ``gateway`` section.
    """
    gateway = config.get("gateway")
    if not isinstance(gateway, dict):
        msg = (
            "No 'gateway' section found in clawdbot.json. "
            "Is the ClawdBot gateway enabled?"
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
        return result, original_port, backend_port

    # Deep copy to avoid mutating input
    result = json.loads(json.dumps(config))
    gw = result["gateway"]

    original_port = gw.get("port", _DEFAULT_GATEWAY_PORT)
    if not isinstance(original_port, int):
        original_port = _DEFAULT_GATEWAY_PORT

    backend_port = original_port + port_offset

    gw["port"] = backend_port

    # Write sidecar with original port
    sidecar_data: dict[str, Any] = {"original_port": original_port}

    # Also patch the LaunchAgent plist (macOS) — ClawdBot hardcodes the
    # port as --port CLI arg and CLAWDBOT_GATEWAY_PORT env var in the plist,
    # so editing clawdbot.json alone is not enough.
    plist_path = _launchagent_plist_path()
    if plist_path is not None:
        _patch_plist_port(plist_path, backend_port)
        sidecar_data["plist_path"] = str(plist_path)

    sidecar.write_text(
        json.dumps(sidecar_data, indent=2) + "\n", encoding="utf-8"
    )

    return result, original_port, backend_port


def unwrap_clawdbot_gateway(
    config: dict[str, Any],
    config_path: Path,
) -> tuple[dict[str, Any], bool]:
    """Restore the original ClawdBot gateway port.

    Reads the sidecar file to recover the original port, then removes it.

    Args:
        config: The current clawdbot.json dict.
        config_path: Path to the clawdbot.json file (for sidecar location).

    Returns:
        Tuple of (restored_config, was_wrapped).

    Raises:
        ValueError: If the config has no ``gateway`` section.
    """
    gateway = config.get("gateway")
    if not isinstance(gateway, dict):
        msg = (
            "No 'gateway' section found in clawdbot.json. "
            "Is the ClawdBot gateway enabled?"
        )
        raise ValueError(msg)

    sidecar = _sidecar_path(config_path)

    if not sidecar.exists():
        return json.loads(json.dumps(config)), False

    sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
    original_port = sidecar_data.get("original_port", _DEFAULT_GATEWAY_PORT)

    result = json.loads(json.dumps(config))
    result["gateway"]["port"] = original_port

    # Restore the LaunchAgent plist port if we patched it
    plist_str = sidecar_data.get("plist_path")
    if plist_str is not None:
        plist_path = Path(plist_str)
        if plist_path.exists():
            _patch_plist_port(plist_path, original_port)

    # Remove sidecar
    sidecar.unlink()

    return result, True


def is_clawdbot_gateway_wrapped(config_path: Path) -> bool:
    """Check if the ClawdBot gateway has been wrapped by AgentWard.

    Args:
        config_path: Path to the clawdbot.json file.

    Returns:
        True if the sidecar file exists (port has been swapped).
    """
    return _sidecar_path(config_path).exists()


def get_clawdbot_gateway_ports(config_path: Path) -> tuple[int, int] | None:
    """Get the listen and backend ports for a wrapped ClawdBot gateway.

    Args:
        config_path: Path to the clawdbot.json file.

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
