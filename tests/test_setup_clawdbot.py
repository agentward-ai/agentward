"""Tests for ClawdBot gateway port wrapping in setup.py.

The wrap/unwrap functions use a sidecar file (.agentward-gateway.json)
to track the original port, because ClawdBot rejects unknown keys
in its config.
"""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from agentward.setup import (
    _GATEWAY_SIDECAR_NAME,
    _patch_plist_port,
    get_clawdbot_gateway_ports,
    is_clawdbot_gateway_wrapped,
    read_config,
    unwrap_clawdbot_gateway,
    wrap_clawdbot_gateway,
    write_config,
)


def _make_clawdbot_config(port: int = 18789) -> dict:
    """Create a minimal clawdbot.json config dict."""
    return {
        "gateway": {
            "port": port,
            "mode": "local",
            "bind": "loopback",
            "auth": {
                "mode": "token",
                "token": "test-token",
            },
        },
        "channels": {"telegram": {"enabled": True}},
    }


def _write_clawdbot(tmp_path: Path, port: int = 18789) -> Path:
    """Write a clawdbot.json to disk and return its path."""
    config_path = tmp_path / "clawdbot.json"
    write_config(config_path, _make_clawdbot_config(port), backup=False)
    return config_path


class TestWrapClawdbotGateway:
    """Tests for wrap_clawdbot_gateway()."""

    def test_swaps_port(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        config = _make_clawdbot_config(port=18789)
        wrapped, listen_port, backend_port = wrap_clawdbot_gateway(config, config_path)

        assert listen_port == 18789
        assert backend_port == 18790
        assert wrapped["gateway"]["port"] == 18790

    def test_creates_sidecar(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        config = _make_clawdbot_config(port=18789)
        wrap_clawdbot_gateway(config, config_path)

        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        assert sidecar.exists()
        data = json.loads(sidecar.read_text())
        assert data["original_port"] == 18789

    def test_no_marker_in_config(self, tmp_path: Path) -> None:
        """Config output must not contain any AgentWard marker keys."""
        config_path = _write_clawdbot(tmp_path, port=18789)
        config = _make_clawdbot_config(port=18789)
        wrapped, _, _ = wrap_clawdbot_gateway(config, config_path)

        # No extra keys — only the standard gateway fields
        assert "_agentward" not in json.dumps(wrapped)

    def test_custom_port_offset(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=9000)
        config = _make_clawdbot_config(port=9000)
        wrapped, listen_port, backend_port = wrap_clawdbot_gateway(
            config, config_path, port_offset=5
        )

        assert listen_port == 9000
        assert backend_port == 9005
        assert wrapped["gateway"]["port"] == 9005

    def test_does_not_mutate_input(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        config = _make_clawdbot_config(port=18789)
        original_port = config["gateway"]["port"]
        wrap_clawdbot_gateway(config, config_path)

        assert config["gateway"]["port"] == original_port

    def test_already_wrapped_returns_existing(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18790)
        config = _make_clawdbot_config(port=18790)

        # Create sidecar manually to simulate prior wrap
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({"original_port": 18789}))

        wrapped, listen_port, backend_port = wrap_clawdbot_gateway(config, config_path)

        assert listen_port == 18789
        assert backend_port == 18790
        assert wrapped["gateway"]["port"] == 18790

    def test_preserves_other_fields(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        config = _make_clawdbot_config(port=18789)
        wrapped, _, _ = wrap_clawdbot_gateway(config, config_path)

        assert wrapped["gateway"]["mode"] == "local"
        assert wrapped["gateway"]["auth"]["token"] == "test-token"
        assert wrapped["channels"]["telegram"]["enabled"] is True

    def test_no_gateway_section_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = {"channels": {"telegram": True}}
        with pytest.raises(ValueError, match="No 'gateway' section"):
            wrap_clawdbot_gateway(config, config_path)

    def test_gateway_not_dict_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = {"gateway": "invalid"}
        with pytest.raises(ValueError, match="No 'gateway' section"):
            wrap_clawdbot_gateway(config, config_path)


class TestUnwrapClawdbotGateway:
    """Tests for unwrap_clawdbot_gateway()."""

    def test_restores_port(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18790)

        # Create sidecar
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({"original_port": 18789}))

        config = _make_clawdbot_config(port=18790)
        restored, was_wrapped = unwrap_clawdbot_gateway(config, config_path)

        assert was_wrapped is True
        assert restored["gateway"]["port"] == 18789

    def test_removes_sidecar(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18790)
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({"original_port": 18789}))

        config = _make_clawdbot_config(port=18790)
        unwrap_clawdbot_gateway(config, config_path)

        assert not sidecar.exists()

    def test_not_wrapped_returns_false(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        config = _make_clawdbot_config(port=18789)

        restored, was_wrapped = unwrap_clawdbot_gateway(config, config_path)

        assert was_wrapped is False
        assert restored["gateway"]["port"] == 18789

    def test_does_not_mutate_input(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18790)
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({"original_port": 18789}))

        config = _make_clawdbot_config(port=18790)
        unwrap_clawdbot_gateway(config, config_path)

        assert config["gateway"]["port"] == 18790

    def test_no_gateway_section_raises(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = {"channels": {}}
        with pytest.raises(ValueError, match="No 'gateway' section"):
            unwrap_clawdbot_gateway(config, config_path)


class TestHelpers:
    """Tests for is_clawdbot_gateway_wrapped and get_clawdbot_gateway_ports."""

    def test_is_wrapped_false(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path)
        assert is_clawdbot_gateway_wrapped(config_path) is False

    def test_is_wrapped_true(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path)
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({"original_port": 18789}))
        assert is_clawdbot_gateway_wrapped(config_path) is True

    def test_get_ports_none(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path)
        assert get_clawdbot_gateway_ports(config_path) is None

    def test_get_ports_wrapped(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18790)
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({"original_port": 18789}))

        ports = get_clawdbot_gateway_ports(config_path)
        assert ports == (18789, 18790)


class TestRoundTrip:
    """Test wrap then unwrap restores original."""

    def test_wrap_unwrap_round_trip(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        original = _make_clawdbot_config(port=18789)

        wrapped, _, _ = wrap_clawdbot_gateway(original, config_path)
        restored, was_wrapped = unwrap_clawdbot_gateway(wrapped, config_path)

        assert was_wrapped is True
        assert restored["gateway"]["port"] == 18789

    def test_file_round_trip(self, tmp_path: Path) -> None:
        """Test write/read/wrap/unwrap round trip via disk."""
        config_path = _write_clawdbot(tmp_path, port=18789)

        # Wrap
        loaded = read_config(config_path)
        wrapped, listen_port, backend_port = wrap_clawdbot_gateway(loaded, config_path)
        write_config(config_path, wrapped, backup=True)

        # Verify wrapped on disk
        on_disk = read_config(config_path)
        assert on_disk["gateway"]["port"] == backend_port
        # No marker keys in the config
        assert "_agentward" not in json.dumps(on_disk)
        # Sidecar exists
        assert is_clawdbot_gateway_wrapped(config_path)

        # Unwrap
        restored, was_wrapped = unwrap_clawdbot_gateway(on_disk, config_path)
        assert was_wrapped is True
        write_config(config_path, restored, backup=False)

        # Verify restored on disk
        final = read_config(config_path)
        assert final["gateway"]["port"] == 18789
        assert not is_clawdbot_gateway_wrapped(config_path)


# ---------------------------------------------------------------------------
# LaunchAgent plist tests
# ---------------------------------------------------------------------------


def _make_plist(port: int = 18789) -> dict:
    """Create a minimal ClawdBot LaunchAgent plist dict."""
    return {
        "Label": "com.clawdbot.gateway",
        "ProgramArguments": [
            "/opt/homebrew/bin/node",
            "/opt/homebrew/lib/node_modules/clawdbot/dist/entry.js",
            "gateway",
            "--port",
            str(port),
        ],
        "EnvironmentVariables": {
            "CLAWDBOT_GATEWAY_PORT": str(port),
            "CLAWDBOT_GATEWAY_TOKEN": "test-token",
        },
        "KeepAlive": True,
        "RunAtLoad": True,
    }


def _write_plist(tmp_path: Path, port: int = 18789) -> Path:
    """Write a plist file and return its path."""
    plist_path = tmp_path / "com.clawdbot.gateway.plist"
    with plist_path.open("wb") as f:
        plistlib.dump(_make_plist(port), f)
    return plist_path


class TestPatchPlistPort:
    """Tests for _patch_plist_port()."""

    def test_patches_program_argument(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        _patch_plist_port(plist_path, 18790)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)

        args = plist["ProgramArguments"]
        port_idx = args.index("--port") + 1
        assert args[port_idx] == "18790"

    def test_patches_env_var(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        _patch_plist_port(plist_path, 18790)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)

        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_PORT"] == "18790"

    def test_preserves_other_fields(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        _patch_plist_port(plist_path, 18790)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)

        assert plist["Label"] == "com.clawdbot.gateway"
        assert plist["KeepAlive"] is True
        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_TOKEN"] == "test-token"

    def test_returns_true_when_modified(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        assert _patch_plist_port(plist_path, 18790) is True

    def test_returns_false_when_no_port_fields(self, tmp_path: Path) -> None:
        plist_path = tmp_path / "empty.plist"
        with plist_path.open("wb") as f:
            plistlib.dump({"Label": "test", "ProgramArguments": ["node"]}, f)

        assert _patch_plist_port(plist_path, 18790) is False

    def test_round_trip(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)

        _patch_plist_port(plist_path, 18790)
        _patch_plist_port(plist_path, 18789)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)

        args = plist["ProgramArguments"]
        port_idx = args.index("--port") + 1
        assert args[port_idx] == "18789"
        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_PORT"] == "18789"


class TestWrapUnwrapWithPlist:
    """Tests for wrap/unwrap when a plist file is involved."""

    def test_wrap_records_plist_in_sidecar(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        plist_path = _write_plist(tmp_path, port=18789)

        # Monkeypatch _launchagent_plist_path to return our temp plist
        import agentward.setup as setup_mod

        monkeypatch.setattr(setup_mod, "_launchagent_plist_path", lambda: plist_path)

        config = _make_clawdbot_config(port=18789)
        wrap_clawdbot_gateway(config, config_path)

        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar_data = json.loads(sidecar.read_text())
        assert sidecar_data["plist_path"] == str(plist_path)

    def test_wrap_patches_plist(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        plist_path = _write_plist(tmp_path, port=18789)

        import agentward.setup as setup_mod

        monkeypatch.setattr(setup_mod, "_launchagent_plist_path", lambda: plist_path)

        config = _make_clawdbot_config(port=18789)
        wrap_clawdbot_gateway(config, config_path)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        args = plist["ProgramArguments"]
        assert args[args.index("--port") + 1] == "18790"
        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_PORT"] == "18790"

    def test_unwrap_restores_plist(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18790)
        plist_path = _write_plist(tmp_path, port=18790)

        # Create sidecar with plist_path
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({
            "original_port": 18789,
            "plist_path": str(plist_path),
        }))

        config = _make_clawdbot_config(port=18790)
        unwrap_clawdbot_gateway(config, config_path)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        args = plist["ProgramArguments"]
        assert args[args.index("--port") + 1] == "18789"
        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_PORT"] == "18789"
