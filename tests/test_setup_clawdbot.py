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
    _patch_model_base_urls,
    _patch_plist_auth,
    _patch_plist_port,
    _patch_plist_tls_reject,
    _restore_model_base_urls,
    _restore_plist_auth,
    _restore_plist_tls_reject,
    get_clawdbot_gateway_ports,
    get_clawdbot_llm_proxy_config,
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
        # Auth is disabled in the wrapped config (proxy handles WS relay)
        assert wrapped["gateway"]["auth"] == {"mode": "none"}
        assert wrapped["channels"]["telegram"]["enabled"] is True

    def test_disables_gateway_auth(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18789)
        config = _make_clawdbot_config(port=18789)
        wrapped, _, _ = wrap_clawdbot_gateway(config, config_path)

        # Auth disabled in wrapped config
        assert wrapped["gateway"]["auth"] == {"mode": "none"}

        # Original auth saved in sidecar
        sidecar_path = config_path.parent / ".agentward-gateway.json"
        sidecar = json.loads(sidecar_path.read_text())
        assert sidecar["original_gateway_auth"]["mode"] == "token"
        assert sidecar["original_gateway_auth"]["token"] == "test-token"

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

    def test_restores_gateway_auth(self, tmp_path: Path) -> None:
        """Unwrap restores original gateway auth from sidecar."""
        config_path = _write_clawdbot(tmp_path, port=18790)

        # Create sidecar with original auth saved
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(
            json.dumps(
                {
                    "original_port": 18789,
                    "original_gateway_auth": {
                        "mode": "token",
                        "token": "test-token",
                    },
                }
            )
        )

        config = _make_clawdbot_config(port=18790)
        # Simulate wrapped state: auth disabled
        config["gateway"]["auth"] = {"mode": "none"}

        restored, was_wrapped = unwrap_clawdbot_gateway(config, config_path)

        assert was_wrapped is True
        assert restored["gateway"]["auth"]["mode"] == "token"
        assert restored["gateway"]["auth"]["token"] == "test-token"

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
        # Auth restored to original
        assert restored["gateway"]["auth"]["mode"] == "token"
        assert restored["gateway"]["auth"]["token"] == "test-token"

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


class TestPatchPlistAuth:
    """Tests for _patch_plist_auth() and _restore_plist_auth()."""

    def test_disable_removes_token(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        original = _patch_plist_auth(plist_path, disable=True)

        assert original == "test-token"

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert "CLAWDBOT_GATEWAY_TOKEN" not in plist["EnvironmentVariables"]

    def test_disable_returns_none_when_no_token(self, tmp_path: Path) -> None:
        plist_path = tmp_path / "no-token.plist"
        with plist_path.open("wb") as f:
            plistlib.dump({"Label": "test", "EnvironmentVariables": {}}, f)

        result = _patch_plist_auth(plist_path, disable=True)
        assert result is None

    def test_restore_adds_token(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        # First disable
        _patch_plist_auth(plist_path, disable=True)
        # Then restore
        _restore_plist_auth(plist_path, "restored-token")

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["EnvironmentVariables"]["OPENCLAW_GATEWAY_TOKEN"] == "restored-token"

    def test_openclaw_token_removed(self, tmp_path: Path) -> None:
        """Handles OPENCLAW_GATEWAY_TOKEN (new env var name)."""
        plist_path = tmp_path / "ai.openclaw.gateway.plist"
        plist = {
            "Label": "ai.openclaw.gateway",
            "ProgramArguments": ["node", "gateway", "--port", "18790"],
            "EnvironmentVariables": {
                "OPENCLAW_GATEWAY_PORT": "18790",
                "OPENCLAW_GATEWAY_TOKEN": "oc-token-123",
            },
        }
        with plist_path.open("wb") as f:
            plistlib.dump(plist, f)

        original = _patch_plist_auth(plist_path, disable=True)
        assert original == "oc-token-123"

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert "OPENCLAW_GATEWAY_TOKEN" not in plist["EnvironmentVariables"]


class TestPatchPlistTlsReject:
    """Tests for _patch_plist_tls_reject() and _restore_plist_tls_reject()."""

    def test_disable_sets_env_var(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        original = _patch_plist_tls_reject(plist_path, disable=True)

        # No previous value
        assert original is None

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["EnvironmentVariables"]["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"

    def test_disable_returns_existing_value(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        # Pre-set a value
        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        plist["EnvironmentVariables"]["NODE_TLS_REJECT_UNAUTHORIZED"] = "1"
        with plist_path.open("wb") as f:
            plistlib.dump(plist, f)

        original = _patch_plist_tls_reject(plist_path, disable=True)
        assert original == "1"

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["EnvironmentVariables"]["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"

    def test_disable_false_is_noop(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        result = _patch_plist_tls_reject(plist_path, disable=False)
        assert result is None

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert "NODE_TLS_REJECT_UNAUTHORIZED" not in plist["EnvironmentVariables"]

    def test_restore_removes_key_when_none(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        # First set it
        _patch_plist_tls_reject(plist_path, disable=True)
        # Then restore with None (means it wasn't there before)
        _restore_plist_tls_reject(plist_path, None)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert "NODE_TLS_REJECT_UNAUTHORIZED" not in plist["EnvironmentVariables"]

    def test_restore_sets_original_value(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        _patch_plist_tls_reject(plist_path, disable=True)
        _restore_plist_tls_reject(plist_path, "1")

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["EnvironmentVariables"]["NODE_TLS_REJECT_UNAUTHORIZED"] == "1"

    def test_preserves_other_env_vars(self, tmp_path: Path) -> None:
        plist_path = _write_plist(tmp_path, port=18789)
        _patch_plist_tls_reject(plist_path, disable=True)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_PORT"] == "18789"
        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_TOKEN"] == "test-token"


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
        # Token should be cleared from plist
        assert "CLAWDBOT_GATEWAY_TOKEN" not in plist["EnvironmentVariables"]
        # TLS reject should be disabled for Telegram CONNECT proxy
        assert plist["EnvironmentVariables"]["NODE_TLS_REJECT_UNAUTHORIZED"] == "0"

        # Original token saved in sidecar
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar_data = json.loads(sidecar.read_text())
        assert sidecar_data["original_plist_token"] == "test-token"
        # Original TLS reject saved (None = was not set)
        assert sidecar_data["original_tls_reject"] is None

    def test_unwrap_restores_plist(self, tmp_path: Path) -> None:
        config_path = _write_clawdbot(tmp_path, port=18790)
        plist_path = _write_plist(tmp_path, port=18790)

        # Simulate wrapped state: remove token, add TLS reject
        with plist_path.open("rb") as f:
            plist_data = plistlib.load(f)
        plist_data["EnvironmentVariables"].pop("CLAWDBOT_GATEWAY_TOKEN", None)
        plist_data["EnvironmentVariables"]["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
        with plist_path.open("wb") as f:
            plistlib.dump(plist_data, f)

        # Create sidecar with plist_path, saved token, and TLS reject state
        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar.write_text(json.dumps({
            "original_port": 18789,
            "plist_path": str(plist_path),
            "original_plist_token": "test-token",
            "original_tls_reject": None,
        }))

        config = _make_clawdbot_config(port=18790)
        unwrap_clawdbot_gateway(config, config_path)

        with plist_path.open("rb") as f:
            plist = plistlib.load(f)
        args = plist["ProgramArguments"]
        assert args[args.index("--port") + 1] == "18789"
        assert plist["EnvironmentVariables"]["CLAWDBOT_GATEWAY_PORT"] == "18789"
        # Token should be restored
        assert plist["EnvironmentVariables"]["OPENCLAW_GATEWAY_TOKEN"] == "test-token"
        # TLS reject should be removed (was not set before)
        assert "NODE_TLS_REJECT_UNAUTHORIZED" not in plist["EnvironmentVariables"]


# ---------------------------------------------------------------------------
# baseUrl patching tests
# ---------------------------------------------------------------------------


def _make_clawdbot_config_with_models(port: int = 18789) -> dict:
    """Create a clawdbot.json config with model entries."""
    config = _make_clawdbot_config(port)
    config["agents"] = {
        "defaults": {
            "models": {
                "anthropic/claude-opus-4-5": {"alias": "opus"},
                "openai/codex-mini-latest": {},
            },
        },
    }
    return config


class TestPatchModelBaseUrls:
    """Tests for _patch_model_base_urls() — provider-level baseUrl patching."""

    def test_patches_anthropic_provider(self) -> None:
        config = _make_clawdbot_config_with_models()
        sidecar: dict = {}

        originals = _patch_model_base_urls(config, sidecar)

        providers = config["models"]["providers"]
        assert providers["anthropic"]["baseUrl"] == "http://127.0.0.1:18900"
        assert providers["anthropic"]["models"] == []  # required by zod schema
        assert originals["anthropic"] == "https://api.anthropic.com"

    def test_patches_openai_provider(self) -> None:
        config = _make_clawdbot_config_with_models()
        sidecar: dict = {}

        originals = _patch_model_base_urls(config, sidecar)

        providers = config["models"]["providers"]
        assert providers["openai"]["baseUrl"] == "http://127.0.0.1:18900"
        assert providers["openai"]["models"] == []  # required by zod schema
        assert originals["openai"] == "https://api.openai.com"

    def test_preserves_model_fields(self) -> None:
        """Model entries in agents.defaults.models are NOT touched."""
        config = _make_clawdbot_config_with_models()
        sidecar: dict = {}

        _patch_model_base_urls(config, sidecar)

        model = config["agents"]["defaults"]["models"]["anthropic/claude-opus-4-5"]
        assert model["alias"] == "opus"
        assert "baseUrl" not in model  # Must NOT add baseUrl to model entries

    def test_explicit_provider_base_url_preserved(self) -> None:
        """If models.providers already has a custom baseUrl, it's captured."""
        config = _make_clawdbot_config_with_models()
        config["models"] = {
            "providers": {
                "anthropic": {"baseUrl": "https://custom.example.com", "models": []},
            },
        }
        sidecar: dict = {}

        originals = _patch_model_base_urls(config, sidecar)

        assert originals["anthropic"] == "https://custom.example.com"
        assert config["models"]["providers"]["anthropic"]["baseUrl"] == "http://127.0.0.1:18900"

    def test_unknown_provider_skipped(self) -> None:
        config = _make_clawdbot_config_with_models()
        config["agents"]["defaults"]["models"]["unknown/model"] = {}
        sidecar: dict = {}

        originals = _patch_model_base_urls(config, sidecar)

        assert "unknown" not in originals

    def test_idempotent_with_existing_sidecar(self) -> None:
        config = _make_clawdbot_config_with_models()
        config["models"] = {
            "providers": {
                "anthropic": {"baseUrl": "http://127.0.0.1:18900", "models": []},
            },
        }
        sidecar = {
            "original_base_urls": {
                "anthropic": "https://api.anthropic.com",
                "openai": "https://api.openai.com",
            },
        }

        originals = _patch_model_base_urls(config, sidecar)

        # Uses sidecar originals, not the current (proxied) value
        assert originals["anthropic"] == "https://api.anthropic.com"

    def test_no_models_returns_empty(self) -> None:
        config = _make_clawdbot_config()
        sidecar: dict = {}

        originals = _patch_model_base_urls(config, sidecar)

        assert originals == {}

    def test_custom_llm_port_from_sidecar(self) -> None:
        config = _make_clawdbot_config_with_models()
        sidecar = {"llm_proxy_port": 19000}

        _patch_model_base_urls(config, sidecar)

        providers = config["models"]["providers"]
        assert providers["anthropic"]["baseUrl"] == "http://127.0.0.1:19000"


class TestRestoreModelBaseUrls:
    """Tests for _restore_model_base_urls()."""

    def test_removes_default_provider_entry(self) -> None:
        """If original was a provider default, remove the provider entry entirely."""
        config = _make_clawdbot_config_with_models()
        config["models"] = {
            "providers": {
                "anthropic": {"baseUrl": "http://127.0.0.1:18900", "models": []},
            },
        }

        _restore_model_base_urls(config, {
            "anthropic": "https://api.anthropic.com",
        })

        # Provider entry should be removed (it didn't exist before)
        assert "anthropic" not in config.get("models", {}).get("providers", {})

    def test_restores_custom_base_url(self) -> None:
        config = _make_clawdbot_config_with_models()
        config["models"] = {
            "providers": {
                "anthropic": {"baseUrl": "http://127.0.0.1:18900", "models": []},
            },
        }

        _restore_model_base_urls(config, {
            "anthropic": "https://custom.example.com",
        })

        assert config["models"]["providers"]["anthropic"]["baseUrl"] == "https://custom.example.com"

    def test_cleans_up_empty_models_section(self) -> None:
        """If all providers are removed, models section is cleaned up."""
        config = _make_clawdbot_config_with_models()
        config["models"] = {
            "providers": {
                "anthropic": {"baseUrl": "http://127.0.0.1:18900", "models": []},
                "openai": {"baseUrl": "http://127.0.0.1:18900", "models": []},
            },
        }

        _restore_model_base_urls(config, {
            "anthropic": "https://api.anthropic.com",
            "openai": "https://api.openai.com",
        })

        # Both were defaults, so models section should be gone
        assert "models" not in config


class TestBaseUrlRoundTrip:
    """Test wrap/unwrap round trip with baseUrl patching."""

    def test_wrap_adds_base_urls_to_sidecar(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = _make_clawdbot_config_with_models()
        write_config(config_path, config, backup=False)

        wrapped, _, _ = wrap_clawdbot_gateway(config, config_path)

        sidecar = tmp_path / _GATEWAY_SIDECAR_NAME
        sidecar_data = json.loads(sidecar.read_text())
        assert "original_base_urls" in sidecar_data
        assert "llm_proxy_port" in sidecar_data
        # Keyed by provider name, not model key
        assert sidecar_data["original_base_urls"]["anthropic"] == "https://api.anthropic.com"

    def test_wrap_patches_provider_base_urls(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = _make_clawdbot_config_with_models()
        write_config(config_path, config, backup=False)

        wrapped, _, _ = wrap_clawdbot_gateway(config, config_path)

        # baseUrl should be on models.providers, NOT on agents.defaults.models
        providers = wrapped["models"]["providers"]
        assert providers["anthropic"]["baseUrl"] == "http://127.0.0.1:18900"
        assert providers["anthropic"]["models"] == []  # required by zod schema
        assert providers["openai"]["baseUrl"] == "http://127.0.0.1:18900"
        assert providers["openai"]["models"] == []  # required by zod schema
        # Model entries must NOT have baseUrl (ClawdBot rejects it)
        assert "baseUrl" not in wrapped["agents"]["defaults"]["models"]["anthropic/claude-opus-4-5"]

    def test_unwrap_restores_base_urls(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = _make_clawdbot_config_with_models()
        write_config(config_path, config, backup=False)

        wrapped, _, _ = wrap_clawdbot_gateway(config, config_path)

        # Now unwrap
        restored, was_wrapped = unwrap_clawdbot_gateway(wrapped, config_path)

        assert was_wrapped is True
        # Provider entries should be removed (they were defaults)
        assert "models" not in restored or "providers" not in restored.get("models", {})

    def test_get_llm_proxy_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = _make_clawdbot_config_with_models()
        write_config(config_path, config, backup=False)

        wrap_clawdbot_gateway(config, config_path)

        result = get_clawdbot_llm_proxy_config(config_path)
        assert result is not None
        llm_port, provider_urls = result
        assert llm_port == 18900
        # Keyed by provider name
        assert "anthropic" in provider_urls
        assert provider_urls["anthropic"] == "https://api.anthropic.com"

    def test_get_llm_proxy_config_none_without_setup(self, tmp_path: Path) -> None:
        config_path = tmp_path / "clawdbot.json"
        config = _make_clawdbot_config()
        write_config(config_path, config, backup=False)

        assert get_clawdbot_llm_proxy_config(config_path) is None
