"""Tests for the ``agentward init`` command."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import click.exceptions
import pytest
from rich.console import Console

from agentward.init import (
    _find_gateway_binary,
    _has_any_risk,
    _is_port_listening,
    _risk_summary,
    _source_summary,
    generate_init_policy,
    print_risk_summary,
    restart_openclaw_gateway,
    run_init,
    start_proxy,
    wrap_openclaw_gateway,
)
from agentward.scan.chains import ChainDetection, ChainRisk
from agentward.scan.config import ServerConfig, TransportType
from agentward.scan.enumerator import ToolInfo
from agentward.scan.permissions import (
    DataAccess,
    DataAccessType,
    RiskLevel,
    ScanResult,
    ServerPermissionMap,
    ToolPermission,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _tool(name: str) -> ToolInfo:
    return ToolInfo(name=name, description=f"Tool: {name}", input_schema={})


def _perm(
    name: str,
    risk: RiskLevel = RiskLevel.LOW,
    access: list[DataAccess] | None = None,
    destructive: bool = False,
    read_only: bool = True,
) -> ToolPermission:
    return ToolPermission(
        tool=_tool(name),
        data_access=access or [],
        risk_level=risk,
        risk_reasons=["test"],
        is_destructive=destructive,
        is_read_only=read_only,
    )


def _access(
    typ: DataAccessType,
    read: bool = True,
    write: bool = False,
) -> DataAccess:
    return DataAccess(type=typ, read=read, write=write, reason="test")


def _server(
    name: str,
    tools: list[ToolPermission],
    risk: RiskLevel = RiskLevel.LOW,
) -> ServerPermissionMap:
    return ServerPermissionMap(
        server=ServerConfig(
            name=name,
            transport=TransportType.STDIO,
            command="test",
            client="test",
            source_file=Path("/tmp/test.json"),
        ),
        enumeration_method="live",
        tools=tools,
        overall_risk=risk,
    )


def _scan(*servers: ServerPermissionMap) -> ScanResult:
    return ScanResult(
        servers=list(servers),
        config_sources=["/tmp/test.json"],
        scan_timestamp="2026-01-01T00:00:00Z",
    )


def _chain(source: str, target: str, risk: ChainRisk = ChainRisk.HIGH) -> ChainDetection:
    return ChainDetection(
        source_server=source,
        target_server=target,
        risk=risk,
        label=f"{source} → {target}",
        description="test chain",
        attack_vector="test",
    )


# ---------------------------------------------------------------------------
# _source_summary
# ---------------------------------------------------------------------------


class TestSourceSummary:
    def test_single_server(self) -> None:
        scan = _scan(_server("my-server", [_perm("read_file")]))
        lines = _source_summary(scan)
        assert len(lines) == 1
        assert "my-server" not in lines[0]  # shows source_file, not server name
        assert "1 tool(s)" in lines[0]

    def test_openclaw_skills(self) -> None:
        server = ServerPermissionMap(
            server=ServerConfig(
                name="openclaw-skills",
                transport=TransportType.STDIO,
                command="test",
                client="test",
                source_file=Path("/tmp/skills/"),
            ),
            enumeration_method="openclaw_skill",
            tools=[_perm("email-manager"), _perm("shell-runner")],
            overall_risk=RiskLevel.LOW,
        )
        scan = _scan(server)
        lines = _source_summary(scan)
        assert len(lines) == 1
        assert "2 skill(s)" in lines[0]

    def test_multiple_servers(self) -> None:
        scan = _scan(
            _server("server-a", [_perm("tool-a")]),
            _server("server-b", [_perm("tool-b1"), _perm("tool-b2")]),
        )
        lines = _source_summary(scan)
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# _risk_summary
# ---------------------------------------------------------------------------


class TestRiskSummary:
    def test_buckets_by_risk(self) -> None:
        scan = _scan(
            _server(
                "mixed",
                [
                    _perm("exec", risk=RiskLevel.CRITICAL),
                    _perm("delete_file", risk=RiskLevel.HIGH),
                    _perm("send_email", risk=RiskLevel.MEDIUM),
                    _perm("read_file", risk=RiskLevel.LOW),
                ],
            )
        )
        buckets, chains = _risk_summary(scan, [])
        assert buckets[RiskLevel.CRITICAL] == ["exec"]
        assert buckets[RiskLevel.HIGH] == ["delete_file"]
        assert buckets[RiskLevel.MEDIUM] == ["send_email"]
        assert buckets[RiskLevel.LOW] == ["read_file"]
        assert chains == []

    def test_chain_labels(self) -> None:
        scan = _scan(_server("s", [_perm("t")]))
        chains = [_chain("email-mgr", "web-browser")]
        _, chain_labels = _risk_summary(scan, chains)
        assert chain_labels == ["email-mgr → web-browser"]


# ---------------------------------------------------------------------------
# _has_any_risk
# ---------------------------------------------------------------------------


class TestHasAnyRisk:
    def test_no_risk(self) -> None:
        buckets = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: ["read_file"],
        }
        assert _has_any_risk(buckets, []) is False

    def test_critical_risk(self) -> None:
        buckets = {
            RiskLevel.CRITICAL: ["exec"],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: [],
        }
        assert _has_any_risk(buckets, []) is True

    def test_high_risk(self) -> None:
        buckets = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: ["delete_file"],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: [],
        }
        assert _has_any_risk(buckets, []) is True

    def test_chains_only(self) -> None:
        buckets = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: [],
        }
        assert _has_any_risk(buckets, ["a → b"]) is True

    def test_medium_only_is_not_risky(self) -> None:
        """MEDIUM alone doesn't trigger the prompt."""
        buckets = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: ["send_email"],
            RiskLevel.LOW: [],
        }
        assert _has_any_risk(buckets, []) is False


# ---------------------------------------------------------------------------
# print_risk_summary
# ---------------------------------------------------------------------------


class TestPrintRiskSummary:
    def test_no_risk_prints_green(self) -> None:
        console = Console(stderr=True, file=__import__("io").StringIO())
        buckets = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: ["safe_tool"],
        }
        print_risk_summary(console, buckets, [])
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "No high-risk tools detected" in output

    def test_critical_shown(self) -> None:
        console = Console(stderr=True, file=__import__("io").StringIO())
        buckets = {
            RiskLevel.CRITICAL: ["shell_exec"],
            RiskLevel.HIGH: [],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: [],
        }
        print_risk_summary(console, buckets, [])
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "1 CRITICAL" in output
        assert "shell_exec" in output

    def test_chains_shown(self) -> None:
        console = Console(stderr=True, file=__import__("io").StringIO())
        buckets = {
            RiskLevel.CRITICAL: [],
            RiskLevel.HIGH: ["delete_file"],
            RiskLevel.MEDIUM: [],
            RiskLevel.LOW: [],
        }
        print_risk_summary(console, buckets, ["email → shell"])
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "1 chain(s)" in output
        assert "email → shell" in output


# ---------------------------------------------------------------------------
# generate_init_policy
# ---------------------------------------------------------------------------


class TestGenerateInitPolicy:
    def test_critical_tools_are_denied(self) -> None:
        scan = _scan(
            _server(
                "my-server",
                [
                    _perm(
                        "shell_exec",
                        risk=RiskLevel.CRITICAL,
                        access=[_access(DataAccessType.SHELL, write=True)],
                        read_only=False,
                    ),
                ],
                risk=RiskLevel.CRITICAL,
            )
        )
        policy = generate_init_policy(scan, [])
        # CRITICAL tool should be denied at resource level
        assert "my-server" in policy.skills
        assert "shell_exec" in policy.skills["my-server"]
        assert policy.skills["my-server"]["shell_exec"].denied is True

    def test_high_tools_require_approval(self) -> None:
        scan = _scan(
            _server(
                "fs-server",
                [
                    _perm(
                        "delete_file",
                        risk=RiskLevel.HIGH,
                        access=[_access(DataAccessType.FILESYSTEM, write=True)],
                        destructive=True,
                        read_only=False,
                    ),
                ],
                risk=RiskLevel.HIGH,
            )
        )
        policy = generate_init_policy(scan, [])
        assert "delete_file" in policy.require_approval

    def test_low_tools_are_allowed(self) -> None:
        scan = _scan(
            _server(
                "safe-server",
                [_perm("read_file", risk=RiskLevel.LOW)],
                risk=RiskLevel.LOW,
            )
        )
        policy = generate_init_policy(scan, [])
        # LOW tools should not appear in require_approval or be denied
        assert "read_file" not in policy.require_approval

    def test_mixed_risk_levels(self) -> None:
        scan = _scan(
            _server(
                "mixed-server",
                [
                    _perm(
                        "exec_cmd",
                        risk=RiskLevel.CRITICAL,
                        access=[_access(DataAccessType.SHELL, write=True)],
                        read_only=False,
                    ),
                    _perm(
                        "delete_record",
                        risk=RiskLevel.HIGH,
                        access=[_access(DataAccessType.DATABASE, write=True)],
                        destructive=True,
                        read_only=False,
                    ),
                    _perm("list_files", risk=RiskLevel.LOW),
                ],
            )
        )
        policy = generate_init_policy(scan, [])
        # CRITICAL → denied
        assert policy.skills["mixed-server"]["exec_cmd"].denied is True
        # HIGH → require_approval
        assert "delete_record" in policy.require_approval
        # LOW → not blocked
        assert "list_files" not in policy.require_approval

    def test_chaining_mode_set_to_content(self) -> None:
        from agentward.policy.schema import ChainingMode

        scan = _scan(_server("s", [_perm("t")]))
        policy = generate_init_policy(scan, [])
        assert policy.chaining_mode == ChainingMode.CONTENT


# ---------------------------------------------------------------------------
# wrap_openclaw_gateway
# ---------------------------------------------------------------------------


class TestWrapOpenclawGateway:
    def test_no_openclaw_returns_false(self) -> None:
        console = Console(stderr=True, file=__import__("io").StringIO())
        with patch("agentward.init.find_clawdbot_config", return_value=None):
            assert wrap_openclaw_gateway(console) is False

    def test_already_wrapped_returns_true(self) -> None:
        console = Console(stderr=True, file=__import__("io").StringIO())
        with (
            patch("agentward.init.find_clawdbot_config", return_value=Path("/tmp/clawdbot.json")),
            patch("agentward.init.read_config", return_value={"gateway": {"port": 18789}}),
            patch("agentward.init.wrap_clawdbot_gateway", side_effect=ValueError("already wrapped")),
        ):
            assert wrap_openclaw_gateway(console) is True

    def test_successful_wrap(self) -> None:
        console = Console(stderr=True, file=__import__("io").StringIO())
        mock_config = {"gateway": {"port": 18789}}
        mock_wrapped = {"gateway": {"port": 18790}}
        with (
            patch("agentward.init.find_clawdbot_config", return_value=Path("/tmp/clawdbot.json")),
            patch("agentward.init.read_config", return_value=mock_config),
            patch("agentward.init.wrap_clawdbot_gateway", return_value=(mock_wrapped, 18789, 18790)),
            patch("agentward.init.write_config"),
        ):
            assert wrap_openclaw_gateway(console) is True


# ---------------------------------------------------------------------------
# run_init — integration-level tests (with mocked scan)
# ---------------------------------------------------------------------------


def _mock_scan_result() -> ScanResult:
    """Build a scan result with mixed risk levels for integration tests."""
    return _scan(
        _server(
            "test-server",
            [
                _perm(
                    "shell_exec",
                    risk=RiskLevel.CRITICAL,
                    access=[_access(DataAccessType.SHELL, write=True)],
                    read_only=False,
                ),
                _perm(
                    "delete_file",
                    risk=RiskLevel.HIGH,
                    access=[_access(DataAccessType.FILESYSTEM, write=True)],
                    destructive=True,
                    read_only=False,
                ),
                _perm("read_file", risk=RiskLevel.LOW),
            ],
        )
    )


def _patch_scan_pipeline(scan_result: ScanResult):
    """Context manager that patches the scan pipeline to return canned results."""
    from unittest.mock import patch
    from agentward.scan.chains import ChainDetection

    return [
        patch("agentward.init.discover_configs", return_value=[]),
        patch("agentward.init.parse_config_file", return_value=[]),
        patch("agentward.init.enumerate_all", return_value=[]),
        patch(
            "agentward.init.scan_openclaw",
            return_value=[
                MagicMock(
                    server=MagicMock(
                        name="test-server",
                        source_file=Path("/tmp/skills/"),
                    ),
                    tools=[
                        MagicMock(name="shell_exec"),
                        MagicMock(name="delete_file"),
                        MagicMock(name="read_file"),
                    ],
                    enumeration_method="openclaw_skill",
                    error=None,
                    capabilities=None,
                ),
            ],
        ),
        patch(
            "agentward.init.build_permission_map",
            return_value=scan_result,
        ),
        patch("agentward.init.generate_recommendations", return_value=[]),
        patch("agentward.init.detect_chains", return_value=[]),
    ]


class TestRunInit:
    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            with pytest.raises(click.exceptions.Exit):
                run_init(console=console, dry_run=True, policy_path=policy_path)

        assert not policy_path.exists()
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "DRY RUN" in output

    def test_yes_flag_skips_prompt(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("agentward.init.wrap_openclaw_gateway", return_value=False),
        ):
            run_init(console=console, yes=True, policy_path=policy_path)

        assert policy_path.exists()
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "Policy written" in output

    def test_no_risk_exits_cleanly(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        scan = _scan(
            _server("safe-server", [_perm("read_file", risk=RiskLevel.LOW)])
        )

        patches = _patch_scan_pipeline(scan)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            with pytest.raises(click.exceptions.Exit) as exc_info:
                run_init(console=console, policy_path=policy_path)
            assert exc_info.value.exit_code == 0  # type: ignore[union-attr]

        assert not policy_path.exists()
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "No high-risk tools detected" in output

    def test_existing_policy_overwrite_declined(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        policy_path.write_text("old policy", encoding="utf-8")
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("agentward.init.typer.confirm", side_effect=[True, False]),
        ):
            with pytest.raises(click.exceptions.Exit):
                run_init(console=console, policy_path=policy_path)

        # Original file untouched
        assert policy_path.read_text(encoding="utf-8") == "old policy"

    def test_existing_policy_overwrite_accepted(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        policy_path.write_text("old policy", encoding="utf-8")
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("agentward.init.typer.confirm", side_effect=[True, True]),
            patch("agentward.init.wrap_openclaw_gateway", return_value=False),
        ):
            run_init(console=console, policy_path=policy_path)

        assert policy_path.read_text(encoding="utf-8") != "old policy"

    def test_yes_flag_overwrites_existing(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        policy_path.write_text("old policy", encoding="utf-8")
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("agentward.init.wrap_openclaw_gateway", return_value=False),
        ):
            run_init(console=console, yes=True, policy_path=policy_path)

        assert policy_path.read_text(encoding="utf-8") != "old policy"

    def test_openclaw_wrapped_restarts_and_starts_proxy(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        mock_restart = MagicMock(return_value=True)
        mock_start = MagicMock()
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("agentward.init.wrap_openclaw_gateway", return_value=True),
            patch("agentward.init.restart_openclaw_gateway", mock_restart),
            patch("agentward.init.start_proxy", mock_start),
        ):
            run_init(console=console, yes=True, policy_path=policy_path)

        mock_restart.assert_called_once()
        mock_start.assert_called_once()
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "boundaries, not blindfolds" in output

    def test_openclaw_restart_failed_prints_manual_instructions(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("agentward.init.wrap_openclaw_gateway", return_value=True),
            patch("agentward.init.restart_openclaw_gateway", return_value=False),
        ):
            run_init(console=console, yes=True, policy_path=policy_path)

        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "Could not restart" in output
        assert "openclaw gateway restart" in output

    def test_no_openclaw_still_writes_policy(self, tmp_path: Path) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        policy_path = tmp_path / "agentward.yaml"
        scan = _mock_scan_result()

        patches = _patch_scan_pipeline(scan)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("agentward.init.wrap_openclaw_gateway", return_value=False),
        ):
            run_init(console=console, yes=True, policy_path=policy_path)

        assert policy_path.exists()
        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "OpenClaw not detected" in output
        assert "Policy written" in output


# ---------------------------------------------------------------------------
# CLI integration (via typer testing)
# ---------------------------------------------------------------------------


class TestFindGatewayBinary:
    def test_finds_openclaw(self) -> None:
        with patch("agentward.init.shutil.which", side_effect=lambda n: "/usr/bin/openclaw" if n == "openclaw" else None):
            assert _find_gateway_binary() == "openclaw"

    def test_finds_clawdbot_fallback(self) -> None:
        with patch("agentward.init.shutil.which", side_effect=lambda n: "/usr/bin/clawdbot" if n == "clawdbot" else None):
            assert _find_gateway_binary() == "clawdbot"

    def test_returns_none_when_missing(self) -> None:
        with patch("agentward.init.shutil.which", return_value=None):
            assert _find_gateway_binary() is None


class TestRestartOpenclawGateway:
    def test_no_binary_returns_false(self) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        with patch("agentward.init._find_gateway_binary", return_value=None):
            assert restart_openclaw_gateway(console) is False

    def test_successful_restart(self) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        mock_result = MagicMock(returncode=0, stderr="")
        with (
            patch("agentward.init._find_gateway_binary", return_value="openclaw"),
            patch("agentward.init.subprocess.run", return_value=mock_result) as mock_run,
        ):
            assert restart_openclaw_gateway(console) is True
            mock_run.assert_called_once_with(
                ["openclaw", "gateway", "restart"],
                capture_output=True,
                text=True,
                timeout=30,
            )

        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "gateway restarted" in output

    def test_failed_restart_no_fallback(self) -> None:
        """Command fails and backend port is not listening → False."""
        import io

        console = Console(stderr=True, file=io.StringIO())
        mock_result = MagicMock(returncode=1, stderr="port conflict")
        with (
            patch("agentward.init._find_gateway_binary", return_value="openclaw"),
            patch("agentward.init.subprocess.run", return_value=mock_result),
            patch("agentward.init.find_clawdbot_config", return_value=None),
        ):
            assert restart_openclaw_gateway(console) is False

    def test_failed_healthcheck_but_port_listening(self) -> None:
        """Command fails health check but gateway is actually on backend port → True."""
        import io

        console = Console(stderr=True, file=io.StringIO())
        mock_result = MagicMock(returncode=1, stderr="Gateway did not become healthy")
        with (
            patch("agentward.init._find_gateway_binary", return_value="openclaw"),
            patch("agentward.init.subprocess.run", return_value=mock_result),
            patch("agentward.init.find_clawdbot_config", return_value=Path("/tmp/c.json")),
            patch("agentward.init.get_clawdbot_gateway_ports", return_value=(18790, 18791)),
            patch("agentward.init._is_port_listening", return_value=True),
        ):
            assert restart_openclaw_gateway(console) is True

        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "gateway restarted" in output
        assert "18791" in output

    def test_timeout_returns_false(self) -> None:
        import io
        import subprocess

        console = Console(stderr=True, file=io.StringIO())
        with (
            patch("agentward.init._find_gateway_binary", return_value="openclaw"),
            patch("agentward.init.subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)),
        ):
            assert restart_openclaw_gateway(console) is False


class TestStartProxy:
    def test_missing_config_returns_early(self) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        with patch("agentward.init.find_clawdbot_config", return_value=None):
            start_proxy(console, Path("agentward.yaml"))

        output = console.file.getvalue()  # type: ignore[attr-defined]
        assert "not found" in output

    def test_missing_ports_returns_early(self) -> None:
        import io

        console = Console(stderr=True, file=io.StringIO())
        with (
            patch("agentward.init.find_clawdbot_config", return_value=Path("/tmp/c.json")),
            patch("agentward.init.get_clawdbot_gateway_ports", return_value=None),
        ):
            # Need a valid policy file for load_policy
            start_proxy(console, Path("/nonexistent/agentward.yaml"))

        output = console.file.getvalue()  # type: ignore[attr-defined]
        # Either "Cannot load policy" or "ports not configured"
        assert "Cannot load policy" in output or "not configured" in output

    def test_starts_http_proxy(self, tmp_path: Path) -> None:
        """start_proxy should create an HttpProxy and call asyncio.run."""
        import io

        console = Console(stderr=True, file=io.StringIO())

        # Create a minimal valid policy file
        policy_path = tmp_path / "agentward.yaml"
        policy_path.write_text("version: '1.0'\n", encoding="utf-8")

        with (
            patch("agentward.init.find_clawdbot_config", return_value=Path("/tmp/c.json")),
            patch("agentward.init.get_clawdbot_gateway_ports", return_value=(18789, 18790)),
            patch("agentward.init.get_clawdbot_llm_proxy_config", return_value=None),
            patch("agentward.proxy.http.HttpProxy") as mock_http_proxy_cls,
            patch("agentward.init.asyncio.run") as mock_asyncio_run,
        ):
            start_proxy(console, policy_path)

        mock_http_proxy_cls.assert_called_once()
        mock_asyncio_run.assert_called_once()


# ---------------------------------------------------------------------------
# CLI integration (via typer testing)
# ---------------------------------------------------------------------------


class TestInitCli:
    def test_help_output(self) -> None:
        """Smoke test that the CLI command is registered."""
        from typer.testing import CliRunner
        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["init", "--help"])
        assert result.exit_code == 0
        assert "One-command setup" in result.stdout
        assert "--dry-run" in result.stdout
        assert "--yes" in result.stdout
