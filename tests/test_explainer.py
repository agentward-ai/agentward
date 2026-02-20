"""Tests for the risk explainer module."""

from __future__ import annotations

import pytest

from agentward.scan.enumerator import ToolInfo
from agentward.scan.explainer import (
    RiskExplanation,
    _BROWSER_SCENARIO,
    _CREDENTIAL_SCENARIO,
    _DATABASE_WRITE_SCENARIO,
    _DESTRUCTIVE_SCENARIO,
    _EMAIL_WRITE_SCENARIO,
    _EXFILTRATION_SCENARIO,
    _FILESYSTEM_WRITE_SCENARIO,
    _MESSAGING_WRITE_SCENARIO,
    _SHELL_SCENARIO,
    explain_risk,
)
from agentward.scan.permissions import (
    DataAccess,
    DataAccessType,
    RiskLevel,
    ServerPermissionMap,
    ToolPermission,
)
from pathlib import Path

from agentward.scan.config import ServerConfig, TransportType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tool(name: str = "test_tool") -> ToolInfo:
    return ToolInfo(name=name, description="", input_schema={})


def _perm(
    name: str = "test_tool",
    risk: RiskLevel = RiskLevel.HIGH,
    access: list[DataAccess] | None = None,
    destructive: bool = False,
    read_only: bool = False,
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


def _server(tools: list[ToolPermission]) -> ServerPermissionMap:
    return ServerPermissionMap(
        server=ServerConfig(
            name="test-server",
            transport=TransportType.STDIO,
            command="test",
            client="test",
            source_file=Path("/tmp/test.json"),
        ),
        enumeration_method="live",
        tools=tools,
        overall_risk=RiskLevel.HIGH,
    )


# ---------------------------------------------------------------------------
# Tests: LOW risk returns None
# ---------------------------------------------------------------------------


class TestLowRiskReturnsNone:
    def test_low_risk_tool_returns_none(self) -> None:
        perm = _perm(risk=RiskLevel.LOW)
        assert explain_risk(perm) is None

    def test_low_risk_with_server_returns_none(self) -> None:
        perm = _perm(risk=RiskLevel.LOW)
        server = _server([perm])
        assert explain_risk(perm, server) is None


# ---------------------------------------------------------------------------
# Tests: Individual scenario matching
# ---------------------------------------------------------------------------


class TestShellScenario:
    def test_shell_access_returns_shell_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.CRITICAL,
            access=[_access(DataAccessType.SHELL, write=True)],
        )
        result = explain_risk(perm)
        assert result is _SHELL_SCENARIO

    def test_shell_takes_priority_over_other_signals(self) -> None:
        """Shell is highest priority — should be returned even with other signals."""
        perm = _perm(
            risk=RiskLevel.CRITICAL,
            access=[
                _access(DataAccessType.SHELL, write=True),
                _access(DataAccessType.FILESYSTEM, write=True),
                _access(DataAccessType.CREDENTIALS),
            ],
            destructive=True,
        )
        result = explain_risk(perm)
        assert result is _SHELL_SCENARIO


class TestExfiltrationScenario:
    def test_network_plus_credentials_on_server(self) -> None:
        """Network + credentials on same server → exfiltration scenario."""
        tool_net = _perm(
            name="fetch",
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.NETWORK)],
        )
        tool_cred = _perm(
            name="get_secret",
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.CREDENTIALS)],
        )
        server = _server([tool_net, tool_cred])

        # Check a tool that doesn't have shell — should get exfiltration
        result = explain_risk(tool_net, server)
        assert result is _EXFILTRATION_SCENARIO

    def test_no_exfiltration_without_both_signals(self) -> None:
        """Network alone should not trigger exfiltration."""
        perm = _perm(
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.NETWORK)],
        )
        server = _server([perm])
        result = explain_risk(perm, server)
        assert result is not _EXFILTRATION_SCENARIO


class TestEmailWriteScenario:
    def test_email_write_returns_email_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.EMAIL, write=True)],
        )
        result = explain_risk(perm)
        assert result is _EMAIL_WRITE_SCENARIO

    def test_email_read_only_no_email_scenario(self) -> None:
        """Read-only email should not trigger email write scenario."""
        perm = _perm(
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.EMAIL, read=True, write=False)],
        )
        result = explain_risk(perm)
        assert result is not _EMAIL_WRITE_SCENARIO


class TestMessagingWriteScenario:
    def test_messaging_write_returns_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.MESSAGING, write=True)],
        )
        result = explain_risk(perm)
        assert result is _MESSAGING_WRITE_SCENARIO


class TestDestructiveScenario:
    def test_destructive_tool_returns_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.DATABASE)],
            destructive=True,
        )
        result = explain_risk(perm)
        assert result is _DESTRUCTIVE_SCENARIO


class TestDatabaseWriteScenario:
    def test_database_write_returns_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.DATABASE, write=True)],
        )
        result = explain_risk(perm)
        assert result is _DATABASE_WRITE_SCENARIO


class TestFilesystemWriteScenario:
    def test_filesystem_write_returns_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.FILESYSTEM, write=True)],
        )
        result = explain_risk(perm)
        assert result is _FILESYSTEM_WRITE_SCENARIO


class TestBrowserScenario:
    def test_browser_access_returns_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.BROWSER)],
        )
        result = explain_risk(perm)
        assert result is _BROWSER_SCENARIO


class TestCredentialScenario:
    def test_credential_access_returns_scenario(self) -> None:
        perm = _perm(
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.CREDENTIALS)],
        )
        result = explain_risk(perm)
        assert result is _CREDENTIAL_SCENARIO


# ---------------------------------------------------------------------------
# Tests: Edge cases and explanation fields
# ---------------------------------------------------------------------------


class TestExplanationQuality:
    def test_all_scenarios_have_nonempty_fields(self) -> None:
        """Every scenario template must have non-empty strings."""
        scenarios = [
            _SHELL_SCENARIO,
            _EXFILTRATION_SCENARIO,
            _EMAIL_WRITE_SCENARIO,
            _MESSAGING_WRITE_SCENARIO,
            _DESTRUCTIVE_SCENARIO,
            _DATABASE_WRITE_SCENARIO,
            _FILESYSTEM_WRITE_SCENARIO,
            _BROWSER_SCENARIO,
            _CREDENTIAL_SCENARIO,
        ]
        for scenario in scenarios:
            assert isinstance(scenario, RiskExplanation)
            assert len(scenario.scenario) > 10
            assert len(scenario.example) > 10
            assert len(scenario.impact) > 5
            assert len(scenario.mitigation) > 5

    def test_medium_risk_gets_explanation(self) -> None:
        """MEDIUM risk tools should also get explanations."""
        perm = _perm(
            risk=RiskLevel.MEDIUM,
            access=[_access(DataAccessType.BROWSER)],
        )
        result = explain_risk(perm)
        assert result is not None

    def test_no_access_types_returns_none(self) -> None:
        """A HIGH risk tool with no recognized access types returns None."""
        perm = _perm(
            risk=RiskLevel.HIGH,
            access=[_access(DataAccessType.UNKNOWN)],
        )
        result = explain_risk(perm)
        assert result is None

    def test_server_none_is_safe(self) -> None:
        """explain_risk works without server context."""
        perm = _perm(
            risk=RiskLevel.CRITICAL,
            access=[_access(DataAccessType.SHELL, write=True)],
        )
        result = explain_risk(perm, server=None)
        assert result is _SHELL_SCENARIO
