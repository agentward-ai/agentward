"""Tests for the skill chain analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentward.scan.chains import (
    ChainDetection,
    ChainRisk,
    detect_chains,
)
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
# Helpers
# ---------------------------------------------------------------------------


def _tool(name: str) -> ToolInfo:
    return ToolInfo(name=name, description=f"Tool: {name}", input_schema={})


def _perm(
    name: str,
    risk: RiskLevel = RiskLevel.LOW,
    access: list[DataAccess] | None = None,
) -> ToolPermission:
    return ToolPermission(
        tool=_tool(name),
        data_access=access or [],
        risk_level=risk,
        risk_reasons=["test"],
        is_destructive=False,
        is_read_only=True,
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
        config_sources=[],
        scan_timestamp="2026-02-18T00:00:00Z",
    )


# ---------------------------------------------------------------------------
# Tests: Chain detection
# ---------------------------------------------------------------------------


class TestDetectChains:
    """Tests for detect_chains()."""

    def test_email_to_browser_chain(self) -> None:
        """Email + browser servers produce an email→browser chain."""
        email_srv = _server(
            "email-mgr",
            [_perm("read_email", access=[_access(DataAccessType.EMAIL)])],
        )
        browser_srv = _server(
            "web-browser",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        scan = _scan(email_srv, browser_srv)
        chains = detect_chains(scan)

        assert len(chains) >= 1
        labels = {c.label for c in chains}
        assert "email-mgr \u2192 web-browser" in labels

        # Check the specific chain details
        email_browser = next(c for c in chains if "email-mgr" in c.source_server and "web-browser" in c.target_server)
        assert email_browser.risk == ChainRisk.HIGH
        assert "email" in email_browser.description.lower()
        assert "brows" in email_browser.description.lower()

    def test_email_to_shell_chain(self) -> None:
        """Email + shell servers produce a CRITICAL chain."""
        email_srv = _server(
            "email-mgr",
            [_perm("read_email", access=[_access(DataAccessType.EMAIL)])],
        )
        shell_srv = _server(
            "shell-exec",
            [_perm("run_cmd", access=[_access(DataAccessType.SHELL, write=True)])],
            RiskLevel.CRITICAL,
        )
        scan = _scan(email_srv, shell_srv)
        chains = detect_chains(scan)

        critical_chains = [c for c in chains if c.risk == ChainRisk.CRITICAL]
        assert len(critical_chains) >= 1
        assert any(
            c.source_server == "email-mgr" and c.target_server == "shell-exec"
            for c in critical_chains
        )

    def test_browser_to_shell_chain(self) -> None:
        """Browser + shell produces CRITICAL code execution chain."""
        browser_srv = _server(
            "web-browser",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        shell_srv = _server(
            "shell-exec",
            [_perm("run_cmd", access=[_access(DataAccessType.SHELL, write=True)])],
            RiskLevel.CRITICAL,
        )
        scan = _scan(browser_srv, shell_srv)
        chains = detect_chains(scan)

        assert any(
            c.source_server == "web-browser"
            and c.target_server == "shell-exec"
            and c.risk == ChainRisk.CRITICAL
            for c in chains
        )

    def test_single_server_homogeneous_no_chains(self) -> None:
        """A single server with one capability type cannot chain to itself."""
        srv = _server(
            "all-email",
            [
                _perm("read_email", access=[_access(DataAccessType.EMAIL)]),
                _perm("send_email", access=[_access(DataAccessType.EMAIL)]),
            ],
        )
        scan = _scan(srv)
        chains = detect_chains(scan)
        assert len(chains) == 0

    def test_single_server_heterogeneous_detects_chains(self) -> None:
        """A single server with multiple capability types detects intra-server chains.

        This handles the OpenClaw case where many skills are grouped under one
        server but have distinct capabilities (email, browser, shell, etc.).
        """
        srv = _server(
            "openclaw:skills",
            [
                _perm("himalaya", access=[_access(DataAccessType.EMAIL)]),
                _perm("web-browse", access=[_access(DataAccessType.BROWSER)]),
            ],
        )
        scan = _scan(srv)
        chains = detect_chains(scan)
        # Should detect email→browser chain with tool-level labels
        assert len(chains) >= 1
        labels = {c.label for c in chains}
        assert "himalaya \u2192 web-browse" in labels

    def test_no_chains_for_unrelated_servers(self) -> None:
        """Servers with non-chainable capabilities produce no chains."""
        fs_srv = _server(
            "filesystem",
            [_perm("read_file", access=[_access(DataAccessType.FILESYSTEM)])],
        )
        db_srv = _server(
            "database",
            [_perm("query_db", access=[_access(DataAccessType.DATABASE)])],
        )
        scan = _scan(fs_srv, db_srv)
        chains = detect_chains(scan)
        assert len(chains) == 0

    def test_chain_direction_matters(self) -> None:
        """email→browser and browser→email are different chains."""
        email_srv = _server(
            "email-mgr",
            [_perm("read_email", access=[_access(DataAccessType.EMAIL)])],
        )
        browser_srv = _server(
            "web-browser",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        scan = _scan(email_srv, browser_srv)
        chains = detect_chains(scan)

        # Email→browser exists (email content leaks via browsing)
        assert any(
            c.source_server == "email-mgr" and c.target_server == "web-browser"
            for c in chains
        )
        # Browser→email also exists (web content triggers email actions)
        assert any(
            c.source_server == "web-browser" and c.target_server == "email-mgr"
            for c in chains
        )

    def test_critical_chains_sorted_first(self) -> None:
        """CRITICAL chains should appear before HIGH chains."""
        email_srv = _server(
            "email-mgr",
            [_perm("read_email", access=[_access(DataAccessType.EMAIL)])],
        )
        browser_srv = _server(
            "web-browser",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        shell_srv = _server(
            "shell-exec",
            [_perm("run_cmd", access=[_access(DataAccessType.SHELL, write=True)])],
            RiskLevel.CRITICAL,
        )
        scan = _scan(email_srv, browser_srv, shell_srv)
        chains = detect_chains(scan)

        # Should have both CRITICAL and HIGH chains
        assert any(c.risk == ChainRisk.CRITICAL for c in chains)
        assert any(c.risk == ChainRisk.HIGH for c in chains)

        # First chain should be CRITICAL
        first_critical = next(i for i, c in enumerate(chains) if c.risk == ChainRisk.CRITICAL)
        first_high = next(i for i, c in enumerate(chains) if c.risk == ChainRisk.HIGH)
        assert first_critical < first_high

    def test_chain_has_label_and_description(self) -> None:
        """Each chain has a human-readable label and description."""
        email_srv = _server(
            "email-mgr",
            [_perm("read_email", access=[_access(DataAccessType.EMAIL)])],
        )
        browser_srv = _server(
            "web-browser",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        scan = _scan(email_srv, browser_srv)
        chains = detect_chains(scan)

        for chain in chains:
            assert chain.label  # non-empty
            assert chain.description  # non-empty
            assert chain.attack_vector  # non-empty
            assert "\u2192" in chain.label  # contains arrow

    def test_messaging_to_shell_chain(self) -> None:
        """Messaging + shell produces CRITICAL chain."""
        msg_srv = _server(
            "slack",
            [_perm("read_message", access=[_access(DataAccessType.MESSAGING)])],
        )
        shell_srv = _server(
            "shell-exec",
            [_perm("run_cmd", access=[_access(DataAccessType.SHELL, write=True)])],
        )
        scan = _scan(msg_srv, shell_srv)
        chains = detect_chains(scan)

        assert any(
            c.source_server == "slack"
            and c.target_server == "shell-exec"
            and c.risk == ChainRisk.CRITICAL
            for c in chains
        )

    def test_filesystem_to_shell_chain(self) -> None:
        """Filesystem + shell produces CRITICAL chain."""
        fs_srv = _server(
            "filesystem",
            [_perm("read_file", access=[_access(DataAccessType.FILESYSTEM)])],
        )
        shell_srv = _server(
            "shell-exec",
            [_perm("run_cmd", access=[_access(DataAccessType.SHELL, write=True)])],
        )
        scan = _scan(fs_srv, shell_srv)
        chains = detect_chains(scan)

        assert any(
            c.source_server == "filesystem"
            and c.target_server == "shell-exec"
            and c.risk == ChainRisk.CRITICAL
            for c in chains
        )

    def test_deduplication(self) -> None:
        """Same chain pattern on same server pair should not duplicate."""
        email_srv = _server(
            "email-mgr",
            [
                _perm("read_email", access=[_access(DataAccessType.EMAIL)]),
                _perm("search_email", access=[_access(DataAccessType.EMAIL)]),
            ],
        )
        browser_srv = _server(
            "web-browser",
            [
                _perm("browse", access=[_access(DataAccessType.BROWSER)]),
                _perm("navigate", access=[_access(DataAccessType.BROWSER)]),
            ],
        )
        scan = _scan(email_srv, browser_srv)
        chains = detect_chains(scan)

        # Should have exactly 2 chains: email→browser and browser→email
        # NOT duplicates from multiple tools on same servers
        email_to_browser = [
            c for c in chains
            if c.source_server == "email-mgr" and c.target_server == "web-browser"
        ]
        # Should not exceed the number of unique patterns for this pair
        descriptions = {c.description for c in email_to_browser}
        assert len(email_to_browser) == len(descriptions)

    def test_three_servers_multiple_chains(self) -> None:
        """Three servers with dangerous combos produce multiple chains."""
        email_srv = _server(
            "email-mgr",
            [_perm("read_email", access=[_access(DataAccessType.EMAIL)])],
        )
        browser_srv = _server(
            "web-browser",
            [_perm("browse", access=[_access(DataAccessType.BROWSER)])],
        )
        shell_srv = _server(
            "shell-exec",
            [_perm("run_cmd", access=[_access(DataAccessType.SHELL, write=True)])],
        )
        scan = _scan(email_srv, browser_srv, shell_srv)
        chains = detect_chains(scan)

        # Should detect: email→browser, email→shell, browser→shell,
        # browser→email, plus potentially network→shell etc.
        assert len(chains) >= 4

    def test_empty_scan_no_chains(self) -> None:
        """An empty scan produces no chains."""
        scan = _scan()
        chains = detect_chains(scan)
        assert chains == []

    def test_database_to_shell_chain(self) -> None:
        """Database + shell produces CRITICAL chain."""
        db_srv = _server(
            "postgres",
            [_perm("query_db", access=[_access(DataAccessType.DATABASE)])],
        )
        shell_srv = _server(
            "shell-exec",
            [_perm("run_cmd", access=[_access(DataAccessType.SHELL, write=True)])],
        )
        scan = _scan(db_srv, shell_srv)
        chains = detect_chains(scan)

        assert any(
            c.source_server == "postgres"
            and c.target_server == "shell-exec"
            and c.risk == ChainRisk.CRITICAL
            for c in chains
        )
