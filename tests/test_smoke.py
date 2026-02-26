"""End-to-end CLI smoke tests for the first-use journey.

These tests verify the critical path a new user follows:
  pip install agentward → agentward scan → agentward configure → agentward map

They use typer.testing.CliRunner (in-process, fast, deterministic) with
one subprocess test to catch real entrypoint/import failures.

MCP server enumeration is mocked — no real servers needed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentward.cli import app
from agentward.scan.config import ServerConfig
from agentward.scan.enumerator import EnumerationResult, ToolInfo

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"
CONFIGS = FIXTURES / "configs"
OPENCLAW_SKILLS = FIXTURES / "openclaw_skills"
FULL_POLICY = FIXTURES / "full_policy.yaml"
SIMPLE_POLICY = FIXTURES / "simple_policy.yaml"


# ---------------------------------------------------------------------------
# Shared mock for enumerate_all
# ---------------------------------------------------------------------------


async def _mock_enumerate_all(
    servers: list[ServerConfig], timeout: float = 15.0
) -> list[EnumerationResult]:
    """Return realistic EnumerationResult objects without spawning processes."""
    results: list[EnumerationResult] = []
    for server in servers:
        tools = [
            ToolInfo(
                name="read_file",
                description="Read a file from the filesystem",
                input_schema={
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                },
            ),
            ToolInfo(
                name="write_file",
                description="Write content to a file",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                },
            ),
        ]
        results.append(
            EnumerationResult(
                server=server,
                tools=tools,
                enumeration_method="live_stdio",
            )
        )
    return results


# ---------------------------------------------------------------------------
# 1. Entrypoint tests
# ---------------------------------------------------------------------------


class TestEntrypoint:
    """Verify the installed package can be invoked at all."""

    def test_entrypoint_subprocess(self) -> None:
        """Verify the package is importable and the CLI app loads.

        This is the only test that catches packaging-level failures:
        missing dependencies, broken __init__.py, busted cli:app entrypoint.
        """
        # Test 1: package imports cleanly
        result = subprocess.run(
            [sys.executable, "-c", "from agentward.cli import app; print('ok')"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0
        assert "ok" in result.stdout

        # Test 2: version is accessible
        result = subprocess.run(
            [sys.executable, "-c", "import agentward; print(agentward.__version__)"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0
        assert result.stdout.strip() != ""

    def test_version_clirunner(self) -> None:
        """Quick CliRunner sanity: --version exits cleanly."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "agentward" in (result.output or "").lower()


# ---------------------------------------------------------------------------
# 2. Scan — no configs
# ---------------------------------------------------------------------------


class TestScanNoConfigs:
    """Verify scan gives clear errors when nothing is found."""

    def test_scan_no_configs(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Auto-discover with nothing to find → exit 1 with clear message."""
        # Redirect home/cwd so auto-discovery finds nothing
        monkeypatch.setattr("agentward.scan.config.Path.home", lambda: tmp_path)
        monkeypatch.setattr(
            "agentward.scan.config.discover_configs", lambda: []
        )
        monkeypatch.setattr(
            "agentward.scan.openclaw.discover_skill_dirs", lambda: []
        )
        monkeypatch.setattr(
            "agentward.scan.openclaw.scan_openclaw", lambda: []
        )
        monkeypatch.setattr(
            "agentward.scan.enumerator.enumerate_all", _mock_enumerate_all
        )

        result = runner.invoke(app, ["scan"])
        assert result.exit_code == 1
        combined = result.output or ""
        assert "no tools found" in combined.lower() or "no mcp" in combined.lower()

    def test_scan_nonexistent_path(self) -> None:
        """Explicit path that doesn't exist → exit 1 with clear message."""
        result = runner.invoke(app, ["scan", "/nonexistent/path/to/config.json"])
        assert result.exit_code == 1
        combined = result.output or ""
        assert "does not exist" in combined.lower()


# ---------------------------------------------------------------------------
# 3. Scan — with fixtures
# ---------------------------------------------------------------------------


class TestScanWithFixtures:
    """Verify scan works end-to-end with existing test fixtures."""

    def test_scan_with_fixture_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Scan claude_desktop.json with mocked enumeration → success."""
        monkeypatch.setattr(
            "agentward.scan.enumerator.enumerate_all", _mock_enumerate_all
        )
        config_path = str(CONFIGS / "claude_desktop.json")
        result = runner.invoke(app, ["scan", config_path])

        assert result.exit_code == 0
        combined = result.output or ""
        # Should contain server names from the fixture
        assert "filesystem" in combined.lower()

    def test_scan_openclaw_fixtures(self) -> None:
        """Scan OpenClaw skill fixtures → success (no enumeration mock needed)."""
        result = runner.invoke(app, ["scan", str(OPENCLAW_SKILLS)])
        assert result.exit_code == 0
        combined = result.output or ""
        # Should find at least one skill name from the fixture directory
        low = combined.lower()
        assert "email" in low or "shell" in low or "coding" in low or "skill" in low

    def test_scan_json_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Scan with --json flag produces valid JSON somewhere in output."""
        monkeypatch.setattr(
            "agentward.scan.enumerator.enumerate_all", _mock_enumerate_all
        )
        config_path = str(CONFIGS / "claude_desktop.json")
        result = runner.invoke(app, ["scan", "--json", config_path])

        assert result.exit_code == 0
        # CliRunner mixes stderr (rich progress) with stdout (JSON).
        # Extract the JSON object from the mixed output.
        output = result.output or ""
        # Find the first '{' that starts the JSON block
        start = output.find("{")
        assert start != -1, f"No JSON object found in output: {output[:200]}"
        # Find the matching closing brace by parsing from that point
        data = json.loads(output[start:])
        assert "servers" in data


# ---------------------------------------------------------------------------
# 4. Configure — round-trip validation
# ---------------------------------------------------------------------------


class TestConfigureRoundTrip:
    """Verify configure generates valid, loadable policy YAML."""

    def test_configure_generates_valid_yaml(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Configure produces a file that parses as valid YAML with 'version' key."""
        monkeypatch.setattr(
            "agentward.scan.enumerator.enumerate_all", _mock_enumerate_all
        )
        output_path = tmp_path / "agentward.yaml"
        config_path = str(CONFIGS / "claude_desktop.json")

        result = runner.invoke(
            app, ["configure", config_path, "-o", str(output_path)]
        )
        assert result.exit_code == 0
        assert output_path.exists()

        data = yaml.safe_load(output_path.read_text())
        assert isinstance(data, dict)
        assert "version" in data

    def test_configure_round_trips_through_loader(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Generated policy can be loaded back by the policy engine."""
        from agentward.policy.loader import load_policy

        monkeypatch.setattr(
            "agentward.scan.enumerator.enumerate_all", _mock_enumerate_all
        )
        output_path = tmp_path / "agentward.yaml"
        config_path = str(CONFIGS / "claude_desktop.json")

        result = runner.invoke(
            app, ["configure", config_path, "-o", str(output_path)]
        )
        assert result.exit_code == 0

        # This must not raise ValidationError
        policy = load_policy(output_path)
        assert policy.version == "1.0"


# ---------------------------------------------------------------------------
# 5. Map command
# ---------------------------------------------------------------------------


class TestMapCommand:
    """Verify map renders without crashing."""

    def test_map_terminal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Map with terminal output → exit 0, contains graph marker."""
        monkeypatch.setattr(
            "agentward.scan.enumerator.enumerate_all", _mock_enumerate_all
        )
        config_path = str(CONFIGS / "claude_desktop.json")
        result = runner.invoke(app, ["map", config_path])

        assert result.exit_code == 0
        combined = result.output or ""
        assert "permission graph" in combined.lower() or "map" in combined.lower()

    def test_map_with_policy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Map with policy overlay → must not crash even if skills don't match."""
        monkeypatch.setattr(
            "agentward.scan.enumerator.enumerate_all", _mock_enumerate_all
        )
        config_path = str(CONFIGS / "claude_desktop.json")
        result = runner.invoke(
            app, ["map", config_path, "--policy", str(FULL_POLICY)]
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# 6. Setup — dry-run safety
# ---------------------------------------------------------------------------


class TestSetupDryRun:
    """Verify setup --dry-run previews changes without modifying files."""

    def test_setup_dry_run(self, tmp_path: Path) -> None:
        """Dry-run on a copy of a fixture config → exit 0, file unchanged."""
        # Copy fixture files into tmp_path so we don't touch originals
        src_config = CONFIGS / "claude_desktop.json"
        tmp_config = tmp_path / "mcp.json"
        shutil.copy2(src_config, tmp_config)

        src_policy = SIMPLE_POLICY
        tmp_policy = tmp_path / "agentward.yaml"
        shutil.copy2(src_policy, tmp_policy)

        original_content = tmp_config.read_text()

        result = runner.invoke(
            app,
            [
                "setup",
                "--config", str(tmp_config),
                "--policy", str(tmp_policy),
                "--dry-run",
            ],
        )
        assert result.exit_code == 0
        # Dry-run must not modify the config file
        assert tmp_config.read_text() == original_content


# ---------------------------------------------------------------------------
# 7. Comply — guard test
# ---------------------------------------------------------------------------


class TestComplyCommand:
    """Verify comply command works with --framework hipaa."""

    def test_comply_runs_without_crash(self) -> None:
        """Comply --framework hipaa → runs policy-only checks (exit 0 or 1)."""
        result = runner.invoke(app, ["comply", "--framework", "hipaa"])
        # Exit 1 is valid (required controls failed on empty policy),
        # but it should NOT crash with NotImplementedError
        assert result.exit_code in (0, 1)
        assert "NotImplementedError" not in (result.output or "")
