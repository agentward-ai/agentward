"""Tests for the `agentward sanitize` CLI command.

Uses typer's CliRunner for isolated testing without subprocesses.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentward.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


class TestSanitizeCLI:
    def test_basic_sanitize_stdout(self) -> None:
        """Sanitized text goes to stdout by default."""
        result = runner.invoke(app, ["sanitize", str(FIXTURES / "sanitize_sample.txt")])
        assert result.exit_code == 0
        # SSN should be redacted.
        assert "123-45-6789" not in result.stdout
        assert "[SSN_1]" in result.stdout

    def test_output_file(self, tmp_path: Path) -> None:
        """--output writes sanitized text to file."""
        out = tmp_path / "clean.txt"
        result = runner.invoke(
            app,
            ["sanitize", str(FIXTURES / "sanitize_sample.txt"), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        content = out.read_text()
        assert "123-45-6789" not in content
        assert "[SSN_1]" in content

    def test_json_output_no_raw_pii(self) -> None:
        """--json produces valid JSON WITHOUT raw PII text or entity_map."""
        result = runner.invoke(
            app,
            ["sanitize", str(FIXTURES / "sanitize_sample.txt"), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["has_pii"] is True
        assert data["entity_count"] > 0
        assert "sanitized_text" in data
        # Raw PII must NOT appear in stdout JSON.
        assert "entity_map" not in data
        for ent in data["entities"]:
            assert "text" not in ent

    def test_json_entity_map_sidecar(self, tmp_path: Path) -> None:
        """--json --output writes entity map to a sidecar file."""
        out = tmp_path / "clean.txt"
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(FIXTURES / "sanitize_sample.txt"),
                "--json",
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # Sidecar path should be referenced in JSON.
        assert "entity_map_file" in data
        map_path = Path(data["entity_map_file"])
        assert map_path.exists()
        map_data = json.loads(map_path.read_text())
        # Sidecar DOES contain raw PII (entity_map + full entities).
        assert "entity_map" in map_data
        assert "entities" in map_data
        assert any("text" in e for e in map_data["entities"])

    def test_preview_mode_no_raw_pii(self) -> None:
        """--preview shows entities without exposing raw PII text."""
        result = runner.invoke(
            app,
            ["sanitize", str(FIXTURES / "sanitize_sample.txt"), "--preview"],
        )
        assert result.exit_code == 0
        output = result.stdout + (result.stderr or "")
        assert "Detected" in output or "ssn" in output.lower()
        # Raw PII values must NOT appear in preview output.
        assert "123-45-6789" not in output
        assert "4111" not in output
        # Placeholder format should appear instead.
        assert "SSN_1" in output.upper()

    def test_report_mode(self) -> None:
        """--report shows a summary table."""
        result = runner.invoke(
            app,
            ["sanitize", str(FIXTURES / "sanitize_sample.txt"), "--report"],
        )
        assert result.exit_code == 0
        output = result.stdout + (result.stderr or "")
        assert "Summary" in output or "Total" in output

    def test_category_filter(self) -> None:
        """--categories filters detection to specified types."""
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(FIXTURES / "sanitize_sample.txt"),
                "--categories",
                "ssn",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # All detected entities should be SSN.
        for ent in data["entities"]:
            assert ent["category"] == "ssn"

    def test_clean_file_no_pii(self) -> None:
        """Clean file produces output with no redactions."""
        result = runner.invoke(
            app,
            ["sanitize", str(FIXTURES / "sanitize_clean.txt"), "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        # No financial or identity PII.
        financial = {"credit_card", "ssn", "cvv"}
        detected_cats = {e["category"] for e in data["entities"]}
        assert not (detected_cats & financial)

    def test_file_not_found(self) -> None:
        result = runner.invoke(app, ["sanitize", "/nonexistent/file.txt"])
        assert result.exit_code == 1

    def test_invalid_category(self) -> None:
        result = runner.invoke(
            app,
            [
                "sanitize",
                str(FIXTURES / "sanitize_sample.txt"),
                "--categories",
                "nonexistent_category",
            ],
        )
        assert result.exit_code == 1

    def test_output_creates_parent_dirs(self, tmp_path: Path) -> None:
        """--output creates parent directories if they don't exist."""
        out = tmp_path / "sub" / "dir" / "clean.txt"
        result = runner.invoke(
            app,
            ["sanitize", str(FIXTURES / "sanitize_sample.txt"), "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
