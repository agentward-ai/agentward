"""Tests for the npm advisory registry (Feature 4).

Covers:
  - Loading built-in npm_advisories.yaml
  - Advisory lookup by package name
  - Version-specific compromise checks
  - Known packages: axios, plain-crypto-js, event-stream, ua-parser-js, etc.
  - NpmCheckResult properties (has_critical, has_high)
  - scan_node_modules integration
  - Extra advisory YAML loading
  - CLI: registry check-npm command
  - Advisory count (at least 20 entries)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agentward.registry import NpmAdvisory, NpmAdvisoryRegistry, NpmCheckResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_npm_advisory_yaml(tmp_path: Path, advisories: list[dict]) -> Path:
    path = tmp_path / "extra_advisories.yaml"
    path.write_text(yaml.dump({"advisories": advisories}), encoding="utf-8")
    return path


def _make_node_modules(tmp_path: Path) -> Path:
    nm = tmp_path / "node_modules"
    nm.mkdir()
    return nm


def _write_npm_package(nm: Path, name: str, version: str) -> None:
    pkg_dir = nm / name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": name, "version": version}),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# NpmCheckResult tests
# ---------------------------------------------------------------------------


class TestNpmCheckResult:
    def test_empty_result(self) -> None:
        r = NpmCheckResult()
        assert not r.has_critical
        assert not r.has_high

    def test_has_critical_match(self) -> None:
        adv = NpmAdvisory(
            package="axios",
            compromised_versions=["1.14.1"],
            date="2026-03-25",
            actor="UNC1069",
            attack_type="maintainer-account-hijack",
            payload="RAT",
            severity="critical",
        )
        r = NpmCheckResult(matches=[("axios", "1.14.1", adv)])
        assert r.has_critical
        assert r.has_high

    def test_has_high_not_critical(self) -> None:
        adv = NpmAdvisory(
            package="colors",
            compromised_versions=["1.4.1"],
            date="2022-01-08",
            actor="Marak",
            attack_type="maintainer-sabotage",
            payload="DoS",
            severity="high",
        )
        r = NpmCheckResult(matches=[("colors", "1.4.1", adv)])
        assert not r.has_critical
        assert r.has_high


# ---------------------------------------------------------------------------
# Advisory loading tests
# ---------------------------------------------------------------------------


class TestAdvisoryLoading:
    def test_loads_builtin_advisories(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert len(reg.all_advisories()) >= 20

    def test_all_advisories_have_required_fields(self) -> None:
        reg = NpmAdvisoryRegistry()
        for adv in reg.all_advisories():
            assert adv.package
            assert adv.date
            assert adv.severity in ("critical", "high", "medium", "low")
            assert adv.attack_type

    def test_advisories_sorted_by_date_desc(self) -> None:
        reg = NpmAdvisoryRegistry()
        dates = [a.date for a in reg.all_advisories()]
        assert dates == sorted(dates, reverse=True)

    def test_extra_path_merged(self, tmp_path: Path) -> None:
        extra = _write_npm_advisory_yaml(tmp_path, [{
            "package": "test-evil-pkg",
            "compromised_versions": ["1.0.0"],
            "date": "2026-01-01",
            "actor": "Test Actor",
            "attack_type": "test",
            "payload": "nothing",
            "severity": "high",
        }])
        reg = NpmAdvisoryRegistry(extra_paths=[extra])
        assert reg.is_compromised("test-evil-pkg")

    def test_builtin_has_axios(self) -> None:
        reg = NpmAdvisoryRegistry()
        advisories = reg.lookup("axios")
        assert advisories

    def test_builtin_has_plain_crypto_js(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("plain-crypto-js")

    def test_builtin_has_event_stream(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("event-stream")

    def test_builtin_has_ua_parser_js(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("ua-parser-js")

    def test_builtin_has_colors(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("colors")

    def test_builtin_has_faker(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("faker")

    def test_builtin_has_node_ipc(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("node-ipc")

    def test_builtin_has_eslint_scope(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("eslint-scope")

    def test_builtin_has_coa(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("coa")

    def test_builtin_has_rc(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("rc")


# ---------------------------------------------------------------------------
# Lookup and version tests
# ---------------------------------------------------------------------------


class TestLookup:
    def test_lookup_case_insensitive(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.lookup("AXIOS") == reg.lookup("axios")

    def test_lookup_unknown_returns_empty(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.lookup("not-a-real-evil-package-xyz") == []

    def test_is_compromised_any_version(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("axios")

    def test_is_compromised_specific_bad_version(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert reg.is_compromised("axios", "1.14.1")

    def test_is_compromised_good_version_returns_false(self) -> None:
        reg = NpmAdvisoryRegistry()
        # 1.6.0 is not in the compromised list
        assert not reg.is_compromised("axios", "1.6.0")

    def test_is_compromised_unknown_package(self) -> None:
        reg = NpmAdvisoryRegistry()
        assert not reg.is_compromised("totally-safe-pkg")

    def test_check_packages_empty_returns_no_matches(self) -> None:
        reg = NpmAdvisoryRegistry()
        result = reg.check_packages({})
        assert result.matches == []

    def test_check_packages_finds_compromised(self) -> None:
        reg = NpmAdvisoryRegistry()
        result = reg.check_packages({"axios": "1.14.1", "lodash": "4.17.21"})
        assert any(pkg == "axios" for pkg, _, _ in result.matches)
        assert not any(pkg == "lodash" for pkg, _, _ in result.matches)

    def test_check_packages_with_none_version(self) -> None:
        reg = NpmAdvisoryRegistry()
        result = reg.check_packages({"axios": None})
        assert any(pkg == "axios" for pkg, _, _ in result.matches)

    def test_advisory_has_actor_info(self) -> None:
        reg = NpmAdvisoryRegistry()
        advisories = reg.lookup("axios")
        assert advisories
        assert "UNC1069" in advisories[0].actor or advisories[0].actor

    def test_advisory_has_payload_info(self) -> None:
        reg = NpmAdvisoryRegistry()
        advisories = reg.lookup("plain-crypto-js")
        assert advisories
        assert advisories[0].payload


# ---------------------------------------------------------------------------
# scan_node_modules tests
# ---------------------------------------------------------------------------


class TestScanNodeModules:
    def test_empty_node_modules_no_matches(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        reg = NpmAdvisoryRegistry()
        result = reg.scan_node_modules(tmp_path)
        assert result.matches == []

    def test_compromised_package_detected(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_npm_package(nm, "plain-crypto-js", "4.2.1")
        reg = NpmAdvisoryRegistry()
        result = reg.scan_node_modules(tmp_path)
        assert any(pkg == "plain-crypto-js" for pkg, _, _ in result.matches)

    def test_safe_packages_not_flagged(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_npm_package(nm, "lodash", "4.17.21")
        _write_npm_package(nm, "axios", "1.6.0")  # safe version
        reg = NpmAdvisoryRegistry()
        result = reg.scan_node_modules(tmp_path)
        # axios 1.6.0 is not in compromised list
        assert not any(
            pkg == "axios" and ver == "1.6.0"
            for pkg, ver, _ in result.matches
        )

    def test_nonexistent_dir_returns_empty(self, tmp_path: Path) -> None:
        reg = NpmAdvisoryRegistry()
        result = reg.scan_node_modules(tmp_path / "nonexistent")
        assert result.matches == []

    def test_accepts_project_root(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_npm_package(nm, "event-stream", "3.3.6")
        reg = NpmAdvisoryRegistry()
        result = reg.scan_node_modules(tmp_path)  # Project root, not node_modules
        assert any(pkg == "event-stream" for pkg, _, _ in result.matches)

    def test_scoped_package_detected(self, tmp_path: Path) -> None:
        """Scoped packages like @evil/pkg should be found."""
        nm = _make_node_modules(tmp_path)
        # Add a custom advisory for a scoped package
        extra_path = tmp_path / "extra.yaml"
        extra_path.write_text(yaml.dump({"advisories": [{
            "package": "@evil/malware",
            "compromised_versions": ["1.0.0"],
            "date": "2026-01-01",
            "actor": "test",
            "attack_type": "test",
            "payload": "test",
            "severity": "critical",
        }]}))
        scope_dir = nm / "@evil"
        scope_dir.mkdir()
        pkg_dir = scope_dir / "malware"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text(
            json.dumps({"name": "@evil/malware", "version": "1.0.0"})
        )
        reg = NpmAdvisoryRegistry(extra_paths=[extra_path])
        result = reg.scan_node_modules(tmp_path)
        assert any(pkg == "@evil/malware" for pkg, _, _ in result.matches)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestNpmAdvisoriesCLI:
    def test_registry_check_npm_command(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_npm_package(nm, "lodash", "4.17.21")

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "check-npm", str(tmp_path)])
        assert result.exit_code == 0

    def test_registry_check_npm_json_output(self, tmp_path: Path) -> None:
        import json as _json
        from typer.testing import CliRunner
        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_npm_package(nm, "lodash", "4.17.21")

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "check-npm", "--json", str(tmp_path)])
        assert result.exit_code == 0
        data = _json.loads(result.output)
        assert isinstance(data, list)

    def test_registry_check_npm_exits_2_on_critical(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_npm_package(nm, "plain-crypto-js", "4.2.1")

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "check-npm", str(tmp_path)])
        assert result.exit_code == 2

    def test_advisory_list_command(self) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["registry", "list-advisories"])
        assert result.exit_code == 0
