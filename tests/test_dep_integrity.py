"""Tests for dependency integrity verification.

Covers:
  - Lockfile integrity: hash mismatch, missing packages, missing package.json
  - Phantom dependency detection: never-imported packages
  - Import extraction from JS/TS source files
  - New package detection (mocked registry calls)
  - Maintainer change detection (mocked registry calls)
  - Version anomaly detection: rapid publication, unpublished versions
  - IntegrityResult properties (has_critical, has_warning)
  - IntegrityCheckOptions (offline mode, selective checks)
  - verify_dependencies entrypoint
  - CLI commands (verify-deps)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from agentward.scan.dep_integrity import (
    IntegrityCheckOptions,
    IntegrityFinding,
    IntegrityResult,
    _collect_source_imports,
    _extract_imports_from_file,
    _extract_lockfile_packages,
    check_lockfile_integrity,
    check_maintainer_changes,
    check_new_packages,
    check_phantom_dependencies,
    check_version_anomalies,
    verify_dependencies,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pkg_json(project_dir: Path, data: dict) -> None:
    (project_dir / "package.json").write_text(json.dumps(data), encoding="utf-8")


def _write_lockfile(project_dir: Path, data: dict) -> None:
    (project_dir / "package-lock.json").write_text(json.dumps(data), encoding="utf-8")


def _make_node_modules_pkg(project_dir: Path, name: str, version: str = "1.0.0") -> Path:
    """Create a minimal package in node_modules."""
    nm = project_dir / "node_modules"
    nm.mkdir(exist_ok=True)
    pkg_dir = nm / name
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "package.json").write_text(
        json.dumps({"name": name, "version": version}),
        encoding="utf-8",
    )
    return pkg_dir


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _hours_ago_iso(hours: float) -> str:
    t = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    return t.isoformat()


def _days_ago_iso(days: int) -> str:
    t = datetime.now(tz=timezone.utc) - timedelta(days=days)
    return t.isoformat()


# ---------------------------------------------------------------------------
# IntegrityResult property tests
# ---------------------------------------------------------------------------


class TestIntegrityResult:
    def test_empty_result(self) -> None:
        r = IntegrityResult()
        assert not r.has_critical
        assert not r.has_warning
        assert r.critical_count == 0
        assert r.warning_count == 0

    def test_has_critical(self) -> None:
        r = IntegrityResult(findings=[
            IntegrityFinding(
                severity="CRITICAL",
                check="lockfile_hash_mismatch",
                package_name="axios",
                description="hash mismatch",
                evidence="expected!=actual",
                recommendation="Run npm ci",
            )
        ])
        assert r.has_critical
        assert r.critical_count == 1

    def test_has_warning(self) -> None:
        r = IntegrityResult(findings=[
            IntegrityFinding(
                severity="WARNING",
                check="phantom_dependency",
                package_name="unused",
                description="never imported",
                evidence="",
                recommendation="Remove it",
            )
        ])
        assert r.has_warning
        assert r.warning_count == 1

    def test_mixed_severity(self) -> None:
        r = IntegrityResult(findings=[
            IntegrityFinding(severity="CRITICAL", check="x", package_name="a", description="d", evidence="e", recommendation="r"),
            IntegrityFinding(severity="WARNING", check="y", package_name="b", description="d", evidence="e", recommendation="r"),
        ])
        assert r.has_critical and r.has_warning


# ---------------------------------------------------------------------------
# Lockfile integrity tests
# ---------------------------------------------------------------------------


class TestLockfileIntegrity:
    def test_no_lockfile_returns_empty(self, tmp_path: Path) -> None:
        findings = check_lockfile_integrity(tmp_path)
        assert findings == []

    def test_invalid_lockfile_returns_warning(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text("NOT JSON")
        findings = check_lockfile_integrity(tmp_path)
        assert findings
        assert findings[0].severity == "WARNING"

    def test_matching_versions_no_findings(self, tmp_path: Path) -> None:
        _write_lockfile(tmp_path, {
            "lockfileVersion": 2,
            "packages": {
                "node_modules/axios": {
                    "version": "1.0.0",
                    "integrity": "sha512-abc",
                    "resolved": "https://registry.npmjs.org/axios/-/axios-1.0.0.tgz",
                }
            }
        })
        _make_node_modules_pkg(tmp_path, "axios", version="1.0.0")
        findings = check_lockfile_integrity(tmp_path)
        assert not any(f.check == "lockfile_hash_mismatch" for f in findings)

    def test_version_mismatch_is_critical(self, tmp_path: Path) -> None:
        _write_lockfile(tmp_path, {
            "lockfileVersion": 2,
            "packages": {
                "node_modules/axios": {
                    "version": "1.0.0",
                    "integrity": "sha512-abc",
                }
            }
        })
        # Disk has version 1.0.1
        _make_node_modules_pkg(tmp_path, "axios", version="1.0.1")
        findings = check_lockfile_integrity(tmp_path)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert any(f.check == "lockfile_hash_mismatch" for f in critical)

    def test_missing_package_in_node_modules_is_critical(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        nm.mkdir()
        _write_lockfile(tmp_path, {
            "lockfileVersion": 2,
            "packages": {
                "node_modules/missing-pkg": {
                    "version": "1.0.0",
                    "integrity": "sha512-abc",
                }
            }
        })
        findings = check_lockfile_integrity(tmp_path)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert any(f.check == "missing_package" for f in critical)

    def test_missing_package_json_in_dir_is_critical(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        nm.mkdir()
        pkg_dir = nm / "ghost-pkg"
        pkg_dir.mkdir()
        # No package.json in the dir
        _write_lockfile(tmp_path, {
            "lockfileVersion": 2,
            "packages": {
                "node_modules/ghost-pkg": {
                    "version": "1.0.0",
                    "integrity": "sha512-abc",
                }
            }
        })
        findings = check_lockfile_integrity(tmp_path)
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert any(f.check == "missing_package_json" for f in critical)

    def test_root_package_entry_skipped(self, tmp_path: Path) -> None:
        """Lockfile root entry (empty string key) should be skipped."""
        _write_lockfile(tmp_path, {
            "lockfileVersion": 2,
            "packages": {
                "": {
                    "version": "0.0.1",
                    "name": "my-app",
                }
            }
        })
        nm = tmp_path / "node_modules"
        nm.mkdir()
        findings = check_lockfile_integrity(tmp_path)
        assert not findings

    def test_v1_lockfile_format_parsed(self, tmp_path: Path) -> None:
        """v1 lockfile (dependencies key) should be handled."""
        _write_lockfile(tmp_path, {
            "lockfileVersion": 1,
            "dependencies": {
                "axios": {
                    "version": "1.0.0",
                    "integrity": "sha512-abc",
                    "resolved": "https://registry.npmjs.org/axios/-/axios-1.0.0.tgz",
                }
            }
        })
        nm = tmp_path / "node_modules"
        nm.mkdir()
        _make_node_modules_pkg(tmp_path, "axios", version="1.0.0")
        # Should not raise, even if package paths differ between v1 and v2
        findings = check_lockfile_integrity(tmp_path)
        assert isinstance(findings, list)

    def test_no_node_modules_returns_empty(self, tmp_path: Path) -> None:
        _write_lockfile(tmp_path, {
            "lockfileVersion": 2,
            "packages": {"node_modules/x": {"version": "1.0", "integrity": "sha512-x"}}
        })
        # No node_modules dir
        findings = check_lockfile_integrity(tmp_path)
        assert findings == []


# ---------------------------------------------------------------------------
# Phantom dependency tests
# ---------------------------------------------------------------------------


class TestPhantomDependencies:
    def test_no_package_json_returns_empty(self, tmp_path: Path) -> None:
        assert check_phantom_dependencies(tmp_path) == []

    def test_no_deps_returns_empty(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"name": "test", "version": "1.0.0"})
        assert check_phantom_dependencies(tmp_path) == []

    def test_imported_package_not_flagged(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {
            "name": "test",
            "dependencies": {"lodash": "^4.0.0"},
        })
        src = tmp_path / "src"
        src.mkdir()
        (src / "index.js").write_text("const _ = require('lodash');")
        findings = check_phantom_dependencies(tmp_path)
        assert not any(f.package_name == "lodash" for f in findings)

    def test_phantom_dependency_flagged_as_warning(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {
            "name": "test",
            "dependencies": {
                "lodash": "^4.0.0",
                "plain-crypto-js": "^4.2.1",  # never imported
            },
        })
        src = tmp_path / "src"
        src.mkdir()
        (src / "index.js").write_text("const _ = require('lodash');")
        findings = check_phantom_dependencies(tmp_path)
        phantom = [f for f in findings if f.package_name == "plain-crypto-js"]
        assert phantom
        assert phantom[0].severity == "WARNING"
        assert phantom[0].check == "phantom_dependency"

    def test_scoped_package_import_recognized(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {
            "name": "test",
            "dependencies": {"@babel/core": "^7.0.0"},
        })
        src = tmp_path / "src"
        src.mkdir()
        (src / "index.ts").write_text("import { transform } from '@babel/core';")
        findings = check_phantom_dependencies(tmp_path)
        assert not any(f.package_name == "@babel/core" for f in findings)

    def test_dynamic_import_recognized(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {
            "name": "test",
            "dependencies": {"axios": "^1.0.0"},
        })
        src = tmp_path / "src"
        src.mkdir()
        (src / "index.js").write_text("const mod = await import('axios');")
        findings = check_phantom_dependencies(tmp_path)
        assert not any(f.package_name == "axios" for f in findings)

    def test_empty_source_dir_no_phantom_flagging(self, tmp_path: Path) -> None:
        """If no source files found, phantom detection is skipped."""
        _write_pkg_json(tmp_path, {
            "name": "test",
            "dependencies": {"axios": "^1.0.0"},
        })
        # No source files → imported set is empty → phantoms not flagged
        findings = check_phantom_dependencies(tmp_path)
        assert not findings


# ---------------------------------------------------------------------------
# Import extraction tests
# ---------------------------------------------------------------------------


class TestImportExtraction:
    def test_require_simple(self, tmp_path: Path) -> None:
        f = tmp_path / "index.js"
        f.write_text("const a = require('lodash');")
        imports = _extract_imports_from_file(f)
        assert "lodash" in imports

    def test_import_from(self, tmp_path: Path) -> None:
        f = tmp_path / "index.ts"
        f.write_text("import { foo } from 'axios';")
        imports = _extract_imports_from_file(f)
        assert "axios" in imports

    def test_dynamic_import(self, tmp_path: Path) -> None:
        f = tmp_path / "index.js"
        f.write_text("const m = import('fs-extra');")
        imports = _extract_imports_from_file(f)
        assert "fs-extra" in imports

    def test_scoped_import(self, tmp_path: Path) -> None:
        f = tmp_path / "index.ts"
        f.write_text("import core from '@babel/core';")
        imports = _extract_imports_from_file(f)
        assert "@babel/core" in imports

    def test_relative_import_ignored(self, tmp_path: Path) -> None:
        f = tmp_path / "index.js"
        f.write_text("const x = require('./local');")
        imports = _extract_imports_from_file(f)
        assert "./local" not in imports
        assert "local" not in imports

    def test_subpath_normalized_to_package(self, tmp_path: Path) -> None:
        f = tmp_path / "index.js"
        f.write_text("const fp = require('lodash/fp');")
        imports = _extract_imports_from_file(f)
        assert "lodash" in imports

    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        imports = _extract_imports_from_file(tmp_path / "nonexistent.js")
        assert imports == set()

    def test_collect_source_imports_skips_node_modules(self, tmp_path: Path) -> None:
        src = tmp_path / "src"
        src.mkdir()
        (src / "index.js").write_text("const a = require('axios');")
        nm_src = tmp_path / "node_modules" / "some-pkg" / "index.js"
        nm_src.parent.mkdir(parents=True)
        nm_src.write_text("const b = require('evil-lib');")
        imports = _collect_source_imports(tmp_path)
        assert "axios" in imports
        assert "evil-lib" not in imports


# ---------------------------------------------------------------------------
# New package detection (mocked)
# ---------------------------------------------------------------------------


class TestNewPackageDetection:
    def test_offline_mode_returns_empty(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        findings = check_new_packages(tmp_path, offline=True)
        assert findings == []

    def test_no_package_json_returns_empty(self, tmp_path: Path) -> None:
        findings = check_new_packages(tmp_path, offline=True)
        assert findings == []

    def test_new_package_flagged_as_warning(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"new-evil-pkg": "^1.0.0"}})
        published_time = _hours_ago_iso(12)  # 12 hours ago → < 48h threshold
        mock_meta = {
            "time": {
                "created": _hours_ago_iso(13),
                "modified": published_time,
                "1.0.0": published_time,
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_new_packages(tmp_path, offline=False)
        assert any(f.check == "new_package" for f in findings)
        assert all(f.severity == "WARNING" for f in findings)

    def test_old_package_not_flagged(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"stable-pkg": "^1.0.0"}})
        published_time = _days_ago_iso(90)
        mock_meta = {
            "time": {
                "created": _days_ago_iso(180),
                "modified": published_time,
                "1.0.0": published_time,
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_new_packages(tmp_path, offline=False)
        assert not any(f.check == "new_package" for f in findings)

    def test_registry_failure_no_crash(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"some-pkg": "^1.0.0"}})
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=None,
        ):
            findings = check_new_packages(tmp_path, offline=False)
        assert findings == []

    def test_dev_dependencies_also_checked(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {
            "dependencies": {},
            "devDependencies": {"new-dev-pkg": "^1.0.0"},
        })
        published_time = _hours_ago_iso(6)
        mock_meta = {
            "time": {
                "created": _hours_ago_iso(7),
                "modified": published_time,
                "1.0.0": published_time,
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_new_packages(tmp_path, offline=False)
        assert any(f.check == "new_package" for f in findings)


# ---------------------------------------------------------------------------
# Maintainer change detection (mocked)
# ---------------------------------------------------------------------------


class TestMaintainerChangeDetection:
    def test_offline_mode_returns_empty(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        findings = check_maintainer_changes(tmp_path, offline=True)
        assert findings == []

    def test_no_package_json_returns_empty(self, tmp_path: Path) -> None:
        findings = check_maintainer_changes(tmp_path, offline=True)
        assert findings == []

    def test_maintainer_change_flagged(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        # 3 versions by "alice", then 1 recent version by "bob"
        mock_meta = {
            "time": {
                "modified": _days_ago_iso(2),
            },
            "versions": {
                "0.1.0": {"_npmUser": {"name": "alice"}},
                "0.2.0": {"_npmUser": {"name": "alice"}},
                "1.0.0": {"_npmUser": {"name": "alice"}},
                "1.14.1": {"_npmUser": {"name": "bob"}},  # Different maintainer
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_maintainer_changes(tmp_path, offline=False)
        assert any(f.check == "maintainer_change" for f in findings)

    def test_same_maintainer_not_flagged(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        mock_meta = {
            "time": {"modified": _days_ago_iso(2)},
            "versions": {
                "1.0.0": {"_npmUser": {"name": "alice"}},
                "1.1.0": {"_npmUser": {"name": "alice"}},
                "1.2.0": {"_npmUser": {"name": "alice"}},
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_maintainer_changes(tmp_path, offline=False)
        assert not any(f.check == "maintainer_change" for f in findings)

    def test_old_change_not_flagged(self, tmp_path: Path) -> None:
        """Changes older than 30 days should not be flagged."""
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        mock_meta = {
            "time": {"modified": _days_ago_iso(60)},  # 60 days old
            "versions": {
                "1.0.0": {"_npmUser": {"name": "alice"}},
                "1.1.0": {"_npmUser": {"name": "alice"}},
                "1.2.0": {"_npmUser": {"name": "alice"}},
                "1.3.0": {"_npmUser": {"name": "bob"}},
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_maintainer_changes(tmp_path, offline=False)
        assert not any(f.check == "maintainer_change" for f in findings)


# ---------------------------------------------------------------------------
# Version anomaly detection (mocked)
# ---------------------------------------------------------------------------


class TestVersionAnomalyDetection:
    def test_offline_mode_returns_empty(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        findings = check_version_anomalies(tmp_path, offline=True)
        assert findings == []

    def test_rapid_publication_flagged(self, tmp_path: Path) -> None:
        """Two versions published 39 minutes apart → should be flagged."""
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        t1 = datetime.now(tz=timezone.utc) - timedelta(hours=48)
        t2 = t1 + timedelta(minutes=39)  # 39 min later
        mock_meta = {
            "time": {
                "created": (t1 - timedelta(days=100)).isoformat(),
                "modified": t2.isoformat(),
                "1.14.0": t1.isoformat(),
                "1.14.1": t2.isoformat(),  # Rapid follow-up (axios attack pattern)
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_version_anomalies(tmp_path, offline=False)
        rapid = [f for f in findings if f.check == "rapid_version_publication"]
        assert rapid

    def test_normal_publication_cadence_not_flagged(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"lodash": "^4.0.0"}})
        t1 = datetime.now(tz=timezone.utc) - timedelta(days=180)
        t2 = t1 + timedelta(days=30)
        t3 = t2 + timedelta(days=30)
        mock_meta = {
            "time": {
                "created": t1.isoformat(),
                "modified": t3.isoformat(),
                "4.0.0": t1.isoformat(),
                "4.1.0": t2.isoformat(),
                "4.2.0": t3.isoformat(),
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_version_anomalies(tmp_path, offline=False)
        rapid = [f for f in findings if f.check == "rapid_version_publication"]
        assert not rapid

    def test_unpublished_version_flagged(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        mock_meta = {
            "time": {
                "created": _days_ago_iso(365),
                "modified": _days_ago_iso(5),
                "unpublished": _days_ago_iso(3),
                "1.0.0": _days_ago_iso(365),
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_version_anomalies(tmp_path, offline=False)
        assert any(f.check == "unpublished_version" for f in findings)

    def test_single_version_no_rapid_pub(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"single-version": "^1.0.0"}})
        mock_meta = {
            "time": {
                "created": _days_ago_iso(100),
                "1.0.0": _days_ago_iso(100),
            }
        }
        with patch(
            "agentward.scan.dep_integrity._fetch_npm_package_metadata",
            return_value=mock_meta,
        ):
            findings = check_version_anomalies(tmp_path, offline=False)
        assert not any(f.check == "rapid_version_publication" for f in findings)


# ---------------------------------------------------------------------------
# verify_dependencies entrypoint
# ---------------------------------------------------------------------------


class TestVerifyDependencies:
    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        result = verify_dependencies(tmp_path / "nonexistent")
        assert result.errors

    def test_empty_project_no_crash(self, tmp_path: Path) -> None:
        result = verify_dependencies(tmp_path, IntegrityCheckOptions(offline=True))
        assert isinstance(result, IntegrityResult)

    def test_offline_mode_skips_network_checks(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {"dependencies": {"axios": "^1.0.0"}})
        opts = IntegrityCheckOptions(
            lockfile=False,
            phantoms=False,
            new_packages=True,
            maintainer_changes=True,
            version_anomalies=True,
            offline=True,
        )
        result = verify_dependencies(tmp_path, opts)
        # With offline=True, no network checks should run
        assert "new_packages" not in result.checks_run
        assert "maintainer_changes" not in result.checks_run
        assert "version_anomalies" not in result.checks_run

    def test_lockfile_check_in_checks_run(self, tmp_path: Path) -> None:
        opts = IntegrityCheckOptions(
            lockfile=True,
            phantoms=False,
            new_packages=False,
            maintainer_changes=False,
            version_anomalies=False,
        )
        result = verify_dependencies(tmp_path, opts)
        assert "lockfile_integrity" in result.checks_run

    def test_phantom_check_in_checks_run(self, tmp_path: Path) -> None:
        opts = IntegrityCheckOptions(
            lockfile=False,
            phantoms=True,
            new_packages=False,
            maintainer_changes=False,
            version_anomalies=False,
        )
        result = verify_dependencies(tmp_path, opts)
        assert "phantom_dependencies" in result.checks_run

    def test_packages_counted_from_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        nm.mkdir()
        for name in ["a", "b", "c"]:
            (nm / name).mkdir()
        opts = IntegrityCheckOptions(offline=True, lockfile=False, phantoms=False)
        result = verify_dependencies(tmp_path, opts)
        assert result.packages_checked >= 3

    def test_full_offline_run_no_crash(self, tmp_path: Path) -> None:
        _write_pkg_json(tmp_path, {
            "name": "test",
            "dependencies": {"lodash": "^4.0.0"},
        })
        _make_node_modules_pkg(tmp_path, "lodash")
        src = tmp_path / "src"
        src.mkdir()
        (src / "index.js").write_text("const _ = require('lodash');")
        opts = IntegrityCheckOptions(offline=True)
        result = verify_dependencies(tmp_path, opts)
        assert isinstance(result, IntegrityResult)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestVerifyDepsCLI:
    def test_verify_deps_command_runs(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        _write_pkg_json(tmp_path, {"name": "test", "dependencies": {}})
        runner = CliRunner()
        result = runner.invoke(app, ["verify-deps", str(tmp_path)])
        assert result.exit_code in (0, 1, 2)

    def test_verify_deps_json_output(self, tmp_path: Path) -> None:
        import json as _json
        from typer.testing import CliRunner
        from agentward.cli import app

        _write_pkg_json(tmp_path, {"name": "test", "dependencies": {}})
        runner = CliRunner()
        result = runner.invoke(app, ["verify-deps", "--json", str(tmp_path)])
        assert result.exit_code in (0, 1, 2)
        data = _json.loads(result.output)
        assert "findings" in data
        assert "packages_checked" in data

    def test_verify_deps_lockfile_only_flag(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["verify-deps", "--lockfile-only", str(tmp_path)])
        assert result.exit_code in (0, 1, 2)

    def test_verify_deps_phantoms_only_flag(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        _write_pkg_json(tmp_path, {"name": "test", "dependencies": {}})
        runner = CliRunner()
        result = runner.invoke(app, ["verify-deps", "--phantoms-only", str(tmp_path)])
        assert result.exit_code in (0, 1, 2)
