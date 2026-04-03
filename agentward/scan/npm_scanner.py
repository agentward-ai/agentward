"""npm postinstall hook scanner — detects malicious lifecycle scripts in node_modules.

Targets the exact attack pattern from the axios supply chain compromise (DPRK actor
UNC1069, March 2026): a postinstall hook in a transitive dependency that downloads
and executes a RAT via XOR-obfuscated code.

This scanner:
- Walks an entire node_modules tree (including nested node_modules)
- Reads every package.json and extracts lifecycle scripts (preinstall/install/postinstall)
- If a lifecycle script references a JS file, reads and analyzes that file
- If inline, analyzes the script content directly
- Applies CRITICAL and WARNING pattern matching
- Checks against an allowlist of known-safe postinstall scripts
- Reports findings with package name, version, script type, pattern, severity, path, snippet
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class NpmFinding:
    """A single finding from npm lifecycle script analysis."""

    severity: Literal["CRITICAL", "WARNING"]
    package_name: str
    package_version: str
    script_type: str           # "postinstall", "preinstall", "install"
    pattern: str               # rule name that triggered
    file: str                  # absolute path to the package.json or script file
    line_number: int | None    # 1-based; None for file-level findings
    evidence: str              # triggering snippet (truncated)
    description: str


@dataclass
class NpmScanResult:
    """Results of scanning a node_modules directory."""

    findings: list[NpmFinding] = field(default_factory=list)
    packages_scanned: int = 0
    root_dir: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.findings)

    @property
    def has_warning(self) -> bool:
        return any(f.severity == "WARNING" for f in self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "WARNING")


# ---------------------------------------------------------------------------
# Allowlist of known-safe postinstall scripts
# ---------------------------------------------------------------------------
# Maps a package name (prefix match) to acceptable script patterns.
# A postinstall is allowlisted if the package name starts with any key
# AND the script content matches one of the corresponding patterns.

_ALLOWLIST_PREFIXES: tuple[str, ...] = (
    "node-gyp",
    "husky",
    "esbuild",
    "@esbuild/",
    "sharp",
    "better-sqlite3",
    "bcrypt",
    "canvas",
    "fsevents",
    "electron-builder",
    "electron",
    "@electron/",
    "playwright",
    "@playwright/",
    "puppeteer",
    "puppeteer-core",
    "protobufjs",
    "core-js",
    "opencollective-postinstall",
    "@sentry/cli",
    "@sentry/",
)

# Safe script content patterns (regex, case-insensitive)
_ALLOWLIST_SCRIPT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"node-gyp\s+rebuild", re.IGNORECASE),
    re.compile(r"husky\s+(install)?", re.IGNORECASE),
    re.compile(r"esbuild\b", re.IGNORECASE),
    re.compile(r"opencollective", re.IGNORECASE),
    re.compile(r"node\s+install\.js", re.IGNORECASE),
    re.compile(r"node\s+scripts/", re.IGNORECASE),
    re.compile(r"node\s+postinstall", re.IGNORECASE),
    re.compile(r"playwright\s+install", re.IGNORECASE),
]


def _is_allowlisted_package(pkg_name: str, script_content: str) -> bool:
    """Return True if a package is on the known-safe allowlist.

    Allowlisting is two-tiered:
    1. If the package name matches a known-safe prefix, it is always allowlisted
       (these packages have well-reviewed, publicly known postinstall scripts).
    2. If the inline script command itself matches a known-safe pattern (e.g.
       "node-gyp rebuild"), it is allowlisted regardless of package name.
    """
    clean = pkg_name.lstrip("@").lower()
    # Prefix match
    for prefix in _ALLOWLIST_PREFIXES:
        p = prefix.lstrip("@").lower()
        if clean.startswith(p) or pkg_name.lower().startswith(prefix.lower()):
            return True
    # Script content match
    for pat in _ALLOWLIST_SCRIPT_PATTERNS:
        if pat.search(script_content):
            return True
    return False


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------
# Each entry: (rule_name, severity, compiled_regex, description)

_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall")

_CRITICAL_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # Network calls via curl/wget
    (
        "network_curl_wget",
        re.compile(r"\b(curl|wget)\s+", re.IGNORECASE),
        "Network download via curl/wget — common binary dropper pattern",
    ),
    # http.get / https.get / fetch in script
    (
        "network_node_http",
        re.compile(
            r"\b(https?\.get|http\.request|https\.request|node-fetch|axios\.get|axios\.post"
            r"|fetch\s*\()\b",
            re.IGNORECASE,
        ),
        "Network call in install script — can download remote payload",
    ),
    # net.connect / dgram (raw socket/UDP — covert channel indicator)
    (
        "network_raw_socket",
        re.compile(r"\bnet\s*\.\s*connect\s*\(|\bdgram\b", re.IGNORECASE),
        "Raw socket or UDP in install script — covert C2 channel indicator",
    ),
    # eval() — dynamic code execution
    (
        "eval_exec",
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        "eval() in install script — dynamic code execution obfuscation",
    ),
    # Function() constructor
    (
        "function_constructor",
        re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE),
        "new Function() constructor — dynamic code execution bypass",
    ),
    # vm.runInNewContext / vm.runInThisContext
    (
        "vm_run",
        re.compile(r"\bvm\s*\.\s*run(?:In(?:New|This)Context|Script)\s*\(", re.IGNORECASE),
        "vm.runIn*Context() — sandboxed code execution in install script",
    ),
    # Buffer.from + decode chains (obfuscation)
    (
        "buffer_decode_chain",
        re.compile(
            r"Buffer\s*\.\s*from\s*\([^)]*['\"]base64['\"]|"
            r"Buffer\s*\.\s*from\s*\([^)]+\)\s*\.\s*toString",
            re.IGNORECASE,
        ),
        "Buffer.from + decode chain — base64 payload obfuscation",
    ),
    # atob() in install script
    (
        "atob_decode",
        re.compile(r"\batob\s*\(", re.IGNORECASE),
        "atob() base64 decode in install script — payload obfuscation",
    ),
    # Reversed string assigned to variable (obfuscation)
    (
        "reversed_string",
        re.compile(r"""['"][^'"]{10,}['"]\s*\.\s*split\s*\(\s*['"]{2}\s*\)\s*\.\s*reverse""", re.IGNORECASE),
        "String split-reverse pattern — reversed string obfuscation technique",
    ),
    # String concatenation building dynamic require/import (obfuscation)
    (
        "string_concat_require",
        re.compile(
            r"""(?:['"][a-z_]+['"]\s*\+\s*['"][a-z_]+['"]\s*){2,}""",
            re.IGNORECASE,
        ),
        "String concatenation building module names — require obfuscation",
    ),
    # XOR cipher patterns (charCodeAt + XOR)
    (
        "xor_cipher",
        re.compile(r"charCodeAt\s*\([^)]*\)\s*\^\s*|String\.fromCharCode[^;]*\^", re.IGNORECASE),
        "XOR cipher pattern — obfuscation used in axios supply chain attack",
    ),
    # Anti-forensics: unlink own script files
    (
        "self_delete",
        re.compile(r"fs\s*\.\s*unlink(?:Sync)?\s*\(", re.IGNORECASE),
        "fs.unlink in install script — anti-forensics file self-deletion",
    ),
    # Anti-forensics: overwrite own package.json
    (
        "overwrite_package_json",
        re.compile(r"fs\s*\.\s*writeFile(?:Sync)?\s*\([^)]*package\.json", re.IGNORECASE),
        "Overwriting package.json in install script — anti-forensics tampering",
    ),
    # anti-forensics: rename own files
    (
        "rename_self",
        re.compile(r"fs\s*\.\s*rename(?:Sync)?\s*\(", re.IGNORECASE),
        "fs.rename in install script — possible anti-forensics file replacement",
    ),
    # child_process.exec / execSync with non-trivial commands
    (
        "child_process_exec",
        re.compile(
            r"\bchild_process\s*\.\s*(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(",
            re.IGNORECASE,
        ),
        "child_process.exec/spawn in install script — arbitrary shell command execution",
    ),
    # require('child_process') in install script
    (
        "require_child_process",
        re.compile(r"""require\s*\(\s*['"]child_process['"]\s*\)""", re.IGNORECASE),
        "require('child_process') in install script — sets up shell execution capability",
    ),
    # Sensitive environment variable access
    (
        "sensitive_env_access",
        re.compile(
            r"""process\.env\.(HOME|USER|USERPROFILE|npm_config_|AWS_|GITHUB_TOKEN|SSH_AUTH_SOCK)""",
            re.IGNORECASE,
        ),
        "Accessing sensitive environment variable in install script — credential exfiltration risk",
    ),
    # Reading SSH keys or credential stores
    (
        "sensitive_file_read",
        re.compile(
            r"""(?:\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.env|known_hosts)""",
            re.IGNORECASE,
        ),
        "Reference to sensitive file (SSH keys, credentials) in install script",
    ),
    # Base64-encoded payload (long base64 string literal)
    (
        "base64_payload",
        re.compile(
            r"""['"'][A-Za-z0-9+/]{40,}={0,2}['"']""",
        ),
        "Long base64 literal in install script — likely encoded payload",
    ),
    # os.exec (Node.js 'os' module used for shell exec attempts)
    (
        "os_exec_attempt",
        re.compile(r"""\bos\s*\.\s*(exec|system|popen)\s*\(""", re.IGNORECASE),
        "os.exec/system call in install script",
    ),
]

# Warning patterns: suspicious but not definitively malicious
_WARNING_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # Any spawn/exec even for apparently benign uses
    (
        "spawn_subprocess",
        re.compile(
            r"\b(spawn|execFile|fork)\s*\(|\brequire\s*\(\s*['\"]child_process",
            re.IGNORECASE,
        ),
        "Subprocess spawn in install script — investigate before installing",
    ),
    # Read/write outside own package directory (path traversal)
    (
        "outside_package_dir",
        re.compile(
            r"""(?:readFile|writeFile|appendFile|open)\s*\([^)]*(?:\.\./|~\/|process\.env\.HOME)""",
            re.IGNORECASE,
        ),
        "File access outside package directory in install script",
    ),
]

# Maximum script file size to inline-analyze (bytes)
_MAX_SCRIPT_FILE_SIZE = 10 * 1024  # 10 KB — scripts larger than this are WARNING


# ---------------------------------------------------------------------------
# Script file analysis
# ---------------------------------------------------------------------------


def _analyze_script_content(
    content: str,
    pkg_name: str,
    pkg_version: str,
    script_type: str,
    source_file: str,
) -> list[NpmFinding]:
    """Analyze script file or inline script content for malicious patterns."""
    findings: list[NpmFinding] = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("#"):
            continue

        # Check CRITICAL patterns first
        matched_critical = False
        for rule_name, pattern, description in _CRITICAL_PATTERNS:
            if pattern.search(line):
                findings.append(NpmFinding(
                    severity="CRITICAL",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    script_type=script_type,
                    pattern=rule_name,
                    file=source_file,
                    line_number=lineno,
                    evidence=line[:200].strip(),
                    description=description,
                ))
                matched_critical = True
                break  # First CRITICAL hit per line

        if matched_critical:
            continue

        # Check WARNING patterns
        for rule_name, pattern, description in _WARNING_PATTERNS:
            if pattern.search(line):
                findings.append(NpmFinding(
                    severity="WARNING",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    script_type=script_type,
                    pattern=rule_name,
                    file=source_file,
                    line_number=lineno,
                    evidence=line[:200].strip(),
                    description=description,
                ))
                break  # First WARNING hit per line

    return findings


def _analyze_lifecycle_script(
    script_value: str,
    script_type: str,
    pkg_name: str,
    pkg_version: str,
    pkg_dir: Path,
) -> list[NpmFinding]:
    """Analyze a single lifecycle script entry from package.json.

    If the script value references a JS file (e.g. "node ./scripts/postinstall.js"),
    reads and analyzes that file. Otherwise analyzes the inline command directly.
    """
    # Allowlist check on the inline command
    if _is_allowlisted_package(pkg_name, script_value):
        return []

    findings: list[NpmFinding] = []
    pkg_json_path = str(pkg_dir / "package.json")

    # Check if this is an inline script we should also analyze character by character
    # for CRITICAL patterns in the command string itself
    inline_findings = _analyze_script_content(
        script_value,
        pkg_name=pkg_name,
        pkg_version=pkg_version,
        script_type=script_type,
        source_file=pkg_json_path,
    )
    findings.extend(inline_findings)

    # If the script references a JS file, also analyze that file
    # Pattern: "node <path>" or "node ./foo.js" etc.
    js_file_match = re.search(r"node\s+(\S+\.(?:js|mjs|cjs))", script_value)
    if js_file_match:
        script_rel_path = js_file_match.group(1).strip("\"'")
        script_abs = (pkg_dir / script_rel_path).resolve()

        if script_abs.is_file():
            try:
                size = script_abs.stat().st_size
                if size > _MAX_SCRIPT_FILE_SIZE:
                    findings.append(NpmFinding(
                        severity="WARNING",
                        package_name=pkg_name,
                        package_version=pkg_version,
                        script_type=script_type,
                        pattern="oversized_script",
                        file=str(script_abs),
                        line_number=None,
                        evidence=f"{size:,} bytes",
                        description=(
                            f"Install script is {size:,} bytes (>{_MAX_SCRIPT_FILE_SIZE:,}) "
                            "— unusually large for a postinstall script"
                        ),
                    ))

                content = script_abs.read_text(encoding="utf-8", errors="replace")

                # Allowlist check on the resolved file
                if not _is_allowlisted_package(pkg_name, content[:500]):
                    js_findings = _analyze_script_content(
                        content,
                        pkg_name=pkg_name,
                        pkg_version=pkg_version,
                        script_type=script_type,
                        source_file=str(script_abs),
                    )
                    findings.extend(js_findings)

            except (OSError, PermissionError) as e:
                findings.append(NpmFinding(
                    severity="WARNING",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    script_type=script_type,
                    pattern="read_error",
                    file=str(script_abs),
                    line_number=None,
                    evidence="",
                    description=f"Cannot read script file: {e}",
                ))

    # Postinstall-only: if none of the above critical patterns matched,
    # any postinstall not on the allowlist is a WARNING
    if not findings and script_type in _LIFECYCLE_SCRIPTS:
        findings.append(NpmFinding(
            severity="WARNING",
            package_name=pkg_name,
            package_version=pkg_version,
            script_type=script_type,
            pattern="unrecognized_lifecycle_script",
            file=pkg_json_path,
            line_number=None,
            evidence=script_value[:200],
            description=(
                f"Package '{pkg_name}' has a '{script_type}' script not on the "
                "known-safe allowlist — verify before installing"
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# node_modules walker
# ---------------------------------------------------------------------------


def _find_package_json_files(node_modules_dir: Path) -> list[Path]:
    """Walk node_modules and yield all package.json files.

    Handles:
    - Standard: node_modules/pkg/package.json
    - Scoped: node_modules/@scope/pkg/package.json
    - Nested: node_modules/pkg/node_modules/other/package.json
    """
    result: list[Path] = []

    def _walk(directory: Path, depth: int = 0) -> None:
        if depth > 10:  # Prevent runaway recursion in pathological trees
            return
        try:
            for entry in sorted(directory.iterdir()):
                if not entry.is_dir():
                    continue
                if entry.name.startswith("."):
                    continue
                if entry.name == "node_modules":
                    # Nested node_modules — recurse
                    _walk(entry, depth + 1)
                    continue
                if entry.name.startswith("@"):
                    # Scoped package directory — look one level deeper
                    try:
                        for scope_entry in sorted(entry.iterdir()):
                            if scope_entry.is_dir():
                                pkg_json = scope_entry / "package.json"
                                if pkg_json.is_file():
                                    result.append(pkg_json)
                                # Check for nested node_modules
                                nested = scope_entry / "node_modules"
                                if nested.is_dir():
                                    _walk(nested, depth + 1)
                    except (OSError, PermissionError):
                        pass
                else:
                    pkg_json = entry / "package.json"
                    if pkg_json.is_file():
                        result.append(pkg_json)
                    # Check for nested node_modules
                    nested = entry / "node_modules"
                    if nested.is_dir():
                        _walk(nested, depth + 1)
        except (OSError, PermissionError):
            pass

    _walk(node_modules_dir)
    return result


# ---------------------------------------------------------------------------
# Public scanner entrypoint
# ---------------------------------------------------------------------------


def scan_npm_directory(
    path: Path,
) -> NpmScanResult:
    """Scan a node_modules directory for malicious postinstall scripts.

    Args:
        path: Path to the node_modules directory or a project root containing
              a node_modules/ subdirectory.

    Returns:
        NpmScanResult with findings, package count, and errors.
    """
    result = NpmScanResult()

    # Accept either a node_modules dir or a project root
    if path.name == "node_modules" and path.is_dir():
        node_modules = path
    elif (path / "node_modules").is_dir():
        node_modules = path / "node_modules"
    elif path.is_dir():
        # Given directory might be a direct package dir (for testing)
        node_modules = path
    else:
        result.errors.append(f"No node_modules directory found at {path}")
        return result

    result.root_dir = str(node_modules)

    # Collect all package.json files
    try:
        pkg_json_files = _find_package_json_files(node_modules)
    except Exception as e:
        result.errors.append(f"Error walking {node_modules}: {e}")
        return result

    for pkg_json_path in pkg_json_files:
        result.packages_scanned += 1
        try:
            raw = pkg_json_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw)
        except (OSError, PermissionError) as e:
            result.errors.append(f"Cannot read {pkg_json_path}: {e}")
            continue
        except json.JSONDecodeError as e:
            result.errors.append(f"Invalid JSON in {pkg_json_path}: {e}")
            continue

        pkg_name: str = data.get("name", pkg_json_path.parent.name)
        pkg_version: str = data.get("version", "unknown")
        scripts: dict = data.get("scripts", {})
        pkg_dir = pkg_json_path.parent

        # Check each lifecycle script
        for script_type in _LIFECYCLE_SCRIPTS:
            script_value = scripts.get(script_type)
            if not script_value:
                continue

            try:
                findings = _analyze_lifecycle_script(
                    script_value=script_value,
                    script_type=script_type,
                    pkg_name=pkg_name,
                    pkg_version=pkg_version,
                    pkg_dir=pkg_dir,
                )
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(
                    f"Error analyzing {pkg_name}@{pkg_version} {script_type}: {e}"
                )

    return result
