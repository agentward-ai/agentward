"""Python supply chain scanner — extends .pth scanning to cover setup.py,
pyproject.toml, and __init__.py files.

Detects:
- setup.py: subprocess/os.system calls, eval/exec, network calls, base64 payloads,
  reads of sensitive files (SSH keys, ~/.aws, etc.)
- pyproject.toml: custom build backends with suspicious scripts, unusual build deps,
  inline build scripts with system commands
- __init__.py: import-time network calls, obfuscated code, sys.path manipulation,
  code injection patterns

Integrates with the existing PthScanResult structure for unified reporting.
"""

from __future__ import annotations

import re
import tomllib  # stdlib in Python 3.11+
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


# ---------------------------------------------------------------------------
# Data models (extend pth_scanner pattern)
# ---------------------------------------------------------------------------


@dataclass
class PythonFinding:
    """A single finding from Python supply chain analysis."""

    severity: Literal["CRITICAL", "WARNING", "INFO"]
    file: str               # Absolute path to the scanned file
    file_type: str          # "setup.py", "pyproject.toml", "__init__.py"
    line_number: int | None # 1-based; None for file-level findings
    pattern: str            # Rule name that triggered
    evidence: str           # The triggering snippet (truncated)
    description: str


@dataclass
class PythonScanResult:
    """Results of Python supply chain scanning."""

    findings: list[PythonFinding] = field(default_factory=list)
    files_scanned: int = 0
    scan_root: str = ""
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
# Pattern definitions
# ---------------------------------------------------------------------------
# Each entry: (rule_name, severity, compiled_regex, description)

_SETUP_PY_CRITICAL: list[tuple[str, re.Pattern[str], str]] = [
    (
        "subprocess_exec",
        re.compile(
            r"\bsubprocess\s*\.\s*(Popen|run|call|check_output|check_call|getoutput)\s*\(",
            re.IGNORECASE,
        ),
        "subprocess execution in setup.py — can run arbitrary commands during pip install",
    ),
    (
        "os_system",
        re.compile(r"\bos\s*\.\s*(system|popen|execv|execve|execvp|execvpe|spawn)\s*\(", re.IGNORECASE),
        "os.system/popen call in setup.py — arbitrary shell execution during install",
    ),
    (
        "eval_exec",
        re.compile(r"\b(eval|exec|compile)\s*\(", re.IGNORECASE),
        "eval/exec/compile in setup.py — dynamic code execution during install",
    ),
    (
        "network_urllib",
        re.compile(
            r"\b(urllib\s*\.\s*(request|urlopen)|requests\s*\.\s*(get|post|put|delete|head)\s*\(|"
            r"http\.client|HTTPSConnection|HTTPConnection|socket\s*\.\s*connect)",
            re.IGNORECASE,
        ),
        "Network call in setup.py — can exfiltrate data or download payload during install",
    ),
    (
        "base64_payload",
        re.compile(
            r"""(?:b64decode|base64\.b64decode|base64\.decodebytes)\s*\(|"""
            r"""['"'][A-Za-z0-9+/]{40,}={0,2}['"']""",
        ),
        "Base64 decode or long base64 literal in setup.py — likely obfuscated payload",
    ),
    (
        "sensitive_file_read",
        re.compile(
            r"""open\s*\([^)]*(?:\.ssh|id_rsa|id_ed25519|\.aws|\.env|\.kube|credentials|secrets)""",
            re.IGNORECASE,
        ),
        "Reading sensitive file in setup.py — credential/key exfiltration risk",
    ),
    (
        "dynamic_import",
        re.compile(r"\b__import__\s*\([^)]{5,}", re.IGNORECASE),
        "Dynamic __import__() in setup.py — obfuscated import technique",
    ),
    (
        "file_write_outside_package",
        re.compile(
            r"""(?:open|shutil\.copy|shutil\.move)\s*\([^)]*(?:/etc/|/usr/|/home/|~/)""",
            re.IGNORECASE,
        ),
        "Writing files outside package directory in setup.py — possible persistence",
    ),
]

_SETUP_PY_WARNING: list[tuple[str, re.Pattern[str], str]] = [
    (
        "unusual_import",
        re.compile(r"^(?:import|from)\s+(requests|httpx|aiohttp|paramiko|fabric)\b", re.MULTILINE),
        "Unusual import in setup.py — network library imported at install time",
    ),
]

# pyproject.toml suspicious build backends
_SUSPICIOUS_BUILD_BACKENDS: frozenset[str] = frozenset({
    "setuptools.build_meta",
    "flit_core.buildapi",
    "hatchling.build",
    "poetry.core.masonry.api",
    "meson.build",
})

_PYPROJECT_INLINE_SCRIPT_CRITICAL: list[tuple[str, re.Pattern[str], str]] = [
    (
        "build_script_subprocess",
        re.compile(r"\bsubprocess\s*\.\s*(run|Popen|call|check_output)\s*\(", re.IGNORECASE),
        "subprocess in pyproject.toml build script — arbitrary command execution",
    ),
    (
        "build_script_os_system",
        re.compile(r"\bos\s*\.\s*(system|popen)\s*\(", re.IGNORECASE),
        "os.system in pyproject.toml build script — shell execution during build",
    ),
    (
        "build_script_eval",
        re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
        "eval/exec in pyproject.toml build script — dynamic code execution",
    ),
    (
        "build_script_network",
        re.compile(r"\b(urllib|requests|http\.client|socket)\b", re.IGNORECASE),
        "Network library in pyproject.toml build script — download risk during build",
    ),
    (
        "build_script_base64",
        re.compile(r"\bb64decode\b|\bbase64\b", re.IGNORECASE),
        "Base64 decode in pyproject.toml build script — obfuscated payload",
    ),
]

# __init__.py critical patterns
_INIT_PY_CRITICAL: list[tuple[str, re.Pattern[str], str]] = [
    (
        "network_on_import",
        re.compile(
            r"\b(?:urllib\s*\.\s*(?:request|urlopen)|requests\s*\.\s*(?:get|post|put|delete)\s*\("
            r"|http\.client|HTTPSConnection|HTTPConnection"
            r"|(?:\w+\s*\.\s*)?connect\s*\(\s*\(|aiohttp\.ClientSession)",
            re.IGNORECASE,
        ),
        "Network call at module import time in __init__.py — can exfiltrate data on every import",
    ),
    (
        "eval_exec_on_import",
        re.compile(r"^(?!\s*#)\s*(eval|exec)\s*\(", re.MULTILINE),
        "eval/exec at module import time in __init__.py — dynamic code execution on every import",
    ),
    (
        "base64_on_import",
        re.compile(r"\bb64decode\s*\(|\bbase64\s*\.\s*b64decode\s*\(", re.IGNORECASE),
        "Base64 decode at import time in __init__.py — encoded payload executed on every import",
    ),
    (
        "subprocess_on_import",
        re.compile(
            r"\bsubprocess\s*\.\s*(Popen|run|call|check_output|getoutput)\s*\(",
            re.IGNORECASE,
        ),
        "subprocess call at module import time — arbitrary command execution on every import",
    ),
    (
        "os_system_on_import",
        re.compile(r"\bos\s*\.\s*(system|popen)\s*\(", re.IGNORECASE),
        "os.system at module import time — shell command execution on every import",
    ),
    (
        "sensitive_file_read_on_import",
        re.compile(
            r"""open\s*\([^)]*(?:\.ssh|id_rsa|\.aws|\.env|credentials)""",
            re.IGNORECASE,
        ),
        "Reading sensitive file at import time in __init__.py",
    ),
]

_INIT_PY_WARNING: list[tuple[str, re.Pattern[str], str]] = [
    (
        "sys_path_manipulation",
        re.compile(r"\bsys\s*\.\s*path\s*\.\s*(append|insert|extend)\s*\(", re.IGNORECASE),
        "sys.path manipulation in __init__.py — can redirect imports to malicious modules",
    ),
    (
        "code_injection_builtin",
        re.compile(r"\bbuiltins\s*\.\s*\w+\s*=", re.IGNORECASE),
        "Overriding builtins in __init__.py — monkey-patching built-in functions",
    ),
    (
        "dynamic_import_on_init",
        re.compile(r"\b__import__\s*\([^)]{5,}", re.IGNORECASE),
        "Dynamic __import__() in __init__.py — obfuscated import",
    ),
]

_MAX_FILE_SIZE = 512 * 1024  # 512 KB


# ---------------------------------------------------------------------------
# Individual file analyzers
# ---------------------------------------------------------------------------


def _analyze_lines(
    content: str,
    file_path: str,
    file_type: str,
    critical_patterns: list[tuple[str, re.Pattern[str], str]],
    warning_patterns: list[tuple[str, re.Pattern[str], str]] | None = None,
) -> list[PythonFinding]:
    """Apply pattern lists to source content, returning findings."""
    findings: list[PythonFinding] = []
    lines = content.splitlines()

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        matched_critical = False
        for rule_name, pattern, description in critical_patterns:
            if pattern.search(line):
                findings.append(PythonFinding(
                    severity="CRITICAL",
                    file=file_path,
                    file_type=file_type,
                    line_number=lineno,
                    pattern=rule_name,
                    evidence=line[:200].strip(),
                    description=description,
                ))
                matched_critical = True
                break  # First CRITICAL per line

        if not matched_critical and warning_patterns:
            for rule_name, pattern, description in warning_patterns:
                if pattern.search(line):
                    findings.append(PythonFinding(
                        severity="WARNING",
                        file=file_path,
                        file_type=file_type,
                        line_number=lineno,
                        pattern=rule_name,
                        evidence=line[:200].strip(),
                        description=description,
                    ))
                    break  # First WARNING per line

    return findings


def analyze_setup_py(path: Path) -> list[PythonFinding]:
    """Analyze a setup.py file for malicious patterns.

    Args:
        path: Path to setup.py file.

    Returns:
        List of findings.
    """
    findings: list[PythonFinding] = []
    abs_path = str(path)

    try:
        size = path.stat().st_size
    except OSError as e:
        return [PythonFinding(
            severity="WARNING",
            file=abs_path,
            file_type="setup.py",
            line_number=None,
            pattern="stat_error",
            evidence="",
            description=f"Cannot stat file: {e}",
        )]

    if size > _MAX_FILE_SIZE:
        findings.append(PythonFinding(
            severity="WARNING",
            file=abs_path,
            file_type="setup.py",
            line_number=None,
            pattern="oversized_file",
            evidence=f"{size:,} bytes",
            description=f"setup.py is {size:,} bytes — unusually large",
        ))

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as e:
        return [PythonFinding(
            severity="WARNING",
            file=abs_path,
            file_type="setup.py",
            line_number=None,
            pattern="read_error",
            evidence="",
            description=f"Cannot read file: {e}",
        )]

    findings.extend(_analyze_lines(content, abs_path, "setup.py", _SETUP_PY_CRITICAL, _SETUP_PY_WARNING))
    return findings


def analyze_pyproject_toml(path: Path) -> list[PythonFinding]:
    """Analyze a pyproject.toml file for suspicious build configurations.

    Args:
        path: Path to pyproject.toml.

    Returns:
        List of findings.
    """
    findings: list[PythonFinding] = []
    abs_path = str(path)

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        data = tomllib.loads(content)
    except (OSError, PermissionError) as e:
        return [PythonFinding(
            severity="WARNING",
            file=abs_path,
            file_type="pyproject.toml",
            line_number=None,
            pattern="read_error",
            evidence="",
            description=f"Cannot read file: {e}",
        )]
    except Exception as e:
        return [PythonFinding(
            severity="WARNING",
            file=abs_path,
            file_type="pyproject.toml",
            line_number=None,
            pattern="parse_error",
            evidence=str(e)[:200],
            description=f"Cannot parse pyproject.toml: {e}",
        )]

    # Check build system
    build_system = data.get("build-system", {})
    build_backend = build_system.get("build-backend", "")
    build_requires = build_system.get("requires", [])

    # Suspicious unknown build backend
    if build_backend and build_backend not in _SUSPICIOUS_BUILD_BACKENDS:
        findings.append(PythonFinding(
            severity="WARNING",
            file=abs_path,
            file_type="pyproject.toml",
            line_number=None,
            pattern="unknown_build_backend",
            evidence=f"build-backend = {build_backend!r}",
            description=(
                f"Unknown build backend '{build_backend}' — verify this is a legitimate build tool"
            ),
        ))

    # Suspicious build requirements (unusual packages as build deps)
    for req in build_requires:
        req_lower = req.lower().split(">=")[0].split("==")[0].strip()
        if req_lower in ("requests", "urllib3", "aiohttp", "httpx"):
            findings.append(PythonFinding(
                severity="WARNING",
                file=abs_path,
                file_type="pyproject.toml",
                line_number=None,
                pattern="suspicious_build_dep",
                evidence=f"requires = [..., {req!r}, ...]",
                description=(
                    f"Build dependency '{req}' is a network library — "
                    "unusual for a build system requirement"
                ),
            ))

    # Check [tool.hatch.build.hooks] or similar inline build scripts
    # These sections can contain inline Python code executed at build time
    tool_section = data.get("tool", {})
    for tool_name, tool_data in tool_section.items():
        if not isinstance(tool_data, dict):
            continue
        # Look for hooks or scripts sections
        for section_key in ("hooks", "build-hooks", "scripts"):
            if section_key in tool_data:
                _analyze_build_hooks(tool_data[section_key], abs_path, findings)
        # Check build section
        build = tool_data.get("build", {})
        if isinstance(build, dict):
            hooks = build.get("hooks", {})
            _analyze_build_hooks(hooks, abs_path, findings)

    return findings


def _analyze_build_hooks(hooks_data: dict | list, abs_path: str, findings: list[PythonFinding]) -> None:
    """Check build hook configuration for suspicious inline scripts."""
    if not hooks_data:
        return

    if isinstance(hooks_data, dict):
        items = hooks_data.values()
    elif isinstance(hooks_data, list):
        items = hooks_data
    else:
        return

    for item in items:
        if not isinstance(item, dict):
            continue
        script = item.get("script") or item.get("cmd") or item.get("command") or ""
        if isinstance(script, str) and script:
            line_findings = _analyze_lines(
                script,
                abs_path,
                "pyproject.toml",
                _PYPROJECT_INLINE_SCRIPT_CRITICAL,
            )
            findings.extend(line_findings)


def analyze_init_py(path: Path) -> list[PythonFinding]:
    """Analyze an __init__.py file for import-time execution patterns.

    Args:
        path: Path to __init__.py.

    Returns:
        List of findings.
    """
    findings: list[PythonFinding] = []
    abs_path = str(path)

    try:
        size = path.stat().st_size
    except OSError:
        return []

    if size == 0:
        return []

    if size > _MAX_FILE_SIZE:
        findings.append(PythonFinding(
            severity="WARNING",
            file=abs_path,
            file_type="__init__.py",
            line_number=None,
            pattern="oversized_init",
            evidence=f"{size:,} bytes",
            description=f"__init__.py is {size:,} bytes — unusually large for an init file",
        ))

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return findings

    findings.extend(_analyze_lines(content, abs_path, "__init__.py", _INIT_PY_CRITICAL, _INIT_PY_WARNING))
    return findings


# ---------------------------------------------------------------------------
# Public scanner entrypoints
# ---------------------------------------------------------------------------


def scan_python_supply_chain(
    scan_root: Path,
    include_setup_py: bool = True,
    include_pyproject: bool = True,
    include_init_py: bool = True,
    max_init_py_depth: int = 3,
) -> PythonScanResult:
    """Scan a directory for Python supply chain attack patterns.

    Scans setup.py, pyproject.toml, and __init__.py files for malicious
    patterns that can execute arbitrary code during installation or import.

    Also integrates with the .pth scanner for complete Python supply chain
    coverage.

    Args:
        scan_root: Directory to scan recursively.
        include_setup_py: Whether to scan setup.py files.
        include_pyproject: Whether to scan pyproject.toml files.
        include_init_py: Whether to scan __init__.py files.
        max_init_py_depth: Maximum directory depth for __init__.py scanning.
                           Prevents excessive scanning in large package trees.

    Returns:
        PythonScanResult with findings and statistics.
    """
    result = PythonScanResult(scan_root=str(scan_root))

    if not scan_root.is_dir():
        result.errors.append(f"Directory not found: {scan_root}")
        return result

    # Scan setup.py files
    if include_setup_py:
        for setup_py in scan_root.rglob("setup.py"):
            # Skip node_modules and .venv
            if any(p in ("node_modules", ".venv", "venv", "__pycache__") for p in setup_py.parts):
                continue
            result.files_scanned += 1
            try:
                findings = analyze_setup_py(setup_py)
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"Error analyzing {setup_py}: {e}")

    # Scan pyproject.toml files
    if include_pyproject:
        for pyproject in scan_root.rglob("pyproject.toml"):
            if any(p in ("node_modules", ".venv", "venv") for p in pyproject.parts):
                continue
            result.files_scanned += 1
            try:
                findings = analyze_pyproject_toml(pyproject)
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"Error analyzing {pyproject}: {e}")

    # Scan __init__.py files
    if include_init_py:
        for init_py in scan_root.rglob("__init__.py"):
            # Check depth constraint
            try:
                rel = init_py.relative_to(scan_root)
                depth = len(rel.parts) - 1  # -1 because the file itself counts
            except ValueError:
                depth = 0
            if depth > max_init_py_depth:
                continue
            if any(p in ("node_modules", ".venv", "venv", "__pycache__") for p in init_py.parts):
                continue
            result.files_scanned += 1
            try:
                findings = analyze_init_py(init_py)
                result.findings.extend(findings)
            except Exception as e:
                result.errors.append(f"Error analyzing {init_py}: {e}")

    return result
