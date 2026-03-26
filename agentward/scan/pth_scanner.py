"""Supply chain attack scanner for Python .pth files.

.pth files in site-packages directories can execute arbitrary Python code at
interpreter startup — any line starting with 'import' is executed immediately
when the interpreter starts. This mechanism was exploited in the March 2026
litellm supply chain attack (litellm_init.pth), which used double-encoded
base64 to obfuscate a malicious payload.

This scanner:
- Locates all site-packages directories (system, user, active venv)
- Reads every .pth file safely (no execution)
- Detects suspicious patterns using regex
- Cross-references against a known-good allowlist
- Reports findings with CRITICAL / WARNING / OK severity
"""

from __future__ import annotations

import re
import site
import sysconfig
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class PthFinding:
    """A finding from .pth file analysis."""

    severity: Literal["CRITICAL", "WARNING", "OK"]
    file: str          # absolute path to the .pth file
    line_number: int | None  # 1-based; None for file-level findings
    pattern: str       # rule name that triggered
    evidence: str      # the triggering line (truncated for safety)
    description: str


@dataclass
class PthScanResult:
    """Results of scanning .pth files across site-packages dirs."""

    findings: list[PthFinding] = field(default_factory=list)
    files_scanned: int = 0
    site_packages_dirs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "CRITICAL" for f in self.findings)

    @property
    def has_warning(self) -> bool:
        return any(f.severity == "WARNING" for f in self.findings)


# ---------------------------------------------------------------------------
# Allowlist of known-good .pth files
# ---------------------------------------------------------------------------
# Maps filename (exact match) to a list of acceptable content patterns.
# A file matches the allowlist if ALL of its executable lines match at least
# one acceptable pattern.  Non-executable lines (bare paths, blank lines,
# comments) are never flagged.
#
# Pattern strings are matched with re.search() against each executable line.

_KNOWN_GOOD_PTH: dict[str, list[str]] = {
    # setuptools
    "distutils-precedence.pth": [r"^import\s+_distutils_hack"],
    "easy-install.pth": [],  # path-only files — no executable content expected
    # pip / wheel
    "wheel.pth": [],
    # editable installs (pip install -e)
    "__editable__": [r"^import\s+__editable__"],
    # pytest / testing
    "pytest-enabler.pth": [r"^import\s+pytest_enabler"],
    "pytest11.pth": [],
    # coverage
    "coverage.pth": [r"^import\s+coverage"],
    # sitecustomize shims
    "sitecustomize.pth": [r"^import\s+sitecustomize"],
    # conda / anaconda
    "conda.pth": [],
    "conda-meta.pth": [],
    # IPython / Jupyter
    "ipython_genutils-nspkg.pth": [],
    # pydev debugger (PyCharm, VS Code)
    "pydev.pth": [r"^import\s+pydev"],
    "pydebugger.pth": [],
    # common virtualenv helpers
    "virtualenv_path_extensions.pth": [],
    "site.pth": [],
    # Apple system Python extras
    "Apple.pth": [],
}

# Filename substrings that are typically safe (editable installs)
_SAFE_FILENAME_SUBSTRINGS: tuple[str, ...] = (
    "__editable__",
    "_mutable_package_",
    "-nspkg.pth",
    "-editable.pth",
)


# ---------------------------------------------------------------------------
# Suspicious pattern definitions
# ---------------------------------------------------------------------------
# Each entry: (rule_name, severity, compiled_regex, description)

_SUSPICIOUS_PATTERNS: list[tuple[str, Literal["CRITICAL", "WARNING"], re.Pattern[str], str]] = [
    # Double/chained base64 (litellm attack signature)
    (
        "double_base64_decode",
        "CRITICAL",
        re.compile(r"b64decode.*b64decode|base64.*base64", re.IGNORECASE),
        "Double base64 decoding — obfuscation technique used in supply chain attacks",
    ),
    # Any base64 decode in an executable line
    (
        "base64_decode",
        "CRITICAL",
        re.compile(r"b64decode|b32decode|b16decode|decodebytes", re.IGNORECASE),
        "Base64/binary decoding in .pth startup code — common obfuscation vector",
    ),
    # Subprocess execution
    (
        "subprocess_exec",
        "CRITICAL",
        re.compile(r"subprocess\s*\.\s*(Popen|run|call|check_output|check_call|getoutput)", re.IGNORECASE),
        "Subprocess execution at interpreter startup",
    ),
    # os.system / os.exec family / os.popen
    (
        "os_exec",
        "CRITICAL",
        re.compile(r"os\s*\.\s*(system|execv|execve|execvp|execvpe|popen|spawn)", re.IGNORECASE),
        "OS command execution at interpreter startup",
    ),
    # eval / exec (obfuscated code execution)
    (
        "eval_exec",
        "CRITICAL",
        re.compile(r"\beval\s*\(|\bexec\s*\(|\bcompile\s*\(", re.IGNORECASE),
        "Dynamic code execution (eval/exec/compile) in .pth startup code",
    ),
    # __import__ with non-trivial arg (dynamic import obfuscation)
    (
        "dynamic_import",
        "CRITICAL",
        re.compile(r"__import__\s*\([^)]{5,}", re.IGNORECASE),
        "Dynamic __import__() call — obfuscation technique",
    ),
    # Network calls — urllib
    (
        "network_urllib",
        "CRITICAL",
        re.compile(r"urllib\s*\.\s*(request|parse|urlopen)|urlopen\s*\(", re.IGNORECASE),
        "Network call via urllib at interpreter startup",
    ),
    # Network calls — requests
    (
        "network_requests",
        "CRITICAL",
        re.compile(r"\brequests\s*\.\s*(get|post|put|delete|head|session|Session)", re.IGNORECASE),
        "Network call via requests library at interpreter startup",
    ),
    # Network calls — http.client
    (
        "network_http_client",
        "CRITICAL",
        re.compile(r"http\.client|HTTPConnection|HTTPSConnection", re.IGNORECASE),
        "Network call via http.client at interpreter startup",
    ),
    # Network calls — socket
    (
        "network_socket",
        "CRITICAL",
        re.compile(r"\bsocket\s*\.\s*(connect|create_connection|socket\s*\()", re.IGNORECASE),
        "Raw socket connection at interpreter startup",
    ),
    # Read sensitive files
    (
        "sensitive_file_read",
        "CRITICAL",
        re.compile(
            r"""open\s*\([^)]*(?:\.ssh|\.aws|\.kube|\.env|\.pem|id_rsa|id_ed25519|credentials|secrets)""",
            re.IGNORECASE,
        ),
        "Reading a sensitive file path (~/.ssh, ~/.aws, ~/.kube, .env, .pem) at startup",
    ),
    # Writes to systemd dirs
    (
        "systemd_write",
        "CRITICAL",
        re.compile(r"""(?:/etc/systemd|/lib/systemd|/usr/lib/systemd|/run/systemd)""", re.IGNORECASE),
        "Reference to systemd directory — potential persistence mechanism",
    ),
    # getattr with dynamic/string args (attribute obfuscation)
    (
        "dynamic_getattr",
        "CRITICAL",
        re.compile(r"getattr\s*\([^,]+,\s*['\"][^'\"]+['\"].*\)\s*\(", re.IGNORECASE),
        "getattr() with dynamic attribute string followed by call — obfuscation technique",
    ),
    # Any other import line (executable but not on allowlist) — WARNING
    # This is the catch-all: any 'import ...' line that didn't match CRITICAL patterns
    (
        "executable_import",
        "WARNING",
        re.compile(r"^import\s+\S+"),
        "Executable import line — runs at interpreter startup (verify this is expected)",
    ),
]

# Max file size to analyze (bytes). Files larger than this are flagged CRITICAL.
_MAX_FILE_SIZE = 1024 * 1024  # 1 MB


# ---------------------------------------------------------------------------
# Site-packages discovery
# ---------------------------------------------------------------------------


def _find_site_packages_dirs() -> list[Path]:
    """Return all site-packages directories to scan.

    Checks:
    - site.getsitepackages() (system/venv site-packages)
    - site.getusersitepackages() (user site)
    - sysconfig purelib / platlib paths
    - VIRTUAL_ENV / CONDA_PREFIX env vars for active virtual envs

    Deduplicates and returns only directories that actually exist.
    """
    import os

    candidates: list[Path] = []

    # Standard site-packages
    try:
        for p in site.getsitepackages():
            candidates.append(Path(p))
    except AttributeError:
        # Some minimal Python environments don't have getsitepackages()
        pass

    # User site-packages
    try:
        user_site = site.getusersitepackages()
        if user_site:
            candidates.append(Path(user_site))
    except AttributeError:
        pass

    # sysconfig paths
    for scheme_key in ("purelib", "platlib"):
        try:
            p = sysconfig.get_path(scheme_key)
            if p:
                candidates.append(Path(p))
        except Exception:
            pass

    # Active virtual environment
    for env_var in ("VIRTUAL_ENV", "CONDA_PREFIX"):
        venv = os.environ.get(env_var)
        if venv:
            venv_path = Path(venv)
            # Common layouts
            for sub in ("lib", "Lib"):
                lib_dir = venv_path / sub
                if lib_dir.is_dir():
                    for child in lib_dir.iterdir():
                        if child.name.startswith("python") and child.is_dir():
                            sp = child / "site-packages"
                            if sp.is_dir():
                                candidates.append(sp)
                    # Windows: Lib/site-packages directly
                    sp = lib_dir / "site-packages"
                    if sp.is_dir():
                        candidates.append(sp)

    # Deduplicate (resolve symlinks)
    seen: set[Path] = set()
    result: list[Path] = []
    for p in candidates:
        try:
            rp = p.resolve()
            if rp not in seen and rp.is_dir():
                seen.add(rp)
                result.append(rp)
        except (OSError, PermissionError):
            pass

    return result


# ---------------------------------------------------------------------------
# .pth file analysis
# ---------------------------------------------------------------------------


def _is_allowlisted(filename: str, executable_lines: list[tuple[int, str]]) -> bool:
    """Return True if the file is fully covered by the known-good allowlist.

    A file is allowlisted if any of:
    1. Its filename contains a safe substring (e.g. __editable__, -nspkg.pth)
       — these are always safe regardless of content.
    2. Its filename matches an entry in _KNOWN_GOOD_PTH AND every executable
       line matches at least one allowed pattern for that entry.

    Empty allowlist patterns in _KNOWN_GOOD_PTH mean "no executable content
    expected" — any executable line in such a file is NOT allowlisted via rule 2
    (but could still be caught by rule 1 if the filename has a safe substring).
    """
    # Rule 1: Safe filename substrings take priority — no content analysis needed
    for substr in _SAFE_FILENAME_SUBSTRINGS:
        if substr in filename:
            return True

    # Rule 2: Exact filename match with pattern verification
    if filename in _KNOWN_GOOD_PTH:
        allowed_patterns = _KNOWN_GOOD_PTH[filename]
        if not allowed_patterns:
            # File is known-good only if it has no executable lines
            return len(executable_lines) == 0
        for _lineno, line in executable_lines:
            if not any(re.search(pat, line) for pat in allowed_patterns):
                return False
        return True

    return False


def _analyze_pth_file(path: Path) -> list[PthFinding]:
    """Analyze a single .pth file for suspicious content.

    Returns a list of PthFinding objects. Empty list means the file is clean.

    .pth file rules (CPython implementation):
    - Lines starting with '#' are comments (ignored)
    - Blank lines are ignored
    - Lines starting with 'import ' are executed as Python code
    - All other lines are treated as path additions (not executed)
    """
    findings: list[PthFinding] = []
    abs_path = str(path)

    # --- File-level checks ---

    # Size check
    try:
        size = path.stat().st_size
    except OSError as e:
        findings.append(PthFinding(
            severity="WARNING",
            file=abs_path,
            line_number=None,
            pattern="stat_error",
            evidence="",
            description=f"Cannot stat file: {e}",
        ))
        return findings

    if size == 0:
        return findings  # empty .pth is harmless

    if size > _MAX_FILE_SIZE:
        findings.append(PthFinding(
            severity="CRITICAL",
            file=abs_path,
            line_number=None,
            pattern="oversized_file",
            evidence=f"{size:,} bytes",
            description=f"File is {size:,} bytes (>{_MAX_FILE_SIZE:,}) — suspiciously large for a .pth file",
        ))

    # Read content
    try:
        raw = path.read_bytes()
    except PermissionError:
        findings.append(PthFinding(
            severity="WARNING",
            file=abs_path,
            line_number=None,
            pattern="permission_denied",
            evidence="",
            description="Permission denied reading file",
        ))
        return findings
    except OSError as e:
        findings.append(PthFinding(
            severity="WARNING",
            file=abs_path,
            line_number=None,
            pattern="read_error",
            evidence="",
            description=f"Cannot read file: {e}",
        ))
        return findings

    # Binary content check — .pth files should be plain text.
    # Must run on raw bytes regardless of whether UTF-8 decode succeeds
    # (NUL bytes are valid UTF-8 but not valid .pth content).
    non_printable = sum(1 for b in raw if b < 0x09 or (0x0D < b < 0x20) or b == 0x7F)
    if non_printable > len(raw) * 0.05:
        findings.append(PthFinding(
            severity="CRITICAL",
            file=abs_path,
            line_number=None,
            pattern="binary_content",
            evidence=f"{non_printable} non-printable bytes ({non_printable / len(raw) * 100:.0f}%)",
            description="Binary content in .pth file — only plain text is expected",
        ))
        return findings

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except Exception:
            findings.append(PthFinding(
                severity="CRITICAL",
                file=abs_path,
                line_number=None,
                pattern="binary_content",
                evidence="",
                description="Cannot decode file as text — binary content in .pth file",
            ))
            return findings

    # --- Line-level analysis ---

    lines = text.splitlines()
    executable_lines: list[tuple[int, str]] = []  # (1-based lineno, line)

    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue  # blank or comment — ignored by Python
        if stripped.startswith("import ") or stripped.startswith("import\t"):
            executable_lines.append((lineno, stripped))

    if not executable_lines:
        # Path-only file: verify paths exist (but don't flag missing — just note)
        return findings

    # Check allowlist first
    if _is_allowlisted(path.name, executable_lines):
        return findings  # all lines are known-good

    # Apply suspicious pattern checks to each executable line
    for lineno, line in executable_lines:
        evidence = line[:200]  # cap evidence length

        matched_critical = False
        for rule_name, severity, pattern, description in _SUSPICIOUS_PATTERNS:
            if severity != "CRITICAL":
                continue
            if pattern.search(line):
                findings.append(PthFinding(
                    severity="CRITICAL",
                    file=abs_path,
                    line_number=lineno,
                    pattern=rule_name,
                    evidence=evidence,
                    description=description,
                ))
                matched_critical = True
                break  # report first CRITICAL hit per line

        if not matched_critical:
            # Executable line but no critical pattern — report WARNING
            findings.append(PthFinding(
                severity="WARNING",
                file=abs_path,
                line_number=lineno,
                pattern="executable_import",
                evidence=evidence,
                description=(
                    f"Executable 'import' line in {path.name} — runs at interpreter startup. "
                    "Verify this is expected for this package."
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Public scanner entrypoint
# ---------------------------------------------------------------------------


def scan_pth_files(
    extra_dirs: list[Path] | None = None,
) -> PthScanResult:
    """Scan site-packages directories for suspicious .pth files.

    Args:
        extra_dirs: Additional directories to scan beyond the auto-discovered
                    site-packages directories.

    Returns:
        PthScanResult with findings, file count, and directory list.
    """
    result = PthScanResult()

    dirs_to_scan = _find_site_packages_dirs()
    if extra_dirs:
        for d in extra_dirs:
            try:
                rp = d.resolve()
                if rp not in {Path(x).resolve() for x in result.site_packages_dirs}:
                    dirs_to_scan.append(rp)
            except OSError:
                pass

    result.site_packages_dirs = [str(d) for d in dirs_to_scan]

    for sp_dir in dirs_to_scan:
        try:
            pth_files = sorted(sp_dir.glob("*.pth"))
        except PermissionError:
            result.errors.append(f"Permission denied listing {sp_dir}")
            continue
        except OSError as e:
            result.errors.append(f"Cannot read {sp_dir}: {e}")
            continue

        for pth_path in pth_files:
            result.files_scanned += 1
            try:
                file_findings = _analyze_pth_file(pth_path)
                result.findings.extend(file_findings)
            except Exception as e:  # pragma: no cover — unexpected errors
                result.errors.append(f"Unexpected error analyzing {pth_path}: {e}")

    return result
