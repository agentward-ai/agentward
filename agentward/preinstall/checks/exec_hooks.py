"""Executable hook and suspicious script detection.

Catches skills that run shell code during installation — a classic
supply-chain attack vector.  Checks:

1. package.json: postinstall / preinstall / install / prepare scripts
2. pyproject.toml: [tool.hatch.build.hooks], custom build-backend hooks
3. setup.py: cmdclass overriding 'install' / 'develop' / 'build'
4. Files with executable UNIX permissions (.sh, .bash, .zsh, .ps1, .bat)
5. Shell scripts in any location that contain suspicious patterns
   (curl | sh, wget | bash, base64 -d | bash, etc.)
"""

from __future__ import annotations

import ast
import json
import re
import stat
from pathlib import Path

from agentward.preinstall.models import PreinstallFinding, ThreatCategory, ThreatLevel


# npm lifecycle hooks that run during `npm install`
_INSTALL_HOOKS = frozenset({
    "preinstall", "install", "postinstall",
    "prepare",    # runs on `npm install` in a cloned repo
})

# Shell script extensions
_SCRIPT_EXTENSIONS = frozenset({".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd"})

# Patterns that fetch and execute remote code
_REMOTE_EXEC_PATTERNS = [
    (re.compile(r"curl\b.*\|\s*(?:bash|sh|zsh)\b",           re.IGNORECASE), "curl pipe to shell"),
    (re.compile(r"wget\b.*\|\s*(?:bash|sh|zsh)\b",           re.IGNORECASE), "wget pipe to shell"),
    (re.compile(r"fetch\b.*\|\s*(?:bash|sh|zsh)\b",          re.IGNORECASE), "fetch pipe to shell"),
    (re.compile(r"base64\s+-d\b.*\|\s*(?:bash|sh)\b",        re.IGNORECASE), "base64-decode pipe to shell"),
    (re.compile(r"python(?:3)?\s+-c\s+['\"].*exec\(",        re.IGNORECASE), "python -c exec"),
    (re.compile(r"eval\s*\$\(",                               re.IGNORECASE), "eval $(...) shell expansion"),
    (re.compile(r"\bexec\s*\(",                               re.IGNORECASE), "exec() call"),
]

# Hatch build hook section — any entry here runs code during sdist/wheel build
_HATCH_HOOK_RE = re.compile(r"^\[tool\.hatch\.build\.hooks\b", re.MULTILINE)


# ---------------------------------------------------------------------------
# Public check functions
# ---------------------------------------------------------------------------


def check_package_json(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Check a package.json for lifecycle hooks that run on install.

    Args:
        path: Absolute path to package.json.
        rel_path: Relative path for display.

    Returns:
        List of findings (may be empty).
    """
    findings: list[PreinstallFinding] = []

    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return findings

    if not isinstance(data, dict):
        return findings

    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    for hook_name in _INSTALL_HOOKS:
        if hook_name in scripts:
            cmd = str(scripts[hook_name])
            # Extra severity if the hook fetches from the network
            has_remote = any(p.search(cmd) for p, _ in _REMOTE_EXEC_PATTERNS)
            level = ThreatLevel.CRITICAL if has_remote else ThreatLevel.HIGH
            findings.append(PreinstallFinding(
                category=ThreatCategory.EXECUTABLE_HOOK,
                level=level,
                file=rel_path,
                line=None,
                description=(
                    f"package.json defines a '{hook_name}' lifecycle hook "
                    f"that runs automatically during `npm install`."
                ),
                evidence=f"scripts.{hook_name}: {cmd[:200]}",
                recommendation=(
                    f"Remove the '{hook_name}' hook or replace it with a "
                    "declarative build step that does not execute shell code "
                    "at install time. Inspect the command carefully before "
                    "proceeding."
                ),
            ))

    return findings


def check_pyproject_hooks(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Check a pyproject.toml for build hooks that run during installation.

    Args:
        path: Absolute path to pyproject.toml.
        rel_path: Relative path for display.

    Returns:
        List of findings (may be empty).
    """
    findings: list[PreinstallFinding] = []

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    import tomllib  # noqa: PLC0415 — stdlib ≥3.11

    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError:
        return findings

    # Hatch build hooks
    hatch_hooks = (
        data.get("tool", {})
            .get("hatch", {})
            .get("build", {})
            .get("hooks", {})
    )
    if hatch_hooks:
        hook_names = ", ".join(sorted(hatch_hooks.keys()))
        findings.append(PreinstallFinding(
            category=ThreatCategory.EXECUTABLE_HOOK,
            level=ThreatLevel.HIGH,
            file=rel_path,
            line=None,
            description=(
                f"pyproject.toml defines Hatch build hook(s) [{hook_names}] "
                "that execute code during package build/install."
            ),
            evidence=f"[tool.hatch.build.hooks]: {hook_names}",
            recommendation=(
                "Review these Hatch build hooks carefully. Hooks run during "
                "`pip install` and can execute arbitrary code. Prefer "
                "declarative build configurations."
            ),
        ))

    # Arbitrary build-backend entrypoint override
    build_system = data.get("build-system", {})
    build_backend = build_system.get("build-backend", "")
    requires = build_system.get("requires", [])
    # Known-safe backends — anything else warrants a look
    _KNOWN_SAFE_BACKENDS = frozenset({
        "hatchling.build", "setuptools.build_meta",
        "flit_core.buildapi", "poetry.core.masonry.api",
        "meson_python.build", "scikit_build_core.build",
        "wheel.build", "pdm.backend",
    })
    if build_backend and build_backend not in _KNOWN_SAFE_BACKENDS:
        findings.append(PreinstallFinding(
            category=ThreatCategory.EXECUTABLE_HOOK,
            level=ThreatLevel.MEDIUM,
            file=rel_path,
            line=None,
            description=(
                f"pyproject.toml uses an unfamiliar build backend "
                f"'{build_backend}'. Custom build backends can execute "
                "arbitrary code during `pip install`."
            ),
            evidence=f"build-system.build-backend = {build_backend!r}",
            recommendation=(
                "Verify that the build backend is from a trusted, "
                "well-maintained package. Prefer hatchling, setuptools, "
                "flit_core, or poetry.core."
            ),
        ))

    return findings


def check_setup_py(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Check a setup.py for overridden install commands (always executes on pip install).

    setup.py itself is always executed by pip — flag it at INFO level
    and escalate if it overrides install/develop commands.

    Args:
        path: Absolute path to setup.py.
        rel_path: Relative path for display.

    Returns:
        List of findings (may be empty).
    """
    findings: list[PreinstallFinding] = []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # setup.py is always run by pip — baseline info finding
    findings.append(PreinstallFinding(
        category=ThreatCategory.EXECUTABLE_HOOK,
        level=ThreatLevel.MEDIUM,
        file=rel_path,
        line=None,
        description=(
            "setup.py is executed by pip during installation. "
            "Any code at module level runs with the installer's privileges."
        ),
        evidence="setup.py present",
        recommendation=(
            "Migrate to pyproject.toml with a declarative build backend "
            "(hatchling, flit_core, or setuptools with setup.cfg). "
            "Inspect setup.py for unexpected module-level code."
        ),
    ))

    # Check for cmdclass overrides — these run custom code for install/develop
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _call_name(node)
        if func_name not in ("setup", "setuptools.setup"):
            continue
        for kw in node.keywords:
            if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict):
                for key in kw.value.keys:
                    if isinstance(key, ast.Constant) and key.value in (
                        "install", "develop", "build", "build_py", "install_lib"
                    ):
                        findings.append(PreinstallFinding(
                            category=ThreatCategory.EXECUTABLE_HOOK,
                            level=ThreatLevel.HIGH,
                            file=rel_path,
                            line=node.lineno,
                            description=(
                                f"setup.py overrides the '{key.value}' command via "
                                "cmdclass — custom code runs during `pip install`."
                            ),
                            evidence=f"cmdclass={{{key.value!r}: ...}}",
                            recommendation=(
                                "Avoid overriding pip installation commands. "
                                "Use a declarative pyproject.toml configuration "
                                "and standard build hooks instead."
                            ),
                        ))

    return findings


def check_script_file(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Flag a shell/batch script, escalating if it contains remote-exec patterns.

    Args:
        path: Absolute path to the script.
        rel_path: Relative path for display.

    Returns:
        List of findings (may be empty).
    """
    findings: list[PreinstallFinding] = []

    # Base finding — script exists
    try:
        st = path.stat()
        is_executable = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        is_executable = False

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    base_level = ThreatLevel.LOW if not is_executable else ThreatLevel.MEDIUM
    findings.append(PreinstallFinding(
        category=ThreatCategory.SUSPICIOUS_SCRIPT,
        level=base_level,
        file=rel_path,
        line=None,
        description=(
            f"Shell script '{path.name}' bundled in skill"
            + (" (has execute bit set)" if is_executable else "")
            + "."
        ),
        evidence=path.name,
        recommendation=(
            "Review this script before allowing it to run. Skill packages "
            "should not include shell scripts unless they are explicitly "
            "part of the documented build process."
        ),
    ))

    # Escalate if we find remote-exec patterns
    for lineno, line in enumerate(content.splitlines(), 1):
        for pattern, label in _REMOTE_EXEC_PATTERNS:
            if pattern.search(line):
                findings.append(PreinstallFinding(
                    category=ThreatCategory.SUSPICIOUS_SCRIPT,
                    level=ThreatLevel.CRITICAL,
                    file=rel_path,
                    line=lineno,
                    description=(
                        f"Script contains a remote code execution pattern ({label}): "
                        "fetches and pipes content directly to a shell interpreter."
                    ),
                    evidence=line.strip()[:200],
                    recommendation=(
                        "Do not run this script. This pattern is a known attack "
                        "technique for supplying malicious code at install time."
                    ),
                ))
                break  # one finding per line is enough

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _call_name(node: ast.Call) -> str:
    """Return a.b.c name for a Call's func, or '' if not resolvable."""
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""
