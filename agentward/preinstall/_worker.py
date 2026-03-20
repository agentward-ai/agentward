"""Subprocess worker for the pre-install scanner.

Run as:
    python -m agentward.preinstall._worker <target_dir>

Walks the target directory, dispatches files to the appropriate check
functions, serialises findings to JSON on stdout, and exits with:
  0 — worker completed successfully (caller checks findings for verdict)
  1 — worker failed (e.g. target directory does not exist)

All parsing in this module uses safe equivalents:
  - yaml.safe_load (never yaml.load)
  - ast.parse     (never exec/import)
  - json.loads    (stdlib)
  - tomllib.loads (stdlib ≥3.11)
  - stat           (no execution)

This module intentionally has no imports from agentward at startup —
the import happens lazily after argument parsing so that any import
error surfaces cleanly as a JSON error response.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Directory traversal config
# ---------------------------------------------------------------------------

_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "node_modules", ".venv", "venv", "env", ".env",
    "dist", "build", ".eggs", "*.egg-info",
    ".tox", ".nox",
})

# Maximum directory depth to prevent traversal of huge trees
_MAX_DEPTH = 10

# Maximum file size to read (8 MB — large files are almost certainly not configs)
_MAX_FILE_BYTES = 8 * 1024 * 1024


def _walk(root: Path) -> list[Path]:
    """Yield all files under root, skipping excluded directories."""
    result: list[Path] = []
    _walk_recursive(root, root, 0, result)
    return result


def _walk_recursive(root: Path, current: Path, depth: int, acc: list[Path]) -> None:
    if depth > _MAX_DEPTH:
        return
    try:
        entries = list(current.iterdir())
    except (PermissionError, OSError):
        return
    for entry in entries:
        if entry.is_dir(follow_symlinks=False):
            if entry.name not in _SKIP_DIRS and not entry.name.endswith(".egg-info"):
                _walk_recursive(root, entry, depth + 1, acc)
        elif entry.is_file(follow_symlinks=False):
            try:
                if entry.stat().st_size <= _MAX_FILE_BYTES:
                    acc.append(entry)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# File dispatch
# ---------------------------------------------------------------------------


def _scan_directory(root: Path) -> tuple[list[dict], int]:
    """Scan all files under root and return (serialised_findings, file_count)."""
    from agentward.preinstall.checks.yaml_safety import check_yaml_safety, check_yaml_load_in_python
    from agentward.preinstall.checks.pickle_detect import (
        check_pickle,
        check_pickle_binary,
    )
    from agentward.preinstall.checks.exec_hooks import (
        check_package_json,
        check_pyproject_hooks,
        check_setup_py,
        check_script_file,
    )
    from agentward.preinstall.checks.dependencies import (
        check_requirements_txt,
        check_pyproject_deps,
        check_package_json_deps,
    )

    all_findings: list[dict] = []
    files = _walk(root)

    for path in files:
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = path.name

        name_lower = path.name.lower()
        suffix = path.suffix.lower()
        findings = []

        if suffix in (".yaml", ".yml"):
            findings = check_yaml_safety(path, rel)

        elif suffix == ".py":
            findings = check_pickle(path, rel) + check_yaml_load_in_python(path, rel)
            if name_lower == "setup.py":
                findings = findings + check_setup_py(path, rel)

        elif suffix in (".pkl", ".pickle", ".joblib"):
            findings = check_pickle_binary(path, rel)

        elif name_lower == "package.json":
            findings = check_package_json(path, rel) + check_package_json_deps(path, rel)

        elif name_lower == "pyproject.toml":
            findings = check_pyproject_hooks(path, rel) + check_pyproject_deps(path, rel)

        elif name_lower in ("requirements.txt",) or (
            name_lower.startswith("requirements") and suffix == ".txt"
        ):
            findings = check_requirements_txt(path, rel)

        elif suffix in (".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd"):
            findings = check_script_file(path, rel)

        for f in findings:
            all_findings.append(asdict(f))

    return all_findings, len(files)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    if len(sys.argv) != 2:
        _error("Usage: python -m agentward.preinstall._worker <target_dir>")
        return 1

    target = Path(sys.argv[1])
    if not target.exists():
        _error(f"Target directory does not exist: {target}")
        return 1
    if not target.is_dir():
        _error(f"Target is not a directory: {target}")
        return 1

    try:
        findings, file_count = _scan_directory(target)
    except Exception as exc:  # noqa: BLE001
        _error(f"Scan failed: {exc}")
        return 1

    result = {"findings": findings, "files_scanned": file_count}
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    return 0


def _error(msg: str) -> None:
    """Write an error JSON to stdout so the parent process can read it."""
    sys.stdout.write(json.dumps({"error": msg, "findings": [], "files_scanned": 0}))
    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
