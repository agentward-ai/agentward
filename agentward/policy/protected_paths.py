"""Protected path invariants — non-overridable safety floor.

Blocks tool calls that reference sensitive filesystem paths regardless of
policy configuration. These paths contain credentials, keys, and
configuration that should NEVER be accessible to agents.

Resolves symlinks to prevent escape attacks (e.g., a symlink at
~/innocent pointing to ~/.ssh).

This module is defense-in-depth: even if a policy explicitly allows
access, these paths remain blocked. The only way to disable this is
to modify this source file.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

# Home directory (resolved once at import time)
_HOME = Path.home()

# Protected paths: these directories (and everything under them) are
# ALWAYS blocked. Paths are relative to $HOME.
PROTECTED_DIRS: tuple[str, ...] = (
    ".ssh",
    ".gnupg",
    ".gpg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
)

# Resolved absolute paths for fast prefix matching.
_PROTECTED_RESOLVED: tuple[str, ...] = tuple(
    str((_HOME / d).resolve()) for d in PROTECTED_DIRS
)


def check_arguments(arguments: dict[str, Any] | None) -> str | None:
    """Check if any tool argument references a protected path.

    Walks all string values in the arguments dict and checks each one
    against the protected path list. Handles tilde expansion, absolute
    paths, relative paths, and symlink resolution.

    Args:
        arguments: The tool call arguments dict.

    Returns:
        A human-readable reason string if a protected path was found,
        or None if all arguments are safe.
    """
    if not arguments:
        return None

    for field_path, value in _walk_strings(arguments):
        result = _check_single_value(value)
        if result is not None:
            return f"Protected path invariant: argument '{field_path}' references {result}. " \
                   f"Access to this path is always blocked regardless of policy."

    return None


def _check_single_value(value: str) -> str | None:
    """Check a single string value against protected paths.

    Args:
        value: A string value from tool arguments.

    Returns:
        The protected path that was matched, or None.
    """
    # Skip values that are clearly not paths
    if not value or len(value) < 3:
        return None

    # Only check values that look like paths
    if not (
        value.startswith("/")
        or value.startswith("~")
        or value.startswith(".")
        or ("/" in value and not value.startswith("http"))
    ):
        return None

    # Expand tilde
    expanded = os.path.expanduser(value)

    # Try to resolve symlinks. If the path doesn't exist, resolve()
    # still canonicalizes ".." and "." components (but can't resolve
    # symlinks for non-existent intermediate dirs — acceptable trade-off).
    try:
        resolved = str(Path(expanded).resolve())
    except (OSError, ValueError):
        # Invalid path — not dangerous
        return None

    # Check against all protected directories
    for protected in _PROTECTED_RESOLVED:
        if resolved == protected or resolved.startswith(protected + "/"):
            return protected

    return None


def _walk_strings(
    obj: Any, path: str = ""
) -> Iterator[tuple[str, str]]:
    """Recursively yield (field_path, string_value) from nested structures.

    Args:
        obj: The object to walk.
        path: Current dot-separated path prefix.

    Yields:
        (field_path, string_value) for every string leaf.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{path}.{key}" if path else str(key)
            yield from _walk_strings(value, child)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            child = f"{path}[{i}]" if path else f"[{i}]"
            yield from _walk_strings(value, child)
    elif isinstance(obj, str):
        if obj:
            yield (path, obj)
