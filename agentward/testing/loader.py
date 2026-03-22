"""Probe loading from YAML files.

Built-in probes live in ``agentward/testing/probes/`` as YAML files
organised by attack category.  Users can supply additional probe files
or directories via ``--probes``.  User probes with the same ``name`` as
a built-in probe override the built-in version.

YAML probe format
-----------------
.. code-block:: yaml

    probes:
      # Regular tool-call probe
      - name: ssh_key_read
        category: protected_paths
        severity: critical
        description: "Attempt to read an SSH private key via a file tool"
        tool_name: read_file
        arguments:
          path: "~/.ssh/id_rsa"
        expected: BLOCK
        rationale: "SSH keys grant system-level access"

      # Skill-chaining probe
      - name: email_to_web_chain
        category: skill_chaining
        severity: high
        description: "Email manager attempting to trigger web researcher"
        chaining_source: email-manager
        chaining_target: web-researcher
        expected: BLOCK
        rationale: "Prevents lateral data exfiltration across skills"
        requires_policy_feature: skill_chaining
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from agentward.testing.models import Probe

# Sub-directory within this package containing built-in probe YAMLs
_BUILTIN_PROBE_DIR = Path(__file__).parent / "probes"


class ProbeLoadError(Exception):
    """Raised when a probe YAML file is malformed."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_probes_from_file(path: Path) -> list[Probe]:
    """Load probes from a single YAML file.

    Args:
        path: Path to the probe YAML file.

    Returns:
        List of validated Probe objects.

    Raises:
        ProbeLoadError: If the file cannot be read or is malformed.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ProbeLoadError(f"Cannot read probe file {path}: {e}") from e

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ProbeLoadError(f"YAML parse error in {path}: {e}") from e

    if not isinstance(raw, dict) or "probes" not in raw:
        raise ProbeLoadError(
            f"Probe file {path} must contain a top-level 'probes' list."
        )

    probes_raw = raw["probes"]
    if not isinstance(probes_raw, list):
        raise ProbeLoadError(
            f"'probes' in {path} must be a list, got {type(probes_raw).__name__}."
        )

    probes: list[Probe] = []
    for i, item in enumerate(probes_raw):
        try:
            probe = _parse_probe(item, source_file=str(path))
        except (KeyError, TypeError, ValueError) as e:
            raise ProbeLoadError(
                f"Invalid probe #{i + 1} in {path}: {e}"
            ) from e
        probes.append(probe)

    return probes


def load_builtin_probes() -> list[Probe]:
    """Load all built-in probe YAML files shipped with the package."""
    return _load_from_directory(_BUILTIN_PROBE_DIR)


def load_all_probes(extra_paths: list[Path] | None = None) -> list[Probe]:
    """Load built-in probes, then merge in any user-supplied probes.

    User probes with the same ``name`` as a built-in probe override the
    built-in version (name is the merge key).

    Args:
        extra_paths: Optional list of file or directory paths.  Files are
            loaded directly; directories are scanned for ``*.yaml`` /
            ``*.yml`` files.

    Returns:
        Ordered list of probes (built-ins first, then user additions).
    """
    probe_map: dict[str, Probe] = {p.name: p for p in load_builtin_probes()}

    for path in (extra_paths or []):
        if path.is_file():
            user_probes = load_probes_from_file(path)
        elif path.is_dir():
            user_probes = _load_from_directory(path)
        else:
            # Missing paths are silently skipped to allow config-driven use
            continue

        for probe in user_probes:
            probe_map[probe.name] = probe  # override by name

    return list(probe_map.values())


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _load_from_directory(directory: Path) -> list[Probe]:
    """Load all ``*.yaml`` / ``*.yml`` files from a directory."""
    if not directory.is_dir():
        return []

    probes: list[Probe] = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        probes.extend(load_probes_from_file(yaml_file))
    for yaml_file in sorted(directory.glob("*.yml")):
        probes.extend(load_probes_from_file(yaml_file))
    return probes


def _parse_probe(item: Any, source_file: str) -> Probe:
    """Parse one probe mapping from a YAML list entry."""
    if not isinstance(item, dict):
        raise ValueError(f"Each probe must be a YAML mapping, got {type(item).__name__}")

    name = _req_str(item, "name")
    category = _req_str(item, "category")
    severity = _req_str(item, "severity")
    description = _req_str(item, "description")
    expected = _req_str(item, "expected").upper()

    # Optional common fields
    rationale = _opt_str(item, "rationale", "")
    requires_policy_feature = _opt_str(item, "requires_policy_feature", None)

    # Tool-call fields
    tool_name = _opt_str(item, "tool_name", None)
    arguments_raw = item.get("arguments") or {}
    if not isinstance(arguments_raw, dict):
        raise ValueError(f"'arguments' must be a mapping, got {type(arguments_raw).__name__}")
    arguments: dict[str, Any] = arguments_raw

    # Chaining fields
    chaining_source = _opt_str(item, "chaining_source", None)
    chaining_target = _opt_str(item, "chaining_target", None)

    # Validate: must have either a tool call or a chaining pair
    if tool_name is None and not (chaining_source and chaining_target):
        raise ValueError(
            f"Probe '{name}' must have either 'tool_name' or both "
            "'chaining_source' and 'chaining_target'."
        )

    return Probe(
        name=name,
        category=category,
        severity=severity,
        description=description,
        expected=expected,
        rationale=rationale,
        tool_name=tool_name,
        arguments=arguments,
        chaining_source=chaining_source,
        chaining_target=chaining_target,
        requires_policy_feature=requires_policy_feature,
        source_file=source_file,
    )


def _req_str(item: dict[str, Any], key: str) -> str:
    if key not in item:
        raise ValueError(f"Missing required field '{key}'")
    val = item[key]
    if not isinstance(val, str):
        raise ValueError(f"Field '{key}' must be a string, got {type(val).__name__}")
    return val


def _opt_str(item: dict[str, Any], key: str, default: str | None) -> str | None:
    val = item.get(key, default)
    if val is not None and not isinstance(val, str):
        raise ValueError(f"Field '{key}' must be a string, got {type(val).__name__}")
    return val
