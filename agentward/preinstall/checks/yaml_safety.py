"""YAML unsafe construct detection.

Scans YAML/YML files for tags that trigger arbitrary code execution
when loaded with yaml.load() (FullLoader, UnsafeLoader, or legacy
Loader). The safe equivalent — yaml.safe_load() — rejects these.

Dangerous tag families:
  !!python/object/apply  — calls arbitrary Python callables
  !!python/object        — constructs arbitrary Python objects
  !!python/module        — imports arbitrary modules
  !!python/name          — resolves arbitrary names
  !!python/reduce        — invokes __reduce__ (pickle-like)
  !!python/new           — calls __new__ on arbitrary types
  Language-level tags for ruby/java/php — deserialization attack vectors
  in polyglot / multi-language environments.

All of the above are DESERIALIZATION ATTACK VECTORS and are flagged CRITICAL.

Also detects unsafe yaml.load() calls in Python source files:
  yaml.load(data)                              — unsafe (no Loader)
  yaml.load(data, Loader=yaml.Loader)          — unsafe
  yaml.load(data, Loader=yaml.FullLoader)      — unsafe (can construct objects)
  yaml.load(data, Loader=yaml.UnsafeLoader)    — unsafe (explicit)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agentward.preinstall.models import PreinstallFinding, ThreatCategory, ThreatLevel


# Matches dangerous YAML tag prefixes
_UNSAFE_TAG_RE = re.compile(
    r"!!\s*"
    r"(?:python/(?:object(?:/apply|/reduce|/new)?|module|name|apply|reduce|new)"
    r"|ruby/"
    r"|java/"
    r"|php/)"
    r"\S*",
    re.IGNORECASE,
)

# Human-readable label per tag prefix
_TAG_LABELS: dict[str, str] = {
    "python/object/apply": "arbitrary callable invocation",
    "python/object/reduce": "pickle-style __reduce__ invocation",
    "python/object/new":    "arbitrary __new__ construction",
    "python/object":        "arbitrary Python object construction",
    "python/module":        "arbitrary module import",
    "python/name":          "arbitrary name resolution",
    "python/apply":         "arbitrary callable invocation",
    "python/reduce":        "pickle-style __reduce__ invocation",
    "python/new":           "arbitrary __new__ construction",
    "ruby/":                "Ruby object construction",
    "java/":                "Java object construction",
    "php/":                 "PHP object construction",
}


def _tag_label(raw_tag: str) -> str:
    lower = raw_tag.lower().lstrip("!")
    for prefix, label in sorted(_TAG_LABELS.items(), key=lambda kv: -len(kv[0])):
        if lower.startswith(prefix):
            return label
    return "unsafe YAML tag"


def check_yaml_safety(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Scan a YAML file for unsafe tags that enable code execution.

    Args:
        path: Absolute path to the YAML file.
        rel_path: Relative path for display in findings.

    Returns:
        List of PreinstallFinding objects (may be empty).
    """
    findings: list[PreinstallFinding] = []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # Phase 1: line-by-line regex scan (fast, catches obfuscated constructs)
    for lineno, line in enumerate(text.splitlines(), 1):
        match = _UNSAFE_TAG_RE.search(line)
        if match:
            raw_tag = match.group(0).strip()
            # ALL unsafe YAML tags are deserialization attack vectors — CRITICAL
            level = ThreatLevel.CRITICAL
            label = _tag_label(raw_tag)
            findings.append(PreinstallFinding(
                category=ThreatCategory.YAML_INJECTION,
                level=level,
                file=rel_path,
                line=lineno,
                description=(
                    f"Unsafe YAML tag '{raw_tag.strip()}' enables {label} "
                    f"during deserialization."
                ),
                evidence=line.strip()[:200],
                recommendation=(
                    "Remove all !!python/ and language-level YAML tags. "
                    "Skill config files should only use plain YAML scalars, "
                    "mappings, and sequences — never executable constructors."
                ),
            ))

    # Phase 2: attempt yaml.safe_load to catch tags that evaded the regex
    # (e.g. multi-line tags, whitespace tricks)
    if not findings:
        try:
            import yaml  # noqa: PLC0415 — intentionally lazy
            yaml.safe_load(text)
        except yaml.constructor.ConstructorError as exc:
            findings.append(PreinstallFinding(
                category=ThreatCategory.YAML_INJECTION,
                level=ThreatLevel.CRITICAL,
                file=rel_path,
                line=None,
                description=(
                    "YAML file contains constructs blocked by safe_load. "
                    "This is a strong indicator of a deserialization attack."
                ),
                evidence=str(exc)[:200],
                recommendation=(
                    "This file cannot be safely loaded with yaml.safe_load(). "
                    "Inspect manually before use and do not load it with "
                    "yaml.load() or yaml.full_load()."
                ),
            ))
        except Exception:  # noqa: BLE001 — any parse error is non-critical
            pass

    return findings


# Unsafe YAML Loader names — anything other than SafeLoader / BaseLoader is dangerous
_UNSAFE_LOADERS = frozenset({
    "Loader",       # yaml.Loader — full Python tags
    "FullLoader",   # yaml.FullLoader — can construct Python objects since 5.1
    "UnsafeLoader", # yaml.UnsafeLoader — explicitly unsafe
    "CLoader",      # yaml.CLoader — C accelerator of Loader (same risk)
})

# Pre-filter: any file containing yaml.load( is worth AST-parsing
_YAML_LOAD_RE = re.compile(r"\byaml\s*\.\s*load\s*\(")


def check_yaml_load_in_python(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Scan a Python source file for unsafe yaml.load() calls.

    yaml.load() with Loader=yaml.Loader, yaml.FullLoader, yaml.UnsafeLoader,
    or no Loader argument is a deserialization attack vector — an attacker-
    controlled YAML document can execute arbitrary Python code.

    yaml.safe_load() and yaml.load(data, Loader=yaml.SafeLoader) are safe
    and will NOT be flagged.

    Args:
        path: Absolute path to the .py file.
        rel_path: Relative path for display in findings.

    Returns:
        List of PreinstallFinding objects (may be empty).
    """
    findings: list[PreinstallFinding] = []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    if not _YAML_LOAD_RE.search(source):
        return findings

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    lines = source.splitlines()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        dotted = _dotted_yaml_name(node.func)
        if dotted != "yaml.load":
            continue

        # Determine Loader argument
        loader = _extract_loader(node)

        if loader is None:
            # No Loader argument — unsafe (legacy behaviour, deprecated since 5.1)
            findings.append(PreinstallFinding(
                category=ThreatCategory.YAML_INJECTION,
                level=ThreatLevel.CRITICAL,
                file=rel_path,
                line=node.lineno,
                description=(
                    "yaml.load() called without a Loader argument. "
                    "This uses the full Python deserializer and executes "
                    "arbitrary code in attacker-controlled YAML documents."
                ),
                evidence=_source_line(lines, node.lineno),
                recommendation=(
                    "Replace with yaml.safe_load(). If you need a custom Loader, "
                    "use yaml.load(data, Loader=yaml.SafeLoader)."
                ),
            ))
        elif loader in _UNSAFE_LOADERS:
            findings.append(PreinstallFinding(
                category=ThreatCategory.YAML_INJECTION,
                level=ThreatLevel.CRITICAL,
                file=rel_path,
                line=node.lineno,
                description=(
                    f"yaml.load() with Loader=yaml.{loader} is a deserialization "
                    "attack vector. Attacker-controlled YAML documents can execute "
                    "arbitrary Python code via !!python/object tags."
                ),
                evidence=_source_line(lines, node.lineno),
                recommendation=(
                    "Replace with yaml.safe_load() or use "
                    "yaml.load(data, Loader=yaml.SafeLoader)."
                ),
            ))
        # Loader=yaml.SafeLoader or Loader=yaml.BaseLoader → safe, no finding

    return findings


def _dotted_yaml_name(node: ast.expr) -> str:
    """Extract a.b name from an AST Attribute/Name node (two levels only)."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return ""


def _extract_loader(call: ast.Call) -> str | None:
    """Return the Loader name string from a yaml.load() call, or None if absent."""
    # Positional: yaml.load(data, yaml.Loader) — second positional arg
    if len(call.args) >= 2:
        arg = call.args[1]
        if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
            return arg.attr  # e.g. "Loader", "SafeLoader"

    # Keyword: yaml.load(data, Loader=yaml.Loader)
    for kw in call.keywords:
        if kw.arg == "Loader":
            val = kw.value
            if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
                return val.attr
            if isinstance(val, ast.Name):
                return val.id

    return None  # No Loader argument


def _source_line(lines: list[str], lineno: int) -> str:
    idx = lineno - 1
    if 0 <= idx < len(lines):
        return lines[idx].strip()[:200]
    return ""
