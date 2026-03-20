"""Deserialization attack detection: pickle, marshal, shelve.

ALL of these are CRITICAL deserialization attack vectors:

1. Binary pickle files (.pkl, .pickle, .joblib extensions)
2. Python source using:
   - pickle.loads / pickle.load / cPickle.* / _pickle.*
   - marshal.loads / marshal.load  (executes arbitrary bytecode)
   - shelve.open                   (uses pickle internally)
   - torch.load without weights_only=True
   - numpy.load with allow_pickle=True
3. Direct imports: `from pickle import loads`, `from marshal import loads`

The scanner never loads or executes files — it uses AST analysis only.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from agentward.preinstall.models import PreinstallFinding, ThreatCategory, ThreatLevel


# Extensions that indicate serialized binary data
_PICKLE_EXTENSIONS = frozenset({".pkl", ".pickle", ".joblib"})

# Patterns that load arbitrary binary data (matched by module.function)
# ALL are CRITICAL — every entry here is a deserialization attack vector
_DANGEROUS_CALLS: dict[str, str] = {
    # pickle family
    "pickle.loads":     "deserializes arbitrary bytes — trivial RCE vector",
    "pickle.load":      "deserializes an arbitrary file stream — trivial RCE vector",
    "cPickle.loads":    "deserializes arbitrary bytes (C extension) — trivial RCE vector",
    "cPickle.load":     "deserializes an arbitrary file stream (C extension) — trivial RCE vector",
    "joblib.load":      "deserializes pickled objects — RCE if file is attacker-controlled",
    "_pickle.loads":    "low-level C pickle deserializer — RCE vector",
    "_pickle.load":     "low-level C pickle deserializer — RCE vector",
    # marshal — executes arbitrary compiled bytecode
    "marshal.loads":    "deserializes arbitrary Python bytecode — arbitrary code execution",
    "marshal.load":     "deserializes arbitrary Python bytecode from file — arbitrary code execution",
    # shelve — backed by pickle, same RCE risk
    "shelve.open":      "opens a shelve database backed by pickle — RCE if db file is attacker-controlled",
}

# torch.load is only safe with weights_only=True (added in PyTorch 1.13)
_TORCH_LOAD = "torch.load"

# numpy.load on .npy/.npz allows pickles via allow_pickle=True
_NUMPY_LOAD = "numpy.load"

# Regex for a quick pre-filter before AST parsing
_PICKLE_IMPORT_RE = re.compile(r"\bimport\s+(?:pickle|cPickle|_pickle|marshal|shelve)\b")
_PICKLE_CALL_RE = re.compile(
    r"\b(?:pickle|cPickle|_pickle|marshal|shelve)\s*\.\s*(?:loads?|dumps?|open)\b"
)


def check_pickle(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Scan a Python file for pickle deserialization usage.

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

    # Quick pre-filter — skip AST overhead if no deser references at all
    has_deser_ref = (
        _PICKLE_IMPORT_RE.search(source)
        or _PICKLE_CALL_RE.search(source)
        or "from pickle" in source
        or "from cPickle" in source
        or "from _pickle" in source
        or "from marshal" in source
        or "from shelve" in source
    )
    if not has_deser_ref:
        has_joblib = "joblib" in source
        has_torch_load = "torch.load" in source
        has_numpy_load = "numpy.load" in source
        if not (has_joblib or has_torch_load or has_numpy_load):
            return findings

    # Full AST analysis
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return findings

    visitor = _PickleVisitor(rel_path, source)
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings


def check_pickle_binary(path: Path, rel_path: str) -> list[PreinstallFinding]:
    """Flag a binary pickle file by extension.

    Presence of a .pkl/.pickle/.joblib file in a skill package is a
    CRITICAL deserialization attack vector — loading it executes arbitrary code.

    Args:
        path: Absolute path to the file.
        rel_path: Relative path for display.

    Returns:
        A single CRITICAL finding, always (extension is sufficient signal).
    """
    return [
        PreinstallFinding(
            category=ThreatCategory.PICKLE_DESERIALIZATION,
            level=ThreatLevel.CRITICAL,
            file=rel_path,
            line=None,
            description=(
                f"Pickle binary file '{path.name}' found. "
                "Loading this file with pickle.load() executes arbitrary code."
            ),
            evidence=path.name,
            recommendation=(
                "Do not distribute serialized model weights or data as pickle files. "
                "Use safe formats (JSON, ONNX, safetensors, CSV) instead. "
                "If this file is required, verify its SHA-256 checksum from the "
                "official source before loading."
            ),
        )
    ]


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------


class _PickleVisitor(ast.NodeVisitor):
    """Walk an AST and collect dangerous pickle/deserialization usages."""

    _DESER_MODULES = frozenset({"pickle", "cPickle", "_pickle", "marshal", "shelve"})

    def __init__(self, rel_path: str, source: str) -> None:
        self._rel_path = rel_path
        self._lines = source.splitlines()
        self.findings: list[PreinstallFinding] = []
        self._pickle_aliases: set[str] = set()  # local names for deser modules

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in self._DESER_MODULES:
                name = alias.asname if alias.asname else alias.name
                self._pickle_aliases.add(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in ("pickle", "cPickle", "_pickle"):
            for alias in node.names:
                imported = alias.asname if alias.asname else alias.name
                if imported in ("loads", "load"):
                    self._add_finding(
                        node.lineno,
                        ThreatLevel.CRITICAL,
                        f"Direct import of pickle.{imported} — deserialization of "
                        "untrusted data leads to arbitrary code execution.",
                        self._source_line(node.lineno),
                    )
        elif node.module == "marshal":
            for alias in node.names:
                imported = alias.asname if alias.asname else alias.name
                if imported in ("loads", "load"):
                    self._add_finding(
                        node.lineno,
                        ThreatLevel.CRITICAL,
                        f"Direct import of marshal.{imported} — deserializes arbitrary "
                        "Python bytecode, leading to arbitrary code execution.",
                        self._source_line(node.lineno),
                    )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        if dotted:
            self._check_call(node, dotted)
        self.generic_visit(node)

    def _check_call(self, node: ast.Call, dotted: str) -> None:
        # pickle.loads / cPickle.load etc.
        if dotted in _DANGEROUS_CALLS:
            reason = _DANGEROUS_CALLS[dotted]
            self._add_finding(
                node.lineno,
                ThreatLevel.CRITICAL,
                f"Call to {dotted}() — {reason}.",
                self._source_line(node.lineno),
            )
            return

        # torch.load — safe only with weights_only=True
        if dotted == _TORCH_LOAD:
            weights_only = _kwarg_bool(node, "weights_only")
            if weights_only is not True:
                self._add_finding(
                    node.lineno,
                    ThreatLevel.CRITICAL,
                    "torch.load() without weights_only=True deserializes a pickle "
                    "stream — arbitrary code execution if the file is attacker-controlled.",
                    self._source_line(node.lineno),
                )
            return

        # numpy.load — only risky with allow_pickle=True
        if dotted == _NUMPY_LOAD:
            allow_pickle = _kwarg_bool(node, "allow_pickle")
            if allow_pickle is True:
                self._add_finding(
                    node.lineno,
                    ThreatLevel.CRITICAL,
                    "numpy.load() with allow_pickle=True deserializes pickled objects "
                    "embedded in .npy/.npz files — arbitrary code execution if the "
                    "file is attacker-controlled.",
                    self._source_line(node.lineno),
                )
            return

        # Dynamic alias usage: if someone did `import pickle as p`, flag p.loads
        for alias in self._pickle_aliases:
            if dotted.startswith(f"{alias}."):
                suffix = dotted[len(alias) + 1:]
                if suffix in ("loads", "load"):
                    self._add_finding(
                        node.lineno,
                        ThreatLevel.CRITICAL,
                        f"Call to {dotted}() via aliased pickle import — "
                        "deserialization of untrusted data leads to arbitrary code execution.",
                        self._source_line(node.lineno),
                    )
                    return

    def _source_line(self, lineno: int) -> str:
        idx = lineno - 1
        if 0 <= idx < len(self._lines):
            return self._lines[idx].strip()[:200]
        return ""

    def _add_finding(
        self,
        lineno: int,
        level: ThreatLevel,
        description: str,
        evidence: str,
    ) -> None:
        self.findings.append(PreinstallFinding(
            category=ThreatCategory.PICKLE_DESERIALIZATION,
            level=level,
            file=self._rel_path,
            line=lineno,
            description=description,
            evidence=evidence,
            recommendation=(
                "Replace pickle with a safe serialization format: JSON for "
                "structured data, safetensors/ONNX for ML weights, msgpack for "
                "binary data. If pickle is required, load only from verified, "
                "cryptographically signed sources."
            ),
        ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dotted_name(node: ast.expr) -> str | None:
    """Extract a.b.c dotted name from an AST Attribute/Name chain."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def _kwarg_bool(call: ast.Call, kwarg_name: str) -> bool | None:
    """Extract the bool value of a keyword argument from a Call node."""
    for kw in call.keywords:
        if kw.arg == kwarg_name:
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, bool):
                return kw.value.value
    return None
