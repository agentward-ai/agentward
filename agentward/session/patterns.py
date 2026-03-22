"""Session-level attack pattern detectors.

Each pattern matcher implements the ``PatternMatcher`` abstract base class:
it receives a list of ``BufferEntry`` objects representing the recent call
sequence (oldest first) and returns a ``MatchResult`` with a confidence score
(0.0–1.0) and human-readable evidence.

Five patterns are implemented, targeting distinct evasion techniques:

  - ``PayloadFragmentation``: Detects base64/hex/URL-encoded chunks and split
    shell commands spread across calls that individually look harmless but
    assemble into a complete payload.

  - ``PrivilegeEscalation``: Detects read→write→execute capability accumulation
    over the session, with bonus scoring when the same resource appears across
    tiers.

  - ``ReconnaissancePattern``: Detects systematic probing — sequential file path
    enumeration, environment variable reads, network endpoint scanning.

  - ``CircularChaining``: Detects A→B→C→A tool call loops of length ≥ 3 that
    launder data between tools.

  - ``ExfiltrationSequence``: Detects read-from-sensitive-source followed by
    write-to-external-destination within a configurable call window.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from agentward.session.buffer import BufferEntry

# ─────────────────────────────────────────────────────────────────────────────
# Result type
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class MatchResult:
    """Result from a single pattern matcher.

    Attributes:
        matched: Whether the pattern was positively detected.
        score: Confidence score from 0.0 (no signal) to 1.0 (certain match).
        reason: Human-readable explanation of the match (empty if no match).
        evidence: Specific evidence strings supporting the match (up to 5).
        pattern_name: Name of the pattern that produced this result.
    """

    matched: bool
    score: float
    reason: str
    evidence: list[str] = field(default_factory=list)
    pattern_name: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Abstract base class
# ─────────────────────────────────────────────────────────────────────────────


class PatternMatcher(ABC):
    """Abstract base class for session-level attack pattern detectors."""

    name: str = "unknown"

    @abstractmethod
    def match(self, entries: list[BufferEntry]) -> MatchResult:
        """Evaluate the pattern against the entry window.

        Args:
            entries: Recent tool call entries, oldest first.

        Returns:
            A ``MatchResult`` with the detected signal and score.
        """

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_string_values(arguments: dict[str, Any]) -> list[str]:
        """Recursively extract all string values from an arguments dict."""
        results: list[str] = []
        for val in arguments.values():
            if isinstance(val, str):
                results.append(val)
            elif isinstance(val, dict):
                results.extend(PatternMatcher._extract_string_values(val))
            elif isinstance(val, (list, tuple)):
                for item in val:
                    if isinstance(item, str):
                        results.append(item)
        return results


# ─────────────────────────────────────────────────────────────────────────────
# 1. Payload Fragmentation
# ─────────────────────────────────────────────────────────────────────────────

# Minimum 16 chars to avoid false-positives on short tokens.
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
# At least 20 hex chars (0x prefix optional).
_HEX_RE = re.compile(r'^(?:0x)?[0-9a-fA-F]{20,}$')
# Shell fragment: value ends with pipe/semicolon or starts with &&/||
_SHELL_FRAGMENT_RE = re.compile(r'(?:[|;&]\s*$|^\s*(?:&&|\|\|))')
# URL-encoded content: 8+ consecutive percent-encoded bytes
_URL_ENCODED_RE = re.compile(r'(?:%[0-9A-Fa-f]{2}){8,}')


class PayloadFragmentation(PatternMatcher):
    """Detect payloads split across multiple tool calls.

    Looks for base64 chunks, hex-encoded segments, shell command fragments,
    and URL-encoded content that appear individually harmless but collectively
    assemble into a complete payload.

    Score = min(1.0, signal_count / 4.0) — four or more entries with
    fragmentation signals saturates the score.
    """

    name = "payload_fragmentation"

    def match(self, entries: list[BufferEntry]) -> MatchResult:
        if len(entries) < 2:
            return MatchResult(
                matched=False, score=0.0, reason="",
                pattern_name=self.name,
            )

        signal_entries: list[str] = []
        for entry in entries:
            values = self._extract_string_values(entry.arguments)
            for val in values:
                stripped = val.strip()
                if _BASE64_RE.match(stripped):
                    signal_entries.append(
                        f"{entry.tool_name}: base64 chunk ({stripped[:24]}…)"
                    )
                    break
                if _HEX_RE.match(stripped):
                    signal_entries.append(
                        f"{entry.tool_name}: hex segment ({stripped[:24]}…)"
                    )
                    break
                if _SHELL_FRAGMENT_RE.search(stripped):
                    signal_entries.append(
                        f"{entry.tool_name}: shell fragment ({stripped[:40]})"
                    )
                    break
                if _URL_ENCODED_RE.search(stripped):
                    signal_entries.append(
                        f"{entry.tool_name}: url-encoded fragment"
                    )
                    break

        if not signal_entries:
            return MatchResult(
                matched=False, score=0.0,
                reason="No fragmentation signals detected.",
                pattern_name=self.name,
            )

        score = min(1.0, len(signal_entries) / 4.0)
        matched = len(signal_entries) >= 2

        return MatchResult(
            matched=matched,
            score=score,
            reason=(
                f"Potential payload fragmentation: {len(signal_entries)} call(s) "
                f"carry encoded or split data."
            ),
            evidence=signal_entries[:5],
            pattern_name=self.name,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. Privilege Escalation
# ─────────────────────────────────────────────────────────────────────────────

# Tool names use snake_case, kebab-case, or camelCase.  Split into words
# to avoid the `\b` word-boundary problem with underscores.
_SPLIT_RE = re.compile(r'[_\-./]')


def _tool_words(tool_name: str) -> frozenset[str]:
    """Return the lowercase words in a tool name split on separators."""
    return frozenset(w for w in _SPLIT_RE.split(tool_name.lower()) if w)


# Tier 1 = read, Tier 2 = write, Tier 3 = execute.
# Checked highest-tier first so "execute_read_file" → tier 3, not tier 1.
_TIER_3_WORDS = frozenset({
    "exec", "execute", "run", "eval", "spawn", "invoke",
    "shell", "cmd", "bash", "sh", "launch", "start",
})
_TIER_2_WORDS = frozenset({
    "write", "create", "put", "post", "update", "set", "save",
    "upload", "modify", "edit", "append", "store", "insert", "delete", "remove",
})
_TIER_1_WORDS = frozenset({
    "read", "get", "fetch", "list", "view", "show", "describe",
    "query", "find", "search", "stat", "ls", "open",
})

# Argument keys that commonly carry a resource path/identifier
_RESOURCE_ARG_KEYS = frozenset({
    "path", "file", "filename", "filepath", "url", "uri",
    "target", "resource", "key", "name", "src", "dst",
    "source", "destination", "input", "output", "object",
})


def _tool_capability_tier(tool_name: str) -> int | None:
    """Return the capability tier (1/2/3) for a tool name, or None if unknown."""
    words = _tool_words(tool_name)
    if words & _TIER_3_WORDS:
        return 3
    if words & _TIER_2_WORDS:
        return 2
    if words & _TIER_1_WORDS:
        return 1
    return None


def _extract_resource_paths(arguments: dict[str, Any]) -> set[str]:
    """Extract resource path values by argument key name."""
    paths: set[str] = set()
    for key, val in arguments.items():
        if key.lower() in _RESOURCE_ARG_KEYS and isinstance(val, str) and val.strip():
            paths.add(val.strip())
    return paths


class PrivilegeEscalation(PatternMatcher):
    """Detect read→write→execute capability accumulation over a session.

    Tracks the capability tier of each tool call and the resource paths in
    arguments. Flags when tier progression occurs, with higher scores for
    full escalation and for escalation targeting the same resource.

    Scoring:
        read→write on same resource  : 0.60
        read→write (any resource)    : 0.40
        partial escalation with exec : 0.65
        full read→write→exec         : 0.85
        full on same resource        : 1.00
    """

    name = "privilege_escalation"

    def match(self, entries: list[BufferEntry]) -> MatchResult:
        if len(entries) < 2:
            return MatchResult(
                matched=False, score=0.0, reason="",
                pattern_name=self.name,
            )

        tiers_seen: set[int] = set()
        resource_by_tier: dict[int, set[str]] = {1: set(), 2: set(), 3: set()}

        for entry in entries:
            tier = _tool_capability_tier(entry.tool_name)
            if tier is not None:
                tiers_seen.add(tier)
                paths = _extract_resource_paths(entry.arguments)
                resource_by_tier[tier].update(paths)

        if not tiers_seen:
            return MatchResult(
                matched=False, score=0.0,
                reason="No capability-mapped tools in window.",
                pattern_name=self.name,
            )

        evidence: list[str] = []
        score = 0.0
        reason = ""

        if 1 in tiers_seen and 2 in tiers_seen and 3 in tiers_seen:
            shared = (
                resource_by_tier[1] & resource_by_tier[2] & resource_by_tier[3]
            )
            if shared:
                score = 1.0
                reason = "Full read→write→execute escalation on shared resource(s)."
                evidence = [f"Shared resource: {r}" for r in sorted(shared)[:3]]
            else:
                score = 0.85
                reason = "Full read→write→execute capability escalation observed."
                evidence = [
                    f"Read tools accessed: {resource_by_tier[1] or '{unspecified}'}",
                    f"Write tools accessed: {resource_by_tier[2] or '{unspecified}'}",
                    f"Exec tools invoked: {resource_by_tier[3] or '{unspecified}'}",
                ]
        elif 3 in tiers_seen and (1 in tiers_seen or 2 in tiers_seen):
            score = 0.65
            reason = "Capability escalation includes execute-tier tool invocation."
            evidence = [f"Tiers present: {sorted(tiers_seen)}"]
        elif 1 in tiers_seen and 2 in tiers_seen:
            shared = resource_by_tier[1] & resource_by_tier[2]
            if shared:
                score = 0.60
                reason = "Read→write escalation targeting the same resource."
                evidence = [f"Shared resource: {r}" for r in sorted(shared)[:3]]
            else:
                score = 0.40
                reason = "Read→write capability transition observed."

        matched = score >= 0.55
        return MatchResult(
            matched=matched,
            score=score,
            reason=reason or "No escalation pattern.",
            evidence=evidence,
            pattern_name=self.name,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 3. Reconnaissance Pattern
# ─────────────────────────────────────────────────────────────────────────────

_ENV_PROBE_WORDS = frozenset({
    "env", "environ", "getenv", "config", "settings",
    "variable", "secret", "credential", "token",
})
_FS_PROBE_WORDS = frozenset({
    "ls", "list", "dir", "stat", "readdir", "glob",
    "find", "walk", "tree", "scandir",
})
_NET_PROBE_WORDS = frozenset({
    "scan", "ping", "probe", "nmap", "port",
    "connect", "socket", "lookup", "resolve", "dns",
})
# Directory traversal sequences in argument values
_PATH_TRAVERSAL_RE = re.compile(r'(?:\.\./|/\.\.|~/)')
# Trailing digits to strip for prefix comparison (file1.txt → file.txt)
_NUMERIC_SUFFIX_RE = re.compile(r'\d+(\.[^./\\]+)?$')


def _path_prefix(s: str) -> str:
    """Return the path stripped of its trailing numeric suffix."""
    return _NUMERIC_SUFFIX_RE.sub('', s).rstrip('/\\')


class ReconnaissancePattern(PatternMatcher):
    """Detect systematic probing behaviour across multiple calls.

    Three sub-patterns are recognised:
      1. **Environment probing**: repeated calls to tools that read env vars,
         config, secrets, or credential stores.
      2. **Filesystem enumeration**: calls with repeated path prefixes
         (sequential reads) or directory traversal attempts.
      3. **Network scanning**: repeated network probe tools.

    Score = min(1.0, total_signals / max(len(entries), 1) * 1.5)
    """

    name = "reconnaissance"

    def match(self, entries: list[BufferEntry]) -> MatchResult:
        if len(entries) < 3:
            return MatchResult(
                matched=False, score=0.0, reason="",
                pattern_name=self.name,
            )

        env_probes: list[str] = []
        fs_probes: list[str] = []
        net_probes: list[str] = []
        path_prefixes: list[str] = []

        for entry in entries:
            tool = entry.tool_name
            words = _tool_words(tool)
            if words & _ENV_PROBE_WORDS:
                env_probes.append(tool)
            if words & _FS_PROBE_WORDS:
                fs_probes.append(tool)
            if words & _NET_PROBE_WORDS:
                net_probes.append(tool)

            for val in self._extract_string_values(entry.arguments):
                if '/' in val or '\\' in val or val.startswith('.'):
                    path_prefixes.append(_path_prefix(val))
                if _PATH_TRAVERSAL_RE.search(val):
                    fs_probes.append(f"traversal:{tool}")
                    break

        # A prefix appearing 3+ times suggests repeated reads of same location
        prefix_counts: dict[str, int] = {}
        for p in path_prefixes:
            if p:
                prefix_counts[p] = prefix_counts.get(p, 0) + 1
        repeated_prefixes = [p for p, c in prefix_counts.items() if c >= 3]

        evidence: list[str] = []
        total_signals = 0

        if len(env_probes) >= 2:
            total_signals += len(env_probes)
            unique_tools = ", ".join(sorted(set(env_probes))[:3])
            evidence.append(
                f"Environment probing: {len(env_probes)} call(s) ({unique_tools})"
            )
        if len(fs_probes) >= 2 or repeated_prefixes:
            total_signals += len(fs_probes) + len(repeated_prefixes) * 2
            if repeated_prefixes:
                evidence.append(
                    f"Path enumeration: {', '.join(repeated_prefixes[:2])}"
                )
            if fs_probes:
                unique = ", ".join(sorted(set(fs_probes))[:3])
                evidence.append(f"Filesystem probing: {len(fs_probes)} call(s) ({unique})")
        if len(net_probes) >= 2:
            total_signals += len(net_probes)
            evidence.append(
                f"Network probing: {len(net_probes)} call(s) "
                f"({', '.join(sorted(set(net_probes))[:3])})"
            )

        if not evidence:
            return MatchResult(
                matched=False, score=0.0,
                reason="No reconnaissance signals detected.",
                pattern_name=self.name,
            )

        signal_density = total_signals / max(len(entries), 1)
        score = min(1.0, signal_density * 1.5)
        matched = score >= 0.35

        return MatchResult(
            matched=matched,
            score=score,
            reason=f"Reconnaissance pattern: {'; '.join(evidence)}",
            evidence=evidence,
            pattern_name=self.name,
        )


# ─────────────────────────────────────────────────────────────────────────────
# 4. Circular Chaining
# ─────────────────────────────────────────────────────────────────────────────


class CircularChaining(PatternMatcher):
    """Detect A→B→C→A tool call loops that launder data between tools.

    Builds a directed graph of consecutive tool call transitions and runs DFS
    cycle detection. Only cycles involving at least 3 distinct tools are
    flagged — simple A→B→A back-and-forth retries are not.

    Scoring:
        Cycle length 3   : 0.70
        Cycle length 4+  : 0.90
    """

    name = "circular_chaining"

    def match(self, entries: list[BufferEntry]) -> MatchResult:
        if len(entries) < 3:
            return MatchResult(
                matched=False, score=0.0, reason="",
                pattern_name=self.name,
            )

        # Build directed adjacency from consecutive tool pairs
        graph: dict[str, set[str]] = {}
        for i in range(len(entries) - 1):
            src = entries[i].tool_name
            dst = entries[i + 1].tool_name
            if src == dst:
                continue  # self-loops are not meaningful
            graph.setdefault(src, set()).add(dst)

        cycle = self._find_cycle(graph)
        if not cycle:
            return MatchResult(
                matched=False, score=0.0,
                reason="No circular chains detected.",
                pattern_name=self.name,
            )

        score = 0.90 if len(cycle) >= 4 else 0.70
        chain_str = " → ".join(cycle) + f" → {cycle[0]}"
        return MatchResult(
            matched=True,
            score=score,
            reason=f"Circular tool chain detected: {chain_str}",
            evidence=[f"Cycle ({len(cycle)} nodes): {chain_str}"],
            pattern_name=self.name,
        )

    @staticmethod
    def _find_cycle(graph: dict[str, set[str]]) -> list[str] | None:
        """Find a simple cycle of length ≥ 3 in the directed graph.

        Uses recursive DFS with a recursion stack. Returns the node list
        forming the cycle body (without the closing back-edge), or None.
        """
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def _dfs(node: str, path: list[str]) -> list[str] | None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)
            for neighbour in graph.get(node, set()):
                if neighbour in rec_stack:
                    # Back-edge found — extract cycle
                    try:
                        start = path.index(neighbour)
                    except ValueError:
                        continue
                    cycle = path[start:]
                    if len(cycle) >= 3:
                        return cycle
                    # Two-node cycle — skip
                elif neighbour not in visited:
                    result = _dfs(neighbour, path)
                    if result is not None:
                        return result
            path.pop()
            rec_stack.discard(node)
            return None

        for start_node in list(graph.keys()):
            if start_node not in visited:
                result = _dfs(start_node, [])
                if result is not None:
                    return result

        return None


# ─────────────────────────────────────────────────────────────────────────────
# 5. Exfiltration Sequence
# ─────────────────────────────────────────────────────────────────────────────

# Source: reads from sensitive internal data stores
_SOURCE_VERB_WORDS = frozenset({
    "read", "get", "fetch", "query", "select", "scan", "dump",
    "export", "extract", "load", "retrieve", "list", "find",
})
_SOURCE_NOUN_WORDS = frozenset({
    "file", "db", "database", "sql", "table", "record", "row",
    "secret", "password", "credential", "token", "key", "cert",
    "certificate", "config", "settings", "env", "private", "vault",
})

# Sink: writes to external / untrusted destinations
_SINK_VERB_WORDS = frozenset({
    "send", "post", "upload", "write", "push", "transmit",
    "email", "mail", "webhook", "notify", "publish", "broadcast",
    "forward", "relay", "emit", "output", "export", "request", "http", "curl", "put",
})
_SINK_NOUN_WORDS = frozenset({
    "email", "smtp", "http", "https", "url", "endpoint", "webhook",
    "server", "remote", "external", "cloud", "api", "internet",
    "slack", "discord", "telegram", "s3", "blob", "bucket",
})

# Max steps between a source and a sink to be considered a sequence
_EXFIL_WINDOW = 10


def _is_source_tool(tool_name: str) -> bool:
    words = _tool_words(tool_name)
    return bool(words & _SOURCE_VERB_WORDS and words & _SOURCE_NOUN_WORDS)


def _is_sink_tool(tool_name: str) -> bool:
    """Return True if the tool name suggests writing to an external destination.

    Requires BOTH a sink verb AND a sink noun so that local-write tools such
    as ``write_file`` or ``output_log`` are not false-positively classified as
    exfiltration sinks.  Tools like ``send_email``, ``post_webhook``, and
    ``upload_s3`` match because both components are present.
    """
    words = _tool_words(tool_name)
    return bool(words & _SINK_VERB_WORDS and words & _SINK_NOUN_WORDS)


class ExfiltrationSequence(PatternMatcher):
    """Detect read-from-sensitive-source then write-to-external-sink sequences.

    Classifies each tool by name heuristics and looks for source→sink pairs
    within a call window of ``_EXFIL_WINDOW`` steps. Bonus score when the
    same argument values appear in both source and sink (data continuity).

    Scoring:
        1 source→sink pair                        : 0.60
        2+ source→sink pairs                      : 0.80
        Any pair with shared argument values      : 0.90
    """

    name = "exfiltration_sequence"

    def match(self, entries: list[BufferEntry]) -> MatchResult:
        if len(entries) < 2:
            return MatchResult(
                matched=False, score=0.0, reason="",
                pattern_name=self.name,
            )

        sources: list[tuple[int, BufferEntry]] = []
        sinks: list[tuple[int, BufferEntry]] = []

        for i, entry in enumerate(entries):
            if _is_source_tool(entry.tool_name):
                sources.append((i, entry))
            elif _is_sink_tool(entry.tool_name):
                sinks.append((i, entry))

        if not sources or not sinks:
            return MatchResult(
                matched=False, score=0.0,
                reason="No source/sink tool pair found.",
                pattern_name=self.name,
            )

        # Find source→sink pairs within the exfil window
        pairs: list[tuple[BufferEntry, BufferEntry]] = []
        for src_idx, src_entry in sources:
            for sink_idx, sink_entry in sinks:
                gap = sink_idx - src_idx
                if 0 < gap <= _EXFIL_WINDOW:
                    pairs.append((src_entry, sink_entry))

        if not pairs:
            return MatchResult(
                matched=False, score=0.0,
                reason="Source and sink tools present but no sequential pair.",
                pattern_name=self.name,
            )

        # Check for data continuity: same string value appears in source and sink args
        continuity_pairs: list[tuple[BufferEntry, BufferEntry]] = []
        for src, sink in pairs:
            src_vals = set(self._extract_string_values(src.arguments))
            sink_vals = set(self._extract_string_values(sink.arguments))
            if src_vals & sink_vals:
                continuity_pairs.append((src, sink))

        evidence = [
            f"{src.tool_name} → {sink.tool_name}"
            for src, sink in pairs[:3]
        ]

        if continuity_pairs:
            score = 0.90
            reason = (
                f"Exfiltration sequence with argument continuity: "
                f"{len(continuity_pairs)} pair(s)."
            )
        elif len(pairs) >= 2:
            score = 0.80
            reason = f"Multiple source→sink sequences: {len(pairs)} pair(s)."
        else:
            src, sink = pairs[0]
            score = 0.60
            reason = f"Potential exfiltration: {src.tool_name} → {sink.tool_name}."

        return MatchResult(
            matched=True,
            score=score,
            reason=reason,
            evidence=evidence,
            pattern_name=self.name,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Registry — all built-in pattern matchers
# ─────────────────────────────────────────────────────────────────────────────

ALL_PATTERNS: list[PatternMatcher] = [
    PayloadFragmentation(),
    PrivilegeEscalation(),
    ReconnaissancePattern(),
    CircularChaining(),
    ExfiltrationSequence(),
]
