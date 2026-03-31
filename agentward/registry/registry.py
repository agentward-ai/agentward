"""MCP server risk registry — local risk metadata for known MCP servers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from agentward.registry.models import (
    RISK_LEVEL_ORDER,
    KnownRisk,
    RecommendedConstraint,
    RiskLevel,
    ServerEntry,
)

_BUILTIN_DATA = Path(__file__).parent / "data" / "servers.yaml"

# Characters that separate package scope/prefix from the server name
_PACKAGE_NAME_RE = re.compile(r"(?:@[^/]+/)?(?:mcp-server-|server-)?(.+)$")


def _strip_package_prefix(name: str) -> str:
    """Extract the base server name from a package identifier.

    Examples:
        "@modelcontextprotocol/server-filesystem" → "filesystem"
        "mcp-server-github" → "github"
        "filesystem" → "filesystem"
    """
    m = _PACKAGE_NAME_RE.match(name.lower().strip())
    if m:
        return m.group(1)
    return name.lower().strip()


def _parse_entry(raw: dict[str, Any]) -> ServerEntry:
    """Parse a raw YAML dict into a :class:`ServerEntry`."""
    known_risks = [
        KnownRisk(
            type=r["type"],
            description=r["description"],
            severity=r["severity"],
            cve=r.get("cve"),
        )
        for r in raw.get("known_risks", [])
    ]
    recommended = [
        RecommendedConstraint(
            argument=c["argument"],
            constraint=c["constraint"],
            value=c["value"],
        )
        for c in raw.get("recommended_constraints", [])
    ]
    return ServerEntry(
        name=raw["name"],
        package=raw["package"],
        category=raw["category"],
        risk_level=raw["risk_level"],
        known_risks=known_risks,
        recommended_constraints=recommended,
        aliases=raw.get("aliases", []),
        last_updated=raw.get("last_updated", ""),
        source=raw.get("source", "manual-review"),
        notes=raw.get("notes", ""),
    )


class ServerRegistry:
    """Local registry of MCP servers with risk metadata.

    Loads the built-in ``servers.yaml`` plus any extra registry files
    provided by the caller. Supports name/alias lookup, category/risk
    filtering, and audit event enrichment.

    Args:
        extra_registry_paths: Optional list of additional YAML files to load.
            Each file must have a top-level ``servers`` list in the same format
            as the built-in registry.
    """

    def __init__(self, extra_registry_paths: list[Path] | None = None) -> None:
        self._entries: list[ServerEntry] = []
        self._by_name: dict[str, ServerEntry] = {}

        # Load built-in data
        self._load_yaml(_BUILTIN_DATA)

        # Load extra paths if provided
        for path in extra_registry_paths or []:
            self._load_yaml(path)

    def _load_yaml(self, path: Path) -> None:
        """Load a registry YAML file and merge into the in-memory store."""
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        for raw in data.get("servers", []):
            try:
                entry = _parse_entry(raw)
            except (KeyError, TypeError):
                continue
            self._entries.append(entry)
            # Index by canonical name
            self._by_name[entry.name.lower()] = entry
            # Index by all aliases
            for alias in entry.aliases:
                alias_key = alias.lower()
                if alias_key not in self._by_name:
                    self._by_name[alias_key] = entry
            # Index by stripped package name
            stripped = _strip_package_prefix(entry.package)
            if stripped not in self._by_name:
                self._by_name[stripped] = entry

    def lookup(self, server_name: str) -> ServerEntry | None:
        """Find a registry entry by name or alias.

        Matching is case-insensitive. Also tries stripping common prefixes
        like ``@scope/mcp-server-`` so that raw package names resolve correctly.

        Args:
            server_name: Server name, package name, or alias to look up.

        Returns:
            The :class:`ServerEntry` if found, otherwise None.
        """
        key = server_name.lower().strip()
        if key in self._by_name:
            return self._by_name[key]
        # Try stripping package prefix
        stripped = _strip_package_prefix(key)
        if stripped in self._by_name:
            return self._by_name[stripped]
        return None

    def get_risk_level(self, server_name: str) -> RiskLevel | None:
        """Return the risk level for a server, or None if unknown.

        Args:
            server_name: Server name, package name, or alias.

        Returns:
            One of ``"critical"``, ``"high"``, ``"medium"``, ``"low"``, or None.
        """
        entry = self.lookup(server_name)
        return entry.risk_level if entry is not None else None

    def get_recommended_constraints(self, server_name: str) -> list[RecommendedConstraint]:
        """Return recommended constraints for a server.

        Args:
            server_name: Server name, package name, or alias.

        Returns:
            List of :class:`RecommendedConstraint`, empty if server not found.
        """
        entry = self.lookup(server_name)
        return entry.recommended_constraints if entry is not None else []

    def search(
        self,
        category: str | None = None,
        min_risk: RiskLevel | None = None,
    ) -> list[ServerEntry]:
        """Filter registry entries by category and/or minimum risk level.

        Args:
            category: If provided, only return entries with this category.
            min_risk: If provided, only return entries with risk_level >= this.

        Returns:
            Filtered list of :class:`ServerEntry`.
        """
        results = list(self._entries)
        if category is not None:
            results = [e for e in results if e.category.lower() == category.lower()]
        if min_risk is not None:
            min_rank = RISK_LEVEL_ORDER.get(min_risk, 0)
            results = [
                e for e in results
                if RISK_LEVEL_ORDER.get(e.risk_level, 0) >= min_rank
            ]
        return results

    def all_servers(self) -> list[ServerEntry]:
        """Return all servers sorted by risk_level descending, then name ascending."""
        return sorted(
            self._entries,
            key=lambda e: (-RISK_LEVEL_ORDER.get(e.risk_level, 0), e.name),
        )

    def enrich_audit_entry(self, server_name: str) -> dict[str, Any] | None:
        """Return a dict suitable for inclusion in an audit log entry.

        Args:
            server_name: Server name, package name, or alias.

        Returns:
            Dict with ``server``, ``risk_level``, and ``known_risks`` keys,
            or None if the server is not in the registry.
        """
        entry = self.lookup(server_name)
        if entry is None:
            return None
        return {
            "server": entry.name,
            "risk_level": entry.risk_level,
            "known_risks": [
                {"type": r.type, "severity": r.severity, "description": r.description}
                for r in entry.known_risks
            ],
        }
