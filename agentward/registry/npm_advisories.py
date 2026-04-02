"""npm package advisory registry — known compromised npm packages.

Loads the built-in npm_advisories.yaml and provides lookup by package name
and version. Integrates with ServerRegistry to flag compromised npm dependencies
of MCP servers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml

_BUILTIN_ADVISORIES = Path(__file__).parent / "data" / "npm_advisories.yaml"

NpmSeverity = Literal["critical", "high", "medium", "low"]


@dataclass
class NpmAdvisory:
    """A known compromise advisory for an npm package.

    Attributes:
        package: npm package name.
        compromised_versions: List of version strings that are compromised.
        date: ISO date of the compromise disclosure.
        actor: Threat actor name or description (if known).
        attack_type: Category of attack.
        payload: What the malicious code does.
        severity: Overall severity rating.
        notes: Optional extended notes.
    """

    package: str
    compromised_versions: list[str]
    date: str
    actor: str
    attack_type: str
    payload: str
    severity: NpmSeverity
    notes: str = ""


@dataclass
class NpmCheckResult:
    """Result of checking a set of packages against the advisory database."""

    matches: list[tuple[str, str | None, NpmAdvisory]] = field(default_factory=list)
    """List of (package_name, version_found, advisory) for each match."""

    @property
    def has_critical(self) -> bool:
        return any(adv.severity == "critical" for _, _, adv in self.matches)

    @property
    def has_high(self) -> bool:
        return any(adv.severity in ("critical", "high") for _, _, adv in self.matches)


def _parse_advisory(raw: dict) -> NpmAdvisory | None:
    """Parse a raw YAML dict into an NpmAdvisory. Returns None on parse error."""
    try:
        return NpmAdvisory(
            package=raw["package"],
            compromised_versions=raw.get("compromised_versions", []),
            date=raw.get("date", ""),
            actor=raw.get("actor", "Unknown"),
            attack_type=raw.get("attack_type", "unknown"),
            payload=raw.get("payload", ""),
            severity=raw.get("severity", "high"),
            notes=str(raw.get("notes", "") or ""),
        )
    except (KeyError, TypeError):
        return None


class NpmAdvisoryRegistry:
    """Registry of known compromised npm packages.

    Args:
        extra_paths: Optional list of additional YAML files to merge.
            Each file must have a top-level ``advisories`` list.
    """

    def __init__(self, extra_paths: list[Path] | None = None) -> None:
        self._advisories: list[NpmAdvisory] = []
        self._by_package: dict[str, list[NpmAdvisory]] = {}

        self._load_yaml(_BUILTIN_ADVISORIES)

        for path in extra_paths or []:
            self._load_yaml(path)

    def _load_yaml(self, path: Path) -> None:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        for raw in data.get("advisories", []):
            adv = _parse_advisory(raw)
            if adv is None:
                continue
            self._advisories.append(adv)
            key = adv.package.lower()
            self._by_package.setdefault(key, []).append(adv)

    def lookup(self, package_name: str) -> list[NpmAdvisory]:
        """Return all advisories for a package name (case-insensitive).

        Args:
            package_name: npm package name to look up.

        Returns:
            List of advisories, empty if none found.
        """
        return self._by_package.get(package_name.lower(), [])

    def is_compromised(self, package_name: str, version: str | None = None) -> bool:
        """Return True if a package (optionally at a specific version) is compromised.

        Args:
            package_name: npm package name.
            version: Optional specific version to check. If None, returns True
                     if any version of this package has an advisory.

        Returns:
            True if compromised.
        """
        advisories = self.lookup(package_name)
        if not advisories:
            return False
        if version is None:
            return True
        for adv in advisories:
            if version in adv.compromised_versions:
                return True
        return False

    def check_packages(
        self,
        packages: dict[str, str | None],
    ) -> NpmCheckResult:
        """Check a dict of {package_name: version_or_none} against the advisory database.

        Args:
            packages: Dict mapping package name to version (or None if version unknown).

        Returns:
            NpmCheckResult with all matches.
        """
        result = NpmCheckResult()
        for pkg_name, version in packages.items():
            advisories = self.lookup(pkg_name)
            for adv in advisories:
                if version is None or version in adv.compromised_versions or not adv.compromised_versions:
                    result.matches.append((pkg_name, version, adv))
        return result

    def all_advisories(self) -> list[NpmAdvisory]:
        """Return all advisories, sorted by date descending."""
        return sorted(self._advisories, key=lambda a: a.date, reverse=True)

    def scan_node_modules(self, node_modules_dir: Path) -> NpmCheckResult:
        """Scan a node_modules directory against the advisory database.

        Reads each package.json to extract name + version, then checks
        against the advisory database.

        Args:
            node_modules_dir: Path to node_modules directory or project root.

        Returns:
            NpmCheckResult with all compromised package matches found.
        """
        if node_modules_dir.name != "node_modules":
            candidate = node_modules_dir / "node_modules"
            if candidate.is_dir():
                node_modules_dir = candidate

        packages: dict[str, str | None] = {}

        if not node_modules_dir.is_dir():
            return NpmCheckResult()

        # Walk the top level of node_modules (don't recurse deeply for perf)
        try:
            for entry in node_modules_dir.iterdir():
                if not entry.is_dir():
                    continue
                if entry.name.startswith("."):
                    continue
                if entry.name.startswith("@"):
                    # Scoped package
                    try:
                        for scoped in entry.iterdir():
                            if scoped.is_dir():
                                self._read_pkg(scoped, packages)
                    except (OSError, PermissionError):
                        pass
                else:
                    self._read_pkg(entry, packages)
        except (OSError, PermissionError):
            pass

        return self.check_packages(packages)

    def _read_pkg(self, pkg_dir: Path, packages: dict[str, str | None]) -> None:
        """Read package.json and add name/version to packages dict."""
        pkg_json = pkg_dir / "package.json"
        if not pkg_json.is_file():
            return
        try:
            import json
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            name = data.get("name", pkg_dir.name)
            version = data.get("version")
            packages[name] = version
        except Exception:
            pass
