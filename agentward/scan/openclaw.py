"""ClawdBot / OpenClaw skill scanner.

Parses SKILL.md files (YAML frontmatter) and clawdbot.json configs to extract
tool metadata for permission analysis.

ClawdBot skills define their capabilities via SKILL.md files with YAML frontmatter:
  ---
  name: my-skill
  description: What this skill does
  metadata:
    clawdbot:
      requires:
        bins: ["some-binary"]
        env: ["API_KEY"]
  ---

The scanner also reads clawdbot.json to detect configuration-level risks
(exposed credentials, open channels, gateway settings).

Safety: This module NEVER executes user code. It reads SKILL.md as text and
parses the YAML frontmatter only.
"""

from __future__ import annotations

import json
import platform
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentward.scan.config import ServerConfig, TransportType
from agentward.scan.enumerator import EnumerationResult, ToolAnnotations, ToolInfo


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SkillRequirements:
    """Dependencies declared in a skill's YAML frontmatter."""

    bins: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    any_bins: list[str] = field(default_factory=list)


@dataclass
class SkillDefinition:
    """A ClawdBot/OpenClaw skill extracted from a SKILL.md file."""

    name: str
    description: str | None = None
    homepage: str | None = None
    emoji: str | None = None
    os_platforms: list[str] = field(default_factory=list)
    requirements: SkillRequirements = field(default_factory=SkillRequirements)
    primary_env: str | None = None
    install_steps: list[dict[str, Any]] = field(default_factory=list)
    source_file: Path = field(default_factory=lambda: Path("."))
    markdown_body: str = ""


@dataclass
class SkillCapability:
    """A capability section extracted from a SKILL.md markdown body."""

    name: str  # snake_case identifier, e.g. "trading_operations"
    heading: str  # original heading text, e.g. "Trading Operations"
    body_text: str  # collected body text (bullet points, paragraphs)


@dataclass
class ClawdBotConfig:
    """Parsed clawdbot.json configuration with security-relevant fields."""

    source_file: Path
    auth_profiles: list[str] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    gateway_enabled: bool = False
    gateway_port: int | None = None
    gateway_has_auth: bool = False
    enabled_hooks: list[str] = field(default_factory=list)
    enabled_plugins: list[str] = field(default_factory=list)
    skill_dirs: list[Path] = field(default_factory=list)


# ---------------------------------------------------------------------------
# YAML frontmatter parser (no PyYAML dependency — uses simple parsing)
# ---------------------------------------------------------------------------

# We avoid importing yaml to keep dependencies minimal. The SKILL.md
# frontmatter is simple enough to parse with a lightweight approach.
# However, if PyYAML is available (it's already a project dependency for
# policy loading), we use it for correctness.


def _parse_frontmatter(text: str) -> tuple[dict[str, Any], str]:
    """Extract YAML frontmatter and markdown body from a SKILL.md file.

    The frontmatter is delimited by --- lines at the start of the file.

    Args:
        text: The full SKILL.md content.

    Returns:
        Tuple of (frontmatter dict, markdown body string).

    Raises:
        ValueError: If no valid frontmatter is found.
    """
    text = text.lstrip("\ufeff")  # strip BOM if present

    if not text.startswith("---"):
        raise ValueError("No YAML frontmatter found (file must start with ---)")

    # Find the closing ---
    # The first --- is at position 0, find the next one
    end_match = re.search(r"\n---\s*\n", text[3:])
    if end_match is None:
        # Try end of file
        end_match = re.search(r"\n---\s*$", text[3:])
        if end_match is None:
            raise ValueError("No closing --- found for YAML frontmatter")

    yaml_str = text[3 : 3 + end_match.start() + 1]
    body_start = 3 + end_match.end()
    body = text[body_start:].strip()

    # Parse YAML
    try:
        import yaml

        try:
            frontmatter = yaml.safe_load(yaml_str)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in frontmatter: {e}") from e
    except ImportError:
        # Fallback: simple key-value parsing for flat structures
        frontmatter = _simple_yaml_parse(yaml_str)

    if not isinstance(frontmatter, dict):
        raise ValueError(f"Frontmatter must be a YAML mapping, got {type(frontmatter).__name__}")

    return frontmatter, body


def _simple_yaml_parse(text: str) -> dict[str, Any]:
    """Minimal YAML parser for flat key-value frontmatter.

    Only used as fallback when PyYAML is not available.
    Handles: strings, arrays, nested objects (one level).

    Args:
        text: YAML text to parse.

    Returns:
        A dict of parsed values.
    """
    result: dict[str, Any] = {}

    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()

        # Strip quotes
        if value and value[0] in ('"', "'") and value[-1] == value[0]:
            value = value[1:-1]

        # Simple array detection: ["a", "b"]
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1]
            items = [
                item.strip().strip('"').strip("'")
                for item in inner.split(",")
                if item.strip()
            ]
            result[key] = items
        elif value:
            result[key] = value
        # Skip empty values (nested objects need full YAML parser)

    return result


# ---------------------------------------------------------------------------
# SKILL.md scanner
# ---------------------------------------------------------------------------


def parse_skill_md(path: Path) -> SkillDefinition:
    """Parse a single SKILL.md file into a SkillDefinition.

    Args:
        path: Path to the SKILL.md file.

    Returns:
        A SkillDefinition with extracted metadata.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the frontmatter is invalid.
    """
    if not path.exists():
        raise FileNotFoundError(f"SKILL.md not found: {path}")

    text = path.read_text(encoding="utf-8")
    frontmatter, body = _parse_frontmatter(text)

    name = frontmatter.get("name", path.parent.name)
    description = frontmatter.get("description")
    homepage = frontmatter.get("homepage")

    # Extract metadata.clawdbot fields
    metadata = frontmatter.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    # Support both "clawdbot" and "openclaw" keys
    cb_meta = metadata.get("clawdbot", metadata.get("openclaw", {}))
    if not isinstance(cb_meta, dict):
        cb_meta = {}

    emoji = cb_meta.get("emoji")
    os_platforms = cb_meta.get("os", [])
    if not isinstance(os_platforms, list):
        os_platforms = []

    primary_env = cb_meta.get("primaryEnv")

    # Parse requires
    requires_raw = cb_meta.get("requires", {})
    if not isinstance(requires_raw, dict):
        requires_raw = {}

    requirements = SkillRequirements(
        bins=_ensure_list(requires_raw.get("bins", [])),
        env=_ensure_list(requires_raw.get("env", [])),
        any_bins=_ensure_list(requires_raw.get("anyBins", [])),
    )

    # Parse install steps
    install_raw = cb_meta.get("install", [])
    if not isinstance(install_raw, list):
        install_raw = []
    install_steps = [step for step in install_raw if isinstance(step, dict)]

    return SkillDefinition(
        name=name,
        description=description,
        homepage=homepage,
        emoji=emoji,
        os_platforms=os_platforms,
        requirements=requirements,
        primary_env=primary_env,
        install_steps=install_steps,
        source_file=path,
        markdown_body=body,
    )


def _ensure_list(value: Any) -> list[str]:
    """Coerce a value to a list of strings."""
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


# ---------------------------------------------------------------------------
# Skill directory discovery
# ---------------------------------------------------------------------------

# Known locations where ClawdBot/OpenClaw skills are stored
_SKILL_SEARCH_PATHS: list[tuple[str, str]] = [
    # (path_template, description) — ~ expanded, cwd resolved at scan time
    ("~/.codeium/windsurf/cascade/clawdbot/skills", "windsurf bundled"),
    ("~/.openclaw/skills", "openclaw managed"),
    ("~/clawd/skills", "workspace"),
    ("~/.clawdbot/skills", "clawdbot local"),
]

# Relative paths resolved against cwd (where clawdhub install puts skills)
_CWD_SKILL_PATHS: list[tuple[str, str]] = [
    ("skills", "project workspace"),
]


def discover_skill_dirs() -> list[tuple[Path, str]]:
    """Find all ClawdBot/OpenClaw skill directories on the system.

    Checks both fixed home-directory paths and cwd-relative paths
    (where ``clawdhub install`` places skills).

    Returns:
        List of (directory_path, location_label) tuples that exist.
    """
    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()

    for path_template, label in _SKILL_SEARCH_PATHS:
        path = Path(path_template).expanduser().resolve()
        if path.is_dir() and path not in seen:
            found.append((path, label))
            seen.add(path)

    for rel_path, label in _CWD_SKILL_PATHS:
        path = (Path.cwd() / rel_path).resolve()
        if path.is_dir() and path not in seen:
            found.append((path, label))
            seen.add(path)

    return found


def scan_skill_directory(directory: Path) -> list[SkillDefinition]:
    """Scan a directory for SKILL.md files in subdirectories.

    Each immediate subdirectory that contains a SKILL.md file
    is treated as a skill.

    Args:
        directory: Root directory to scan.

    Returns:
        List of parsed SkillDefinition objects.
    """
    if not directory.is_dir():
        return []

    skills: list[SkillDefinition] = []

    for child in sorted(directory.iterdir()):
        if not child.is_dir():
            continue
        skill_md = child / "SKILL.md"
        if skill_md.exists():
            try:
                skill = parse_skill_md(skill_md)
                skills.append(skill)
            except (ValueError, UnicodeDecodeError) as e:
                from rich.console import Console as _Console
                _warn_console = _Console(stderr=True)
                _warn_console.print(
                    f"  [#ffcc00]⚠[/#ffcc00] Skipping {skill_md}: {e}",
                    highlight=False,
                )
                continue

    return skills


def scan_all_skill_dirs() -> list[SkillDefinition]:
    """Discover and scan all known ClawdBot/OpenClaw skill directories.

    Returns:
        All skill definitions found across all known locations.
    """
    all_skills: list[SkillDefinition] = []
    for directory, _label in discover_skill_dirs():
        all_skills.extend(scan_skill_directory(directory))
    return all_skills


# ---------------------------------------------------------------------------
# clawdbot.json parser
# ---------------------------------------------------------------------------

_CONFIG_SEARCH_PATHS = [
    # New OpenClaw paths first, then legacy ClawdBot paths
    "~/.openclaw/openclaw.json",
    "~/.clawdbot/clawdbot.json",
]


def find_clawdbot_config() -> Path | None:
    """Find the OpenClaw/ClawdBot config file.

    Searches for the new ``~/.openclaw/openclaw.json`` first, then falls back
    to the legacy ``~/.clawdbot/clawdbot.json``.

    Returns:
        Path to the config if found, None otherwise.
    """
    for path_str in _CONFIG_SEARCH_PATHS:
        path = Path(path_str).expanduser()
        if path.exists():
            return path
    return None


def parse_clawdbot_config(path: Path) -> ClawdBotConfig:
    """Parse an OpenClaw/ClawdBot config file for security-relevant configuration.

    Extracts auth profiles, channels, gateway settings, hooks, and plugins
    without capturing actual secrets (tokens, passwords).

    Args:
        path: Path to openclaw.json or clawdbot.json.

    Returns:
        A ClawdBotConfig with security-relevant metadata.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the JSON is malformed.
    """
    if not path.exists():
        raise FileNotFoundError(f"OpenClaw config not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse {path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"OpenClaw config must be a JSON object, got {type(data).__name__}")

    # Auth profiles — extract names only, NOT tokens
    auth_data = data.get("auth", {})
    auth_profiles: list[str] = []
    if isinstance(auth_data, dict):
        auth_profiles = list(auth_data.keys())

    # Channels — extract names/types
    channels_data = data.get("channels", {})
    channels: list[str] = []
    if isinstance(channels_data, dict):
        channels = list(channels_data.keys())

    # Gateway
    gateway_data = data.get("gateway", {})
    gateway_enabled = False
    gateway_port = None
    gateway_has_auth = False
    if isinstance(gateway_data, dict):
        gateway_enabled = bool(gateway_data.get("port"))
        port = gateway_data.get("port")
        if isinstance(port, int):
            gateway_port = port
        gateway_has_auth = bool(gateway_data.get("auth"))

    # Hooks
    hooks_data = data.get("hooks", {})
    enabled_hooks: list[str] = []
    if isinstance(hooks_data, dict):
        enabled_hooks = list(hooks_data.keys())

    # Plugins
    plugins_data = data.get("plugins", {})
    enabled_plugins: list[str] = []
    if isinstance(plugins_data, dict):
        enabled_plugins = list(plugins_data.keys())

    # Skill directories from config
    skills_data = data.get("skills", {})
    skill_dirs: list[Path] = []
    if isinstance(skills_data, dict):
        dirs = skills_data.get("dirs", [])
        if isinstance(dirs, list):
            skill_dirs = [Path(d).expanduser() for d in dirs if isinstance(d, str)]

    return ClawdBotConfig(
        source_file=path,
        auth_profiles=auth_profiles,
        channels=channels,
        gateway_enabled=gateway_enabled,
        gateway_port=gateway_port,
        gateway_has_auth=gateway_has_auth,
        enabled_hooks=enabled_hooks,
        enabled_plugins=enabled_plugins,
        skill_dirs=skill_dirs,
    )


# ---------------------------------------------------------------------------
# Bridge: convert to EnumerationResult for the downstream pipeline
# ---------------------------------------------------------------------------

# Known binaries and what data access they imply
_BIN_RISK_SIGNALS: dict[str, dict[str, Any]] = {
    # Shell/execution
    "bash": {"type": "shell"},
    "sh": {"type": "shell"},
    "zsh": {"type": "shell"},
    # Network
    "curl": {"type": "network"},
    "wget": {"type": "network"},
    "http": {"type": "network"},
    # Email
    "himalaya": {"type": "email"},
    "msmtp": {"type": "email"},
    "sendmail": {"type": "email"},
    # Messaging
    "discord": {"type": "messaging"},
    "slack": {"type": "messaging"},
    "imsg": {"type": "messaging"},
    "wacli": {"type": "messaging"},
    "bluebubbles": {"type": "messaging"},
    "bird": {"type": "messaging"},  # X/Twitter CLI
    # Browser
    "chrome": {"type": "browser"},
    "chromium": {"type": "browser"},
    "firefox": {"type": "browser"},
    "playwright": {"type": "browser"},
    # Filesystem
    "rsync": {"type": "filesystem"},
    "tar": {"type": "filesystem"},
    # Code
    "git": {"type": "code"},
    "gh": {"type": "code"},
    # Credentials
    "op": {"type": "credentials"},  # 1Password CLI
    "keychain": {"type": "credentials"},
    # Coding agents (shell execution)
    "claude": {"type": "shell"},
    "codex": {"type": "shell"},
    "opencode": {"type": "shell"},
    "pi": {"type": "shell"},
}

# Known env var patterns and what they signal
_ENV_RISK_PATTERNS: list[tuple[str, str]] = [
    ("API_KEY", "credentials"),
    ("TOKEN", "credentials"),
    ("SECRET", "credentials"),
    ("PASSWORD", "credentials"),
    ("AUTH", "credentials"),
]

# ---------------------------------------------------------------------------
# Markdown body capability extraction
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{2,3})\s+(.+)$")

# Documentation sections that should NOT be treated as capabilities.
_DOC_SECTIONS = frozenset({
    "usage",
    "configuration",
    "setup",
    "install",
    "installation",
    "safety",
    "safety & access control",
    "common commands",
    "prerequisites",
    "requirements",
    "getting started",
    "troubleshooting",
    "faq",
    "notes",
    "examples",
    "reference",
    "references",
    "changelog",
    "license",
    "capabilities overview",
    "features",
    "overview",
    "resources",
    "best practices",
    "tips for success",
    "tips",
    "quick start",
    "api workflow",
    "environment variables",
    "supported chains",
    "error handling",
    "prompt examples by category",
    "common patterns",
    "option 1: bankr cli (recommended)",
    "option 2: rest api (direct)",
    "cli command reference",
    "core commands",
    "configuration commands",
    "getting an api key",
    "first-time setup",
    "see also",
    "uninstall",
    "upgrade",
    "updates",
    "migration",
    "compatibility",
    "contributing",
    "acknowledgements",
    "credits",
    "about",
    "contact",
    "support",
})


def _heading_to_snake_case(heading: str) -> str:
    """Normalize a markdown heading to a snake_case identifier.

    Args:
        heading: The heading text, e.g. "Trading Operations".

    Returns:
        Snake_case identifier, e.g. "trading_operations".
    """
    # Lowercase, strip non-alphanumeric (except spaces), collapse spaces to _
    name = heading.lower().strip()
    name = re.sub(r"[^a-z0-9\s]", "", name)
    name = re.sub(r"\s+", "_", name).strip("_")
    return name


def _extract_capabilities(markdown_body: str) -> list[SkillCapability]:
    """Extract capability sections from a SKILL.md markdown body.

    Strategy: Look for a capabilities parent heading (``## Capabilities Overview``,
    ``## Capabilities``, ``## Features``, etc.) and extract all ``###``
    sub-headings beneath it. This avoids picking up documentation sections
    like ``## Common Commands``, ``## Troubleshooting``, etc.

    Falls back to scanning standalone ``##`` headings only when no
    capabilities parent is found AND there are 3+ non-doc ``##`` sections
    (indicating a structured skill without the standard parent heading).

    Args:
        markdown_body: The markdown content below the YAML frontmatter.

    Returns:
        List of extracted capabilities (empty if skill is simple/unstructured).
    """
    if not markdown_body.strip():
        return []

    # -- Pass 1: parse all sections with their parent context ----------------
    lines = markdown_body.split("\n")

    # Recognized parent headings whose ### children are capabilities
    _CAPABILITY_PARENTS = frozenset({
        "capabilities overview",
        "capabilities",
        "features",
        "what it can do",
        "core features",
    })

    # Track structured sections: (level, heading, body_lines, parent_h2)
    sections: list[tuple[str, str, list[str], str | None]] = []
    current_heading: str | None = None
    current_level: str | None = None
    current_body: list[str] = []
    current_h2_parent: str | None = None  # the ## heading above current ###

    for line in lines:
        match = _HEADING_RE.match(line)
        if match:
            # Save previous section
            if current_heading is not None:
                sections.append(
                    (current_level or "", current_heading, current_body,
                     current_h2_parent if current_level == "###" else None)
                )
            current_level = match.group(1)
            current_heading = match.group(2).strip()
            current_body = []

            # Track current ## parent for ### children
            if current_level == "##":
                current_h2_parent = current_heading.lower()
        else:
            current_body.append(line)

    # Save final section
    if current_heading is not None:
        sections.append(
            (current_level or "", current_heading, current_body,
             current_h2_parent if current_level == "###" else None)
        )

    # -- Pass 2: extract capabilities from ### under capability parents ------
    capabilities: list[SkillCapability] = []

    for level, heading, body_lines, parent_h2 in sections:
        heading_lower = heading.lower()

        if heading_lower in _DOC_SECTIONS:
            continue

        # Primary path: ### headings under a recognized capability parent
        if level == "###" and parent_h2 is not None and parent_h2 in _CAPABILITY_PARENTS:
            body_text = "\n".join(body_lines).strip()
            if not body_text:
                continue
            name = _heading_to_snake_case(heading)
            if not name:
                continue
            capabilities.append(
                SkillCapability(name=name, heading=heading, body_text=body_text)
            )

    # If we found capabilities under a parent heading, return them
    if len(capabilities) >= 2:
        return capabilities

    # -- Fallback: standalone ## sections (for skills without a parent) ------
    # Only used when there's no "## Capabilities Overview" style parent.
    fallback: list[SkillCapability] = []
    for level, heading, body_lines, _ in sections:
        heading_lower = heading.lower()
        if heading_lower in _DOC_SECTIONS:
            continue
        if level == "##":
            body_text = "\n".join(body_lines).strip()
            if not body_text:
                continue
            name = _heading_to_snake_case(heading)
            if not name:
                continue
            fallback.append(
                SkillCapability(name=name, heading=heading, body_text=body_text)
            )

    # Need 3+ standalone ## sections to qualify (high threshold to avoid
    # false positives on simple skills with "## Usage" + "## Safety")
    if len(fallback) >= 3:
        return fallback

    return []


# ---------------------------------------------------------------------------
# Capability keyword classification
# ---------------------------------------------------------------------------

# Keywords indicating financial operations (trading, value transfer, etc.)
_FINANCIAL_KEYWORDS = frozenset({
    "swap", "swaps", "buy", "sell", "trade", "trades", "trading",
    "order", "orders", "bid", "ask",
    "balance", "balances", "portfolio", "price", "prices",
    "market", "markets", "exchange",
    "send", "transfer", "transfers", "withdraw", "deposit", "pay", "fund",
    "bet", "bets", "betting", "wager", "wagers",
    "leverage", "margin", "position", "positions",
    "nft", "nfts", "token", "tokens", "mint", "deploy",
    "profit", "loss", "fee", "fees", "gas", "staking", "yield",
})

# Keywords indicating network access (API calls, web requests)
_NETWORK_KEYWORDS = frozenset({
    "api", "endpoint", "request", "fetch", "query",
    "blockchain", "rpc", "transaction", "block", "chain",
    "url", "http", "webhook", "polling",
})

# Keywords indicating credential/signing operations
_CREDENTIALS_KEYWORDS = frozenset({
    "sign", "approve", "authorize", "authenticate",
    "key", "wallet", "wallets", "secret", "password",
    "deploy", "raw", "submit", "redeem",
})

# Keywords indicating write/mutating operations
_WRITE_KEYWORDS = frozenset({
    "swap", "swaps", "buy", "sell", "execute", "order", "orders",
    "send", "transfer", "withdraw", "deposit", "pay",
    "create", "modify", "update", "set", "write", "post",
    "submit", "sign", "deploy", "mint", "launch", "approve",
    "bet", "bets", "betting", "wager", "wagers",
    "leverage", "short", "long",
    "automate", "schedule", "trigger", "place",
})

# Keywords indicating destructive operations
_DESTRUCTIVE_KEYWORDS = frozenset({
    "delete", "remove", "liquidate", "burn", "revoke", "cancel", "close",
})


def _classify_capability(
    body_text: str,
) -> tuple[set[str], bool, bool]:
    """Classify a capability's risk signals from its body text keywords.

    Tokenizes the body text and checks for membership in keyword sets to
    determine what data access types and mutability the capability implies.

    Args:
        body_text: The collected text from the capability section.

    Returns:
        Tuple of (set of _cap_* property names, is_write, is_destructive).
    """
    lower = body_text.lower()
    # Tokenize: split on non-alphanumeric, filter empties
    tokens = frozenset(re.split(r"[^a-z0-9]+", lower))

    properties: set[str] = set()
    is_write = bool(tokens & _WRITE_KEYWORDS)
    is_destructive = bool(tokens & _DESTRUCTIVE_KEYWORDS)

    if tokens & _FINANCIAL_KEYWORDS:
        properties.add("_cap_financial")
    if tokens & _NETWORK_KEYWORDS:
        properties.add("_cap_network")
    if tokens & _CREDENTIALS_KEYWORDS:
        properties.add("_cap_credentials")

    # If financial or network keywords found but neither property added,
    # ensure at least network is signaled (most capabilities involve network)
    if not properties and (tokens & _FINANCIAL_KEYWORDS or tokens & _NETWORK_KEYWORDS):
        properties.add("_cap_network")

    return properties, is_write, is_destructive


def _build_base_properties(skill: SkillDefinition) -> dict[str, Any]:
    """Build synthetic schema properties from a skill's binary/env requirements.

    These properties encode risk signals (shell, network, credentials, etc.)
    so the downstream schema-based analyzer can detect them.

    Args:
        skill: The parsed skill definition.

    Returns:
        Dict of synthetic JSON schema properties.
    """
    properties: dict[str, Any] = {}

    for bin_name in skill.requirements.bins + skill.requirements.any_bins:
        signal = _BIN_RISK_SIGNALS.get(bin_name)
        if signal:
            risk_type = signal["type"]
            properties[f"_{risk_type}_bin_{bin_name}"] = {
                "type": "string",
                "description": f"Requires binary: {bin_name}",
            }

    for env_var in skill.requirements.env:
        for pattern, risk_type in _ENV_RISK_PATTERNS:
            if pattern in env_var.upper():
                properties[f"_{risk_type}_env_{env_var}"] = {
                    "type": "string",
                    "description": f"Requires env var: {env_var}",
                }
                break

    return properties


def _skill_to_tool_infos(skill: SkillDefinition) -> list[ToolInfo]:
    """Convert a SkillDefinition to one or more ToolInfo objects.

    For simple skills (no structured capability headings), returns a single
    ToolInfo matching the legacy behavior. For complex skills with markdown
    capability sections, returns one ToolInfo per capability — each inheriting
    the parent skill's binary/env signals and adding capability-specific
    risk properties.

    Args:
        skill: The parsed skill definition.

    Returns:
        List of ToolInfo objects for the downstream permission analyzer.
    """
    base_properties = _build_base_properties(skill)
    capabilities = _extract_capabilities(skill.markdown_body)

    # Simple skill path: no capability sections found → single ToolInfo
    if not capabilities:
        schema: dict[str, Any] = {}
        if base_properties:
            schema = {"type": "object", "properties": base_properties}

        desc_parts: list[str] = []
        if skill.description:
            desc_parts.append(skill.description)
        if skill.requirements.bins:
            desc_parts.append(f"Uses: {', '.join(skill.requirements.bins)}")
        if skill.requirements.any_bins:
            desc_parts.append(
                f"Uses one of: {', '.join(skill.requirements.any_bins)}"
            )
        if skill.requirements.env:
            desc_parts.append(f"Env: {', '.join(skill.requirements.env)}")

        return [
            ToolInfo(
                name=skill.name,
                description=" | ".join(desc_parts) if desc_parts else None,
                input_schema=schema,
            )
        ]

    # Complex skill path: one ToolInfo per capability
    tool_infos: list[ToolInfo] = []

    for cap in capabilities:
        cap_properties, is_write, is_destructive = _classify_capability(
            cap.body_text
        )

        # Start with inherited base properties, then add capability-specific
        props = dict(base_properties)
        for cap_prop in cap_properties:
            props[cap_prop] = {
                "type": "string",
                "description": f"Capability signal: {cap.heading}",
            }

        cap_schema: dict[str, Any] = {}
        if props:
            cap_schema = {"type": "object", "properties": props}

        # Set annotations based on keyword analysis
        if is_destructive:
            annotations = ToolAnnotations(
                read_only_hint=False, destructive_hint=True
            )
        elif is_write:
            annotations = ToolAnnotations(read_only_hint=False)
        else:
            annotations = ToolAnnotations(read_only_hint=True)

        # Build description from capability heading + first meaningful line
        first_line = ""
        for line in cap.body_text.split("\n"):
            stripped = line.strip().lstrip("-*").strip()
            if stripped:
                first_line = stripped
                break
        desc = f"{cap.heading}: {first_line}" if first_line else cap.heading

        tool_infos.append(
            ToolInfo(
                name=f"{skill.name}:{cap.name}",
                description=desc,
                input_schema=cap_schema,
                annotations=annotations,
            )
        )

    return tool_infos


def _skill_to_tool_info(skill: SkillDefinition) -> ToolInfo:
    """Convert a SkillDefinition to a single ToolInfo (backward compat).

    Returns the first ToolInfo from _skill_to_tool_infos. Kept for
    backward compatibility with existing callers and tests.

    Args:
        skill: The parsed skill definition.

    Returns:
        A ToolInfo suitable for the downstream permission analyzer.
    """
    return _skill_to_tool_infos(skill)[0]


def skills_to_enumeration_results(
    skills: list[SkillDefinition],
    location_label: str = "openclaw",
) -> list[EnumerationResult]:
    """Convert OpenClaw skill definitions into EnumerationResults.

    Each skill becomes one or more tools within a single "virtual server"
    representing the skill directory. Simple skills produce one tool;
    complex skills with structured capability sections produce one tool
    per capability.

    Args:
        skills: Skill definitions from a single directory.
        location_label: Label for the source location.

    Returns:
        A list of EnumerationResult objects (one per skill directory source).
    """
    if not skills:
        return []

    # Group skills by their parent directory (the skill collection root)
    from collections import defaultdict

    by_root: dict[Path, list[SkillDefinition]] = defaultdict(list)
    for skill in skills:
        # skill.source_file is SKILL.md; its parent is the skill dir;
        # parent of that is the collection root
        root = skill.source_file.parent.parent
        by_root[root].append(skill)

    results: list[EnumerationResult] = []
    for root, root_skills in by_root.items():
        server = ServerConfig(
            name=f"openclaw:{root.name}",
            transport=TransportType.OPENCLAW,
            source_file=root,
            client=f"openclaw:{location_label}",
        )

        tool_infos: list[ToolInfo] = []
        for s in root_skills:
            tool_infos.extend(_skill_to_tool_infos(s))

        results.append(EnumerationResult(
            server=server,
            tools=tool_infos,
            capabilities=None,
            enumeration_method=f"skill_md:{location_label}",
        ))

    return results


def config_to_enumeration_result(
    config: ClawdBotConfig,
) -> EnumerationResult | None:
    """Convert ClawdBot config-level risk signals into an EnumerationResult.

    Creates synthetic "tools" representing config-level risks:
    - Each auth profile becomes a tool (credential access)
    - Each channel becomes a tool (messaging access)
    - Gateway becomes a tool (network access)

    Args:
        config: Parsed clawdbot.json.

    Returns:
        An EnumerationResult, or None if no risk-relevant config found.
    """
    tools: list[ToolInfo] = []

    # Auth profiles → credential access signals
    for profile in config.auth_profiles:
        tools.append(ToolInfo(
            name=f"auth:{profile}",
            description=f"Authentication profile '{profile}' with stored credentials",
            input_schema={
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Stored auth token"},
                    "credentials": {"type": "string", "description": "Stored credentials"},
                },
            },
        ))

    # Channels → messaging access
    for channel in config.channels:
        tools.append(ToolInfo(
            name=f"channel:{channel}",
            description=f"Messaging channel '{channel}'",
            input_schema={
                "type": "object",
                "properties": {
                    "channel": {"type": "string", "description": f"{channel} channel"},
                },
            },
        ))

    # Gateway → network access
    if config.gateway_enabled:
        desc = f"HTTP gateway on port {config.gateway_port}"
        if not config.gateway_has_auth:
            desc += " (NO AUTH)"
        tools.append(ToolInfo(
            name="gateway",
            description=desc,
            input_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Gateway endpoint"},
                },
            },
        ))

    if not tools:
        return None

    server = ServerConfig(
        name="clawdbot-config",
        transport=TransportType.OPENCLAW,
        source_file=config.source_file,
        client="openclaw:config",
    )

    return EnumerationResult(
        server=server,
        tools=tools,
        capabilities=None,
        enumeration_method="config_analysis",
    )


# ---------------------------------------------------------------------------
# High-level scan orchestrator
# ---------------------------------------------------------------------------


def scan_openclaw() -> list[EnumerationResult]:
    """Scan all ClawdBot/OpenClaw skills and config on the system.

    Discovers skill directories, parses SKILL.md files, and analyzes
    clawdbot.json for security signals.

    Returns:
        A list of EnumerationResults for the downstream pipeline.
    """
    results: list[EnumerationResult] = []

    # Scan skill directories
    for directory, label in discover_skill_dirs():
        skills = scan_skill_directory(directory)
        if skills:
            results.extend(skills_to_enumeration_results(skills, label))

    # Analyze clawdbot.json
    config_path = find_clawdbot_config()
    if config_path is not None:
        try:
            config = parse_clawdbot_config(config_path)
            config_result = config_to_enumeration_result(config)
            if config_result is not None:
                results.append(config_result)
        except (ValueError, FileNotFoundError):
            pass  # Skip malformed config

    return results


def scan_openclaw_directory(directory: Path) -> list[EnumerationResult]:
    """Scan a specific directory for OpenClaw skills.

    Unlike scan_openclaw() which auto-discovers locations, this scans
    a user-specified directory. Used when `agentward scan <dir>` is run.

    Handles two cases:
      - ``agentward scan ~/clawd/skills/``     → scans subdirectories for SKILL.md
      - ``agentward scan ~/clawd/skills/bankr/`` → directory itself contains SKILL.md

    Args:
        directory: Directory to scan for SKILL.md files.

    Returns:
        EnumerationResults for any skills found.
    """
    # Check if the directory itself is a single skill (contains SKILL.md)
    skill_md = directory / "SKILL.md"
    if skill_md.exists():
        try:
            skill = parse_skill_md(skill_md)
            return skills_to_enumeration_results([skill], "user-specified")
        except (ValueError, UnicodeDecodeError):
            pass  # Fall through to directory scan

    skills = scan_skill_directory(directory)
    if not skills:
        return []
    return skills_to_enumeration_results(skills, "user-specified")
