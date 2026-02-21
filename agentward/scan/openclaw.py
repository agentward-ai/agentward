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
from agentward.scan.enumerator import EnumerationResult, ToolInfo


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
            except (ValueError, UnicodeDecodeError):
                # Skip skills with malformed frontmatter
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

_CLAWDBOT_CONFIG_PATHS = [
    "~/.clawdbot/clawdbot.json",
]


def find_clawdbot_config() -> Path | None:
    """Find the clawdbot.json config file.

    Returns:
        Path to the config if found, None otherwise.
    """
    for path_str in _CLAWDBOT_CONFIG_PATHS:
        path = Path(path_str).expanduser()
        if path.exists():
            return path
    return None


def parse_clawdbot_config(path: Path) -> ClawdBotConfig:
    """Parse a clawdbot.json file for security-relevant configuration.

    Extracts auth profiles, channels, gateway settings, hooks, and plugins
    without capturing actual secrets (tokens, passwords).

    Args:
        path: Path to clawdbot.json.

    Returns:
        A ClawdBotConfig with security-relevant metadata.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the JSON is malformed.
    """
    if not path.exists():
        raise FileNotFoundError(f"clawdbot.json not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse {path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(f"clawdbot.json must be a JSON object, got {type(data).__name__}")

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


def _skill_to_tool_info(skill: SkillDefinition) -> ToolInfo:
    """Convert a SkillDefinition to a ToolInfo for the permission pipeline.

    The tool name is the skill name. The input_schema is synthesized from
    the skill's required binaries and env vars (these are the "inputs"
    that determine what the skill can access).

    Args:
        skill: The parsed skill definition.

    Returns:
        A ToolInfo suitable for the downstream permission analyzer.
    """
    # Build a synthetic input_schema from requirements
    # This lets the existing schema-based analysis detect risk signals
    properties: dict[str, Any] = {}

    for bin_name in skill.requirements.bins + skill.requirements.any_bins:
        signal = _BIN_RISK_SIGNALS.get(bin_name)
        if signal:
            risk_type = signal["type"]
            # Add a synthetic property that triggers the right pattern match
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

    schema: dict[str, Any] = {}
    if properties:
        schema = {
            "type": "object",
            "properties": properties,
        }

    # Build description from skill metadata
    desc_parts: list[str] = []
    if skill.description:
        desc_parts.append(skill.description)
    if skill.requirements.bins:
        desc_parts.append(f"Uses: {', '.join(skill.requirements.bins)}")
    if skill.requirements.any_bins:
        desc_parts.append(f"Uses one of: {', '.join(skill.requirements.any_bins)}")
    if skill.requirements.env:
        desc_parts.append(f"Env: {', '.join(skill.requirements.env)}")

    return ToolInfo(
        name=skill.name,
        description=" | ".join(desc_parts) if desc_parts else None,
        input_schema=schema,
    )


def skills_to_enumeration_results(
    skills: list[SkillDefinition],
    location_label: str = "openclaw",
) -> list[EnumerationResult]:
    """Convert OpenClaw skill definitions into EnumerationResults.

    Each skill becomes a separate tool within a single "virtual server"
    representing the skill directory. This mirrors how MCP servers and
    Python tool files are represented.

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

        tool_infos = [_skill_to_tool_info(s) for s in root_skills]

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

    Args:
        directory: Directory to scan for SKILL.md files.

    Returns:
        EnumerationResults for any skills found.
    """
    skills = scan_skill_directory(directory)
    if not skills:
        return []
    return skills_to_enumeration_results(skills, "user-specified")
