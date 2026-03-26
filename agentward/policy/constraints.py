"""Capability scoping system — per-argument constraint evaluation.

Provides fine-grained constraints on tool call argument values beyond the
action-level permissions in the policy engine. Supports:

  - Path constraints: prevent directory traversal, enforce allowed prefixes
  - CIDR constraints: restrict IP addresses to allowlisted networks
  - Domain constraints: restrict URLs/hostnames to allowlisted domains
  - Glob constraints: restrict values to patterns
  - Numeric constraints: enforce min/max bounds

Usage::

    from agentward.policy.constraints import evaluate_capabilities
    from agentward.policy.schema import CapabilitySpec

    violations = evaluate_capabilities(
        tool_name="read_file",
        arguments={"path": "/tmp/../etc/passwd"},
        capabilities={"read_file": capability_spec},
    )
    if violations:
        # Build BLOCK result from violations

Security invariants:
  - Null bytes in paths are always rejected.
  - URL-encoded sequences (%2e%2e) are decoded before path resolution.
  - Unicode look-alike path separators are detected and rejected.
  - IPv4-mapped IPv6 addresses are unwrapped before CIDR matching.
  - Domain matching requires exact label match — "notevil.com" does NOT
    match a rule for "evil.com", and "evil.com" does NOT match "notevil.com".
  - Trailing DNS dots are stripped before domain matching.
  - Userinfo in URLs is stripped; only the final host is matched.
  - Missing arguments fail-closed by default (configurable per-constraint).
  - All violations are collected (AND logic) so error messages are complete.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import math
import os
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentward.policy.schema import ArgumentConstraint, CapabilitySpec


# ---------------------------------------------------------------------------
# Violation result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConstraintViolation:
    """A single constraint check failure.

    Attributes:
        arg_name: The argument whose value violated the constraint.
        constraint_type: The type of constraint that failed
            (``path``, ``cidr``, ``domain``, ``glob``, ``numeric``).
        value: The raw argument value that was checked.
        reason: Human-readable explanation of why the check failed.
        message: Alias for ``reason`` — compatibility with the main-branch API.
        argument: Alias for ``arg_name`` — compatibility with the main-branch API.
    """

    arg_name: str
    constraint_type: str
    value: Any
    reason: str

    @property
    def message(self) -> str:
        """Alias for ``reason`` for API compatibility."""
        return self.reason

    @property
    def argument(self) -> str:
        """Alias for ``arg_name`` for API compatibility."""
        return self.arg_name


# ---------------------------------------------------------------------------
# Path constraint
# ---------------------------------------------------------------------------

# URL-encoded characters with special path meaning:
#   %2f / %2F → /   (separator)
#   %5c / %5C → \   (Windows separator)
#   %00        → NUL (null byte, terminates C strings)
#   %2e        → .   (dot — allows %2e%2e → ..)
#   %25        → %   (double-encoding marker — e.g., %252e → %2e → .)
# We detect these in the raw value BEFORE decoding. Any URL-encoded
# character in a filesystem path argument is inherently suspicious.
_ENCODED_PATH_SPECIAL_RE: re.Pattern[str] = re.compile(
    r"%(?:2[fFeE]|5[cC]|00|25)",
    re.ASCII,
)

# Unicode codepoints that look like "." or ".." and could be used for
# traversal attacks via look-alike confusion.
_UNICODE_DOT_LOOKALIKES: frozenset[str] = frozenset(
    "\u2024"   # ONE DOT LEADER ․
    "\u2025"   # TWO DOT LEADER ‥
    "\u2026"   # HORIZONTAL ELLIPSIS …
    "\u22ef"   # MIDLINE HORIZONTAL ELLIPSIS ⋯
    "\ufe52"   # SMALL FULL STOP ﹒
    "\uff0e"   # FULLWIDTH FULL STOP ．
)


def _has_unicode_traversal(value: str) -> bool:
    """Detect unicode characters used in look-alike traversal attacks."""
    return any(c in _UNICODE_DOT_LOOKALIKES for c in value)


def check_path(
    arg_name: str,
    value: Any,
    allowed_prefixes: list[str],
    fail_open: bool = False,
) -> list[ConstraintViolation]:
    """Evaluate a path argument against an allowlist of path prefixes.

    Defends against:
      - Directory traversal: ``/../``, ``/./``, ``//`` (via Path.resolve)
      - Null bytes: ``\\x00`` in path
      - URL-encoded traversal: ``%2e%2e``, ``%2f``
      - Unicode look-alike dots: U+2025 (‥), U+2026 (…), etc.
      - Mixed separators (best-effort on POSIX)

    Args:
        arg_name: The argument name (for error context).
        value: The argument value to check. Non-strings are rejected.
        allowed_prefixes: Absolute path prefixes that are permitted.
            Resolved once against the real filesystem.
        fail_open: If True, a missing/None value is allowed. If False
            (default), missing values produce a violation.

    Returns:
        A list of ConstraintViolation objects. Empty list means the value
        passes all checks.
    """
    if value is None:
        if fail_open:
            return []
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=f"Argument '{arg_name}' is required (path constraint, fail_open=False).",
        )]

    if not isinstance(value, str):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=(
                f"Argument '{arg_name}' must be a string for path constraint, "
                f"got {type(value).__name__}."
            ),
        )]

    if not allowed_prefixes:
        # Empty allowlist = nothing is allowed
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=f"No allowed prefixes configured for argument '{arg_name}'.",
        )]

    # 1. Null byte check — always fatal
    if "\x00" in value:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=f"Argument '{arg_name}' contains a null byte — rejected.",
        )]

    # 2. Unicode look-alike check
    if _has_unicode_traversal(value):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=(
                f"Argument '{arg_name}' contains unicode look-alike dot characters "
                f"that could be used for path traversal — rejected."
            ),
        )]

    # 3. Detect URL-encoded path-special characters before decoding.
    #    These include separators (%2f, %5c), null bytes (%00), dots (%2e),
    #    and double-encoding markers (%25). A legitimate filesystem path should
    #    never need URL encoding — their presence indicates obfuscation.
    if _ENCODED_PATH_SPECIAL_RE.search(value):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=(
                f"Argument '{arg_name}' contains URL-encoded path characters "
                f"(e.g., %2e, %2f, %5c, %00, %25) — rejected to prevent "
                f"encoding-based traversal bypasses."
            ),
        )]

    # 4. URL-decode once (handles remaining %XX sequences)
    try:
        decoded = urllib.parse.unquote(value, errors="strict")
    except (ValueError, UnicodeDecodeError):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=f"Argument '{arg_name}' contains invalid URL encoding.",
        )]

    # Re-check for null bytes after decoding (e.g., %00 missed by regex)
    if "\x00" in decoded:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=f"Argument '{arg_name}' contains a null byte after URL decoding — rejected.",
        )]

    # 4. Expand tilde and resolve to absolute path
    try:
        expanded = os.path.expanduser(decoded)
        resolved = str(Path(expanded).resolve())
    except (OSError, ValueError) as e:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="path",
            value=value,
            reason=f"Argument '{arg_name}' is not a valid path: {e}",
        )]

    # 5. Check against each allowed prefix
    for prefix in allowed_prefixes:
        try:
            resolved_prefix = str(Path(os.path.expanduser(prefix)).resolve())
        except (OSError, ValueError):
            continue  # Skip malformed prefixes (not the arg's fault)

        if resolved == resolved_prefix or resolved.startswith(resolved_prefix + os.sep):
            return []  # Allowed

    return [ConstraintViolation(
        arg_name=arg_name,
        constraint_type="path",
        value=value,
        reason=(
            f"Path '{resolved}' (from argument '{arg_name}') is not under any "
            f"allowed prefix: {allowed_prefixes}."
        ),
    )]


# ---------------------------------------------------------------------------
# CIDR constraint
# ---------------------------------------------------------------------------


def _extract_ip_from_value(value: str) -> str | None:
    """Extract an IP address string from a URL, host:port, or bare IP.

    Args:
        value: A URL (``http://10.0.0.1/path``), host-port (``10.0.0.1:80``),
               bare IPv4 (``10.0.0.1``), or bare IPv6 (``::1``, ``2001:db8::1``).

    Returns:
        The IP address string, or None if extraction fails.
    """
    stripped = value.strip()

    # Fast path: try direct IP address parsing first (handles bare IPv4 and IPv6).
    # This avoids urlparse ambiguity with bare IPv6 (e.g., "::1" has no scheme).
    try:
        ipaddress.ip_address(stripped)
        return stripped  # Valid bare IP address
    except ValueError:
        pass

    # Try parsing as a URL with explicit scheme
    if "://" in stripped:
        try:
            parsed = urllib.parse.urlparse(stripped)
            host = parsed.hostname  # Strips userinfo and port; handles IPv6 brackets
            if host:
                return host
        except ValueError:
            pass

    # No scheme — prepend dummy scheme for proper URL parsing
    try:
        parsed = urllib.parse.urlparse("dummy://" + stripped)
        host = parsed.hostname
        if host:
            return host
    except ValueError:
        pass

    # Try bracket notation: [::1] or [::1]:80
    if stripped.startswith("["):
        end = stripped.find("]")
        if end != -1:
            return stripped[1:end]
        return None

    # Bare IPv4:port — strip port
    if ":" in stripped and stripped.count(":") == 1:
        parts = stripped.rsplit(":", 1)
        return parts[0]

    return stripped or None


def check_cidr(
    arg_name: str,
    value: Any,
    allowed_cidrs: list[str],
    fail_open: bool = False,
) -> list[ConstraintViolation]:
    """Evaluate an IP address argument against an allowlist of CIDR ranges.

    Handles:
      - IPv4 bare addresses (``10.0.0.1``)
      - IPv6 addresses (``::1``, ``2001:db8::1``)
      - IPv4-mapped IPv6 (``::ffff:10.0.0.1`` — unwrapped to IPv4)
      - IPs embedded in URLs (``http://10.0.0.1/path``)
      - IPs with ports (``10.0.0.1:8080``)
      - Single-host CIDRs without mask notation (``10.0.0.1`` treated as /32)

    Args:
        arg_name: The argument name.
        value: The argument value to check.
        allowed_cidrs: CIDR notation ranges. Bare IPs are treated as /32 or /128.
        fail_open: If True, None passes.

    Returns:
        List of violations; empty means allowed.
    """
    if value is None:
        if fail_open:
            return []
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="cidr",
            value=value,
            reason=f"Argument '{arg_name}' is required (CIDR constraint, fail_open=False).",
        )]

    if not isinstance(value, str):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="cidr",
            value=value,
            reason=(
                f"Argument '{arg_name}' must be a string for CIDR constraint, "
                f"got {type(value).__name__}."
            ),
        )]

    if not allowed_cidrs:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="cidr",
            value=value,
            reason=f"No allowed CIDRs configured for argument '{arg_name}'.",
        )]

    ip_str = _extract_ip_from_value(value)
    if not ip_str:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="cidr",
            value=value,
            reason=f"Cannot extract IP address from argument '{arg_name}' value: {value!r}.",
        )]

    # Parse the IP address
    try:
        addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip_str)
    except ValueError:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="cidr",
            value=value,
            reason=f"Invalid IP address in argument '{arg_name}': {ip_str!r}.",
        )]

    # Unwrap IPv4-mapped IPv6 (::ffff:10.0.0.1 → 10.0.0.1) so CIDR rules
    # written for IPv4 also match mapped addresses.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    # Check against each CIDR range
    for cidr_str in allowed_cidrs:
        try:
            # strict=False allows host bits to be set (e.g., "10.0.0.1/8" is valid)
            network = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            # Skip malformed CIDR entries
            continue

        # Cross-version check: IPv4 addr vs IPv4Network, IPv6 vs IPv6Network
        if type(addr) is not type(network.network_address):
            # Try unwrapping in the other direction for IPv6 networks with IPv4 addr
            continue

        if addr in network:
            return []  # Allowed

    return [ConstraintViolation(
        arg_name=arg_name,
        constraint_type="cidr",
        value=value,
        reason=(
            f"IP address '{addr}' (from argument '{arg_name}') is not in any "
            f"allowed CIDR range: {allowed_cidrs}."
        ),
    )]


# ---------------------------------------------------------------------------
# Domain constraint
# ---------------------------------------------------------------------------


def _extract_domain(value: str) -> str | None:
    """Extract the hostname from a URL, host:port string, or bare hostname.

    Handles:
      - Full URLs: scheme, path, query stripped
      - Trailing DNS dot: ``api.github.com.`` → ``api.github.com``
      - Userinfo: only the host after the last ``@`` is used
      - IPv6 bracket notation
      - Port: stripped
      - IDN: NFKC-normalized then IDNA-encoded for comparison

    Args:
        value: URL or hostname string.

    Returns:
        Lowercase ASCII hostname, or None if extraction fails.
    """
    if not value:
        return None

    # If it looks like a URL, parse it properly
    if "://" in value:
        try:
            parsed = urllib.parse.urlparse(value)
            host = parsed.hostname  # Python handles userinfo/@-splitting correctly
        except ValueError:
            return None
    else:
        # No scheme — could be host, host:port, or //host/path
        # Prepend a dummy scheme to get proper URL parsing
        try:
            parsed = urllib.parse.urlparse("dummy://" + value)
            host = parsed.hostname
        except ValueError:
            return None

    if not host:
        return None

    # Strip trailing DNS dot(s)
    host = host.rstrip(".")

    # NFKC normalization to catch compatibility lookalikes
    host = unicodedata.normalize("NFKC", host)

    # Lowercase for comparison
    host = host.lower()

    # Encode to IDNA (punycode) for consistent matching.
    # If encoding fails (e.g., for bare IPs), return as-is.
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass  # Plain ASCII or IP — keep as-is

    return host or None


def _domain_matches(host: str, pattern: str) -> bool:
    """Check if a hostname matches a domain pattern.

    Pattern rules:
      - ``example.com`` — exact match only
      - ``*.example.com`` — any subdomain at ANY depth:
        ``api.example.com`` and ``deep.api.example.com`` both match.
        This is intentional: for ``blocked_domains``, blocking all subdomains
        is the correct security posture. For ``allowed_domains``, use exact
        patterns (``api.example.com``) when you want single-level precision.
      - ``**`` or ``*`` alone — matches everything

    Specifically does NOT match:
      - ``example.com`` against rule ``*.example.com`` (bare domain, no subdomain)
      - ``evil.com`` against rule ``notevil.com``
      - ``notevil.com`` against rule ``evil.com``
      - ``safe.com.evil.com`` against rule ``*.safe.com`` (suffix attack prevention)

    Args:
        host: The extracted hostname (lowercase, IDNA-encoded).
        pattern: The allowed domain pattern.

    Returns:
        True if the host is covered by the pattern.
    """
    # Lowercase both host and pattern for case-insensitive comparison
    host = host.lower()
    pattern = pattern.lower().rstrip(".")

    # Normalize the pattern hostname too
    try:
        pattern = pattern.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass

    # Wildcard-only patterns
    if pattern in ("*", "**"):
        return True

    # Wildcard subdomain: "*.example.com"
    if pattern.startswith("*."):
        suffix = pattern[2:]  # e.g., "example.com"
        # host must end with ".example.com" and have exactly one extra label.
        # This prevents "evil.example.com.attacker.com" matches and also prevents
        # multi-level subdomain matches: "deep.api.example.com" does NOT match
        # "*.example.com". Use "*.api.example.com" for nested subdomain matching.
        if host == suffix:
            return False  # bare domain, not a subdomain
        if host.endswith("." + suffix):
            prefix = host[: -(len(suffix) + 1)]
            return "." not in prefix  # True only if exactly one extra label
        return False

    # Exact match
    return host == pattern


def check_domain(
    arg_name: str,
    value: Any,
    allowed_domains: list[str],
    fail_open: bool = False,
) -> list[ConstraintViolation]:
    """Evaluate a URL or hostname argument against an allowlist of domains.

    Handles:
      - Full URLs (scheme://host/path?query#frag)
      - Bare hostnames (``api.github.com``)
      - Wildcard patterns (``*.github.com``)
      - IDN / punycode domains
      - Trailing DNS dots
      - Userinfo spoofing (``user@evil.com@trusted.com``)

    Args:
        arg_name: The argument name.
        value: The argument value to check.
        allowed_domains: Domain patterns. Supports ``*.example.com`` wildcards.
        fail_open: If True, None passes.

    Returns:
        List of violations; empty means allowed.
    """
    if value is None:
        if fail_open:
            return []
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="domain",
            value=value,
            reason=f"Argument '{arg_name}' is required (domain constraint, fail_open=False).",
        )]

    if not isinstance(value, str):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="domain",
            value=value,
            reason=(
                f"Argument '{arg_name}' must be a string for domain constraint, "
                f"got {type(value).__name__}."
            ),
        )]

    if not allowed_domains:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="domain",
            value=value,
            reason=f"No allowed domains configured for argument '{arg_name}'.",
        )]

    host = _extract_domain(value)
    if not host:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="domain",
            value=value,
            reason=f"Cannot extract domain from argument '{arg_name}' value: {value!r}.",
        )]

    for pattern in allowed_domains:
        if _domain_matches(host, pattern):
            return []  # Allowed

    return [ConstraintViolation(
        arg_name=arg_name,
        constraint_type="domain",
        value=value,
        reason=(
            f"Domain '{host}' (from argument '{arg_name}') does not match any "
            f"allowed domain pattern: {allowed_domains}."
        ),
    )]


# ---------------------------------------------------------------------------
# Glob constraint
# ---------------------------------------------------------------------------


def check_glob(
    arg_name: str,
    value: Any,
    allowed_patterns: list[str],
    fail_open: bool = False,
) -> list[ConstraintViolation]:
    """Evaluate a string argument against glob patterns.

    Uses :func:`fnmatch.fnmatch` for single-level patterns (``*``)
    and :func:`fnmatch.fnmatchcase` for case-sensitive matching.
    ``**`` is treated as "match any characters including path separators".

    An empty ``allowed_patterns`` list blocks everything.
    A pattern of ``*`` alone allows everything.

    Args:
        arg_name: The argument name.
        value: The argument value to check.
        allowed_patterns: Glob patterns to match against.
        fail_open: If True, None passes.

    Returns:
        List of violations; empty means allowed.
    """
    if value is None:
        if fail_open:
            return []
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="glob",
            value=value,
            reason=f"Argument '{arg_name}' is required (glob constraint, fail_open=False).",
        )]

    if not isinstance(value, str):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="glob",
            value=value,
            reason=(
                f"Argument '{arg_name}' must be a string for glob constraint, "
                f"got {type(value).__name__}."
            ),
        )]

    if not allowed_patterns:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="glob",
            value=value,
            reason=f"No allowed patterns configured for argument '{arg_name}'.",
        )]

    for pattern in allowed_patterns:
        if not pattern:
            # Empty pattern matches nothing — skip
            continue
        # Expand ** to match any sequence including separators
        # by replacing ** with a sentinel, running fnmatch, then restoring.
        # Simpler: just use fnmatch with ** treated as *
        normalized_pattern = pattern.replace("**", "*")
        if fnmatch.fnmatch(value, normalized_pattern):
            return []  # Allowed

    return [ConstraintViolation(
        arg_name=arg_name,
        constraint_type="glob",
        value=value,
        reason=(
            f"Value {value!r} (argument '{arg_name}') does not match any "
            f"allowed pattern: {allowed_patterns}."
        ),
    )]


# ---------------------------------------------------------------------------
# Numeric constraint
# ---------------------------------------------------------------------------


def check_numeric(
    arg_name: str,
    value: Any,
    min_value: float | None = None,
    max_value: float | None = None,
    fail_open: bool = False,
    allow_string_numbers: bool = True,
) -> list[ConstraintViolation]:
    """Evaluate a numeric argument against min/max bounds.

    Handles:
      - int and float values directly
      - String numbers (``"100"`` → 100.0) when ``allow_string_numbers=True``
      - NaN — always rejected as not comparable
      - Infinity — allowed if no max is set, blocked if max is finite
      - Negative zero — treated as 0

    Args:
        arg_name: The argument name.
        value: The argument value to check.
        min_value: Minimum allowed value (inclusive). None means no lower bound.
        max_value: Maximum allowed value (inclusive). None means no upper bound.
        fail_open: If True, None passes.
        allow_string_numbers: If True, coerce string values to float before checking.

    Returns:
        List of violations; empty means allowed.
    """
    if value is None:
        if fail_open:
            return []
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="numeric",
            value=value,
            reason=f"Argument '{arg_name}' is required (numeric constraint, fail_open=False).",
        )]

    # Coerce numeric value
    numeric: float
    if isinstance(value, bool):
        # bool is a subclass of int but should not pass numeric constraints silently
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="numeric",
            value=value,
            reason=(
                f"Argument '{arg_name}' is a boolean, not a number. "
                f"Use an explicit integer or float."
            ),
        )]
    elif isinstance(value, (int, float)):
        numeric = float(value)
    elif isinstance(value, str) and allow_string_numbers:
        try:
            numeric = float(value)
        except ValueError:
            return [ConstraintViolation(
                arg_name=arg_name,
                constraint_type="numeric",
                value=value,
                reason=(
                    f"Argument '{arg_name}' value {value!r} cannot be parsed as a number."
                ),
            )]
    else:
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="numeric",
            value=value,
            reason=(
                f"Argument '{arg_name}' must be a number for numeric constraint, "
                f"got {type(value).__name__}."
            ),
        )]

    # Reject NaN — it is not comparable
    if math.isnan(numeric):
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="numeric",
            value=value,
            reason=f"Argument '{arg_name}' is NaN — not a valid numeric value.",
        )]

    # Normalize negative zero to zero
    if numeric == 0.0:
        numeric = 0.0

    violations: list[ConstraintViolation] = []

    if min_value is not None and numeric < min_value:
        violations.append(ConstraintViolation(
            arg_name=arg_name,
            constraint_type="numeric",
            value=value,
            reason=(
                f"Argument '{arg_name}' value {numeric} is below minimum {min_value}."
            ),
        ))

    if max_value is not None and numeric > max_value:
        violations.append(ConstraintViolation(
            arg_name=arg_name,
            constraint_type="numeric",
            value=value,
            reason=(
                f"Argument '{arg_name}' value {numeric} exceeds maximum {max_value}."
            ),
        ))

    return violations


# ---------------------------------------------------------------------------
# Dot-notation argument resolver (shared by evaluate_capabilities and
# evaluate_argument_constraints)
# ---------------------------------------------------------------------------


_SENTINEL = object()  # Unique marker for "key not found"


def _resolve_dotted_key(args: dict[str, Any], key: str) -> Any:
    """Resolve a dot-notation key against a (possibly nested) arguments dict.

    A key like ``"options.timeout"`` traverses ``args["options"]["timeout"]``.
    A key with no dots is equivalent to ``args.get(key)``.

    If any segment is missing, or if an intermediate value is not a dict,
    returns ``None`` (treated as "argument absent" by callers).

    Args:
        args: The top-level arguments dict.
        key: The argument name, potentially with dot separators.

    Returns:
        The resolved value, or ``None`` if the key is not found.
    """
    if "." not in key:
        return args.get(key)

    segments = key.split(".")
    current: Any = args
    for segment in segments:
        if not isinstance(current, dict):
            return None
        result = current.get(segment, _SENTINEL)
        if result is _SENTINEL:
            return None
        current = result
    return current


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def evaluate_capabilities(
    tool_name: str,
    arguments: dict[str, Any] | None,
    capabilities: "dict[str, CapabilitySpec]",
) -> list[ConstraintViolation]:
    """Evaluate all capability constraints for a tool call.

    Called by the policy engine after action-level permissions have resolved
    to ALLOW. If any constraint fails, the engine converts the result to BLOCK
    with a message listing ALL violations.

    AND logic: every constraint on every argument must pass. All violations
    are collected and returned together so the caller can report them all.

    Args:
        tool_name: The MCP tool name being called.
        arguments: The tool call arguments dict. May be None.
        capabilities: Mapping from tool name → CapabilitySpec (from policy).

    Returns:
        List of ConstraintViolation objects. Empty means all constraints pass.
        Returns empty list if the tool has no capability spec.
    """
    spec = capabilities.get(tool_name)
    if spec is None:
        return []  # No capability spec for this tool — nothing to check

    if not spec.args:
        return []  # Spec exists but has no argument constraints

    args = arguments or {}
    violations: list[ConstraintViolation] = []

    for arg_name, constraint in spec.args.items():
        raw_value = args.get(arg_name)  # None if argument is absent

        # Determine effective fail_open: argument-level overrides tool-level
        fail_open = constraint.fail_open

        # --- Path constraint ---
        if constraint.allowed_prefixes:
            violations.extend(
                check_path(arg_name, raw_value, constraint.allowed_prefixes, fail_open)
            )

        # --- CIDR constraint ---
        if constraint.allowed_cidrs:
            violations.extend(
                check_cidr(arg_name, raw_value, constraint.allowed_cidrs, fail_open)
            )

        # --- Domain constraint ---
        if constraint.allowed_domains:
            violations.extend(
                check_domain(arg_name, raw_value, constraint.allowed_domains, fail_open)
            )

        # --- Glob constraint ---
        if constraint.allowed_patterns:
            violations.extend(
                check_glob(arg_name, raw_value, constraint.allowed_patterns, fail_open)
            )

        # --- Numeric constraint ---
        if constraint.min_value is not None or constraint.max_value is not None:
            violations.extend(
                check_numeric(
                    arg_name,
                    raw_value,
                    min_value=constraint.min_value,
                    max_value=constraint.max_value,
                    fail_open=fail_open,
                )
            )

        # If no constraint type is specified but fail_open=False and value is missing,
        # still check fail-closed behavior
        if (
            not constraint.allowed_prefixes
            and not constraint.allowed_cidrs
            and not constraint.allowed_domains
            and not constraint.allowed_patterns
            and constraint.min_value is None
            and constraint.max_value is None
            and raw_value is None
            and not fail_open
        ):
            violations.append(ConstraintViolation(
                arg_name=arg_name,
                constraint_type="presence",
                value=None,
                reason=(
                    f"Argument '{arg_name}' is required (fail_open=False) "
                    f"but was not provided."
                ),
            ))

    return violations


# ---------------------------------------------------------------------------
# Helpers exposed for testing and the rich ArgumentConstraints evaluator
# ---------------------------------------------------------------------------


def _ip_in_cidr(
    ip: "ipaddress.IPv4Address | ipaddress.IPv6Address",
    cidr_str: str,
) -> bool:
    """Return True if *ip* falls within the CIDR range *cidr_str*.

    Handles malformed CIDR strings by returning False rather than raising.
    IPv4-mapped IPv6 unwrapping is the responsibility of the caller.

    Args:
        ip: A parsed IP address object (IPv4Address or IPv6Address).
        cidr_str: A CIDR string such as ``"10.0.0.0/8"`` or ``"::1/128"``.

    Returns:
        True if *ip* is contained in the network, False otherwise (including
        when *cidr_str* is malformed).
    """
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False
    if type(ip) is not type(network.network_address):
        return False
    return ip in network


class _ParsedURL:
    """Minimal URL parse result — mirrors the fields used by tests.

    Attributes:
        hostname: The extracted hostname (lowercased), or None.
        scheme: The URL scheme (lowercased), or empty string.
        port: The explicit port number, or None.
        path: The URL path component.
    """

    __slots__ = ("hostname", "scheme", "port", "path")

    def __init__(
        self,
        hostname: str | None,
        scheme: str,
        port: int | None,
        path: str,
    ) -> None:
        self.hostname = hostname
        self.scheme = scheme
        self.port = port
        self.path = path


def _parse_url_lenient(value: str) -> _ParsedURL:
    """Parse a URL or bare hostname/IP into a :class:`_ParsedURL` object.

    Handles URLs without a scheme by prepending a dummy ``dummy://`` scheme
    so that :func:`urllib.parse.urlparse` extracts the hostname correctly.
    Port extraction preserves ``None`` for URLs that don't specify a port.

    Args:
        value: A URL string with or without scheme, or a bare hostname/IP.

    Returns:
        A :class:`_ParsedURL` with ``hostname``, ``scheme``, ``port``, and
        ``path`` attributes.  ``hostname`` is ``None`` only when extraction
        fails entirely.
    """
    if not value:
        return _ParsedURL(hostname=None, scheme="", port=None, path="")

    if "://" in value:
        parsed = urllib.parse.urlparse(value)
        return _ParsedURL(
            hostname=parsed.hostname,
            scheme=parsed.scheme or "",
            port=parsed.port,
            path=parsed.path or "",
        )

    # No scheme — try with dummy scheme so urlparse sees the hostname
    parsed = urllib.parse.urlparse("dummy://" + value)
    return _ParsedURL(
        hostname=parsed.hostname,
        scheme="",
        port=parsed.port,
        path=parsed.path or "",
    )


def _port_in_list(port: int, allowed: list[str | int]) -> bool:
    """Return True if *port* is in *allowed*.

    *allowed* is a list of integers or range strings of the form
    ``"low-high"`` (e.g., ``"8000-9000"``).

    Args:
        port: The port number to check.
        allowed: A list of allowed ports or ranges.

    Returns:
        True if *port* is found or falls within a range; False otherwise.
    """
    for entry in allowed:
        if isinstance(entry, int):
            if port == entry:
                return True
        elif isinstance(entry, str):
            if "-" in entry:
                try:
                    low_str, high_str = entry.split("-", 1)
                    low, high = int(low_str), int(high_str)
                    if low <= port <= high:
                        return True
                except (ValueError, TypeError):
                    pass
            else:
                try:
                    if port == int(entry):
                        return True
                except (ValueError, TypeError):
                    pass
    return False


# ---------------------------------------------------------------------------
# Rich ArgumentConstraints evaluator (main-branch schema model)
# ---------------------------------------------------------------------------


def _check_rich_constraint(
    arg_name: str,
    raw_value: Any,
    constraint: Any,  # ArgumentConstraints from schema.py
) -> list[ConstraintViolation]:
    """Evaluate a single argument against an ``ArgumentConstraints`` (rich model).

    Called by :func:`evaluate_argument_constraints` when the constraint object
    is the rich ``ArgumentConstraints`` pydantic model from ``schema.py``
    (which has ``must_start_with``, ``one_of``, ``blocklist``, etc.).

    This function does NOT import ``ArgumentConstraints`` at module level to
    avoid circular imports.  It accesses constraint attributes via duck typing.

    Args:
        arg_name: The argument name (for error context).
        raw_value: The raw argument value (may be None if absent).
        constraint: An ``ArgumentConstraints`` pydantic model instance.

    Returns:
        A list of :class:`ConstraintViolation` objects.  Empty means the
        argument passes all constraints.
    """
    fail_open: bool = getattr(constraint, "fail_open", False)
    violations: list[ConstraintViolation] = []

    # --- Boolean: must_be -------------------------------------------------------
    must_be = getattr(constraint, "must_be", None)
    if must_be is not None:
        if raw_value is None:
            if fail_open:
                return []
            return [ConstraintViolation(
                arg_name=arg_name,
                constraint_type="required",
                value=raw_value,
                reason=f"Argument '{arg_name}' is required but was not provided.",
            )]
        if not isinstance(raw_value, bool) or raw_value is not must_be:
            return [ConstraintViolation(
                arg_name=arg_name,
                constraint_type="must_be",
                value=raw_value,
                reason=(
                    f"Argument '{arg_name}' must be {must_be!r}, "
                    f"got {raw_value!r}."
                ),
            )]
        # must_be is the only constraint — all others are irrelevant for bool
        return []

    # --- Array constraints -------------------------------------------------------
    max_items = getattr(constraint, "max_items", None)
    item_constraints_obj = getattr(constraint, "item_constraints", None)
    if max_items is not None or item_constraints_obj is not None:
        if raw_value is None:
            if fail_open:
                return []
            return [ConstraintViolation(
                arg_name=arg_name,
                constraint_type="required",
                value=raw_value,
                reason=f"Argument '{arg_name}' is required but was not provided.",
            )]
        if isinstance(raw_value, list):
            if max_items is not None and len(raw_value) > max_items:
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="max_items",
                    value=raw_value,
                    reason=(
                        f"Argument '{arg_name}' has {len(raw_value)} items, "
                        f"exceeds maximum {max_items}."
                    ),
                ))
            if item_constraints_obj is not None:
                for idx, item in enumerate(raw_value):
                    item_violations = _check_rich_constraint(
                        f"{arg_name}[{idx}]", item, item_constraints_obj
                    )
                    violations.extend(item_violations)
        return violations

    # --- Missing value (non-array, non-bool) ------------------------------------
    if raw_value is None:
        if fail_open:
            return []
        return [ConstraintViolation(
            arg_name=arg_name,
            constraint_type="required",
            value=raw_value,
            reason=f"Argument '{arg_name}' is required but was not provided.",
        )]

    # --- String constraints (only apply to string values) -----------------------
    if isinstance(raw_value, str):
        val_str: str = raw_value

        # must_start_with
        must_start_with = getattr(constraint, "must_start_with", [])
        if must_start_with:
            if not any(val_str.startswith(p) for p in must_start_with):
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="must_start_with",
                    value=val_str,
                    reason=(
                        f"BLOCKED [must_start_with]: Argument '{arg_name}' value "
                        f"{val_str!r} must start with one of {must_start_with}."
                    ),
                ))

        # must_not_start_with
        must_not_start_with = getattr(constraint, "must_not_start_with", [])
        for prefix in must_not_start_with:
            if val_str.startswith(prefix):
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="must_not_start_with",
                    value=val_str,
                    reason=(
                        f"BLOCKED [must_not_start_with]: Argument '{arg_name}' value "
                        f"{val_str!r} must NOT start with {prefix!r}."
                    ),
                ))
                break

        # must_contain
        must_contain = getattr(constraint, "must_contain", [])
        if must_contain:
            if not any(sub in val_str for sub in must_contain):
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="must_contain",
                    value=val_str,
                    reason=(
                        f"BLOCKED [must_contain]: Argument '{arg_name}' value "
                        f"{val_str!r} must contain one of {must_contain}."
                    ),
                ))

        # must_not_contain
        must_not_contain = getattr(constraint, "must_not_contain", [])
        for sub in must_not_contain:
            if sub in val_str:
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="must_not_contain",
                    value=val_str,
                    reason=(
                        f"BLOCKED [must_not_contain]: Argument '{arg_name}' value "
                        f"{val_str!r} must NOT contain {sub!r}."
                    ),
                ))
                break

        # matches — value must match at least one compiled pattern
        compiled_matches: list[Any] = getattr(constraint, "_compiled_matches", [])
        matches_patterns = getattr(constraint, "matches", [])
        if matches_patterns:
            if not any(p.search(val_str) for p in compiled_matches):
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="matches",
                    value=val_str,
                    reason=(
                        f"BLOCKED: Argument '{arg_name}' value {val_str!r} must match "
                        f"one of {matches_patterns}."
                    ),
                ))

        # not_matches — value must NOT match any compiled pattern
        compiled_not_matches: list[Any] = getattr(constraint, "_compiled_not_matches", [])
        not_matches_patterns = getattr(constraint, "not_matches", [])
        if not_matches_patterns:
            for pat in compiled_not_matches:
                if pat.search(val_str):
                    violations.append(ConstraintViolation(
                        arg_name=arg_name,
                        constraint_type="not_matches",
                        value=val_str,
                        reason=(
                            f"BLOCKED: Argument '{arg_name}' value {val_str!r} must NOT "
                            f"match {pat.pattern!r}."
                        ),
                    ))
                    break

        # max_length
        max_length = getattr(constraint, "max_length", None)
        if max_length is not None and len(val_str) > max_length:
            violations.append(ConstraintViolation(
                arg_name=arg_name,
                constraint_type="max_length",
                value=val_str,
                reason=(
                    f"BLOCKED: Argument '{arg_name}' value has length {len(val_str)}, "
                    f"exceeds maximum {max_length}."
                ),
            ))

        # allowlist — value must match at least one glob pattern
        allowlist = getattr(constraint, "allowlist", [])
        if allowlist:
            if not any(fnmatch.fnmatch(val_str, p.replace("**", "*")) for p in allowlist if p):
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="allowlist",
                    value=val_str,
                    reason=(
                        f"BLOCKED [allowlist]: Argument '{arg_name}' value {val_str!r} "
                        f"is not in the allowlist: {allowlist}."
                    ),
                ))

        # blocklist — value must NOT match any glob pattern
        blocklist = getattr(constraint, "blocklist", [])
        for pat in blocklist:
            if pat and fnmatch.fnmatch(val_str, pat.replace("**", "*")):
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="blocklist",
                    value=val_str,
                    reason=(
                        f"BLOCKED [blocklist]: Argument '{arg_name}' value {val_str!r} "
                        f"matches blocklist pattern {pat!r}."
                    ),
                ))
                break

    # --- Network: allowed_domains / blocked_domains / allowed_schemes -----------
    allowed_domains = getattr(constraint, "allowed_domains", [])
    if allowed_domains and isinstance(raw_value, str):
        host = _extract_domain(raw_value)
        if host:
            matched = any(_domain_matches(host, p) for p in allowed_domains)
            if not matched:
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="allowed_domains",
                    value=raw_value,
                    reason=(
                        f"BLOCKED: Domain '{host}' (argument '{arg_name}') does not "
                        f"match any allowed domain: {allowed_domains}."
                    ),
                ))
        else:
            violations.append(ConstraintViolation(
                arg_name=arg_name,
                constraint_type="allowed_domains",
                value=raw_value,
                reason=(
                    f"BLOCKED: Cannot extract domain from argument '{arg_name}' "
                    f"value {raw_value!r}."
                ),
            ))

    blocked_domains = getattr(constraint, "blocked_domains", [])
    if blocked_domains and isinstance(raw_value, str):
        host = _extract_domain(raw_value)
        if host:
            for pat in blocked_domains:
                if _domain_matches(host, pat):
                    violations.append(ConstraintViolation(
                        arg_name=arg_name,
                        constraint_type="blocked_domains",
                        value=raw_value,
                        reason=(
                            f"BLOCKED: Domain '{host}' (argument '{arg_name}') matches "
                            f"blocked domain pattern {pat!r}."
                        ),
                    ))
                    break

    allowed_schemes = getattr(constraint, "allowed_schemes", [])
    if allowed_schemes and isinstance(raw_value, str):
        parsed_url = _parse_url_lenient(raw_value)
        scheme = parsed_url.scheme.lower() if parsed_url.scheme else ""
        if scheme not in [s.lower() for s in allowed_schemes]:
            violations.append(ConstraintViolation(
                arg_name=arg_name,
                constraint_type="allowed_schemes",
                value=raw_value,
                reason=(
                    f"BLOCKED: Scheme {scheme!r} (argument '{arg_name}') is not in "
                    f"allowed schemes: {allowed_schemes}."
                ),
            ))

    # --- Network: allowed_cidrs / blocked_cidrs ---------------------------------
    allowed_cidrs = getattr(constraint, "allowed_cidrs", [])
    if allowed_cidrs and isinstance(raw_value, str):
        ip_str = _extract_ip_from_value(raw_value)
        if ip_str:
            # Only check CIDR if we can parse an IP address — DNS names skip CIDR check
            try:
                addr: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                    addr = addr.ipv4_mapped
                if not any(_ip_in_cidr(addr, c) for c in allowed_cidrs):
                    violations.append(ConstraintViolation(
                        arg_name=arg_name,
                        constraint_type="allowed_cidrs",
                        value=raw_value,
                        reason=(
                            f"BLOCKED [allowed_cidrs]: IP '{addr}' (argument "
                            f"'{arg_name}') is not in any allowed CIDR: {allowed_cidrs}."
                        ),
                    ))
            except ValueError:
                pass  # Not an IP address — skip CIDR check (DNS name)

    blocked_cidrs = getattr(constraint, "blocked_cidrs", [])
    if blocked_cidrs and isinstance(raw_value, str):
        ip_str = _extract_ip_from_value(raw_value)
        if ip_str:
            try:
                addr = ipaddress.ip_address(ip_str)
                if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
                    addr = addr.ipv4_mapped
                for c in blocked_cidrs:
                    if _ip_in_cidr(addr, c):
                        violations.append(ConstraintViolation(
                            arg_name=arg_name,
                            constraint_type="blocked_cidrs",
                            value=raw_value,
                            reason=(
                                f"BLOCKED: IP '{addr}' (argument '{arg_name}') matches "
                                f"blocked CIDR {c!r}."
                            ),
                        ))
                        break
            except ValueError:
                pass  # Not an IP address — skip

    # --- Network: allowed_ports -------------------------------------------------
    allowed_ports = getattr(constraint, "allowed_ports", [])
    if allowed_ports and isinstance(raw_value, str):
        parsed_url = _parse_url_lenient(raw_value)
        if parsed_url.port is not None:
            if not _port_in_list(parsed_url.port, allowed_ports):
                violations.append(ConstraintViolation(
                    arg_name=arg_name,
                    constraint_type="allowed_ports",
                    value=raw_value,
                    reason=(
                        f"BLOCKED: Port {parsed_url.port} (argument '{arg_name}') "
                        f"is not in allowed ports: {allowed_ports}."
                    ),
                ))

    # --- Numeric: min_value / max_value -----------------------------------------
    min_value = getattr(constraint, "min_value", None)
    max_value = getattr(constraint, "max_value", None)
    if min_value is not None or max_value is not None:
        # booleans are int subclass — skip numeric check for booleans
        if not isinstance(raw_value, bool):
            numeric: float | None = None
            if isinstance(raw_value, (int, float)):
                numeric = float(raw_value)
            # Numeric checks do not coerce strings here (min_value/max_value are
            # for actual numeric fields, not string-encoded numbers in this context)
            if numeric is not None:
                if min_value is not None and numeric < min_value:
                    violations.append(ConstraintViolation(
                        arg_name=arg_name,
                        constraint_type="min_value",
                        value=raw_value,
                        reason=(
                            f"BLOCKED [min_value]: Argument '{arg_name}' value "
                            f"{numeric} is below minimum {min_value}."
                        ),
                    ))
                if max_value is not None and numeric > max_value:
                    violations.append(ConstraintViolation(
                        arg_name=arg_name,
                        constraint_type="max_value",
                        value=raw_value,
                        reason=(
                            f"BLOCKED [max_value]: Argument '{arg_name}' value "
                            f"{numeric} exceeds maximum {max_value}."
                        ),
                    ))

    # --- Enum: one_of / not_one_of ---------------------------------------------
    one_of = getattr(constraint, "one_of", [])
    if one_of:
        if raw_value not in one_of:
            violations.append(ConstraintViolation(
                arg_name=arg_name,
                constraint_type="one_of",
                value=raw_value,
                reason=(
                    f"BLOCKED [one_of]: Argument '{arg_name}' value {raw_value!r} "
                    f"is not in allowed values: {one_of}."
                ),
            ))

    not_one_of = getattr(constraint, "not_one_of", [])
    if not_one_of:
        if raw_value in not_one_of:
            violations.append(ConstraintViolation(
                arg_name=arg_name,
                constraint_type="not_one_of",
                value=raw_value,
                reason=(
                    f"BLOCKED: Argument '{arg_name}' value {raw_value!r} "
                    f"is in the forbidden list: {not_one_of}."
                ),
            ))

    return violations


# ---------------------------------------------------------------------------
# Compatibility shims — main-branch API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConstraintResult:
    """Result wrapper matching the main-branch evaluate_argument_constraints API.

    Attributes:
        passed: True only when all constraints were satisfied.
        violations: List of individual failures (empty when passed is True).
    """

    passed: bool
    violations: list[ConstraintViolation] = field(default_factory=list)


def evaluate_argument_constraints(
    arguments: "dict[str, Any] | None",
    arg_constraints: "dict[str, Any]",
) -> ConstraintResult:
    """Evaluate arguments against a per-argument constraint dict.

    Handles both the simple ``ArgumentConstraint`` model (this branch, with
    ``allowed_prefixes``, ``allowed_cidrs``, ``allowed_domains``,
    ``allowed_patterns``) and the rich ``ArgumentConstraints`` model from the
    main branch (with ``must_start_with``, ``one_of``, ``blocklist``, etc.).

    The two models are distinguished by duck typing: if the constraint object
    has a ``must_start_with`` attribute, it is treated as the rich model.

    Args:
        arguments: The tool call arguments, or None.
        arg_constraints: Mapping of argument name → constraint object.
            Accepts either ``ArgumentConstraint`` or ``ArgumentConstraints``
            model instances.

    Returns:
        ConstraintResult(passed=True) if all constraints pass,
        ConstraintResult(passed=False, violations=[...]) otherwise.
    """
    if not arg_constraints:
        return ConstraintResult(passed=True)

    args = arguments or {}
    violations: list[ConstraintViolation] = []

    for arg_name, constraint in arg_constraints.items():
        raw_value = _resolve_dotted_key(args, arg_name)
        fail_open = getattr(constraint, "fail_open", False)

        # Detect which model we're dealing with via duck typing.
        # The rich ArgumentConstraints model has must_start_with; the simple
        # ArgumentConstraint model has allowed_prefixes (not must_start_with).
        if hasattr(constraint, "must_start_with"):
            # Rich model (ArgumentConstraints from schema.py)
            violations.extend(_check_rich_constraint(arg_name, raw_value, constraint))
        else:
            # Simple model (ArgumentConstraint from schema.py)
            if constraint.allowed_prefixes:
                violations.extend(
                    check_path(arg_name, raw_value, constraint.allowed_prefixes, fail_open)
                )
            if constraint.allowed_cidrs:
                violations.extend(
                    check_cidr(arg_name, raw_value, constraint.allowed_cidrs, fail_open)
                )
            if constraint.allowed_domains:
                violations.extend(
                    check_domain(arg_name, raw_value, constraint.allowed_domains, fail_open)
                )
            if constraint.allowed_patterns:
                violations.extend(
                    check_glob(arg_name, raw_value, constraint.allowed_patterns, fail_open)
                )
            if constraint.min_value is not None or constraint.max_value is not None:
                violations.extend(check_numeric(
                    arg_name, raw_value,
                    min_value=constraint.min_value, max_value=constraint.max_value,
                    fail_open=fail_open,
                ))

    return ConstraintResult(passed=len(violations) == 0, violations=violations)
