"""Argument constraint evaluator for AgentWard capability scoping.

Pure evaluation module — no side effects, no I/O, no dependency on the
rest of the engine.  Given a tool call's arguments dict and the
ArgumentConstraints declared for each parameter, returns a structured result
describing which constraints passed and which failed.

Design:
  - evaluate_argument_constraints() is the single public entry point.
  - All helper functions are pure (no state mutation, no globals).
  - CIDR matching uses stdlib ``ipaddress``.
  - Glob matching uses stdlib ``fnmatch``.
  - URL parsing uses stdlib ``urllib.parse``.
  - Regex patterns are pre-compiled on the ArgumentConstraints model;
    the evaluator accesses them via the private attributes.

Failure semantics:
  - Constraints use AND logic: ALL specified constraints must pass.
  - A missing argument defaults to BLOCK (fail-closed) unless the
    ArgumentConstraints for that argument has ``fail_open: true``.
  - Unknown constraint fields (future schema additions) are silently ignored
    by the evaluator — it only checks what it recognises.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentward.policy.schema import ArgumentConstraints


# ── Public result types ────────────────────────────────────────────────────────


@dataclass
class ConstraintViolation:
    """Describes a single argument constraint that was not satisfied.

    Attributes:
        argument: Argument name or dot-notation path (e.g. ``"options.timeout"``).
        constraint_type: The constraint kind that failed (e.g. ``"must_start_with"``).
        value: The actual argument value that caused the violation.
        message: Human-readable, actionable explanation suitable for audit logs
                 and operator dashboards.
    """

    argument: str
    constraint_type: str
    value: Any
    message: str


@dataclass
class ConstraintResult:
    """Result of evaluating a tool call against its capability constraints.

    Attributes:
        passed: True only when every declared constraint was satisfied.
        violations: List of individual failures (empty when passed is True).
    """

    passed: bool
    violations: list[ConstraintViolation] = field(default_factory=list)


# ── Public entry point ─────────────────────────────────────────────────────────


def evaluate_argument_constraints(
    arguments: dict[str, Any] | None,
    arg_constraints: dict[str, "ArgumentConstraints"],
) -> ConstraintResult:
    """Evaluate tool call arguments against declared capability constraints.

    Args:
        arguments: The tool call arguments.  May be None if the tool takes no
                   arguments.
        arg_constraints: Mapping of argument name (or dot-path) to its
                         ``ArgumentConstraints``.  Empty dict → instant PASS.

    Returns:
        ``ConstraintResult(passed=True)`` when all constraints are satisfied.
        ``ConstraintResult(passed=False, violations=[...])`` otherwise.
    """
    if not arg_constraints:
        return ConstraintResult(passed=True)

    args = arguments or {}
    violations: list[ConstraintViolation] = []

    for arg_path, constraints in arg_constraints.items():
        value, missing = _get_nested_value(args, arg_path)

        if missing:
            if not constraints.fail_open:
                violations.append(
                    ConstraintViolation(
                        argument=arg_path,
                        constraint_type="required",
                        value=None,
                        message=(
                            f"BLOCKED: Argument '{arg_path}' is required by "
                            f"capability constraints but was not provided."
                        ),
                    )
                )
            # Either way — skip further checks on a missing value.
            continue

        violations.extend(_check_value(arg_path, value, constraints))

    return ConstraintResult(passed=len(violations) == 0, violations=violations)


# ── Nested argument access ─────────────────────────────────────────────────────


def _get_nested_value(arguments: dict[str, Any], path: str) -> tuple[Any, bool]:
    """Retrieve a value from a nested dict using dot-notation.

    Args:
        arguments: The (potentially nested) arguments dict.
        path: Dot-separated key path, e.g. ``"options.timeout"``.

    Returns:
        ``(value, False)`` if the path exists, ``(None, True)`` if missing.
    """
    parts = path.split(".")
    current: Any = arguments
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return None, True
        current = current[part]
    return current, False


# ── Per-value dispatcher ───────────────────────────────────────────────────────


def _check_value(
    arg_path: str,
    value: Any,
    constraints: "ArgumentConstraints",
) -> list[ConstraintViolation]:
    """Check a single resolved argument value against all its constraints.

    Args:
        arg_path: Argument name / dot-path (used in violation messages).
        value: The resolved argument value.
        constraints: The full set of declared constraints for this argument.

    Returns:
        List of violations (empty = all constraints satisfied).
    """
    violations: list[ConstraintViolation] = []

    # ── Boolean (must_be) — checked first; stops further type-specific checks ──
    if constraints.must_be is not None:
        if not isinstance(value, bool) or value != constraints.must_be:
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="must_be",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'must_be'. "
                        f"Required: {constraints.must_be}."
                    ),
                )
            )
        # Return early — no further type-specific checks are meaningful.
        return violations

    # ── one_of / not_one_of (type-agnostic) ───────────────────────────────────
    if constraints.one_of and value not in constraints.one_of:
        violations.append(
            ConstraintViolation(
                argument=arg_path,
                constraint_type="one_of",
                value=value,
                message=(
                    f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                    f"capability constraint 'one_of'. "
                    f"Allowed values: {constraints.one_of}."
                ),
            )
        )

    if constraints.not_one_of and value in constraints.not_one_of:
        violations.append(
            ConstraintViolation(
                argument=arg_path,
                constraint_type="not_one_of",
                value=value,
                message=(
                    f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                    f"capability constraint 'not_one_of'. "
                    f"Forbidden values: {constraints.not_one_of}."
                ),
            )
        )

    # ── Numeric constraints ────────────────────────────────────────────────────
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        violations.extend(_check_numeric(arg_path, value, constraints))

    # ── Array constraints ──────────────────────────────────────────────────────
    if isinstance(value, list):
        violations.extend(_check_array(arg_path, value, constraints))

    # ── String constraints (includes network constraints for URL strings) ──────
    if isinstance(value, str):
        violations.extend(_check_string(arg_path, value, constraints))

    return violations


# ── Numeric ────────────────────────────────────────────────────────────────────


def _check_numeric(
    arg_path: str,
    value: int | float,
    constraints: "ArgumentConstraints",
) -> list[ConstraintViolation]:
    violations: list[ConstraintViolation] = []

    if constraints.min_value is not None and value < constraints.min_value:
        violations.append(
            ConstraintViolation(
                argument=arg_path,
                constraint_type="min_value",
                value=value,
                message=(
                    f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                    f"capability constraint 'min_value'. "
                    f"Minimum: {constraints.min_value}."
                ),
            )
        )

    if constraints.max_value is not None and value > constraints.max_value:
        violations.append(
            ConstraintViolation(
                argument=arg_path,
                constraint_type="max_value",
                value=value,
                message=(
                    f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                    f"capability constraint 'max_value'. "
                    f"Maximum: {constraints.max_value}."
                ),
            )
        )

    return violations


# ── Array ──────────────────────────────────────────────────────────────────────


def _check_array(
    arg_path: str,
    value: list[Any],
    constraints: "ArgumentConstraints",
) -> list[ConstraintViolation]:
    violations: list[ConstraintViolation] = []

    if constraints.max_items is not None and len(value) > constraints.max_items:
        violations.append(
            ConstraintViolation(
                argument=arg_path,
                constraint_type="max_items",
                value=value,
                message=(
                    f"BLOCKED: Argument '{arg_path}' has {len(value)} items, "
                    f"violating capability constraint 'max_items'. "
                    f"Maximum allowed: {constraints.max_items}."
                ),
            )
        )

    if constraints.item_constraints is not None:
        for idx, item in enumerate(value):
            item_path = f"{arg_path}[{idx}]"
            item_violations = _check_value(item_path, item, constraints.item_constraints)
            violations.extend(item_violations)

    return violations


# ── String ─────────────────────────────────────────────────────────────────────


def _check_string(
    arg_path: str,
    value: str,
    constraints: "ArgumentConstraints",
) -> list[ConstraintViolation]:
    violations: list[ConstraintViolation] = []

    # max_length
    if constraints.max_length is not None and len(value) > constraints.max_length:
        violations.append(
            ConstraintViolation(
                argument=arg_path,
                constraint_type="max_length",
                value=value,
                message=(
                    f"BLOCKED: Argument '{arg_path}' value exceeds max length "
                    f"({len(value)} > {constraints.max_length})."
                ),
            )
        )

    # must_start_with
    if constraints.must_start_with:
        if not any(value.startswith(prefix) for prefix in constraints.must_start_with):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="must_start_with",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'must_start_with'. "
                        f"Allowed prefixes: {constraints.must_start_with}."
                    ),
                )
            )

    # must_not_start_with
    for prefix in constraints.must_not_start_with:
        if value.startswith(prefix):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="must_not_start_with",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'must_not_start_with'. "
                        f"Forbidden prefix: {prefix!r}."
                    ),
                )
            )
            break  # Report first offending prefix only

    # must_contain
    if constraints.must_contain:
        if not any(sub in value for sub in constraints.must_contain):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="must_contain",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'must_contain'. "
                        f"Value must contain at least one of: {constraints.must_contain}."
                    ),
                )
            )

    # must_not_contain
    for substring in constraints.must_not_contain:
        if substring in value:
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="must_not_contain",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'must_not_contain'. "
                        f"Forbidden substring: {substring!r}."
                    ),
                )
            )
            break  # Report first offending substring only

    # matches (pre-compiled regexes from _compiled_matches private attr)
    if constraints.matches:
        compiled = constraints._compiled_matches  # noqa: SLF001
        if not any(p.search(value) for p in compiled):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="matches",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'matches'. "
                        f"Value must match at least one of: {constraints.matches}."
                    ),
                )
            )

    # not_matches (pre-compiled regexes from _compiled_not_matches private attr)
    compiled_not = constraints._compiled_not_matches  # noqa: SLF001
    for idx, pattern in enumerate(compiled_not):
        if pattern.search(value):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="not_matches",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'not_matches'. "
                        f"Value must not match: {constraints.not_matches[idx]!r}."
                    ),
                )
            )
            break  # Report first offending pattern only

    # allowlist (glob patterns)
    if constraints.allowlist:
        if not any(fnmatch.fnmatch(value, pattern) for pattern in constraints.allowlist):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="allowlist",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'allowlist'. "
                        f"Allowed patterns: {constraints.allowlist}."
                    ),
                )
            )

    # blocklist (glob patterns)
    for pattern in constraints.blocklist:
        if fnmatch.fnmatch(value, pattern):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="blocklist",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'blocklist'. "
                        f"Matched forbidden pattern: {pattern!r}."
                    ),
                )
            )
            break  # Report first offending pattern only

    # ── Network constraints ────────────────────────────────────────────────────
    has_network = (
        constraints.allowed_domains
        or constraints.blocked_domains
        or constraints.allowed_schemes
        or constraints.allowed_cidrs
        or constraints.blocked_cidrs
        or constraints.allowed_ports
    )
    if has_network:
        violations.extend(_check_network(arg_path, value, constraints))

    return violations


# ── Network ────────────────────────────────────────────────────────────────────


def _check_network(
    arg_path: str,
    value: str,
    constraints: "ArgumentConstraints",
) -> list[ConstraintViolation]:
    """Evaluate network-specific constraints on a URL/hostname/IP string."""
    violations: list[ConstraintViolation] = []

    parsed = _parse_url_lenient(value)
    hostname = parsed.hostname or ""  # empty string if unparseable
    scheme = parsed.scheme or ""
    port = parsed.port  # None if not specified

    # allowed_schemes
    if constraints.allowed_schemes and scheme:
        if scheme.lower() not in [s.lower() for s in constraints.allowed_schemes]:
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="allowed_schemes",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'allowed_schemes'. "
                        f"Scheme {scheme!r} is not in allowed list: "
                        f"{constraints.allowed_schemes}."
                    ),
                )
            )

    # allowed_domains — hostname must match at least one
    if constraints.allowed_domains and hostname:
        if not any(
            _domain_matches(hostname, pattern) for pattern in constraints.allowed_domains
        ):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="allowed_domains",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'allowed_domains'. "
                        f"Hostname {hostname!r} is not in allowed domains: "
                        f"{constraints.allowed_domains}."
                    ),
                )
            )

    # blocked_domains — hostname must not match any
    for pattern in constraints.blocked_domains:
        if hostname and _domain_matches(hostname, pattern):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="blocked_domains",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'blocked_domains'. "
                        f"Hostname {hostname!r} matched forbidden pattern {pattern!r}."
                    ),
                )
            )
            break

    # allowed_ports
    if constraints.allowed_ports and port is not None:
        if not _port_in_list(port, constraints.allowed_ports):
            violations.append(
                ConstraintViolation(
                    argument=arg_path,
                    constraint_type="allowed_ports",
                    value=value,
                    message=(
                        f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                        f"capability constraint 'allowed_ports'. "
                        f"Port {port} is not in allowed ports: "
                        f"{constraints.allowed_ports}."
                    ),
                )
            )

    # CIDR constraints — attempt to resolve hostname as IP
    if constraints.allowed_cidrs or constraints.blocked_cidrs:
        ip = _resolve_to_ip(hostname)
        if ip is not None:
            if constraints.allowed_cidrs and not _ip_in_any_cidr(ip, constraints.allowed_cidrs):
                violations.append(
                    ConstraintViolation(
                        argument=arg_path,
                        constraint_type="allowed_cidrs",
                        value=value,
                        message=(
                            f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                            f"capability constraint 'allowed_cidrs'. "
                            f"IP {hostname!r} is not in allowed ranges: "
                            f"{constraints.allowed_cidrs}."
                        ),
                    )
                )

            for cidr in constraints.blocked_cidrs:
                if _ip_in_cidr(ip, cidr):
                    violations.append(
                        ConstraintViolation(
                            argument=arg_path,
                            constraint_type="blocked_cidrs",
                            value=value,
                            message=(
                                f"BLOCKED: Argument '{arg_path}' value {value!r} violates "
                                f"capability constraint 'blocked_cidrs'. "
                                f"IP {hostname!r} falls within blocked range {cidr!r}."
                            ),
                        )
                    )
                    break

    return violations


# ── Network helpers ────────────────────────────────────────────────────────────


def _parse_url_lenient(value: str) -> urllib.parse.ParseResult:
    """Parse a string as a URL, adding a scheme if absent.

    Handles raw hostnames/IPs (no scheme) by prepending ``https://`` so that
    ``urllib.parse.urlparse`` can extract the hostname correctly.
    """
    # If value has no scheme, prepend one so urlparse works
    if "://" not in value:
        value = "https://" + value
    return urllib.parse.urlparse(value)


def _domain_matches(hostname: str, pattern: str) -> bool:
    """Check if a hostname matches a domain pattern.

    Patterns:
      - ``"api.github.com"``     → exact match only
      - ``"*.github.com"``       → matches ``api.github.com`` but NOT ``github.com``
                                   and NOT ``deep.api.github.com``

    Args:
        hostname: The resolved hostname from the URL/argument.
        pattern: A literal domain or a ``*.``-prefixed wildcard pattern.

    Returns:
        True if the hostname matches the pattern.
    """
    hostname = hostname.lower()
    pattern = pattern.lower()

    if pattern.startswith("*."):
        suffix = pattern[2:]  # e.g. "github.com"
        # Must end with ".suffix" AND have exactly one subdomain level
        if hostname == suffix:
            return False  # exact domain doesn't satisfy *.domain
        return hostname.endswith("." + suffix)

    return hostname == pattern


def _port_in_list(port: int, allowed: list[str | int]) -> bool:
    """Check if a port is in an allowed-ports list (integers or range strings).

    Args:
        port: The port number to check.
        allowed: List of allowed entries: plain ints or ``"start-end"`` strings.

    Returns:
        True if the port is covered by any entry.
    """
    for entry in allowed:
        if isinstance(entry, int):
            if port == entry:
                return True
        elif isinstance(entry, str):
            if "-" in entry:
                try:
                    start, end = entry.split("-", 1)
                    if int(start) <= port <= int(end):
                        return True
                except (ValueError, TypeError):
                    pass  # Malformed range — skip
            else:
                try:
                    if port == int(entry):
                        return True
                except (ValueError, TypeError):
                    pass
    return False


def _resolve_to_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Try to parse a hostname string as a literal IP address.

    Returns None if the string is a DNS name rather than a literal IP.
    No DNS resolution is performed — CIDR checks only work for literal IPs.
    """
    if not hostname:
        return None
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _ip_in_cidr(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, cidr: str) -> bool:
    """Check if an IP address falls within a CIDR range.

    Args:
        ip: A parsed IP address object.
        cidr: A CIDR string like ``"10.0.0.0/8"``.

    Returns:
        True if the IP is within the network.  False on any parse error.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return ip in network
    except ValueError:
        return False  # Malformed CIDR — treat as no-match


def _ip_in_any_cidr(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    cidrs: list[str],
) -> bool:
    """Check if an IP address falls within any CIDR in the list."""
    return any(_ip_in_cidr(ip, cidr) for cidr in cidrs)
