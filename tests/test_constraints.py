"""Comprehensive tests for the argument constraint evaluator.

Covers:
  - All string constraint types
  - Network constraints (domains, CIDRs, schemes, ports)
  - Numeric constraints
  - Boolean constraints
  - Array constraints with item_constraints
  - Nested argument access (dot notation)
  - Missing argument handling (fail-open vs fail-closed)
  - URL edge cases
  - CIDR edge cases (IPv4, IPv6, /0, single IPs)
  - Glob edge cases
  - Engine integration (constraints wired into decision pipeline)
  - Backward compatibility (no capabilities = works as before)
  - Multiple constraints on same argument (AND logic)
  - YAML round-trip (load YAML with capabilities, verify parsing)
"""

from __future__ import annotations

import textwrap
from typing import Any

import pytest
import yaml

from agentward.policy.constraints import (
    ConstraintResult,
    ConstraintViolation,
    _domain_matches,
    _ip_in_cidr,
    _parse_url_lenient,
    _port_in_list,
    evaluate_argument_constraints,
)
from agentward.policy.engine import PolicyEngine
from agentward.policy.loader import load_policy
from agentward.policy.schema import (
    AgentWardPolicy,
    ArgumentConstraints,
    PolicyDecision,
    ResourcePermissions,
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def make_constraints(**kwargs: Any) -> ArgumentConstraints:
    """Build an ArgumentConstraints model from keyword args."""
    return ArgumentConstraints(**kwargs)


def evaluate(
    arg_constraints: dict[str, Any],
    arguments: dict[str, Any] | None = None,
) -> ConstraintResult:
    """Build ArgumentConstraints from dicts and evaluate."""
    typed = {k: ArgumentConstraints(**v) for k, v in arg_constraints.items()}
    return evaluate_argument_constraints(arguments, typed)


def passes(arg_constraints: dict[str, Any], arguments: dict[str, Any] | None) -> bool:
    return evaluate(arg_constraints, arguments).passed


def fails(arg_constraints: dict[str, Any], arguments: dict[str, Any] | None) -> bool:
    return not evaluate(arg_constraints, arguments).passed


# ── Empty / trivial ────────────────────────────────────────────────────────────


class TestTrivialCases:
    def test_no_constraints_passes(self) -> None:
        result = evaluate_argument_constraints({"path": "/etc/passwd"}, {})
        assert result.passed

    def test_none_arguments_no_constraints(self) -> None:
        result = evaluate_argument_constraints(None, {})
        assert result.passed

    def test_none_arguments_with_fail_open(self) -> None:
        result = evaluate_argument_constraints(
            None, {"path": make_constraints(must_start_with=["/tmp"], fail_open=True)}
        )
        assert result.passed

    def test_none_arguments_fail_closed(self) -> None:
        result = evaluate_argument_constraints(
            None, {"path": make_constraints(must_start_with=["/tmp"])}
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "required"


# ── Missing argument ───────────────────────────────────────────────────────────


class TestMissingArgument:
    def test_missing_arg_fail_closed_by_default(self) -> None:
        assert fails({"path": {"must_start_with": ["/tmp"]}}, {})

    def test_missing_arg_fail_open(self) -> None:
        assert passes({"path": {"must_start_with": ["/tmp"], "fail_open": True}}, {})

    def test_missing_arg_violation_message(self) -> None:
        result = evaluate({"path": {"must_start_with": ["/tmp"]}}, {})
        assert "path" in result.violations[0].message
        assert "required" in result.violations[0].message.lower()

    def test_missing_nested_arg_fail_closed(self) -> None:
        assert fails({"options.timeout": {"max_value": 30}}, {"options": {}})

    def test_missing_top_level_when_nested_exists(self) -> None:
        # "options" key missing entirely
        assert fails({"options.timeout": {"max_value": 30}}, {})


# ── String: must_start_with ────────────────────────────────────────────────────


class TestMustStartWith:
    def test_passes_matching_prefix(self) -> None:
        assert passes({"path": {"must_start_with": ["/tmp/", "/workspace/"]}}, {"path": "/tmp/foo"})

    def test_passes_second_prefix(self) -> None:
        assert passes({"path": {"must_start_with": ["/tmp/", "/workspace/"]}}, {"path": "/workspace/bar"})

    def test_fails_no_matching_prefix(self) -> None:
        result = evaluate({"path": {"must_start_with": ["/tmp/"]}}, {"path": "/etc/passwd"})
        assert not result.passed
        assert result.violations[0].constraint_type == "must_start_with"
        assert "/etc/passwd" in result.violations[0].message

    def test_violation_lists_allowed_prefixes(self) -> None:
        result = evaluate({"path": {"must_start_with": ["/tmp/", "/workspace/"]}}, {"path": "/etc"})
        assert "/tmp/" in result.violations[0].message
        assert "/workspace/" in result.violations[0].message


# ── String: must_not_start_with ────────────────────────────────────────────────


class TestMustNotStartWith:
    def test_passes_safe_path(self) -> None:
        assert passes({"path": {"must_not_start_with": ["/etc/", "/home/"]}}, {"path": "/tmp/file"})

    def test_fails_forbidden_prefix(self) -> None:
        result = evaluate({"path": {"must_not_start_with": ["/etc/"]}}, {"path": "/etc/shadow"})
        assert not result.passed
        assert result.violations[0].constraint_type == "must_not_start_with"

    def test_fails_second_forbidden_prefix(self) -> None:
        assert fails({"path": {"must_not_start_with": ["/etc/", "/home/"]}}, {"path": "/home/user/.ssh"})


# ── String: must_contain ───────────────────────────────────────────────────────


class TestMustContain:
    def test_passes_when_substring_present(self) -> None:
        assert passes({"q": {"must_contain": ["approved"]}}, {"q": "this is approved"})

    def test_fails_when_no_substring_present(self) -> None:
        result = evaluate({"q": {"must_contain": ["approved"]}}, {"q": "pending"})
        assert not result.passed
        assert result.violations[0].constraint_type == "must_contain"

    def test_passes_one_of_required_substrings(self) -> None:
        assert passes({"q": {"must_contain": ["ok", "approved"]}}, {"q": "status: approved"})


# ── String: must_not_contain ───────────────────────────────────────────────────


class TestMustNotContain:
    def test_passes_clean_value(self) -> None:
        assert passes({"path": {"must_not_contain": [".."]}}, {"path": "/workspace/file.txt"})

    def test_fails_traversal_sequence(self) -> None:
        result = evaluate({"path": {"must_not_contain": [".."]}}, {"path": "/workspace/../etc/passwd"})
        assert not result.passed
        assert result.violations[0].constraint_type == "must_not_contain"

    def test_fails_first_offending_substring_reported(self) -> None:
        result = evaluate({"cmd": {"must_not_contain": ["rm", "sudo"]}}, {"cmd": "sudo rm -rf"})
        # Should report at least one violation (stops at first match)
        assert not result.passed


# ── String: matches (regex) ────────────────────────────────────────────────────


class TestMatches:
    def test_passes_matching_regex(self) -> None:
        assert passes({"email": {"matches": [r"^[^@]+@[^@]+\.[^@]+$"]}}, {"email": "user@example.com"})

    def test_fails_non_matching_regex(self) -> None:
        result = evaluate({"email": {"matches": [r"^[^@]+@[^@]+\.[^@]+$"]}}, {"email": "not-an-email"})
        assert not result.passed
        assert result.violations[0].constraint_type == "matches"

    def test_passes_if_any_pattern_matches(self) -> None:
        assert passes({"v": {"matches": [r"^\d+$", r"^v\d+"]}}, {"v": "v123"})

    def test_invalid_regex_fails_at_load_time(self) -> None:
        with pytest.raises(ValueError, match="Invalid regex"):
            ArgumentConstraints(matches=["[invalid"])


# ── String: not_matches ────────────────────────────────────────────────────────


class TestNotMatches:
    def test_passes_when_no_pattern_matches(self) -> None:
        assert passes({"cmd": {"not_matches": [r"\brm\b", r"\bsudo\b"]}}, {"cmd": "ls -la"})

    def test_fails_when_pattern_matches(self) -> None:
        result = evaluate({"cmd": {"not_matches": [r"\brm\b"]}}, {"cmd": "rm -rf /tmp"})
        assert not result.passed
        assert result.violations[0].constraint_type == "not_matches"

    def test_invalid_regex_fails_at_load_time(self) -> None:
        with pytest.raises(ValueError, match="Invalid regex"):
            ArgumentConstraints(not_matches=["[bad"])


# ── String: one_of ─────────────────────────────────────────────────────────────


class TestOneOf:
    def test_passes_allowed_value(self) -> None:
        assert passes({"method": {"one_of": ["GET", "POST"]}}, {"method": "GET"})

    def test_fails_disallowed_value(self) -> None:
        result = evaluate({"method": {"one_of": ["GET", "POST"]}}, {"method": "DELETE"})
        assert not result.passed
        assert result.violations[0].constraint_type == "one_of"

    def test_numeric_one_of(self) -> None:
        assert passes({"level": {"one_of": [1, 2, 3]}}, {"level": 2})
        assert fails({"level": {"one_of": [1, 2, 3]}}, {"level": 5})


# ── String: not_one_of ─────────────────────────────────────────────────────────


class TestNotOneOf:
    def test_passes_when_not_in_list(self) -> None:
        assert passes({"method": {"not_one_of": ["DELETE", "DROP"]}}, {"method": "GET"})

    def test_fails_when_in_forbidden_list(self) -> None:
        result = evaluate({"method": {"not_one_of": ["DELETE"]}}, {"method": "DELETE"})
        assert not result.passed
        assert result.violations[0].constraint_type == "not_one_of"


# ── String: allowlist (glob) ───────────────────────────────────────────────────


class TestAllowlist:
    def test_passes_matching_glob(self) -> None:
        assert passes({"path": {"allowlist": ["/workspace/**", "/public/**"]}}, {"path": "/workspace/src/main.py"})

    def test_passes_second_glob(self) -> None:
        assert passes({"path": {"allowlist": ["/workspace/**", "/public/**"]}}, {"path": "/public/index.html"})

    def test_fails_no_matching_glob(self) -> None:
        result = evaluate({"path": {"allowlist": ["/workspace/**"]}}, {"path": "/etc/shadow"})
        assert not result.passed
        assert result.violations[0].constraint_type == "allowlist"

    def test_double_star_glob_recursive(self) -> None:
        assert passes({"path": {"allowlist": ["/workspace/**"]}}, {"path": "/workspace/a/b/c/d.txt"})

    def test_single_star_glob_non_recursive(self) -> None:
        # fnmatch: * matches everything including /
        assert passes({"path": {"allowlist": ["/tmp/*.txt"]}}, {"path": "/tmp/notes.txt"})
        # /tmp/a/b.txt - fnmatch * does NOT span / in some implementations
        # but Python's fnmatch does match / with *
        assert passes({"path": {"allowlist": ["/tmp/*"]}}, {"path": "/tmp/file"})


# ── String: blocklist (glob) ───────────────────────────────────────────────────


class TestBlocklist:
    def test_passes_when_no_pattern_matches(self) -> None:
        assert passes({"path": {"blocklist": ["/etc/shadow", "/etc/passwd"]}}, {"path": "/tmp/file"})

    def test_fails_exact_blocked_path(self) -> None:
        result = evaluate({"path": {"blocklist": ["/etc/shadow"]}}, {"path": "/etc/shadow"})
        assert not result.passed
        assert result.violations[0].constraint_type == "blocklist"

    def test_fails_glob_blocked_path(self) -> None:
        assert fails({"path": {"blocklist": ["/etc/**"]}}, {"path": "/etc/nginx/nginx.conf"})

    def test_blocklist_and_allowlist_combined(self) -> None:
        # Must match allowlist AND not match blocklist → both checked (AND logic)
        result = evaluate(
            {"path": {"allowlist": ["/etc/**"], "blocklist": ["/etc/shadow"]}},
            {"path": "/etc/shadow"},
        )
        assert not result.passed


# ── String: max_length ─────────────────────────────────────────────────────────


class TestMaxLength:
    def test_passes_within_limit(self) -> None:
        assert passes({"name": {"max_length": 50}}, {"name": "Alice"})

    def test_fails_exceeds_limit(self) -> None:
        result = evaluate({"name": {"max_length": 5}}, {"name": "AliceBobCharlie"})
        assert not result.passed
        assert result.violations[0].constraint_type == "max_length"


# ── Numeric constraints ────────────────────────────────────────────────────────


class TestNumericConstraints:
    def test_min_value_passes(self) -> None:
        assert passes({"count": {"min_value": 1}}, {"count": 5})

    def test_min_value_fails_below(self) -> None:
        result = evaluate({"count": {"min_value": 1}}, {"count": 0})
        assert not result.passed
        assert result.violations[0].constraint_type == "min_value"

    def test_min_value_boundary_inclusive(self) -> None:
        assert passes({"count": {"min_value": 1}}, {"count": 1})

    def test_max_value_passes(self) -> None:
        assert passes({"max_ports": {"max_value": 100}}, {"max_ports": 80})

    def test_max_value_fails_above(self) -> None:
        result = evaluate({"max_ports": {"max_value": 100}}, {"max_ports": 101})
        assert not result.passed
        assert result.violations[0].constraint_type == "max_value"

    def test_max_value_boundary_inclusive(self) -> None:
        assert passes({"max_ports": {"max_value": 100}}, {"max_ports": 100})

    def test_min_and_max_combined(self) -> None:
        assert passes({"val": {"min_value": 1, "max_value": 10}}, {"val": 5})
        assert fails({"val": {"min_value": 1, "max_value": 10}}, {"val": 11})

    def test_float_values(self) -> None:
        assert passes({"ratio": {"min_value": 0.0, "max_value": 1.0}}, {"ratio": 0.5})
        assert fails({"ratio": {"min_value": 0.0, "max_value": 1.0}}, {"ratio": 1.5})

    def test_booleans_not_treated_as_numeric(self) -> None:
        # True/False are bool subclass of int in Python — must not be min/max checked
        result = evaluate({"val": {"min_value": 0}}, {"val": True})
        assert result.passed  # bool skips numeric check


# ── Boolean constraints ────────────────────────────────────────────────────────


class TestBooleanConstraints:
    def test_must_be_true_passes(self) -> None:
        assert passes({"confirmed": {"must_be": True}}, {"confirmed": True})

    def test_must_be_true_fails_false(self) -> None:
        result = evaluate({"confirmed": {"must_be": True}}, {"confirmed": False})
        assert not result.passed
        assert result.violations[0].constraint_type == "must_be"

    def test_must_be_false_passes(self) -> None:
        assert passes({"dry_run": {"must_be": False}}, {"dry_run": False})

    def test_must_be_fails_non_bool(self) -> None:
        result = evaluate({"confirmed": {"must_be": True}}, {"confirmed": "true"})
        assert not result.passed

    def test_must_be_stops_further_checks(self) -> None:
        # must_be check returns early — other constraints not evaluated
        result = evaluate(
            {"v": {"must_be": True, "one_of": [True]}},
            {"v": False},
        )
        assert not result.passed
        assert len(result.violations) == 1
        assert result.violations[0].constraint_type == "must_be"


# ── Array constraints ──────────────────────────────────────────────────────────


class TestArrayConstraints:
    def test_max_items_passes(self) -> None:
        assert passes({"tags": {"max_items": 5}}, {"tags": ["a", "b", "c"]})

    def test_max_items_fails_exceeds(self) -> None:
        result = evaluate({"tags": {"max_items": 2}}, {"tags": ["a", "b", "c"]})
        assert not result.passed
        assert result.violations[0].constraint_type == "max_items"

    def test_item_constraints_applied_to_each(self) -> None:
        result = evaluate(
            {"hosts": {"item_constraints": {"must_not_contain": ["internal"]}}},
            {"hosts": ["api.github.com", "api.internal.corp"]},
        )
        assert not result.passed
        # Violation should reference the second item
        assert "[1]" in result.violations[0].argument

    def test_item_constraints_all_pass(self) -> None:
        assert passes(
            {"hosts": {"item_constraints": {"must_not_contain": ["internal"]}}},
            {"hosts": ["api.github.com", "api.example.com"]},
        )

    def test_item_constraints_one_of(self) -> None:
        assert passes(
            {"methods": {"item_constraints": {"one_of": ["GET", "POST"]}}},
            {"methods": ["GET", "POST"]},
        )
        assert fails(
            {"methods": {"item_constraints": {"one_of": ["GET", "POST"]}}},
            {"methods": ["GET", "DELETE"]},
        )

    def test_max_items_and_item_constraints_combined(self) -> None:
        result = evaluate(
            {"tags": {"max_items": 2, "item_constraints": {"max_length": 5}}},
            {"tags": ["short", "also-short", "way-too-long"]},
        )
        assert not result.passed
        # Both max_items AND item constraint violation
        types = {v.constraint_type for v in result.violations}
        assert "max_items" in types


# ── Nested argument access (dot notation) ──────────────────────────────────────


class TestNestedAccess:
    def test_simple_dot_path(self) -> None:
        assert passes(
            {"options.timeout": {"max_value": 30}},
            {"options": {"timeout": 10}},
        )

    def test_dot_path_fails(self) -> None:
        result = evaluate(
            {"options.timeout": {"max_value": 30}},
            {"options": {"timeout": 60}},
        )
        assert not result.passed

    def test_deep_dot_path(self) -> None:
        assert passes(
            {"config.network.proxy.port": {"max_value": 65535}},
            {"config": {"network": {"proxy": {"port": 8080}}}},
        )

    def test_missing_intermediate_key(self) -> None:
        # options.timeout missing because options dict has no 'timeout'
        result = evaluate(
            {"options.timeout": {"max_value": 30}},
            {"options": {"retries": 3}},
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "required"


# ── Network: domain matching ───────────────────────────────────────────────────


class TestDomainMatching:
    def test_exact_match(self) -> None:
        assert _domain_matches("api.github.com", "api.github.com")
        assert not _domain_matches("other.github.com", "api.github.com")

    def test_wildcard_subdomain(self) -> None:
        assert _domain_matches("api.github.com", "*.github.com")
        assert _domain_matches("uploads.github.com", "*.github.com")

    def test_wildcard_does_not_match_root(self) -> None:
        assert not _domain_matches("github.com", "*.github.com")

    def test_wildcard_does_not_match_deep_subdomain(self) -> None:
        # *.github.com matches only single-level subdomains.
        # deep.api.github.com does NOT match — use *.api.github.com for that.
        assert not _domain_matches("deep.api.github.com", "*.github.com")

    def test_case_insensitive(self) -> None:
        assert _domain_matches("API.GITHUB.COM", "api.github.com")
        assert _domain_matches("api.github.com", "*.GITHUB.COM")


class TestAllowedDomains:
    def test_passes_allowed_domain(self) -> None:
        assert passes(
            {"url": {"allowed_domains": ["api.github.com", "api.slack.com"]}},
            {"url": "https://api.github.com/repos"},
        )

    def test_fails_blocked_domain(self) -> None:
        result = evaluate(
            {"url": {"allowed_domains": ["api.github.com"]}},
            {"url": "https://evil.com/steal"},
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "allowed_domains"

    def test_wildcard_domain_allowed(self) -> None:
        assert passes(
            {"url": {"allowed_domains": ["*.github.com"]}},
            {"url": "https://api.github.com/v3"},
        )

    def test_bare_hostname_without_scheme(self) -> None:
        assert passes(
            {"target": {"allowed_domains": ["api.github.com"]}},
            {"target": "api.github.com"},
        )


class TestBlockedDomains:
    def test_passes_non_blocked_domain(self) -> None:
        assert passes(
            {"url": {"blocked_domains": ["*.internal.corp"]}},
            {"url": "https://api.github.com"},
        )

    def test_fails_blocked_wildcard(self) -> None:
        result = evaluate(
            {"url": {"blocked_domains": ["*.internal.corp"]}},
            {"url": "https://secrets.internal.corp/api"},
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "blocked_domains"

    def test_fails_exact_blocked(self) -> None:
        assert fails(
            {"url": {"blocked_domains": ["evil.com"]}},
            {"url": "https://evil.com"},
        )


class TestAllowedSchemes:
    def test_passes_https(self) -> None:
        assert passes(
            {"url": {"allowed_schemes": ["https"]}},
            {"url": "https://api.example.com"},
        )

    def test_fails_http(self) -> None:
        result = evaluate(
            {"url": {"allowed_schemes": ["https"]}},
            {"url": "http://api.example.com"},
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "allowed_schemes"

    def test_fails_ftp(self) -> None:
        assert fails(
            {"url": {"allowed_schemes": ["https", "http"]}},
            {"url": "ftp://files.example.com"},
        )


# ── Network: CIDR matching ─────────────────────────────────────────────────────


class TestCIDRMatching:
    def test_ip_in_cidr(self) -> None:
        import ipaddress
        ip = ipaddress.ip_address("10.0.1.5")
        assert _ip_in_cidr(ip, "10.0.0.0/8")
        assert not _ip_in_cidr(ip, "192.168.0.0/16")

    def test_ip_in_slash_32(self) -> None:
        import ipaddress
        ip = ipaddress.ip_address("192.168.1.1")
        assert _ip_in_cidr(ip, "192.168.1.1/32")
        assert not _ip_in_cidr(ip, "192.168.1.2/32")

    def test_ip_in_slash_0(self) -> None:
        import ipaddress
        # /0 matches everything
        assert _ip_in_cidr(ipaddress.ip_address("1.2.3.4"), "0.0.0.0/0")

    def test_ipv6_cidr(self) -> None:
        import ipaddress
        ip = ipaddress.ip_address("2001:db8::1")
        assert _ip_in_cidr(ip, "2001:db8::/32")
        assert not _ip_in_cidr(ip, "2001:db9::/32")

    def test_malformed_cidr_returns_false(self) -> None:
        import ipaddress
        ip = ipaddress.ip_address("10.0.0.1")
        assert not _ip_in_cidr(ip, "not-a-cidr")


class TestAllowedCIDRs:
    def test_passes_ip_in_allowed_range(self) -> None:
        assert passes(
            {"target": {"allowed_cidrs": ["10.0.0.0/8"]}},
            {"target": "10.1.2.3"},
        )

    def test_fails_ip_outside_allowed_range(self) -> None:
        result = evaluate(
            {"target": {"allowed_cidrs": ["10.0.0.0/8"]}},
            {"target": "192.168.1.1"},
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "allowed_cidrs"

    def test_dns_name_skips_cidr_check(self) -> None:
        # DNS names can't be CIDR-checked without resolution — should pass silently
        result = evaluate(
            {"target": {"allowed_cidrs": ["10.0.0.0/8"]}},
            {"target": "api.example.com"},
        )
        assert result.passed


class TestBlockedCIDRs:
    def test_passes_ip_not_in_blocked(self) -> None:
        assert passes(
            {"target": {"blocked_cidrs": ["0.0.0.0/0"]}},
            {"target": "api.github.com"},  # DNS name, not an IP
        )

    def test_fails_ip_in_blocked_range(self) -> None:
        result = evaluate(
            {"target": {"blocked_cidrs": ["192.168.0.0/16"]}},
            {"target": "192.168.1.100"},
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "blocked_cidrs"

    def test_slash_zero_blocks_everything(self) -> None:
        assert fails(
            {"target": {"blocked_cidrs": ["0.0.0.0/0"]}},
            {"target": "1.2.3.4"},
        )

    def test_ip_from_url_in_blocked_cidr(self) -> None:
        assert fails(
            {"url": {"blocked_cidrs": ["10.0.0.0/8"]}},
            {"url": "https://10.0.0.1/api"},
        )


# ── Network: ports ─────────────────────────────────────────────────────────────


class TestPortConstraints:
    def test_port_in_list(self) -> None:
        assert _port_in_list(443, [80, 443])
        assert not _port_in_list(8080, [80, 443])

    def test_port_in_range(self) -> None:
        assert _port_in_list(8500, ["8000-9000"])
        assert not _port_in_list(7999, ["8000-9000"])

    def test_port_boundary_inclusive(self) -> None:
        assert _port_in_list(8000, ["8000-9000"])
        assert _port_in_list(9000, ["8000-9000"])

    def test_port_mixed_list(self) -> None:
        assert _port_in_list(443, [80, 443, "8000-9000"])
        assert _port_in_list(8080, [80, 443, "8000-9000"])

    def test_allowed_ports_in_url(self) -> None:
        assert passes(
            {"url": {"allowed_ports": [443, "8000-9000"]}},
            {"url": "https://api.example.com:8080/v1"},
        )
        assert fails(
            {"url": {"allowed_ports": [443]}},
            {"url": "https://api.example.com:9090/v1"},
        )


# ── URL parsing edge cases ─────────────────────────────────────────────────────


class TestURLParsing:
    def test_url_with_scheme(self) -> None:
        p = _parse_url_lenient("https://api.example.com/path")
        assert p.hostname == "api.example.com"
        assert p.scheme == "https"

    def test_url_without_scheme(self) -> None:
        p = _parse_url_lenient("api.example.com/path")
        assert p.hostname == "api.example.com"

    def test_ip_address_url(self) -> None:
        p = _parse_url_lenient("https://10.0.0.1:8080/api")
        assert p.hostname == "10.0.0.1"
        assert p.port == 8080

    def test_bare_ip(self) -> None:
        p = _parse_url_lenient("192.168.1.1")
        assert p.hostname == "192.168.1.1"

    def test_url_with_port(self) -> None:
        p = _parse_url_lenient("https://api.example.com:8443/")
        assert p.port == 8443

    def test_url_with_path_and_query(self) -> None:
        p = _parse_url_lenient("https://api.example.com/v1/repos?page=1")
        assert p.hostname == "api.example.com"
        assert p.scheme == "https"


# ── AND logic: multiple constraints on same argument ──────────────────────────


class TestAndLogic:
    def test_multiple_string_constraints_all_pass(self) -> None:
        assert passes(
            {"path": {
                "must_start_with": ["/workspace/"],
                "must_not_contain": [".."],
                "allowlist": ["/workspace/**"],
            }},
            {"path": "/workspace/src/main.py"},
        )

    def test_multiple_string_constraints_one_fails(self) -> None:
        result = evaluate(
            {"path": {
                "must_start_with": ["/workspace/"],
                "must_not_contain": [".."],
            }},
            {"path": "/workspace/../etc/passwd"},
        )
        assert not result.passed
        assert result.violations[0].constraint_type == "must_not_contain"

    def test_two_args_both_must_pass(self) -> None:
        result = evaluate(
            {
                "url": {"allowed_schemes": ["https"]},
                "method": {"one_of": ["GET", "POST"]},
            },
            {"url": "http://api.example.com", "method": "DELETE"},
        )
        assert not result.passed
        types = {v.constraint_type for v in result.violations}
        assert "allowed_schemes" in types
        assert "one_of" in types

    def test_first_arg_fails_second_arg_still_checked(self) -> None:
        # Both args are independently evaluated
        result = evaluate(
            {
                "a": {"must_start_with": ["/safe"]},
                "b": {"max_value": 10},
            },
            {"a": "/unsafe", "b": 100},
        )
        assert not result.passed
        assert len(result.violations) == 2


# ── Engine integration ─────────────────────────────────────────────────────────


def _make_policy_with_caps(capabilities_yaml: str) -> AgentWardPolicy:
    """Build a minimal policy with capabilities from YAML snippet."""
    full_yaml = textwrap.dedent(f"""\
        version: "1.0"
        skills:
          test-skill:
            file:
              read: true
              write: true
              capabilities:
                {textwrap.indent(capabilities_yaml.strip(), "                ")}
    """)
    return AgentWardPolicy(**yaml.safe_load(full_yaml))


class TestEngineIntegration:
    def test_no_capabilities_works_as_before(self) -> None:
        """Backward compat: policy without capabilities evaluates normally."""
        import pathlib
        policy = AgentWardPolicy(
            version="1.0",
            skills={"test-skill": {"file": ResourcePermissions(actions={"read": True})}},
        )
        engine = PolicyEngine(policy)
        # Protected paths (SSH keys, AWS creds) are still blocked by the safety floor.
        # Use the actual home directory to ensure the path matches.
        ssh_key = str(pathlib.Path.home() / ".ssh" / "id_rsa")
        result = engine.evaluate("file_read", {"path": ssh_key})
        assert result.decision == PolicyDecision.BLOCK  # protected path invariant

    def test_no_capabilities_read_allowed(self) -> None:
        policy = AgentWardPolicy(
            version="1.0",
            skills={"test-skill": {"file": ResourcePermissions(actions={"read": True})}},
        )
        engine = PolicyEngine(policy)
        result = engine.evaluate("file_read", {"path": "/tmp/notes.txt"})
        assert result.decision == PolicyDecision.ALLOW

    def test_capabilities_block_forbidden_path(self) -> None:
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              fs:
                file:
                  read: true
                  write: true
                  capabilities:
                    write_file:
                      path:
                        must_start_with: ["/tmp/", "/workspace/"]
                        must_not_contain: [".."]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        # Allowed path
        r = engine.evaluate("write_file", {"path": "/tmp/output.txt"})
        assert r.decision == PolicyDecision.ALLOW

        # Forbidden path — not in must_start_with
        r = engine.evaluate("write_file", {"path": "/etc/cron.d/backdoor"})
        assert r.decision == PolicyDecision.BLOCK
        assert "must_start_with" in r.reason

        # Path traversal attempt
        r = engine.evaluate("write_file", {"path": "/workspace/../etc/passwd"})
        assert r.decision == PolicyDecision.BLOCK
        assert "must_not_contain" in r.reason

    def test_capabilities_block_wrong_http_method(self) -> None:
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              net:
                http:
                  read: true
                  capabilities:
                    http_request:
                      url:
                        allowed_domains: ["api.github.com"]
                        allowed_schemes: ["https"]
                      method:
                        one_of: ["GET", "POST"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        r = engine.evaluate("http_request", {"url": "https://api.github.com/v3", "method": "GET"})
        assert r.decision == PolicyDecision.ALLOW

        r = engine.evaluate("http_request", {"url": "https://api.github.com/v3", "method": "DELETE"})
        assert r.decision == PolicyDecision.BLOCK
        assert "one_of" in r.reason

        r = engine.evaluate("http_request", {"url": "http://evil.com", "method": "GET"})
        assert r.decision == PolicyDecision.BLOCK

    def test_capabilities_block_nmap_outside_allowed_cidr(self) -> None:
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              scanning:
                nmap:
                  read: true
                  capabilities:
                    nmap_scan:
                      target:
                        allowed_cidrs: ["10.0.0.0/8", "192.168.0.0/16"]
                      scan_type:
                        one_of: ["connect", "version"]
                      max_ports:
                        max_value: 100
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        # Allowed target in 10.0.0.0/8
        r = engine.evaluate("nmap_scan", {"target": "10.1.2.3", "scan_type": "connect", "max_ports": 50})
        assert r.decision == PolicyDecision.ALLOW

        # Blocked: target outside allowed CIDRs
        r = engine.evaluate("nmap_scan", {"target": "8.8.8.8", "scan_type": "connect", "max_ports": 50})
        assert r.decision == PolicyDecision.BLOCK
        assert "allowed_cidrs" in r.reason

        # Blocked: scan_type not in one_of
        r = engine.evaluate("nmap_scan", {"target": "10.1.2.3", "scan_type": "stealth", "max_ports": 50})
        assert r.decision == PolicyDecision.BLOCK

        # Blocked: max_ports exceeds limit
        r = engine.evaluate("nmap_scan", {"target": "10.1.2.3", "scan_type": "connect", "max_ports": 200})
        assert r.decision == PolicyDecision.BLOCK
        assert "max_value" in r.reason

    def test_capabilities_missing_required_arg_blocked(self) -> None:
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              fs:
                file:
                  write: true
                  capabilities:
                    write_file:
                      path:
                        must_start_with: ["/tmp/"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        r = engine.evaluate("write_file", {})  # no path argument
        assert r.decision == PolicyDecision.BLOCK
        assert "required" in r.reason.lower() or "path" in r.reason

    def test_tool_without_capabilities_not_blocked(self) -> None:
        """Only the specific tool with capabilities is constrained."""
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              fs:
                file:
                  read: true
                  write: true
                  capabilities:
                    write_file:
                      path:
                        must_start_with: ["/tmp/"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        # read_file has no capability constraints — should pass unconstrained
        r = engine.evaluate("read_file", {"path": "/etc/hosts"})
        # Protected paths block /etc/* — but that's the protected path check, not capabilities
        # Use a safe path to test capabilities aren't applied to unconstrained tools
        r = engine.evaluate("read_file", {"path": "/tmp/notes.txt"})
        assert r.decision == PolicyDecision.ALLOW

    def test_skill_and_resource_preserved_in_block(self) -> None:
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              my-skill:
                myres:
                  read: true
                  capabilities:
                    myres_read:
                      path:
                        must_start_with: ["/safe"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        r = engine.evaluate("myres_read", {"path": "/unsafe"})
        assert r.decision == PolicyDecision.BLOCK
        assert r.skill == "my-skill"
        assert r.resource == "myres"

    def test_block_reason_is_specific_not_vague(self) -> None:
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              fs:
                file:
                  write: true
                  capabilities:
                    write_file:
                      path:
                        blocklist: ["/etc/shadow", "/etc/passwd"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        r = engine.evaluate("write_file", {"path": "/etc/shadow"})
        assert r.decision == PolicyDecision.BLOCK
        assert "BLOCKED" in r.reason
        assert "path" in r.reason
        assert "/etc/shadow" in r.reason
        assert "blocklist" in r.reason


# ── Backward compatibility ─────────────────────────────────────────────────────


class TestBackwardCompatibility:
    def test_existing_policy_no_capabilities_field(self) -> None:
        """Policies without capabilities load and evaluate without changes."""
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              email-manager:
                gmail:
                  read: true
                  send: false
                  filters:
                    exclude_labels: ["Finance", "Medical"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        r = engine.evaluate("gmail_read", {"label": "inbox"})
        assert r.decision == PolicyDecision.ALLOW

        r = engine.evaluate("gmail_send", {"to": "user@example.com"})
        assert r.decision == PolicyDecision.BLOCK

    def test_filters_still_work_alongside_capabilities(self) -> None:
        """Filters and capabilities coexist — filters run first."""
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              fs:
                file:
                  read: true
                  filters:
                    only_from: ["trusted_source"]
                  capabilities:
                    read_file:
                      path:
                        must_start_with: ["/tmp/"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        engine = PolicyEngine(policy)

        # Fails only_from filter (no "trusted_source" in args) — before caps
        r = engine.evaluate("read_file", {"path": "/tmp/file"})
        assert r.decision == PolicyDecision.BLOCK
        assert "only_from" in r.reason


# ── YAML round-trip ────────────────────────────────────────────────────────────


class TestYAMLRoundTrip:
    def test_capabilities_load_from_yaml_string(self) -> None:
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              filesystem-manager:
                file:
                  read: true
                  write: true
                  capabilities:
                    write_file:
                      path:
                        must_start_with: ["/tmp/", "/workspace/"]
                        must_not_start_with: ["/etc/", "/home/"]
                        must_not_contain: [".."]
                    read_file:
                      path:
                        allowlist: ["/workspace/**", "/public/**"]
                        blocklist: ["/etc/shadow", "/etc/passwd"]
              network-tools:
                http:
                  read: true
                  capabilities:
                    http_request:
                      url:
                        allowed_domains: ["api.github.com", "api.slack.com"]
                        blocked_domains: ["*.internal.corp"]
                        allowed_schemes: ["https"]
                      method:
                        one_of: ["GET", "POST"]
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))

        # Verify parsing
        fs_caps = policy.skills["filesystem-manager"]["file"].capabilities
        assert "write_file" in fs_caps
        assert "read_file" in fs_caps

        write_path = fs_caps["write_file"]["path"]
        assert write_path.must_start_with == ["/tmp/", "/workspace/"]
        assert write_path.must_not_contain == [".."]

        read_path = fs_caps["read_file"]["path"]
        assert "/workspace/**" in read_path.allowlist
        assert "/etc/shadow" in read_path.blocklist

        net_caps = policy.skills["network-tools"]["http"].capabilities
        url_c = net_caps["http_request"]["url"]
        assert "api.github.com" in url_c.allowed_domains
        assert "*.internal.corp" in url_c.blocked_domains
        assert url_c.allowed_schemes == ["https"]

        method_c = net_caps["http_request"]["method"]
        assert "GET" in method_c.one_of

    def test_full_policy_yaml_example(self) -> None:
        """Test the full YAML example from the spec."""
        policy_yaml = textwrap.dedent("""\
            version: "1.0"
            skills:
              scanning-tools:
                nmap:
                  read: true
                  capabilities:
                    nmap_scan:
                      target:
                        allowed_cidrs: ["10.0.0.0/8", "192.168.0.0/16"]
                        blocked_cidrs: ["0.0.0.0/0"]
                      scan_type:
                        one_of: ["connect", "version"]
                      max_ports:
                        max_value: 100
        """)
        policy = AgentWardPolicy(**yaml.safe_load(policy_yaml))
        caps = policy.skills["scanning-tools"]["nmap"].capabilities["nmap_scan"]

        target = caps["target"]
        assert "10.0.0.0/8" in target.allowed_cidrs
        assert "0.0.0.0/0" in target.blocked_cidrs

        scan_type = caps["scan_type"]
        assert scan_type.one_of == ["connect", "version"]

        max_ports = caps["max_ports"]
        assert max_ports.max_value == 100


# ── Schema: ArgumentConstraints model validation ───────────────────────────────


class TestArgumentConstraintsSchema:
    def test_empty_constraints_valid(self) -> None:
        c = ArgumentConstraints()
        assert c.must_start_with == []
        assert c.fail_open is False

    def test_fail_open_default_false(self) -> None:
        c = ArgumentConstraints(must_start_with=["/tmp"])
        assert c.fail_open is False

    def test_regex_compiled_at_construction(self) -> None:
        c = ArgumentConstraints(matches=[r"^\d+$"])
        assert len(c._compiled_matches) == 1

    def test_not_matches_compiled(self) -> None:
        c = ArgumentConstraints(not_matches=[r"\brm\b"])
        assert len(c._compiled_not_matches) == 1

    def test_resource_permissions_with_capabilities(self) -> None:
        rp = ResourcePermissions(**{
            "read": True,
            "capabilities": {
                "read_file": {
                    "path": {"must_start_with": ["/tmp/"]}
                }
            }
        })
        assert rp.actions["read"] is True
        assert "read_file" in rp.capabilities
        assert rp.capabilities["read_file"]["path"].must_start_with == ["/tmp/"]

    def test_resource_permissions_denied_clears_capabilities(self) -> None:
        rp = ResourcePermissions(denied=True)
        assert rp.denied is True
        assert rp.capabilities == {}

    def test_item_constraints_recursive(self) -> None:
        c = ArgumentConstraints(
            max_items=5,
            item_constraints=ArgumentConstraints(must_not_contain=["evil"]),
        )
        assert c.item_constraints is not None
        assert c.item_constraints.must_not_contain == ["evil"]
