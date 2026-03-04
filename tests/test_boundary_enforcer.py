"""Tests for runtime data boundary enforcement (BoundaryEnforcer).

Verifies taint tracking, cross-zone blocking, same-zone pass-through,
LOG_ONLY behaviour, content-flow matching, and edge cases.
"""

from __future__ import annotations

import pytest

from agentward.inspect.enforcer import BoundaryEnforcer, _MIN_SNIPPET_LENGTH
from agentward.policy.engine import EvaluationResult, PolicyEngine
from agentward.policy.schema import (
    AgentWardPolicy,
    DataBoundary,
    PolicyDecision,
    ResourcePermissions,
    ViolationAction,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy(
    boundaries: dict[str, DataBoundary] | None = None,
) -> AgentWardPolicy:
    """Build a minimal policy with skills and optional data boundaries.

    Skills:
      - ehr-connector:   resource 'ehr'      (tools: ehr_read, ehr_search)
      - clinical-notes:  resource 'notes'     (tools: notes_read, notes_write)
      - web-browser:     resource 'browser'   (tools: browser_navigate)
      - finance-tool:    resource 'finance'   (tools: finance_query)
    """
    skills = {
        "ehr-connector": {
            "ehr": ResourcePermissions.model_construct(
                denied=False, actions={"read": True}, filters={},
            ),
        },
        "clinical-notes": {
            "notes": ResourcePermissions.model_construct(
                denied=False, actions={"read": True, "write": True}, filters={},
            ),
        },
        "web-browser": {
            "browser": ResourcePermissions.model_construct(
                denied=False, actions={"navigate": True}, filters={},
            ),
        },
        "finance-tool": {
            "finance": ResourcePermissions.model_construct(
                denied=False, actions={"query": True}, filters={},
            ),
        },
    }

    return AgentWardPolicy(
        version="1.0",
        skills=skills,
        skill_chaining=[],
        require_approval=[],
        data_boundaries=boundaries or {},
    )


def _hipaa_zone(
    on_violation: ViolationAction = ViolationAction.BLOCK_AND_LOG,
) -> DataBoundary:
    """Standard HIPAA zone with ehr-connector + clinical-notes."""
    return DataBoundary(
        skills=["ehr-connector", "clinical-notes"],
        classification="phi",
        on_violation=on_violation,
    )


def _financial_zone(
    on_violation: ViolationAction = ViolationAction.BLOCK_AND_LOG,
) -> DataBoundary:
    return DataBoundary(
        skills=["finance-tool"],
        classification="financial",
        on_violation=on_violation,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBasicTaintAndBlock:
    """Core taint tracking: PHI response taints session, non-zone call blocked."""

    def test_phi_flows_to_browser_blocked(self) -> None:
        """EHR returns a URL → browser uses that URL → BLOCK."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        # EHR returns a response with a URL
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"content": [{"type": "text", "text": "Patient at https://records.hospital.com/p/12345"}]},
        )
        assert enforcer.taint_count == 1

        # Browser tries to navigate to that URL → BLOCK
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://records.hospital.com/p/12345"},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK
        assert "phi" in result.reason
        assert "hipaa_zone" in result.reason

    def test_phi_text_snippet_flows_to_browser(self) -> None:
        """EHR returns text snippet → browser uses that text → BLOCK."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        patient_text = "John Doe diagnosed with Type 2 Diabetes Mellitus on 2024-01-15"
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": patient_text},
        )

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://search.com/", "query": patient_text},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK

    def test_phi_file_path_flows_to_browser(self) -> None:
        """EHR returns a file path → browser tries to use it → BLOCK."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"file": "/data/patients/john-doe/records.pdf"},
        )

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "file:///data/patients/john-doe/records.pdf"},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestSameZoneAllowed:
    """Calls between skills in the same zone are always allowed."""

    def test_phi_flows_within_hipaa_zone(self) -> None:
        """EHR returns data → clinical-notes uses it → ALLOWED."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        url = "https://records.hospital.com/patient/99"
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": f"See records at {url}"},
        )

        result = enforcer.check_tool_call(
            "notes_write", "clinical-notes",
            {"text": f"Linked to {url}"},
        )
        assert result is None  # Same zone → allowed


class TestNoTaintNoBlock:
    """No taint entries means no blocking."""

    def test_no_taint_clean_call(self) -> None:
        """Browser call with no prior taint → allowed."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://example.com"},
        )
        assert result is None

    def test_taint_with_no_matching_content(self) -> None:
        """EHR returns data, browser uses DIFFERENT data → allowed."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": "https://records.hospital.com/patient/99"},
        )

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://news.example.com"},
        )
        assert result is None


class TestLogOnlyPassthrough:
    """LOG_ONLY violations return decision=LOG instead of BLOCK."""

    def test_log_only_returns_log_decision(self) -> None:
        policy = _make_policy({
            "hipaa_zone": _hipaa_zone(on_violation=ViolationAction.LOG_ONLY),
        })
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        url = "https://records.hospital.com/p/123"
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": f"See {url}"},
        )

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": url},
        )
        assert result is not None
        assert result.decision == PolicyDecision.LOG
        assert "log-only" in result.reason


class TestBlockAndNotify:
    """BLOCK_AND_NOTIFY also returns BLOCK (same as BLOCK_AND_LOG)."""

    def test_block_and_notify_returns_block(self) -> None:
        policy = _make_policy({
            "hipaa_zone": _hipaa_zone(on_violation=ViolationAction.BLOCK_AND_NOTIFY),
        })
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        url = "https://records.hospital.com/p/123"
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": f"See {url}"},
        )

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": url},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestShortSnippetsIgnored:
    """Snippets shorter than _MIN_SNIPPET_LENGTH are not tracked."""

    def test_short_text_not_tainted(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        # Response with only short strings (< 20 chars)
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"status": "ok", "count": "5"},
        )

        # Taint entry may exist (if URLs/paths found) but snippets list should be empty
        # Since there's no URL or path AND no long snippet, taint_count should be 0
        assert enforcer.taint_count == 0

    def test_exact_min_length_tracked(self) -> None:
        """A snippet exactly _MIN_SNIPPET_LENGTH chars IS tracked."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        text = "A" * _MIN_SNIPPET_LENGTH  # Exactly 20 chars
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": text},
        )
        assert enforcer.taint_count == 1

        # That snippet flows into browser args → blocked
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"query": text},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestMaxTaintEviction:
    """Old taint entries are evicted when max is exceeded."""

    def test_eviction_at_max(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(
            policy=policy, policy_engine=engine, max_taint_entries=3,
        )

        # Record 5 responses — first 2 should be evicted
        for i in range(5):
            url = f"https://records.hospital.com/patient/{i}"
            enforcer.record_response(
                "ehr_read", "ehr-connector",
                {"result": f"Record at {url}"},
            )

        assert enforcer.taint_count == 3

        # First URL (patient/0) should be evicted
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://records.hospital.com/patient/0"},
        )
        assert result is None  # Evicted

        # Last URL (patient/4) should still be tracked
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://records.hospital.com/patient/4"},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestUnknownSkillSkipped:
    """Unknown skills (None) are skipped for both recording and checking."""

    def test_none_skill_not_recorded(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        enforcer.record_response(
            "unknown_tool", None,
            {"result": "https://records.hospital.com/secret"},
        )
        assert enforcer.taint_count == 0

    def test_none_skill_not_checked(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        url = "https://records.hospital.com/p/1"
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": f"See {url}"},
        )

        # Tool with unknown skill → skip check
        result = enforcer.check_tool_call(
            "unknown_tool", None,
            {"url": url},
        )
        assert result is None


class TestMultipleZones:
    """Multiple boundary zones work independently."""

    def test_cross_zone_both_block(self) -> None:
        """PHI and financial data each blocked from escaping their zones."""
        policy = _make_policy({
            "hipaa_zone": _hipaa_zone(),
            "financial_zone": _financial_zone(),
        })
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        # PHI response
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": "https://records.hospital.com/patient/42"},
        )
        # Financial response
        enforcer.record_response(
            "finance_query", "finance-tool",
            {"result": "https://banking.example.com/account/secret"},
        )

        # Browser using PHI URL → blocked by hipaa_zone
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://records.hospital.com/patient/42"},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK
        assert "phi" in result.reason

        # Browser using financial URL → blocked by financial_zone
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://banking.example.com/account/secret"},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK
        assert "financial" in result.reason

    def test_same_zone_cross_allowed_other_blocked(self) -> None:
        """Finance data can flow within financial_zone but not to hipaa_zone skills."""
        policy = _make_policy({
            "hipaa_zone": _hipaa_zone(),
            "financial_zone": _financial_zone(),
        })
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        url = "https://banking.example.com/account/999"
        enforcer.record_response(
            "finance_query", "finance-tool",
            {"result": f"Account details at {url}"},
        )

        # EHR is NOT in financial_zone → blocked
        result = enforcer.check_tool_call(
            "ehr_read", "ehr-connector",
            {"query": url},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestNoBoundariesConfigured:
    """When no data_boundaries are defined, enforcer never blocks."""

    def test_empty_boundaries_always_none(self) -> None:
        policy = _make_policy(boundaries={})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        # Record and check — should always return None
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": "https://records.hospital.com/patient/1"},
        )
        assert enforcer.taint_count == 0  # ehr-connector not in any zone

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://records.hospital.com/patient/1"},
        )
        assert result is None


class TestEmptyArguments:
    """Edge case: empty or None arguments should not raise."""

    def test_empty_dict(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": "https://records.hospital.com/p/1"},
        )

        result = enforcer.check_tool_call("browser_navigate", "web-browser", {})
        assert result is None


class TestNestedResponseContent:
    """Enforcer extracts content from deeply nested response structures."""

    def test_nested_url_extraction(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        enforcer.record_response(
            "ehr_search", "ehr-connector",
            {
                "results": [
                    {"patient": {"url": "https://records.hospital.com/p/1"}},
                    {"patient": {"url": "https://records.hospital.com/p/2"}},
                ],
            },
        )
        assert enforcer.taint_count == 1

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"url": "https://records.hospital.com/p/2"},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK

    def test_nested_text_snippet_extraction(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        diagnosis = "Patient John Doe has chronic obstructive pulmonary disease"
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"records": [{"diagnosis": diagnosis}]},
        )
        assert enforcer.taint_count == 1

        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"query": diagnosis},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK


class TestSnippetMaxLength:
    """Text snippets are truncated to snippet_max_length."""

    def test_long_text_truncated_but_prefix_matches(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(
            policy=policy, policy_engine=engine, snippet_max_length=30,
        )

        long_text = "A" * 100
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": long_text},
        )

        # First 30 chars should match
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"query": "A" * 30},
        )
        assert result is not None
        assert result.decision == PolicyDecision.BLOCK

    def test_long_text_suffix_does_not_match(self) -> None:
        """Only the first snippet_max_length chars are tracked, so suffix won't match."""
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(
            policy=policy, policy_engine=engine, snippet_max_length=30,
        )

        # Use unique chars so prefix != suffix
        long_text = "X" * 30 + "Y" * 70
        enforcer.record_response(
            "ehr_read", "ehr-connector",
            {"result": long_text},
        )

        # Suffix-only string won't match the tracked prefix snippet
        result = enforcer.check_tool_call(
            "browser_navigate", "web-browser",
            {"query": "Y" * 70},
        )
        assert result is None


class TestNonZoneSkillRecordIgnored:
    """A response from a skill NOT in any zone produces no taint."""

    def test_browser_response_not_tainted(self) -> None:
        policy = _make_policy({"hipaa_zone": _hipaa_zone()})
        engine = PolicyEngine(policy)
        enforcer = BoundaryEnforcer(policy=policy, policy_engine=engine)

        enforcer.record_response(
            "browser_navigate", "web-browser",
            {"result": "https://some-site.com/important-data"},
        )
        assert enforcer.taint_count == 0
