"""Tests for the agentward test command — probe loading, runner, reporter, CLI."""

from __future__ import annotations

import textwrap
from io import StringIO
from pathlib import Path

import pytest
import yaml
from rich.console import Console
from typer.testing import CliRunner

from agentward.cli import app
from agentward.policy.loader import load_policy
from agentward.policy.schema import AgentWardPolicy
from agentward.testing.loader import ProbeLoadError, load_all_probes, load_builtin_probes, load_probes_from_file
from agentward.testing.models import Probe, ProbeCategory, ProbeOutcome, ProbeSeverity, ProbeResult
from agentward.testing.reporter import TestReporter as _TestReporter
from agentward.testing.reporter import exit_code
from agentward.testing.runner import RunnerConfig, TestRunner

FIXTURES = Path(__file__).parent / "fixtures"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy_file(tmp_path: Path, content: str) -> Path:
    """Write a policy YAML to a temp file and return its path."""
    p = tmp_path / "policy.yaml"
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def _make_probe_file(tmp_path: Path, probes_yaml: str, filename: str = "probes.yaml") -> Path:
    """Write a probe YAML file and return its path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(probes_yaml), encoding="utf-8")
    return p


def _console() -> Console:
    return Console(file=StringIO(), highlight=False)


# ---------------------------------------------------------------------------
# ProbeCategory / ProbeSeverity enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_probe_category_values(self) -> None:
        assert ProbeCategory.PROTECTED_PATHS == "protected_paths"
        assert ProbeCategory.SKILL_CHAINING == "skill_chaining"

    def test_probe_severity_values(self) -> None:
        assert ProbeSeverity.CRITICAL == "critical"
        assert ProbeSeverity.LOW == "low"

    def test_probe_outcome_values(self) -> None:
        assert ProbeOutcome.PASS == "pass"
        assert ProbeOutcome.FAIL == "fail"
        assert ProbeOutcome.GAP == "gap"
        assert ProbeOutcome.SKIP == "skip"


# ---------------------------------------------------------------------------
# Probe model
# ---------------------------------------------------------------------------


class TestProbeModel:
    def test_tool_call_probe(self) -> None:
        probe = Probe(
            name="test_probe",
            category="protected_paths",
            severity="critical",
            description="A test probe",
            expected="BLOCK",
            tool_name="read_file",
            arguments={"path": "~/.ssh/id_rsa"},
        )
        assert probe.tool_name == "read_file"
        assert probe.chaining_source is None

    def test_chaining_probe(self) -> None:
        probe = Probe(
            name="chain_probe",
            category="skill_chaining",
            severity="high",
            description="Chain test",
            expected="BLOCK",
            chaining_source="email-manager",
            chaining_target="web-researcher",
        )
        assert probe.chaining_source == "email-manager"
        assert probe.tool_name is None

    def test_default_arguments_are_empty_dict(self) -> None:
        probe = Probe(
            name="p",
            category="scope_creep",
            severity="low",
            description="d",
            expected="BLOCK",
            tool_name="any_tool",
        )
        assert probe.arguments == {}


# ---------------------------------------------------------------------------
# Probe loader
# ---------------------------------------------------------------------------


class TestProbeLoader:
    def test_load_builtin_probes_returns_non_empty_list(self) -> None:
        probes = load_builtin_probes()
        assert len(probes) > 0

    def test_builtin_probes_have_required_fields(self) -> None:
        for probe in load_builtin_probes():
            assert probe.name, f"Probe missing name: {probe}"
            assert probe.category, f"Probe '{probe.name}' missing category"
            assert probe.severity, f"Probe '{probe.name}' missing severity"
            assert probe.description, f"Probe '{probe.name}' missing description"
            assert probe.expected in ("BLOCK", "APPROVE", "REDACT", "LOG", "ALLOW"), (
                f"Probe '{probe.name}' has unexpected expected verdict: {probe.expected}"
            )

    def test_builtin_probes_have_tool_or_chaining(self) -> None:
        for probe in load_builtin_probes():
            has_tool = probe.tool_name is not None
            has_chain = probe.chaining_source is not None and probe.chaining_target is not None
            assert has_tool or has_chain, (
                f"Probe '{probe.name}' has neither tool_name nor chaining pair"
            )

    def test_protected_paths_category_present(self) -> None:
        probes = load_builtin_probes()
        cats = {p.category for p in probes}
        assert "protected_paths" in cats

    def test_all_expected_categories_present(self) -> None:
        probes = load_builtin_probes()
        cats = {p.category for p in probes}
        expected_cats = {
            "protected_paths",
            "path_traversal",
            "prompt_injection",
            "scope_creep",
            "skill_chaining",
            "boundary_violation",
            "pii_injection",
            "deserialization",
            "privilege_escalation",
        }
        assert expected_cats <= cats, f"Missing categories: {expected_cats - cats}"

    def test_load_from_file(self, tmp_path: Path) -> None:
        content = """\
            probes:
              - name: custom_probe_1
                category: scope_creep
                severity: high
                description: "Custom test probe"
                tool_name: gmail_send
                arguments:
                  to: "x@y.com"
                expected: BLOCK
                rationale: "Test"
        """
        probe_file = _make_probe_file(tmp_path, content)
        probes = load_probes_from_file(probe_file)
        assert len(probes) == 1
        assert probes[0].name == "custom_probe_1"
        assert probes[0].expected == "BLOCK"
        assert probes[0].source_file == str(probe_file)

    def test_load_chaining_probe_from_file(self, tmp_path: Path) -> None:
        content = """\
            probes:
              - name: chain_test
                category: skill_chaining
                severity: critical
                description: "Chain probe"
                chaining_source: skill-a
                chaining_target: skill-b
                expected: BLOCK
                requires_policy_feature: skill_chaining
        """
        probe_file = _make_probe_file(tmp_path, content)
        probes = load_probes_from_file(probe_file)
        assert probes[0].chaining_source == "skill-a"
        assert probes[0].chaining_target == "skill-b"
        assert probes[0].requires_policy_feature == "skill_chaining"

    def test_load_all_merges_user_probes(self, tmp_path: Path) -> None:
        """User probes with matching names override built-ins."""
        # Pick an existing built-in name
        builtins = load_builtin_probes()
        existing_name = builtins[0].name

        override_content = f"""\
            probes:
              - name: {existing_name}
                category: scope_creep
                severity: low
                description: "Overridden description"
                tool_name: any_tool
                expected: ALLOW
        """
        probe_file = _make_probe_file(tmp_path, override_content)
        merged = load_all_probes(extra_paths=[probe_file])

        # Override should replace the built-in
        overridden = next(p for p in merged if p.name == existing_name)
        assert overridden.expected == "ALLOW"
        assert overridden.description == "Overridden description"

    def test_load_all_adds_new_user_probes(self, tmp_path: Path) -> None:
        content = """\
            probes:
              - name: brand_new_custom_probe
                category: scope_creep
                severity: low
                description: "Completely new probe"
                tool_name: custom_tool
                expected: BLOCK
        """
        probe_file = _make_probe_file(tmp_path, content)
        merged = load_all_probes(extra_paths=[probe_file])
        names = {p.name for p in merged}
        assert "brand_new_custom_probe" in names

    def test_load_from_directory(self, tmp_path: Path) -> None:
        probe_dir = tmp_path / "probes"
        probe_dir.mkdir()

        (probe_dir / "a.yaml").write_text(
            "probes:\n"
            "  - name: dir_probe_a\n"
            "    category: scope_creep\n"
            "    severity: low\n"
            "    description: A\n"
            "    tool_name: t\n"
            "    expected: BLOCK\n",
            encoding="utf-8",
        )
        (probe_dir / "b.yaml").write_text(
            "probes:\n"
            "  - name: dir_probe_b\n"
            "    category: scope_creep\n"
            "    severity: low\n"
            "    description: B\n"
            "    tool_name: t\n"
            "    expected: BLOCK\n",
            encoding="utf-8",
        )
        merged = load_all_probes(extra_paths=[probe_dir])
        names = {p.name for p in merged}
        assert "dir_probe_a" in names
        assert "dir_probe_b" in names

    def test_load_error_on_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ProbeLoadError, match="Cannot read probe file"):
            load_probes_from_file(tmp_path / "nonexistent.yaml")

    def test_load_error_on_bad_yaml(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("probes: [: invalid yaml", encoding="utf-8")
        with pytest.raises(ProbeLoadError, match="YAML parse error"):
            load_probes_from_file(bad_file)

    def test_load_error_on_missing_probes_key(self, tmp_path: Path) -> None:
        f = tmp_path / "no_probes.yaml"
        f.write_text("other_key: value\n", encoding="utf-8")
        with pytest.raises(ProbeLoadError, match="top-level 'probes' list"):
            load_probes_from_file(f)

    def test_load_error_on_missing_required_field(self, tmp_path: Path) -> None:
        content = """\
            probes:
              - name: missing_fields
                category: scope_creep
                # severity missing
                description: "No severity"
                tool_name: t
                expected: BLOCK
        """
        f = _make_probe_file(tmp_path, content)
        with pytest.raises(ProbeLoadError, match="Missing required field 'severity'"):
            load_probes_from_file(f)

    def test_load_error_on_no_tool_or_chain(self, tmp_path: Path) -> None:
        content = """\
            probes:
              - name: neither
                category: scope_creep
                severity: low
                description: "No tool or chain"
                expected: BLOCK
        """
        f = _make_probe_file(tmp_path, content)
        with pytest.raises(ProbeLoadError, match="tool_name"):
            load_probes_from_file(f)

    def test_load_silently_skips_missing_directory(self, tmp_path: Path) -> None:
        missing_dir = tmp_path / "does_not_exist"
        probes = load_all_probes(extra_paths=[missing_dir])
        # Should return built-ins only without raising
        assert len(probes) == len(load_builtin_probes())

    def test_expected_normalised_to_uppercase(self, tmp_path: Path) -> None:
        content = """\
            probes:
              - name: lowercase_expected
                category: scope_creep
                severity: low
                description: "lowercase expected"
                tool_name: t
                expected: block
        """
        f = _make_probe_file(tmp_path, content)
        probes = load_probes_from_file(f)
        assert probes[0].expected == "BLOCK"


# ---------------------------------------------------------------------------
# Runner — protected path probes (safety floor, always pass)
# ---------------------------------------------------------------------------


class TestRunnerProtectedPaths:
    """Protected-path probes must PASS against any policy (including an empty one)."""

    @pytest.fixture
    def runner(self) -> TestRunner:
        config = RunnerConfig(policy_path=None)  # no policy → bare default
        r = TestRunner(config)
        r.load()
        return r

    def test_ssh_key_read_blocked(self, runner: TestRunner) -> None:
        probe = Probe(
            name="ssh_test",
            category="protected_paths",
            severity="critical",
            description="SSH key read",
            expected="BLOCK",
            tool_name="read_file",
            arguments={"path": "~/.ssh/id_rsa"},
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.PASS
        assert result.actual_decision == "BLOCK"

    def test_aws_credentials_blocked(self, runner: TestRunner) -> None:
        probe = Probe(
            name="aws_test",
            category="protected_paths",
            severity="critical",
            description="AWS credentials",
            expected="BLOCK",
            tool_name="read_file",
            arguments={"path": "~/.aws/credentials"},
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.PASS

    def test_kube_config_blocked(self, runner: TestRunner) -> None:
        probe = Probe(
            name="kube_test",
            category="protected_paths",
            severity="critical",
            description="Kube config",
            expected="BLOCK",
            tool_name="read_file",
            arguments={"path": "~/.kube/config"},
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.PASS


# ---------------------------------------------------------------------------
# Runner — policy rule interaction (PASS / FAIL / GAP)
# ---------------------------------------------------------------------------


class TestRunnerPolicyRules:
    @pytest.fixture
    def policy_file(self, tmp_path: Path) -> Path:
        return _make_policy_file(
            tmp_path,
            """\
            version: "1.0"
            skills:
              email-manager:
                gmail:
                  read: true
                  send: false
            """,
        )

    @pytest.fixture
    def runner(self, policy_file: Path) -> TestRunner:
        config = RunnerConfig(policy_path=policy_file)
        r = TestRunner(config)
        r.load()
        return r

    def test_pass_when_policy_blocks_expected_action(self, runner: TestRunner) -> None:
        probe = Probe(
            name="gmail_send_block",
            category="scope_creep",
            severity="high",
            description="Gmail send should be blocked",
            expected="BLOCK",
            tool_name="gmail_send",
            arguments={"to": "x@y.com", "body": "hi"},
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.PASS
        assert result.actual_decision == "BLOCK"

    def test_fail_when_policy_allows_expected_block(self, runner: TestRunner) -> None:
        # gmail_read is allowed in our policy, but probe expects BLOCK
        probe = Probe(
            name="gmail_read_should_block",
            category="scope_creep",
            severity="high",
            description="Gmail read expected to block (incorrect expectation to test FAIL)",
            expected="BLOCK",
            tool_name="gmail_read",
            arguments={"query": "inbox"},
        )
        result = runner.run_probe(probe)
        # Policy explicitly allows gmail.read → FAIL (not a gap, there IS a rule)
        assert result.outcome == ProbeOutcome.FAIL
        assert result.actual_decision == "ALLOW"

    def test_gap_when_tool_not_in_policy(self, runner: TestRunner) -> None:
        probe = Probe(
            name="unknown_tool",
            category="privilege_escalation",
            severity="critical",
            description="Unknown tool not in policy",
            expected="BLOCK",
            tool_name="shell_execute",
            arguments={"command": "id"},
        )
        result = runner.run_probe(probe)
        # Policy has no rule for shell_execute → default allow → GAP
        assert result.outcome == ProbeOutcome.GAP

    def test_gap_becomes_fail_in_strict_mode(self, policy_file: Path) -> None:
        config = RunnerConfig(policy_path=policy_file, strict=True)
        runner = TestRunner(config)
        runner.load()

        probe = Probe(
            name="unknown_strict",
            category="privilege_escalation",
            severity="critical",
            description="Unknown tool in strict mode",
            expected="BLOCK",
            tool_name="shell_execute",
            arguments={"command": "id"},
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.FAIL  # strict: GAP → FAIL

    def test_pass_when_expected_allow_matches(self, runner: TestRunner) -> None:
        probe = Probe(
            name="gmail_read_allow",
            category="scope_creep",
            severity="low",
            description="Gmail read is allowed and expected to be allowed",
            expected="ALLOW",
            tool_name="gmail_read",
            arguments={"query": "inbox"},
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.PASS


# ---------------------------------------------------------------------------
# Runner — chaining probes
# ---------------------------------------------------------------------------


class TestRunnerChaining:
    @pytest.fixture
    def policy_file(self, tmp_path: Path) -> Path:
        return _make_policy_file(
            tmp_path,
            """\
            version: "1.0"
            skill_chaining:
              - email-manager cannot trigger web-researcher
            """,
        )

    @pytest.fixture
    def runner(self, policy_file: Path) -> TestRunner:
        config = RunnerConfig(policy_path=policy_file)
        r = TestRunner(config)
        r.load()
        return r

    def test_chaining_probe_blocked_by_rule(self, runner: TestRunner) -> None:
        probe = Probe(
            name="email_to_web",
            category="skill_chaining",
            severity="critical",
            description="Email to web chain",
            expected="BLOCK",
            chaining_source="email-manager",
            chaining_target="web-researcher",
            requires_policy_feature="skill_chaining",
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.PASS
        assert result.actual_decision == "BLOCK"

    def test_allowed_chain_is_not_blocked(self, runner: TestRunner) -> None:
        probe = Probe(
            name="calendar_to_web",
            category="skill_chaining",
            severity="high",
            description="Calendar to web — no rule, should allow",
            expected="ALLOW",
            chaining_source="calendar-assistant",
            chaining_target="web-researcher",
            requires_policy_feature="skill_chaining",
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.PASS
        assert result.actual_decision == "ALLOW"


# ---------------------------------------------------------------------------
# Runner — skip logic
# ---------------------------------------------------------------------------


class TestRunnerSkip:
    @pytest.fixture
    def minimal_runner(self, tmp_path: Path) -> TestRunner:
        policy_file = _make_policy_file(
            tmp_path,
            """\
            version: "1.0"
            """,
        )
        config = RunnerConfig(policy_path=policy_file)
        r = TestRunner(config)
        r.load()
        return r

    def test_skip_chaining_probe_when_no_chaining_rules(
        self, minimal_runner: TestRunner
    ) -> None:
        probe = Probe(
            name="skip_chain",
            category="skill_chaining",
            severity="critical",
            description="Should be skipped",
            expected="BLOCK",
            chaining_source="a",
            chaining_target="b",
            requires_policy_feature="skill_chaining",
        )
        result = minimal_runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.SKIP
        assert "skill_chaining" in result.skip_reason  # type: ignore[operator]

    def test_skip_approval_probe_when_no_approval_rules(
        self, minimal_runner: TestRunner
    ) -> None:
        probe = Probe(
            name="skip_approval",
            category="scope_creep",
            severity="high",
            description="Needs approval rules",
            expected="APPROVE",
            tool_name="some_tool",
            requires_policy_feature="require_approval",
        )
        result = minimal_runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.SKIP

    def test_skip_sensitive_content_probe_when_disabled(
        self, tmp_path: Path
    ) -> None:
        # Explicitly disable sensitive_content so the feature is absent
        policy_file = _make_policy_file(
            tmp_path,
            """\
            version: "1.0"
            sensitive_content:
              enabled: false
            """,
        )
        config = RunnerConfig(policy_path=policy_file)
        runner = TestRunner(config)
        runner.load()
        probe = Probe(
            name="skip_sc",
            category="pii_injection",
            severity="critical",
            description="Needs sensitive_content",
            expected="BLOCK",
            tool_name="gmail_send",
            arguments={"body": "SSN: 123-45-6789"},
            requires_policy_feature="sensitive_content",
        )
        result = runner.run_probe(probe)
        assert result.outcome == ProbeOutcome.SKIP

    def test_no_skip_when_feature_present(self, tmp_path: Path) -> None:
        policy_file = _make_policy_file(
            tmp_path,
            """\
            version: "1.0"
            skill_chaining:
              - email-manager cannot trigger web-researcher
            """,
        )
        config = RunnerConfig(policy_path=policy_file)
        runner = TestRunner(config)
        runner.load()

        probe = Probe(
            name="not_skipped",
            category="skill_chaining",
            severity="critical",
            description="Should not be skipped",
            expected="BLOCK",
            chaining_source="email-manager",
            chaining_target="web-researcher",
            requires_policy_feature="skill_chaining",
        )
        result = runner.run_probe(probe)
        assert result.outcome != ProbeOutcome.SKIP


# ---------------------------------------------------------------------------
# Runner — filtering
# ---------------------------------------------------------------------------


class TestRunnerFiltering:
    def _probes(self) -> list[Probe]:
        return [
            Probe("p1", "protected_paths", "critical", "d", "BLOCK", tool_name="t"),
            Probe("p2", "scope_creep", "high", "d", "BLOCK", tool_name="t"),
            Probe("p3", "scope_creep", "medium", "d", "BLOCK", tool_name="t"),
            Probe("p4", "skill_chaining", "low", "d", "BLOCK", tool_name="t"),
        ]

    def test_filter_by_category(self) -> None:
        config = RunnerConfig(categories=["scope_creep"])
        runner = TestRunner(config)
        runner.load()
        filtered = runner.filter_probes(self._probes())
        assert all(p.category == "scope_creep" for p in filtered)
        assert len(filtered) == 2

    def test_filter_by_severity(self) -> None:
        config = RunnerConfig(severities=["critical"])
        runner = TestRunner(config)
        runner.load()
        filtered = runner.filter_probes(self._probes())
        assert all(p.severity == "critical" for p in filtered)
        assert len(filtered) == 1

    def test_filter_by_multiple_severities(self) -> None:
        config = RunnerConfig(severities=["critical", "high"])
        runner = TestRunner(config)
        runner.load()
        filtered = runner.filter_probes(self._probes())
        assert len(filtered) == 2

    def test_no_filter_returns_all(self) -> None:
        config = RunnerConfig()
        runner = TestRunner(config)
        runner.load()
        probes = self._probes()
        filtered = runner.filter_probes(probes)
        assert len(filtered) == len(probes)

    def test_filter_category_case_insensitive(self) -> None:
        config = RunnerConfig(categories=["Protected_Paths"])
        runner = TestRunner(config)
        runner.load()
        filtered = runner.filter_probes(self._probes())
        assert len(filtered) == 1


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


def _make_result(outcome: ProbeOutcome, expected: str = "BLOCK", actual: str = "ALLOW") -> ProbeResult:
    probe = Probe(
        name=f"probe_{outcome.value}",
        category="scope_creep",
        severity="high",
        description="Test probe",
        expected=expected,
        rationale="Test rationale",
        tool_name="some_tool",
    )
    return ProbeResult(
        probe=probe,
        outcome=outcome,
        actual_decision=actual if outcome != ProbeOutcome.SKIP else None,
        actual_reason="engine said so" if outcome != ProbeOutcome.SKIP else None,
        skip_reason="No rules" if outcome == ProbeOutcome.SKIP else None,
    )


class TestReporterOutput:
    def test_print_results_no_exception(self) -> None:
        results = [
            _make_result(ProbeOutcome.PASS, expected="BLOCK", actual="BLOCK"),
            _make_result(ProbeOutcome.FAIL),
            _make_result(ProbeOutcome.GAP),
            _make_result(ProbeOutcome.SKIP),
        ]
        con = _console()
        reporter = _TestReporter(con, verbose=True)
        reporter.print_results(results)  # must not raise

    def test_probe_list_no_exception(self) -> None:
        probes = load_builtin_probes()[:5]
        con = _console()
        reporter = _TestReporter(con, verbose=False)
        reporter.print_probe_list(probes)  # must not raise

    def test_exit_code_zero_all_pass(self) -> None:
        results = [_make_result(ProbeOutcome.PASS, expected="BLOCK", actual="BLOCK")]
        assert exit_code(results) == 0

    def test_exit_code_zero_with_gaps(self) -> None:
        results = [_make_result(ProbeOutcome.GAP)]
        assert exit_code(results, strict=False) == 0

    def test_exit_code_one_on_fail(self) -> None:
        results = [_make_result(ProbeOutcome.FAIL)]
        assert exit_code(results) == 1

    def test_exit_code_one_on_gap_in_strict_mode(self) -> None:
        results = [_make_result(ProbeOutcome.GAP)]
        assert exit_code(results, strict=True) == 1

    def test_exit_code_zero_skips_only(self) -> None:
        results = [_make_result(ProbeOutcome.SKIP)]
        assert exit_code(results) == 0


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCLI:
    """Smoke tests for the ``agentward test`` command via Typer's test runner."""

    runner = CliRunner()

    def test_list_flag_exits_zero(self) -> None:
        result = self.runner.invoke(app, ["test", "--list"])
        assert result.exit_code == 0, result.output

    def test_list_shows_probe_names(self) -> None:
        result = self.runner.invoke(app, ["test", "--list"])
        # At least one built-in probe name should appear
        assert "ssh" in result.output.lower() or "protected" in result.output.lower()

    def test_list_with_category_filter(self) -> None:
        result = self.runner.invoke(app, ["test", "--list", "--category", "protected_paths"])
        assert result.exit_code == 0

    def test_no_policy_runs_safety_floor(self) -> None:
        """Without --policy, only protected_path probes pass; others show as GAP."""
        result = self.runner.invoke(
            app,
            ["test", "--category", "protected_paths"],
        )
        # Exit code 0: protected_paths always pass (safety floor)
        assert result.exit_code == 0, result.output

    def test_with_simple_policy(self, tmp_path: Path) -> None:
        policy = _make_policy_file(
            tmp_path,
            """\
            version: "1.0"
            skills:
              email-manager:
                gmail:
                  read: true
                  send: false
            """,
        )
        result = self.runner.invoke(
            app,
            ["test", "--policy", str(policy), "--category", "protected_paths"],
        )
        assert result.exit_code == 0

    def test_invalid_policy_path_exits_one(self) -> None:
        result = self.runner.invoke(
            app,
            ["test", "--policy", "/nonexistent/policy.yaml"],
        )
        assert result.exit_code == 1

    def test_custom_probe_file_loaded(self, tmp_path: Path) -> None:
        custom = _make_probe_file(
            tmp_path,
            """\
            probes:
              - name: my_custom_probe
                category: scope_creep
                severity: low
                description: "Custom probe for testing"
                tool_name: read_file
                arguments:
                  path: "~/.ssh/id_rsa"
                expected: BLOCK
            """,
        )
        result = self.runner.invoke(
            app,
            [
                "test",
                "--list",
                "--probes",
                str(custom),
            ],
        )
        assert result.exit_code == 0
        assert "my_custom_probe" in result.output

    def test_verbose_flag_accepted(self, tmp_path: Path) -> None:
        policy = _make_policy_file(tmp_path, 'version: "1.0"\n')
        result = self.runner.invoke(
            app,
            [
                "test",
                "--policy",
                str(policy),
                "--verbose",
                "--category",
                "protected_paths",
            ],
        )
        assert result.exit_code == 0

    def test_strict_flag_causes_exit_one_on_gaps(self, tmp_path: Path) -> None:
        """Minimal policy → shell_execute is uncovered → GAP → exit 1 with --strict."""
        policy = _make_policy_file(tmp_path, 'version: "1.0"\n')
        result = self.runner.invoke(
            app,
            [
                "test",
                "--policy",
                str(policy),
                "--category",
                "privilege_escalation",
                "--strict",
            ],
        )
        # Privilege escalation probes are all gaps with empty policy → strict=1
        assert result.exit_code == 1

    def test_empty_filter_result_exits_zero(self, tmp_path: Path) -> None:
        policy = _make_policy_file(tmp_path, 'version: "1.0"\n')
        result = self.runner.invoke(
            app,
            [
                "test",
                "--policy",
                str(policy),
                "--category",
                "nonexistent_category",
            ],
        )
        assert result.exit_code == 0

    def test_bad_probe_file_exits_one(self, tmp_path: Path) -> None:
        bad_probes = tmp_path / "bad.yaml"
        bad_probes.write_text("not valid probe format: {", encoding="utf-8")
        result = self.runner.invoke(
            app,
            ["test", "--list", "--probes", str(bad_probes)],
        )
        assert result.exit_code == 1
