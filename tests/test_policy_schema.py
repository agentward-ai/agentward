"""Tests for policy schema models and YAML loading."""

from pathlib import Path

import pytest

from agentward.policy.loader import PolicyValidationError, load_policy
from agentward.policy.schema import (
    AgentWardPolicy,
    ChainingRule,
    DataBoundary,
    ResourcePermissions,
    ViolationAction,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestResourcePermissions:
    """Tests for the ResourcePermissions model validator."""

    def test_denied_shorthand(self) -> None:
        perms = ResourcePermissions.model_validate({"denied": True})
        assert perms.denied is True
        assert perms.actions == {}
        assert perms.filters == {}

    def test_action_booleans(self) -> None:
        perms = ResourcePermissions.model_validate({
            "read": True,
            "send": False,
            "delete": False,
        })
        assert perms.denied is False
        assert perms.actions == {"read": True, "send": False, "delete": False}

    def test_with_filters(self) -> None:
        perms = ResourcePermissions.model_validate({
            "read": True,
            "filters": {
                "exclude_labels": ["Finance", "Medical"],
            },
        })
        assert perms.actions == {"read": True}
        assert perms.filters == {"exclude_labels": ["Finance", "Medical"]}

    def test_nested_permissions_flattened(self) -> None:
        perms = ResourcePermissions.model_validate({
            "read": True,
            "modify": {
                "own_events": True,
                "others_events": False,
            },
        })
        assert perms.actions["modify.own_events"] is True
        assert perms.actions["modify.others_events"] is False
        assert perms.actions["read"] is True

    def test_is_action_allowed_denied_resource(self) -> None:
        perms = ResourcePermissions.model_validate({"denied": True})
        assert perms.is_action_allowed("read") is False
        assert perms.is_action_allowed("anything") is False

    def test_is_action_allowed_explicit(self) -> None:
        perms = ResourcePermissions.model_validate({"read": True, "send": False})
        assert perms.is_action_allowed("read") is True
        assert perms.is_action_allowed("send") is False

    def test_is_action_allowed_unknown(self) -> None:
        perms = ResourcePermissions.model_validate({"read": True})
        assert perms.is_action_allowed("delete") is None

    def test_invalid_not_a_dict(self) -> None:
        with pytest.raises(ValueError, match="must be a mapping"):
            ResourcePermissions.model_validate("not a dict")

    def test_invalid_filter_not_list(self) -> None:
        with pytest.raises(ValueError, match="must be a list"):
            ResourcePermissions.model_validate({
                "filters": {"exclude_labels": "not a list"},
            })


class TestChainingRule:
    """Tests for the ChainingRule model validator."""

    def test_parse_specific_target(self) -> None:
        rule = ChainingRule.model_validate(
            "email-manager cannot trigger web-researcher"
        )
        assert rule.source_skill == "email-manager"
        assert rule.target_skill == "web-researcher"

    def test_parse_any_target(self) -> None:
        rule = ChainingRule.model_validate(
            "finance-tracker cannot trigger any other skill"
        )
        assert rule.source_skill == "finance-tracker"
        assert rule.target_skill == "any"

    def test_parse_any_shorthand(self) -> None:
        rule = ChainingRule.model_validate(
            "finance-tracker cannot trigger any"
        )
        assert rule.target_skill == "any"

    def test_blocks_specific(self) -> None:
        rule = ChainingRule.model_validate(
            "email-manager cannot trigger web-researcher"
        )
        assert rule.blocks("email-manager", "web-researcher") is True
        assert rule.blocks("email-manager", "calendar") is False
        assert rule.blocks("other-skill", "web-researcher") is False

    def test_blocks_any(self) -> None:
        rule = ChainingRule.model_validate(
            "finance-tracker cannot trigger any other skill"
        )
        assert rule.blocks("finance-tracker", "email-manager") is True
        assert rule.blocks("finance-tracker", "web-researcher") is True
        # "any other" means it can still call itself
        assert rule.blocks("finance-tracker", "finance-tracker") is False
        assert rule.blocks("other-skill", "email-manager") is False

    def test_from_dict(self) -> None:
        rule = ChainingRule.model_validate({
            "source_skill": "a",
            "target_skill": "b",
        })
        assert rule.source_skill == "a"
        assert rule.target_skill == "b"

    def test_invalid_format(self) -> None:
        with pytest.raises(ValueError, match="Cannot parse"):
            ChainingRule.model_validate("this is not a valid rule")

    def test_invalid_type(self) -> None:
        with pytest.raises(ValueError, match="must be a string or dict"):
            ChainingRule.model_validate(42)


class TestDataBoundary:
    """Tests for the DataBoundary model."""

    def test_full_boundary(self) -> None:
        boundary = DataBoundary.model_validate({
            "skills": ["ehr-connector", "clinical-notes"],
            "classification": "phi",
            "rules": ["phi_data cannot flow outside hipaa_zone"],
            "on_violation": "block_and_notify",
        })
        assert boundary.skills == ["ehr-connector", "clinical-notes"]
        assert boundary.classification == "phi"
        assert boundary.on_violation == ViolationAction.BLOCK_AND_NOTIFY

    def test_default_violation_action(self) -> None:
        boundary = DataBoundary.model_validate({
            "skills": ["test"],
            "classification": "test",
        })
        assert boundary.on_violation == ViolationAction.BLOCK_AND_LOG


class TestLoadPolicy:
    """Tests for loading policy YAML files."""

    def test_load_simple_policy(self) -> None:
        policy = load_policy(FIXTURES / "simple_policy.yaml")
        assert policy.version == "1.0"
        assert "email-manager" in policy.skills
        gmail = policy.skills["email-manager"]["gmail"]
        assert gmail.is_action_allowed("read") is True
        assert gmail.is_action_allowed("send") is False

    def test_load_full_policy(self) -> None:
        policy = load_policy(FIXTURES / "full_policy.yaml")
        assert policy.version == "1.0"

        # Skills
        assert len(policy.skills) == 4
        assert policy.skills["email-manager"]["google_calendar"].denied is True
        assert policy.skills["calendar-assistant"]["gmail"].denied is True
        assert policy.skills["web-researcher"]["filesystem"].denied is True

        # Nested permissions
        cal_modify = policy.skills["calendar-assistant"]["google_calendar"]
        assert cal_modify.is_action_allowed("modify.own_events") is True
        assert cal_modify.is_action_allowed("modify.others_events") is False

        # Chaining rules
        assert len(policy.skill_chaining) == 3

        # Approval gates
        assert "send_email" in policy.require_approval
        assert "delete_file" in policy.require_approval

        # Data boundaries
        assert "hipaa_zone" in policy.data_boundaries
        hipaa = policy.data_boundaries["hipaa_zone"]
        assert hipaa.classification == "phi"
        assert hipaa.on_violation == ViolationAction.BLOCK_AND_NOTIFY

    def test_load_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            load_policy(FIXTURES / "nonexistent.yaml")

    def test_load_invalid_yaml(self, tmp_path: Path) -> None:
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text(":\n  - :\n    invalid: [")
        with pytest.raises(PolicyValidationError, match="Failed to parse YAML"):
            load_policy(bad_yaml)

    def test_load_empty_file(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.yaml"
        empty.write_text("")
        with pytest.raises(PolicyValidationError, match="is empty"):
            load_policy(empty)

    def test_load_non_mapping(self, tmp_path: Path) -> None:
        list_yaml = tmp_path / "list.yaml"
        list_yaml.write_text("- item1\n- item2\n")
        with pytest.raises(PolicyValidationError, match="must contain a YAML mapping"):
            load_policy(list_yaml)

    def test_load_missing_version(self, tmp_path: Path) -> None:
        no_version = tmp_path / "no_version.yaml"
        no_version.write_text("skills:\n  test:\n    api:\n      read: true\n")
        with pytest.raises(PolicyValidationError, match="Policy validation failed"):
            load_policy(no_version)

    def test_minimal_valid_policy(self, tmp_path: Path) -> None:
        """The smallest valid policy is just a version."""
        minimal = tmp_path / "minimal.yaml"
        minimal.write_text('version: "1.0"\n')
        policy = load_policy(minimal)
        assert policy.version == "1.0"
        assert policy.skills == {}
        assert policy.skill_chaining == []
        assert policy.require_approval == []
        assert policy.data_boundaries == {}
