"""YAML policy loading and validation.

Loads agentward.yaml files, validates them against the pydantic schema,
and returns structured policy objects. Errors are always actionable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agentward.policy.schema import AgentWardPolicy


class PolicyValidationError(Exception):
    """Raised when a policy YAML file is malformed or fails validation.

    Attributes:
        path: The path to the policy file that failed validation.
        details: Structured error details from pydantic validation.
    """

    def __init__(self, path: Path, details: list[dict[str, Any]], message: str) -> None:
        self.path = path
        self.details = details
        super().__init__(message)


def load_policy(path: Path) -> AgentWardPolicy:
    """Load and validate an AgentWard policy from a YAML file.

    Args:
        path: Path to the agentward.yaml policy file.

    Returns:
        A validated AgentWardPolicy model.

    Raises:
        FileNotFoundError: If the policy file doesn't exist (with actionable message).
        PolicyValidationError: If the YAML is malformed or fails schema validation.
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Policy file not found at {path}. "
            f"Create one with `agentward configure`, or specify a path with --policy."
        )

    raw_text = path.read_text(encoding="utf-8")

    try:
        raw_data = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        raise PolicyValidationError(
            path=path,
            details=[{"type": "yaml_parse_error", "msg": str(e)}],
            message=f"Failed to parse YAML in {path}: {e}",
        ) from e

    if raw_data is None:
        raise PolicyValidationError(
            path=path,
            details=[{"type": "empty_file"}],
            message=f"Policy file {path} is empty. It must contain at least a 'version' field.",
        )

    if not isinstance(raw_data, dict):
        raise PolicyValidationError(
            path=path,
            details=[{"type": "not_a_mapping", "got": type(raw_data).__name__}],
            message=(
                f"Policy file {path} must contain a YAML mapping (key-value pairs) "
                f"at the top level, got {type(raw_data).__name__}."
            ),
        )

    try:
        return AgentWardPolicy.model_validate(raw_data)
    except ValidationError as e:
        error_details = e.errors()
        # Build a human-readable summary of what went wrong
        error_lines = []
        for err in error_details:
            loc = " → ".join(str(part) for part in err["loc"])
            error_lines.append(f"  - {loc}: {err['msg']}")

        summary = "\n".join(error_lines)
        raise PolicyValidationError(
            path=path,
            details=error_details,
            message=(
                f"Policy validation failed for {path}:\n{summary}\n\n"
                f"See https://agentward.ai/docs/policy-format for the full schema reference."
            ),
        ) from e
