"""Framework registry for compliance controls.

Each framework (HIPAA, SOX, etc.) registers a list of ComplianceControl
objects. The evaluator is generic — adding a new framework means adding
a new controls list, no new evaluation logic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentward.comply.controls import ComplianceControl

_REGISTRY: dict[str, list[ComplianceControl]] = {}


def register_framework(name: str, controls: list[ComplianceControl]) -> None:
    """Register a compliance framework's controls.

    Args:
        name: Framework identifier (e.g., "hipaa").
        controls: List of controls to evaluate against.
    """
    _REGISTRY[name.lower()] = controls


def get_framework(name: str) -> list[ComplianceControl]:
    """Get controls for a registered framework.

    Args:
        name: Framework identifier (e.g., "hipaa").

    Returns:
        List of ComplianceControl objects for the framework.

    Raises:
        ValueError: If the framework is not registered.
    """
    key = name.lower()
    if key not in _REGISTRY:
        available = ", ".join(sorted(_REGISTRY.keys())) or "(none)"
        msg = (
            f"Unknown compliance framework: '{name}'. "
            f"Available frameworks: {available}. "
            f"See https://agentward.ai/docs/compliance for supported frameworks."
        )
        raise ValueError(msg)
    return _REGISTRY[key]


def available_frameworks() -> list[str]:
    """Return sorted list of registered framework names."""
    return sorted(_REGISTRY.keys())
