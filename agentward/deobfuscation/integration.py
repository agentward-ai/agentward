"""Deobfuscation integration — evaluates policy against all decoded argument variants."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentward.deobfuscation.decoder import DeobfuscationPipeline
from agentward.deobfuscation.middleware import (
    DeobfuscatedArgument,
    deobfuscate_arguments,
    get_all_values_for_arg,
)

if TYPE_CHECKING:
    from agentward.policy.engine import EvaluationResult, PolicyEngine


def evaluate_with_deobfuscation(
    policy_engine: "PolicyEngine",
    tool_name: str,
    arguments: dict[str, Any] | None,
    pipeline: DeobfuscationPipeline | None = None,
) -> "EvaluationResult":
    """Evaluate a tool call, checking all decoded variants of string arguments.

    When ``policy_engine.policy.deobfuscation`` is False this falls through to
    the normal :meth:`PolicyEngine.evaluate` call so there is no overhead when
    the feature is disabled.

    If the policy has deobfuscation enabled, each decoded variant of every
    string argument is substituted into the arguments dict and evaluated.  The
    most restrictive result (BLOCK > APPROVE > LOG > ALLOW) wins.

    The reason string for a blocked variant includes the encoding chain so
    operators can see exactly how the obfuscation was layered:

        "Blocked via decoded argument (base64): /etc/passwd"

    Args:
        policy_engine: The :class:`PolicyEngine` to evaluate against.
        tool_name: The MCP tool name.
        arguments: The raw tool call arguments.
        pipeline: Optional :class:`DeobfuscationPipeline`.  Defaults to the
                  shared module-level pipeline when None.

    Returns:
        The most restrictive :class:`EvaluationResult` across all variants.
    """
    from agentward.policy.schema import PolicyDecision

    if not policy_engine.policy.deobfuscation:
        return policy_engine.evaluate(tool_name, arguments)

    # Baseline evaluation on the raw arguments
    base_result = policy_engine.evaluate(tool_name, arguments)

    # If already blocked, no need to check decoded variants
    if base_result.decision == PolicyDecision.BLOCK:
        return base_result

    if not arguments:
        return base_result

    if pipeline is None:
        pipeline = DeobfuscationPipeline()

    deob_map = deobfuscate_arguments({"arguments": arguments}, pipeline=pipeline)

    # Check if any argument has decoded variants at all
    has_any_obfuscation = any(d.has_obfuscation for d in deob_map.values())
    if not has_any_obfuscation:
        return base_result

    # For each string argument that has decoded forms, substitute each decoded
    # variant in turn and evaluate. Most restrictive result wins.
    _decision_rank = {
        PolicyDecision.BLOCK: 4,
        PolicyDecision.APPROVE: 3,
        PolicyDecision.LOG: 2,
        PolicyDecision.ALLOW: 1,
        PolicyDecision.REDACT: 0,
    }

    current_result = base_result

    for arg_name, deob_arg in deob_map.items():
        if not deob_arg.has_obfuscation:
            continue
        for variant in deob_arg.decoded_variants:
            augmented = dict(arguments)
            augmented[arg_name] = variant.value
            variant_result = policy_engine.evaluate(tool_name, augmented)

            if _decision_rank.get(variant_result.decision, 0) > _decision_rank.get(
                current_result.decision, 0
            ):
                # Build an informative reason string
                chain_str = "→".join(variant.chain) if variant.chain else variant.encoding
                from agentward.policy.engine import EvaluationResult

                current_result = EvaluationResult(
                    decision=variant_result.decision,
                    reason=(
                        f"Blocked via decoded argument ({chain_str}): "
                        f"{variant.value!r}. Original reason: {variant_result.reason}"
                    ),
                    skill=variant_result.skill,
                    resource=variant_result.resource,
                )

    return current_result
