"""Integration middleware — applies deobfuscation pipeline to tool call arguments."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentward.deobfuscation.decoder import DecodedVariant, DeobfuscationPipeline

_pipeline: DeobfuscationPipeline | None = None


def _get_default_pipeline() -> DeobfuscationPipeline:
    """Return a module-level shared pipeline (lazy init)."""
    global _pipeline
    if _pipeline is None:
        _pipeline = DeobfuscationPipeline()
    return _pipeline


@dataclass
class DeobfuscatedArgument:
    """Result of running a single argument through the deobfuscation pipeline.

    Attributes:
        raw: The original raw value as provided in the tool call.
        decoded_variants: All decoded forms found by the pipeline.
        has_obfuscation: True if at least one decoding layer was found.
    """

    raw: str
    decoded_variants: list[DecodedVariant] = field(default_factory=list)
    has_obfuscation: bool = False


def deobfuscate_arguments(
    tool_call: dict[str, Any],
    pipeline: DeobfuscationPipeline | None = None,
) -> dict[str, DeobfuscatedArgument]:
    """Run all string arguments of *tool_call* through the deobfuscation pipeline.

    Non-string arguments are returned with only the raw form and no variants.

    Args:
        tool_call: A tool call dict, expected to have an ``arguments`` key
                   mapping argument names to values.
        pipeline: Optional pipeline to use.  Defaults to the module-level
                  shared :class:`DeobfuscationPipeline`.

    Returns:
        Dict mapping argument name → :class:`DeobfuscatedArgument`.
    """
    if pipeline is None:
        pipeline = _get_default_pipeline()

    arguments: dict[str, Any] = tool_call.get("arguments") or {}
    result: dict[str, DeobfuscatedArgument] = {}

    for arg_name, raw_value in arguments.items():
        if not isinstance(raw_value, str):
            # Non-string: return with only the raw form
            result[arg_name] = DeobfuscatedArgument(
                raw=str(raw_value) if raw_value is not None else "",
                decoded_variants=[],
                has_obfuscation=False,
            )
            continue

        variants = pipeline.decode(raw_value)
        # Variants always includes the original at depth 0; strip it for decoded_variants
        decoded = [v for v in variants if v.depth > 0]
        result[arg_name] = DeobfuscatedArgument(
            raw=raw_value,
            decoded_variants=decoded,
            has_obfuscation=len(decoded) > 0,
        )

    return result


def get_all_values_for_arg(deob_arg: DeobfuscatedArgument) -> list[str]:
    """Return all string values to check for an argument: raw + all decoded forms.

    Deduplicates while preserving order (raw first).

    Args:
        deob_arg: A :class:`DeobfuscatedArgument` as returned by
                  :func:`deobfuscate_arguments`.

    Returns:
        Deduplicated list of strings starting with the raw value.
    """
    seen: set[str] = set()
    out: list[str] = []
    for v in [deob_arg.raw] + [dv.value for dv in deob_arg.decoded_variants]:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
