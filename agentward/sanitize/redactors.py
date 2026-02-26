"""Text redaction — replace detected PII entities with numbered placeholders.

Given a list of ``DetectedEntity`` objects and the original text, produces
sanitized text and a reverse mapping (placeholder -> original value).
"""

from __future__ import annotations

from agentward.sanitize.models import DetectedEntity, PIICategory


def redact_text(
    text: str,
    entities: list[DetectedEntity],
) -> tuple[str, dict[str, str]]:
    """Replace detected entities with numbered placeholders.

    Uses forward string slicing for memory efficiency (no ``list(text)``).
    Duplicate values within the same category share a placeholder number.

    Args:
        text: The original text.
        entities: Detected entities sorted by start offset (ascending).

    Returns:
        A tuple of (sanitized_text, entity_map) where entity_map maps
        placeholder strings like ``[CREDIT_CARD_1]`` to original values.
    """
    if not entities:
        return text, {}

    # Deduplicate: same category + same text -> same placeholder number.
    seen: dict[tuple[PIICategory, str], int] = {}
    category_counters: dict[PIICategory, int] = {}
    entity_placeholders: dict[int, str] = {}  # entity index -> placeholder

    for idx, ent in enumerate(entities):
        key = (ent.category, ent.text)
        if key in seen:
            suffix = seen[key]
        else:
            cat_count = category_counters.get(ent.category, 0) + 1
            category_counters[ent.category] = cat_count
            suffix = cat_count
            seen[key] = suffix
        entity_placeholders[idx] = f"[{ent.category.value.upper()}_{suffix}]"

    # Build entity_map: placeholder -> original text.
    entity_map: dict[str, str] = {}
    for idx, ent in enumerate(entities):
        ph = entity_placeholders[idx]
        if ph not in entity_map:
            entity_map[ph] = ent.text

    # Build sanitized text via forward slicing (O(n) with no char-list overhead).
    chunks: list[str] = []
    prev_end = 0
    for idx, ent in enumerate(entities):
        chunks.append(text[prev_end:ent.start])
        chunks.append(entity_placeholders[idx])
        prev_end = ent.end
    chunks.append(text[prev_end:])

    return "".join(chunks), entity_map
