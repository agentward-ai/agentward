"""Sanitize engine — orchestrates detection, deduplication, and redaction.

This is the single entry point for all sanitization.  Both the CLI command
and the standalone skill call through this module.
"""

from __future__ import annotations

from pathlib import Path

from agentward.sanitize.detectors.regex_detector import detect_all as regex_detect_all
from agentward.sanitize.extractors import extract_text
from agentward.sanitize.models import (
    DetectedEntity,
    NER_ONLY_CATEGORIES,
    PIICategory,
    SanitizeConfig,
    SanitizeResult,
)
from agentward.sanitize.redactors import redact_text


def _deduplicate_overlaps(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    """Remove overlapping entities, keeping the longer span.

    When two entities overlap (e.g., a phone regex matches inside a credit
    card number), keep the one with the wider span.  On ties, keep the one
    that appears first in the input list.

    Args:
        entities: Sorted by start offset.

    Returns:
        De-duplicated list sorted by start offset.
    """
    if len(entities) <= 1:
        return entities

    result: list[DetectedEntity] = []
    for ent in entities:
        if result and ent.start < result[-1].end:
            # Overlaps with the previous entity — keep the longer one.
            prev = result[-1]
            prev_len = prev.end - prev.start
            ent_len = ent.end - ent.start
            if ent_len > prev_len:
                result[-1] = ent
            # Otherwise keep prev (already in result).
        else:
            result.append(ent)
    return result


def _merge_entities(
    regex_entities: list[DetectedEntity],
    ner_entities: list[DetectedEntity],
) -> list[DetectedEntity]:
    """Merge regex and NER results, preferring regex when spans overlap.

    Regex detections are treated as ground truth (confidence=1.0).
    NER detections are only kept when they don't overlap with any
    regex match.

    Args:
        regex_entities: Entities from the regex detector.
        ner_entities: Entities from the NER detector.

    Returns:
        Merged list sorted by start offset.
    """
    if not ner_entities:
        return _deduplicate_overlaps(regex_entities)
    if not regex_entities:
        return _deduplicate_overlaps(sorted(ner_entities, key=lambda e: e.start))

    # Build a set of covered character ranges from regex hits.
    covered: set[int] = set()
    for ent in regex_entities:
        covered.update(range(ent.start, ent.end))

    merged = list(regex_entities)
    for ent in ner_entities:
        # Keep NER entity only if it doesn't overlap any regex entity.
        ent_range = range(ent.start, ent.end)
        if not any(pos in covered for pos in ent_range):
            merged.append(ent)
            covered.update(ent_range)

    merged.sort(key=lambda e: e.start)
    return _deduplicate_overlaps(merged)


def sanitize_text(
    text: str,
    config: SanitizeConfig | None = None,
) -> SanitizeResult:
    """Detect and redact PII in a text string.

    Args:
        text: The input text to sanitize.
        config: Sanitization options.  ``None`` uses defaults
            (all regex categories, no NER).

    Returns:
        A ``SanitizeResult`` with sanitized text, entities, and mapping.
    """
    if config is None:
        config = SanitizeConfig()

    # Determine active regex categories.
    run_regex = True
    regex_cats: set[PIICategory] | None = None
    if config.categories is not None:
        regex_cats = config.categories - NER_ONLY_CATEGORIES
        if not regex_cats:
            run_regex = False  # user requested only NER categories

    # Run regex detection.
    regex_entities: list[DetectedEntity] = []
    if run_regex:
        regex_entities = regex_detect_all(text, categories=regex_cats)

    # Run NER detection if requested.
    ner_entities: list[DetectedEntity] = []
    if config.use_ner:
        run_ner = True
        ner_cats: set[PIICategory] | None = None
        if config.categories is not None:
            ner_cats = config.categories & NER_ONLY_CATEGORIES
            if not ner_cats:
                run_ner = False  # user requested only regex categories
        if run_ner:
            from agentward.sanitize.detectors.ner_detector import detect_ner

            ner_entities = detect_ner(
                text,
                categories=ner_cats,
                min_confidence=config.min_confidence,
            )

    # Merge and deduplicate.
    entities = _merge_entities(regex_entities, ner_entities)

    # Redact.
    sanitized, entity_map = redact_text(text, entities)

    return SanitizeResult(
        original_text=text,
        sanitized_text=sanitized,
        entities=entities,
        entity_map=entity_map,
    )


def sanitize_file(
    path: Path,
    config: SanitizeConfig | None = None,
) -> SanitizeResult:
    """Extract text from a file, detect and redact PII.

    Args:
        path: Path to the input file.
        config: Sanitization options.

    Returns:
        A ``SanitizeResult`` with sanitized text, entities, and mapping.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is unsupported.
        ImportError: If optional dependencies (pypdf, spacy) are missing.
    """
    text = extract_text(path)
    return sanitize_text(text, config=config)
