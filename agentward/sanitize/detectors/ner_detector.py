"""Optional spaCy NER-based PII detector.

Only loaded when ``spacy`` is installed (``pip install agentward[sanitize]``).
Falls back gracefully with a clear error if the dependency is missing.
"""

from __future__ import annotations

from agentward.sanitize.models import DetectedEntity, NER_ONLY_CATEGORIES, PIICategory

# spaCy entity label → PIICategory mapping.
_LABEL_MAP: dict[str, PIICategory] = {
    "PERSON": PIICategory.PERSON_NAME,
    "ORG": PIICategory.ORGANIZATION,
    "GPE": PIICategory.LOCATION,
    "LOC": PIICategory.LOCATION,
    "MONEY": PIICategory.MONEY,
}

_DEFAULT_MODEL = "en_core_web_sm"


def _load_model(model_name: str = _DEFAULT_MODEL) -> object:
    """Load a spaCy model, raising a clear error if unavailable.

    Args:
        model_name: The spaCy model to load.

    Returns:
        A loaded spaCy ``Language`` pipeline.

    Raises:
        ImportError: If spaCy is not installed.
        OSError: If the requested model is not downloaded.
    """
    try:
        import spacy  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "spaCy is required for NER-based PII detection. "
            "Install it with: pip install agentward[sanitize]"
        ) from exc

    try:
        return spacy.load(model_name)
    except OSError as exc:
        raise OSError(
            f"spaCy model '{model_name}' not found. "
            f"Download it with: python -m spacy download {model_name}"
        ) from exc


# Module-level cache so we only load the model once per process.
_nlp_cache: dict[str, object] = {}


def detect_ner(
    text: str,
    *,
    categories: set[PIICategory] | None = None,
    min_confidence: float = 0.5,
    model_name: str = _DEFAULT_MODEL,
) -> list[DetectedEntity]:
    """Detect PII entities using spaCy NER.

    Args:
        text: The input text to scan.
        categories: Subset of NER categories to return. ``None`` means
            all NER-detectable categories.
        min_confidence: Minimum entity confidence threshold (0.0–1.0).
            spaCy ``en_core_web_sm`` does not expose per-entity scores,
            so this is applied only for models that provide them.
        model_name: The spaCy model to use.

    Returns:
        List of detected entities sorted by start offset.

    Raises:
        ImportError: If spaCy is not installed.
        OSError: If the model is not downloaded.
    """
    if model_name not in _nlp_cache:
        _nlp_cache[model_name] = _load_model(model_name)

    nlp = _nlp_cache[model_name]
    doc = nlp(text)  # type: ignore[operator]

    active = categories if categories is not None else set(NER_ONLY_CATEGORIES)
    entities: list[DetectedEntity] = []

    for ent in doc.ents:  # type: ignore[attr-defined]
        pii_cat = _LABEL_MAP.get(ent.label_)
        if pii_cat is None:
            continue
        if pii_cat not in active:
            continue

        # Some models expose ent._.score or ent.kb_id_ — use if available.
        score = 1.0
        if hasattr(ent, "_") and hasattr(ent._, "score"):
            score = float(ent._.score)
        if score < min_confidence:
            continue

        entities.append(DetectedEntity(
            category=pii_cat,
            text=ent.text,
            start=ent.start_char,
            end=ent.end_char,
            confidence=score,
            detector="ner",
        ))

    entities.sort(key=lambda e: e.start)
    return entities
