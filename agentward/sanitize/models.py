"""Data models for the sanitize engine.

Pure data structures — no I/O, no external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PIICategory(str, Enum):
    """Categories of PII the sanitize engine can detect."""

    # Financial
    CREDIT_CARD = "credit_card"
    CVV = "cvv"
    EXPIRY_DATE = "expiry_date"
    BANK_ROUTING = "bank_routing"

    # Government IDs
    SSN = "ssn"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"

    # Credentials
    API_KEY = "api_key"

    # Healthcare / professional
    MEDICAL_LICENSE = "medical_license"
    INSURANCE_ID = "insurance_id"

    # Contact / personal
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    ADDRESS = "address"

    # NER-only (spaCy)
    PERSON_NAME = "person_name"
    ORGANIZATION = "organization"
    LOCATION = "location"
    MONEY = "money"


# Categories that only NER can detect (no regex pattern).
NER_ONLY_CATEGORIES: frozenset[PIICategory] = frozenset({
    PIICategory.PERSON_NAME,
    PIICategory.ORGANIZATION,
    PIICategory.LOCATION,
    PIICategory.MONEY,
})

# All categories that have regex patterns.
REGEX_CATEGORIES: frozenset[PIICategory] = frozenset(
    c for c in PIICategory if c not in NER_ONLY_CATEGORIES
)


@dataclass(frozen=True)
class DetectedEntity:
    """A single PII entity found in text.

    Attributes:
        category: The PII category (e.g., CREDIT_CARD, SSN).
        text: The raw matched text.
        start: Start character offset in the source text.
        end: End character offset in the source text.
        confidence: Detection confidence (0.0–1.0). Regex detectors
            return 1.0; NER detectors return the model's score.
        detector: Which detector found this ("regex" or "ner").
    """

    category: PIICategory
    text: str
    start: int
    end: int
    confidence: float = 1.0
    detector: str = "regex"


@dataclass
class SanitizeResult:
    """Result of sanitizing a piece of text or file.

    Attributes:
        original_text: The input text before redaction.
        sanitized_text: Text with PII replaced by placeholders.
        entities: All detected PII entities, sorted by start offset.
        entity_map: Maps placeholder strings to original values
            (e.g. ``{"[CREDIT_CARD_1]": "4111 1111 1111 1111"}``).
    """

    original_text: str
    sanitized_text: str
    entities: list[DetectedEntity] = field(default_factory=list)
    entity_map: dict[str, str] = field(default_factory=dict)

    @property
    def has_pii(self) -> bool:
        """True if any PII was detected."""
        return len(self.entities) > 0

    @property
    def categories_found(self) -> set[PIICategory]:
        """Set of PII categories found in the text."""
        return {e.category for e in self.entities}

    @property
    def summary(self) -> dict[str, int]:
        """Count of entities per category."""
        counts: dict[str, int] = {}
        for e in self.entities:
            key = e.category.value
            counts[key] = counts.get(key, 0) + 1
        return counts


@dataclass
class SanitizeConfig:
    """Configuration for a sanitize run.

    Attributes:
        categories: Which PII categories to detect. ``None`` means all.
        min_confidence: Minimum confidence threshold for NER entities.
        use_ner: Whether to run the spaCy NER detector.
    """

    categories: set[PIICategory] | None = None
    min_confidence: float = 0.5
    use_ner: bool = False
