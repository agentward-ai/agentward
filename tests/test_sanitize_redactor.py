"""Tests for the text redactor."""

from __future__ import annotations

from agentward.sanitize.models import DetectedEntity, PIICategory
from agentward.sanitize.redactors import redact_text


class TestRedactText:
    def test_single_entity(self) -> None:
        text = "SSN: 123-45-6789"
        entities = [
            DetectedEntity(
                category=PIICategory.SSN,
                text="123-45-6789",
                start=5,
                end=16,
            ),
        ]
        sanitized, mapping = redact_text(text, entities)
        assert "[SSN_1]" in sanitized
        assert mapping["[SSN_1]"] == "123-45-6789"
        assert "123-45-6789" not in sanitized

    def test_multiple_entities(self) -> None:
        text = "SSN: 123-45-6789, email: a@b.com"
        entities = [
            DetectedEntity(
                category=PIICategory.SSN,
                text="123-45-6789",
                start=5,
                end=16,
            ),
            DetectedEntity(
                category=PIICategory.EMAIL,
                text="a@b.com",
                start=25,
                end=32,
            ),
        ]
        sanitized, mapping = redact_text(text, entities)
        assert "[SSN_1]" in sanitized
        assert "[EMAIL_1]" in sanitized
        assert len(mapping) == 2

    def test_duplicate_values_share_placeholder(self) -> None:
        text = "first: 123-45-6789 second: 123-45-6789"
        entities = [
            DetectedEntity(
                category=PIICategory.SSN,
                text="123-45-6789",
                start=7,
                end=18,
            ),
            DetectedEntity(
                category=PIICategory.SSN,
                text="123-45-6789",
                start=27,
                end=38,
            ),
        ]
        sanitized, mapping = redact_text(text, entities)
        # Both should use [SSN_1] since they have the same text.
        assert sanitized.count("[SSN_1]") == 2
        assert "[SSN_2]" not in sanitized

    def test_different_values_different_numbers(self) -> None:
        text = "a: 123-45-6789 b: 987-65-4321"
        entities = [
            DetectedEntity(
                category=PIICategory.SSN,
                text="123-45-6789",
                start=3,
                end=14,
            ),
            DetectedEntity(
                category=PIICategory.SSN,
                text="987-65-4321",
                start=18,
                end=29,
            ),
        ]
        sanitized, mapping = redact_text(text, entities)
        assert "[SSN_1]" in sanitized
        assert "[SSN_2]" in sanitized
        assert mapping["[SSN_1]"] == "123-45-6789"
        assert mapping["[SSN_2]"] == "987-65-4321"

    def test_empty_entities(self) -> None:
        text = "no PII here"
        sanitized, mapping = redact_text(text, [])
        assert sanitized == text
        assert mapping == {}

    def test_offsets_preserved(self) -> None:
        """After redaction, text before and after the entity is intact."""
        text = "prefix 123-45-6789 suffix"
        entities = [
            DetectedEntity(
                category=PIICategory.SSN,
                text="123-45-6789",
                start=7,
                end=18,
            ),
        ]
        sanitized, _ = redact_text(text, entities)
        assert sanitized.startswith("prefix ")
        assert sanitized.endswith(" suffix")
