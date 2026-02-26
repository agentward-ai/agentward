"""Tests for the sanitize engine (orchestrator).

Covers sanitize_text, sanitize_file, entity merging, and config options.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentward.sanitize.engine import (
    _deduplicate_overlaps,
    _merge_entities,
    sanitize_file,
    sanitize_text,
)
from agentward.sanitize.models import (
    DetectedEntity,
    PIICategory,
    SanitizeConfig,
    SanitizeResult,
)

FIXTURES = Path(__file__).parent / "fixtures"


# -----------------------------------------------------------------------
# sanitize_text
# -----------------------------------------------------------------------


class TestSanitizeText:
    def test_basic_ssn_redaction(self) -> None:
        result = sanitize_text("SSN: 123-45-6789")
        assert result.has_pii
        assert "[SSN_1]" in result.sanitized_text
        assert "123-45-6789" not in result.sanitized_text
        assert result.entity_map["[SSN_1]"] == "123-45-6789"

    def test_multiple_categories(self) -> None:
        text = "SSN: 123-45-6789, card: 4111 1111 1111 1111"
        result = sanitize_text(text)
        assert PIICategory.SSN in result.categories_found
        assert PIICategory.CREDIT_CARD in result.categories_found

    def test_no_pii(self) -> None:
        result = sanitize_text("just a regular sentence about weather")
        assert not result.has_pii
        assert result.sanitized_text == "just a regular sentence about weather"
        assert result.entities == []

    def test_category_filter(self) -> None:
        text = "SSN: 123-45-6789, email: a@b.com"
        config = SanitizeConfig(categories={PIICategory.EMAIL})
        result = sanitize_text(text, config=config)
        # Should only detect email, not SSN.
        assert PIICategory.EMAIL in result.categories_found
        assert PIICategory.SSN not in result.categories_found
        assert "123-45-6789" in result.sanitized_text  # SSN left untouched

    def test_summary_counts(self) -> None:
        text = "SSN 123-45-6789 and SSN 234-56-7890"
        result = sanitize_text(text)
        assert result.summary["ssn"] == 2

    def test_empty_text(self) -> None:
        result = sanitize_text("")
        assert not result.has_pii
        assert result.sanitized_text == ""

    def test_email_redaction(self) -> None:
        result = sanitize_text("contact: user@example.com")
        assert "[EMAIL_1]" in result.sanitized_text

    def test_ip_redaction(self) -> None:
        result = sanitize_text("server: 192.168.1.100")
        assert "[IP_ADDRESS_1]" in result.sanitized_text

    def test_api_key_redaction(self) -> None:
        key = "sk-" + "a" * 48
        result = sanitize_text(f"key: {key}")
        assert "[API_KEY_1]" in result.sanitized_text
        assert key not in result.sanitized_text

    def test_ner_only_categories_skips_regex(self) -> None:
        """Regression: requesting only NER categories must NOT run regex detectors."""
        text = "SSN: 123-45-6789, email: a@b.com"
        config = SanitizeConfig(categories={PIICategory.PERSON_NAME})
        result = sanitize_text(text, config=config)
        # PERSON_NAME is NER-only and NER is off → no entities detected.
        assert not result.has_pii
        # Original text must be untouched.
        assert result.sanitized_text == text


# -----------------------------------------------------------------------
# sanitize_file
# -----------------------------------------------------------------------


class TestSanitizeFile:
    def test_sample_fixture(self) -> None:
        path = FIXTURES / "sanitize_sample.txt"
        result = sanitize_file(path)
        assert result.has_pii
        # Should detect multiple categories.
        cats = result.categories_found
        assert PIICategory.SSN in cats
        assert PIICategory.EMAIL in cats
        assert PIICategory.CREDIT_CARD in cats

    def test_clean_fixture(self) -> None:
        path = FIXTURES / "sanitize_clean.txt"
        result = sanitize_file(path)
        # Clean file may still match version numbers as false positives for
        # some patterns, but the key PII categories should be absent.
        financial_cats = {PIICategory.CREDIT_CARD, PIICategory.SSN, PIICategory.CVV}
        assert not (result.categories_found & financial_cats)

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            sanitize_file(Path("/nonexistent/file.txt"))

    def test_unsupported_format(self, tmp_path: Path) -> None:
        f = tmp_path / "test.xyz"
        f.write_text("hello")
        with pytest.raises(ValueError, match="Unsupported file format"):
            sanitize_file(f)

    def test_config_passed_through(self) -> None:
        path = FIXTURES / "sanitize_sample.txt"
        config = SanitizeConfig(categories={PIICategory.SSN})
        result = sanitize_file(path, config=config)
        # Only SSN should be detected.
        assert all(e.category == PIICategory.SSN for e in result.entities)


# -----------------------------------------------------------------------
# Entity merging
# -----------------------------------------------------------------------


class TestMergeEntities:
    def test_regex_only(self) -> None:
        regex = [
            DetectedEntity(PIICategory.SSN, "123-45-6789", 0, 11),
        ]
        merged = _merge_entities(regex, [])
        assert merged == regex

    def test_ner_only(self) -> None:
        ner = [
            DetectedEntity(PIICategory.PERSON_NAME, "John", 0, 4, 0.9, "ner"),
        ]
        merged = _merge_entities([], ner)
        assert merged == ner

    def test_no_overlap_keeps_both(self) -> None:
        regex = [DetectedEntity(PIICategory.SSN, "123-45-6789", 0, 11)]
        ner = [DetectedEntity(PIICategory.PERSON_NAME, "John", 20, 24, 0.9, "ner")]
        merged = _merge_entities(regex, ner)
        assert len(merged) == 2
        # Should be sorted by start offset.
        assert merged[0].start < merged[1].start

    def test_overlap_prefers_regex(self) -> None:
        regex = [DetectedEntity(PIICategory.SSN, "123-45-6789", 5, 16)]
        ner = [DetectedEntity(PIICategory.PERSON_NAME, "123-45", 5, 11, 0.8, "ner")]
        merged = _merge_entities(regex, ner)
        # NER entity overlaps regex → should be dropped.
        assert len(merged) == 1
        assert merged[0].detector == "regex"

    def test_both_empty(self) -> None:
        assert _merge_entities([], []) == []


# -----------------------------------------------------------------------
# Overlap deduplication
# -----------------------------------------------------------------------


class TestDeduplicateOverlaps:
    def test_no_overlap(self) -> None:
        entities = [
            DetectedEntity(PIICategory.SSN, "123-45-6789", 0, 11),
            DetectedEntity(PIICategory.EMAIL, "a@b.com", 20, 27),
        ]
        result = _deduplicate_overlaps(entities)
        assert len(result) == 2

    def test_phone_inside_credit_card(self) -> None:
        """Phone regex matching a subsequence of a credit card number."""
        entities = [
            DetectedEntity(PIICategory.CREDIT_CARD, "4111 1111 1111 1111", 0, 19),
            DetectedEntity(PIICategory.PHONE, "4111 1111 1111", 0, 14),
        ]
        result = _deduplicate_overlaps(entities)
        # Credit card is longer — should win.
        assert len(result) == 1
        assert result[0].category == PIICategory.CREDIT_CARD

    def test_shorter_first_longer_second(self) -> None:
        entities = [
            DetectedEntity(PIICategory.PHONE, "555-1234", 0, 8),
            DetectedEntity(PIICategory.CREDIT_CARD, "5551234567890004", 0, 16),
        ]
        result = _deduplicate_overlaps(entities)
        assert len(result) == 1
        assert result[0].category == PIICategory.CREDIT_CARD

    def test_empty_list(self) -> None:
        assert _deduplicate_overlaps([]) == []

    def test_single_entity(self) -> None:
        entities = [DetectedEntity(PIICategory.SSN, "123-45-6789", 0, 11)]
        assert _deduplicate_overlaps(entities) == entities

    def test_credit_card_no_phone_false_positive(self) -> None:
        """End-to-end: credit card should not produce a phone false positive."""
        result = sanitize_text("pay 4111 1111 1111 1111 now")
        cats = [e.category for e in result.entities]
        assert PIICategory.CREDIT_CARD in cats
        assert PIICategory.PHONE not in cats
