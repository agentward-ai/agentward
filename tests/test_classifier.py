"""Tests for the sensitive content classifier.

Covers:
  - Luhn algorithm validation
  - Credit card detection (with and without separators)
  - SSN detection (with area/group validation)
  - CVV/CVC detection (keyword-anchored)
  - Expiry date detection (keyword-anchored)
  - API key detection (provider prefixes)
  - Recursive argument walking
  - Full scenario (user's demo input)
  - Enabled patterns filtering
"""

from __future__ import annotations

import pytest

from agentward.inspect.classifier import (
    ClassificationResult,
    Finding,
    FindingType,
    _detect_api_keys,
    _detect_credit_cards,
    _detect_cvvs,
    _detect_expiry_dates,
    _detect_ssns,
    _luhn_check,
    _walk_arguments,
    classify_arguments,
)


# -----------------------------------------------------------------------
# Luhn algorithm
# -----------------------------------------------------------------------


class TestLuhnCheck:
    """Tests for the Luhn checksum validator."""

    def test_visa_test_card(self) -> None:
        assert _luhn_check("4111111111111111") is True

    def test_mastercard_test_card(self) -> None:
        assert _luhn_check("5500000000000004") is True

    def test_amex_test_card(self) -> None:
        assert _luhn_check("378282246310005") is True

    def test_invalid_digits(self) -> None:
        assert _luhn_check("1234567890123456") is False

    def test_all_ones_16_digits(self) -> None:
        # 1111 1111 1111 1111 — does NOT pass Luhn
        assert _luhn_check("1111111111111111") is False

    def test_empty_string(self) -> None:
        assert _luhn_check("") is False

    def test_non_numeric(self) -> None:
        assert _luhn_check("abcd1234") is False

    def test_single_digit_zero(self) -> None:
        # Luhn of "0" is 0 % 10 == 0 → valid (degenerate case)
        assert _luhn_check("0") is True


# -----------------------------------------------------------------------
# Credit card detection
# -----------------------------------------------------------------------


class TestCreditCardDetection:
    """Tests for credit card number detection."""

    def test_visa_with_spaces(self) -> None:
        findings = _detect_credit_cards("card: 4111 1111 1111 1111", "text")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.CREDIT_CARD
        assert "4111" in findings[0].matched_text
        assert "1111" in findings[0].matched_text

    def test_visa_with_dashes(self) -> None:
        findings = _detect_credit_cards("pay with 4111-1111-1111-1111", "text")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.CREDIT_CARD

    def test_visa_no_separators(self) -> None:
        findings = _detect_credit_cards("cc: 4111111111111111", "text")
        assert len(findings) == 1

    def test_mastercard(self) -> None:
        findings = _detect_credit_cards("5500000000000004", "text")
        assert len(findings) == 1

    def test_amex_15_digits(self) -> None:
        findings = _detect_credit_cards("amex 378282246310005", "text")
        assert len(findings) == 1

    def test_fails_luhn_no_finding(self) -> None:
        # 1234 5678 9012 3456 does not pass Luhn
        findings = _detect_credit_cards("1234 5678 9012 3456", "text")
        assert len(findings) == 0

    def test_too_short(self) -> None:
        findings = _detect_credit_cards("1234", "text")
        assert len(findings) == 0

    def test_all_ones_no_finding(self) -> None:
        findings = _detect_credit_cards("1111 1111 1111 1111", "text")
        assert len(findings) == 0

    def test_field_path_preserved(self) -> None:
        findings = _detect_credit_cards("4111111111111111", "body.content")
        assert findings[0].field_path == "body.content"


# -----------------------------------------------------------------------
# SSN detection
# -----------------------------------------------------------------------


class TestSSNDetection:
    """Tests for US Social Security Number detection."""

    def test_with_dashes(self) -> None:
        findings = _detect_ssns("ssn: 123-45-6789", "text")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.SSN

    def test_with_spaces(self) -> None:
        findings = _detect_ssns("ssn 123 45 6789", "text")
        assert len(findings) == 1

    def test_no_separators(self) -> None:
        findings = _detect_ssns("123456789", "text")
        assert len(findings) == 1

    def test_redacted_shows_last_four(self) -> None:
        findings = _detect_ssns("123-45-6789", "text")
        assert findings[0].matched_text == "***-**-6789"

    def test_invalid_area_000(self) -> None:
        findings = _detect_ssns("000-12-3456", "text")
        assert len(findings) == 0

    def test_invalid_area_666(self) -> None:
        findings = _detect_ssns("666-12-3456", "text")
        assert len(findings) == 0

    def test_invalid_area_900_range(self) -> None:
        findings = _detect_ssns("900-12-3456", "text")
        assert len(findings) == 0
        findings = _detect_ssns("999-12-3456", "text")
        assert len(findings) == 0

    def test_invalid_group_00(self) -> None:
        findings = _detect_ssns("123-00-3456", "text")
        assert len(findings) == 0

    def test_invalid_serial_0000(self) -> None:
        findings = _detect_ssns("123-45-0000", "text")
        assert len(findings) == 0


# -----------------------------------------------------------------------
# CVV detection
# -----------------------------------------------------------------------


class TestCVVDetection:
    """Tests for CVV/CVC detection (keyword-anchored)."""

    def test_cvv_three_digits(self) -> None:
        findings = _detect_cvvs("cvv: 123", "text")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.CVV
        assert findings[0].matched_text == "***"

    def test_cvc_three_digits(self) -> None:
        findings = _detect_cvvs("cvc 456", "text")
        assert len(findings) == 1

    def test_cvv2_four_digits(self) -> None:
        findings = _detect_cvvs("cvv2: 1234", "text")
        assert len(findings) == 1

    def test_security_code(self) -> None:
        findings = _detect_cvvs("security code: 789", "text")
        assert len(findings) == 1

    def test_case_insensitive(self) -> None:
        findings = _detect_cvvs("CVV: 123", "text")
        assert len(findings) == 1

    def test_no_keyword_no_match(self) -> None:
        # Bare 3-digit number without keyword should NOT match
        findings = _detect_cvvs("the code is 123", "text")
        assert len(findings) == 0


# -----------------------------------------------------------------------
# Expiry date detection
# -----------------------------------------------------------------------


class TestExpiryDateDetection:
    """Tests for payment card expiry date detection."""

    def test_expiry_mm_yy(self) -> None:
        findings = _detect_expiry_dates("expiry 01/30", "text")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.EXPIRY_DATE
        assert findings[0].matched_text == "**/**"

    def test_exp_mm_yyyy(self) -> None:
        findings = _detect_expiry_dates("exp: 12/2025", "text")
        assert len(findings) == 1

    def test_expiry_date_keyword(self) -> None:
        findings = _detect_expiry_dates("expiry date: 03/28", "text")
        assert len(findings) == 1

    def test_with_dash_separator(self) -> None:
        findings = _detect_expiry_dates("exp 06-29", "text")
        assert len(findings) == 1

    def test_case_insensitive(self) -> None:
        findings = _detect_expiry_dates("EXPIRY 01/30", "text")
        assert len(findings) == 1

    def test_no_keyword_no_match(self) -> None:
        # Bare date without keyword should NOT match
        findings = _detect_expiry_dates("01/30", "text")
        assert len(findings) == 0


# -----------------------------------------------------------------------
# API key detection
# -----------------------------------------------------------------------


class TestAPIKeyDetection:
    """Tests for API key detection."""

    def test_openai_key(self) -> None:
        key = "sk-" + "a" * 48
        findings = _detect_api_keys(f"key: {key}", "text")
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.API_KEY
        assert "sk-a" in findings[0].matched_text
        # Full key should NOT appear in matched_text
        assert key not in findings[0].matched_text

    def test_github_pat(self) -> None:
        key = "ghp_" + "A" * 36
        findings = _detect_api_keys(f"token={key}", "text")
        assert len(findings) == 1

    def test_slack_bot_token(self) -> None:
        key = "xoxb-" + "abc123-" * 5
        findings = _detect_api_keys(f"SLACK_TOKEN={key}", "text")
        assert len(findings) == 1

    def test_aws_access_key(self) -> None:
        key = "AKIA" + "A" * 16
        findings = _detect_api_keys(f"aws_key={key}", "text")
        assert len(findings) == 1

    def test_short_sk_no_match(self) -> None:
        # Too short — sk- needs 20+ chars after prefix
        findings = _detect_api_keys("sk-abc123", "text")
        assert len(findings) == 0


# -----------------------------------------------------------------------
# Argument walker
# -----------------------------------------------------------------------


class TestWalkArguments:
    """Tests for recursive argument walking."""

    def test_flat_dict(self) -> None:
        pairs = list(_walk_arguments({"name": "test", "url": "https://example.com"}))
        assert ("name", "test") in pairs
        assert ("url", "https://example.com") in pairs

    def test_nested_dict(self) -> None:
        pairs = list(_walk_arguments({"a": {"b": "value"}}))
        assert ("a.b", "value") in pairs

    def test_list_values(self) -> None:
        pairs = list(_walk_arguments({"items": ["alpha", "beta"]}))
        assert ("items[0]", "alpha") in pairs
        assert ("items[1]", "beta") in pairs

    def test_integer_values(self) -> None:
        pairs = list(_walk_arguments({"count": 42}))
        assert ("count", "42") in pairs

    def test_empty_dict(self) -> None:
        pairs = list(_walk_arguments({}))
        assert pairs == []

    def test_empty_string_skipped(self) -> None:
        pairs = list(_walk_arguments({"empty": ""}))
        assert pairs == []

    def test_deeply_nested(self) -> None:
        pairs = list(_walk_arguments({"a": {"b": {"c": "deep"}}}))
        assert ("a.b.c", "deep") in pairs

    def test_none_skipped(self) -> None:
        pairs = list(_walk_arguments({"key": None}))
        assert pairs == []


# -----------------------------------------------------------------------
# Full classify_arguments
# -----------------------------------------------------------------------


class TestClassifyArguments:
    """Tests for the main classify_arguments entry point."""

    def test_clean_arguments(self) -> None:
        result = classify_arguments({"url": "https://amazon.com", "query": "paper towels"})
        assert result.has_sensitive_data is False
        assert result.findings == []

    def test_credit_card_detected(self) -> None:
        result = classify_arguments({"text": "pay with 4111 1111 1111 1111"})
        assert result.has_sensitive_data is True
        assert any(f.finding_type == FindingType.CREDIT_CARD for f in result.findings)

    def test_ssn_detected(self) -> None:
        result = classify_arguments({"body": "my ssn is 123-45-6789"})
        assert result.has_sensitive_data is True
        assert any(f.finding_type == FindingType.SSN for f in result.findings)

    def test_nested_detection(self) -> None:
        result = classify_arguments({"data": {"content": "card 4111111111111111"}})
        assert result.has_sensitive_data is True
        finding = result.findings[0]
        assert finding.field_path == "data.content"

    def test_list_detection(self) -> None:
        result = classify_arguments({"items": ["safe text", "ssn: 123-45-6789"]})
        assert result.has_sensitive_data is True
        finding = next(f for f in result.findings if f.finding_type == FindingType.SSN)
        assert finding.field_path == "items[1]"

    def test_multiple_findings(self) -> None:
        text = "card 4111 1111 1111 1111, cvv: 123, expiry 01/30"
        result = classify_arguments({"text": text})
        assert result.has_sensitive_data is True
        types = {f.finding_type for f in result.findings}
        assert FindingType.CREDIT_CARD in types
        assert FindingType.CVV in types
        assert FindingType.EXPIRY_DATE in types

    def test_enabled_patterns_filter(self) -> None:
        text = "card 4111 1111 1111 1111, cvv: 123"
        # Only check for CVV, not credit cards
        result = classify_arguments({"text": text}, enabled_patterns=["cvv"])
        types = {f.finding_type for f in result.findings}
        assert FindingType.CVV in types
        assert FindingType.CREDIT_CARD not in types

    def test_empty_arguments(self) -> None:
        result = classify_arguments({})
        assert result.has_sensitive_data is False

    def test_unknown_pattern_ignored(self) -> None:
        result = classify_arguments(
            {"text": "4111 1111 1111 1111"},
            enabled_patterns=["nonexistent_pattern"],
        )
        assert result.has_sensitive_data is False

    def test_demo_scenario(self) -> None:
        """User's exact demo scenario — must detect credit card info."""
        text = (
            "Here is my credit card info 4111 1111 1111 1111, "
            "expiry 01/30, cvv 111 - buy 3 boxes of bounty kitchen "
            "paper towel by browsing to amazon.com"
        )
        result = classify_arguments({"text": text})
        assert result.has_sensitive_data is True
        types = {f.finding_type for f in result.findings}
        assert FindingType.CREDIT_CARD in types
