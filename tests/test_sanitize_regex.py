"""Tests for the regex-based PII detector.

Covers all 13 regex-detectable PII categories with positive and negative cases.
"""

from __future__ import annotations

import pytest

from agentward.sanitize.detectors.regex_detector import (
    DETECTORS,
    _detect_addresses,
    _detect_api_keys,
    _detect_credit_cards,
    _detect_cvvs,
    _detect_dob,
    _detect_drivers_licenses,
    _detect_emails,
    _detect_expiry_dates,
    _detect_insurance_ids,
    _detect_ip_addresses,
    _detect_medical_licenses,
    _detect_passports,
    _detect_phones,
    _detect_routing_numbers,
    _detect_ssns,
    detect_all,
)
from agentward.sanitize.models import PIICategory


# -----------------------------------------------------------------------
# Credit cards
# -----------------------------------------------------------------------


class TestCreditCardDetector:
    def test_visa_spaces(self) -> None:
        entities = _detect_credit_cards("card: 4111 1111 1111 1111")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.CREDIT_CARD

    def test_visa_dashes(self) -> None:
        entities = _detect_credit_cards("4111-1111-1111-1111")
        assert len(entities) == 1

    def test_visa_no_sep(self) -> None:
        entities = _detect_credit_cards("4111111111111111")
        assert len(entities) == 1

    def test_amex_15_digits(self) -> None:
        entities = _detect_credit_cards("378282246310005")
        assert len(entities) == 1

    def test_luhn_fail_no_match(self) -> None:
        entities = _detect_credit_cards("1234567890123456")
        assert len(entities) == 0

    def test_too_short(self) -> None:
        entities = _detect_credit_cards("4111")
        assert len(entities) == 0

    def test_dollar_separated_no_match(self) -> None:
        """Regression: [ -] char range bug — must NOT match digits separated by $, #, etc."""
        entities = _detect_credit_cards("4111$1111$1111$1111")
        assert len(entities) == 0

    def test_hash_separated_no_match(self) -> None:
        entities = _detect_credit_cards("4111#1111#1111#1111")
        assert len(entities) == 0

    def test_offsets(self) -> None:
        text = "pay 4111111111111111 now"
        entities = _detect_credit_cards(text)
        assert entities[0].start == 4
        assert entities[0].end == 20
        assert text[entities[0].start:entities[0].end] == "4111111111111111"


# -----------------------------------------------------------------------
# SSNs
# -----------------------------------------------------------------------


class TestSSNDetector:
    def test_with_dashes(self) -> None:
        entities = _detect_ssns("SSN: 123-45-6789")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.SSN

    def test_with_spaces(self) -> None:
        entities = _detect_ssns("123 45 6789")
        assert len(entities) == 1

    def test_no_separators(self) -> None:
        entities = _detect_ssns("123456789")
        assert len(entities) == 1

    def test_invalid_area_000(self) -> None:
        assert len(_detect_ssns("000-12-3456")) == 0

    def test_invalid_area_666(self) -> None:
        assert len(_detect_ssns("666-12-3456")) == 0

    def test_invalid_area_900(self) -> None:
        assert len(_detect_ssns("900-12-3456")) == 0

    def test_invalid_group_00(self) -> None:
        assert len(_detect_ssns("123-00-3456")) == 0

    def test_invalid_serial_0000(self) -> None:
        assert len(_detect_ssns("123-45-0000")) == 0


# -----------------------------------------------------------------------
# CVV
# -----------------------------------------------------------------------


class TestCVVDetector:
    def test_cvv_3_digits(self) -> None:
        entities = _detect_cvvs("CVV: 123")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.CVV

    def test_cvc_4_digits(self) -> None:
        entities = _detect_cvvs("cvc 1234")
        assert len(entities) == 1

    def test_security_code(self) -> None:
        entities = _detect_cvvs("security code: 789")
        assert len(entities) == 1

    def test_bare_number_no_match(self) -> None:
        entities = _detect_cvvs("the code is 123")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# Expiry date
# -----------------------------------------------------------------------


class TestExpiryDetector:
    def test_mm_yy(self) -> None:
        entities = _detect_expiry_dates("expiry 01/30")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.EXPIRY_DATE

    def test_mm_yyyy(self) -> None:
        entities = _detect_expiry_dates("exp: 12/2025")
        assert len(entities) == 1

    def test_no_keyword_no_match(self) -> None:
        entities = _detect_expiry_dates("01/30")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# API keys
# -----------------------------------------------------------------------


class TestAPIKeyDetector:
    def test_openai_key(self) -> None:
        key = "sk-" + "a" * 48
        entities = _detect_api_keys(f"key: {key}")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.API_KEY
        assert entities[0].text == key

    def test_github_pat(self) -> None:
        key = "ghp_" + "A" * 36
        entities = _detect_api_keys(f"token={key}")
        assert len(entities) == 1

    def test_aws_key(self) -> None:
        key = "AKIA" + "B" * 16
        entities = _detect_api_keys(key)
        assert len(entities) == 1

    def test_short_sk_no_match(self) -> None:
        entities = _detect_api_keys("sk-abc")
        assert len(entities) == 0

    def test_openai_proj_key(self) -> None:
        """Regression: sk-proj-* keys contain hyphens that broke the old regex."""
        key = "sk-proj-8kT2vLmN4xR7wQ9pJ3bYcA5dF6hG1iK0"
        entities = _detect_api_keys(f"API key: {key}")
        assert len(entities) == 1
        assert entities[0].text == key

    def test_openai_svcacct_key(self) -> None:
        """Regression: sk-svcacct-* keys contain hyphens."""
        key = "sk-svcacct-" + "a1b2c3d4e5f6g7h8i9j0"
        entities = _detect_api_keys(f"key={key}")
        assert len(entities) == 1
        assert entities[0].text == key


# -----------------------------------------------------------------------
# Email
# -----------------------------------------------------------------------


class TestEmailDetector:
    def test_simple_email(self) -> None:
        entities = _detect_emails("contact: user@example.com")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.EMAIL
        assert entities[0].text == "user@example.com"

    def test_email_with_dots(self) -> None:
        entities = _detect_emails("first.last@company.co.uk")
        assert len(entities) == 1

    def test_email_with_plus(self) -> None:
        entities = _detect_emails("user+tag@gmail.com")
        assert len(entities) == 1

    def test_no_at_sign_no_match(self) -> None:
        entities = _detect_emails("not an email address")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# Phone
# -----------------------------------------------------------------------


class TestPhoneDetector:
    def test_us_format(self) -> None:
        entities = _detect_phones("call 555-123-4567")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.PHONE

    def test_intl_format(self) -> None:
        entities = _detect_phones("+1 555-123-4567")
        assert len(entities) == 1

    def test_too_few_digits_no_match(self) -> None:
        entities = _detect_phones("12-34")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# IP address
# -----------------------------------------------------------------------


class TestIPDetector:
    def test_private_ip(self) -> None:
        entities = _detect_ip_addresses("server: 192.168.1.100")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.IP_ADDRESS
        assert entities[0].text == "192.168.1.100"

    def test_public_ip(self) -> None:
        entities = _detect_ip_addresses("8.8.8.8")
        assert len(entities) == 1

    def test_invalid_octet(self) -> None:
        entities = _detect_ip_addresses("999.999.999.999")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# Date of birth
# -----------------------------------------------------------------------


class TestDOBDetector:
    def test_dob_keyword(self) -> None:
        entities = _detect_dob("DOB: 03/15/1985")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.DATE_OF_BIRTH

    def test_date_of_birth_keyword(self) -> None:
        entities = _detect_dob("date of birth: 1990-01-15")
        assert len(entities) == 1

    def test_born_keyword(self) -> None:
        entities = _detect_dob("born: 12/25/2000")
        assert len(entities) == 1

    def test_birthday_keyword(self) -> None:
        entities = _detect_dob("birthday: 03/15/1985")
        assert len(entities) == 1

    def test_bare_date_no_match(self) -> None:
        entities = _detect_dob("03/15/1985")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# Passport
# -----------------------------------------------------------------------


class TestPassportDetector:
    def test_passport_number(self) -> None:
        entities = _detect_passports("Passport: AB1234567")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.PASSPORT

    def test_passport_no_keyword(self) -> None:
        entities = _detect_passports("AB1234567")
        assert len(entities) == 0

    def test_passport_with_filler_words(self) -> None:
        """Regression: 'Passport on file for ... program: AB1234567' missed by tight regex."""
        entities = _detect_passports(
            "Passport on file for international referral program: AB1234567"
        )
        assert len(entities) == 1
        assert entities[0].text == "AB1234567"

    def test_passport_captures_value_only(self) -> None:
        """Regression: ensure only the passport number is captured, not the filler."""
        entities = _detect_passports("Passport #: XY9876543")
        assert len(entities) == 1
        assert entities[0].text == "XY9876543"


# -----------------------------------------------------------------------
# Driver's license
# -----------------------------------------------------------------------


class TestDriversLicenseDetector:
    def test_dl_number(self) -> None:
        entities = _detect_drivers_licenses("Driver's license: D12345678")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.DRIVERS_LICENSE

    def test_dl_abbreviation(self) -> None:
        entities = _detect_drivers_licenses("DL: D12345678")
        assert len(entities) == 1

    def test_no_keyword_no_match(self) -> None:
        entities = _detect_drivers_licenses("D12345678")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# Bank routing number
# -----------------------------------------------------------------------


class TestRoutingDetector:
    def test_routing_number(self) -> None:
        entities = _detect_routing_numbers("routing number: 021000021")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.BANK_ROUTING

    def test_routing_no_keyword(self) -> None:
        entities = _detect_routing_numbers("021000021")
        assert len(entities) == 0

    def test_routing_with_filler_words(self) -> None:
        """Regression: 'routing number on file: 021000021' missed by tight regex."""
        entities = _detect_routing_numbers(
            "routing number on file: 021000021"
        )
        assert len(entities) == 1
        assert entities[0].text == "021000021"

    def test_routing_captures_value_only(self) -> None:
        """Regression: ensure only the 9-digit number is captured, not the filler."""
        entities = _detect_routing_numbers("routing #: 021000021")
        assert len(entities) == 1
        assert entities[0].text == "021000021"


# -----------------------------------------------------------------------
# Mailing address
# -----------------------------------------------------------------------


class TestAddressDetector:
    def test_street_address(self) -> None:
        entities = _detect_addresses("742 Evergreen Terrace Dr")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.ADDRESS

    def test_avenue(self) -> None:
        entities = _detect_addresses("100 Main Ave")
        assert len(entities) == 1

    def test_directional_n(self) -> None:
        """Addresses with single-letter directional: 100 N Main St."""
        entities = _detect_addresses("100 N Main St")
        assert len(entities) == 1

    def test_directional_e(self) -> None:
        entities = _detect_addresses("200 E Oak Ave")
        assert len(entities) == 1

    def test_no_number_no_match(self) -> None:
        entities = _detect_addresses("Evergreen Terrace")
        assert len(entities) == 0

    def test_full_address_with_city_state_zip(self) -> None:
        """Regression: city/state/zip after street suffix was not captured."""
        entities = _detect_addresses("742 Evergreen Terrace Dr, Springfield, IL 62704")
        assert len(entities) == 1
        assert "Springfield" in entities[0].text
        assert "62704" in entities[0].text

    def test_full_address_with_zip_plus_4(self) -> None:
        entities = _detect_addresses("100 Main St, Boston, MA 02101-1234")
        assert len(entities) == 1
        assert "02101-1234" in entities[0].text


# -----------------------------------------------------------------------
# Medical license
# -----------------------------------------------------------------------


class TestMedicalLicenseDetector:
    def test_state_medical_license(self) -> None:
        entities = _detect_medical_licenses("License: CA-MD-8827341")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.MEDICAL_LICENSE

    def test_medical_license_keyword(self) -> None:
        entities = _detect_medical_licenses("Medical License #: NY-12345678")
        assert len(entities) == 1

    def test_no_keyword_no_match(self) -> None:
        entities = _detect_medical_licenses("CA-MD-8827341")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# Insurance ID
# -----------------------------------------------------------------------


class TestInsuranceIdDetector:
    def test_member_id(self) -> None:
        entities = _detect_insurance_ids("Member ID: BCB-2847193")
        assert len(entities) == 1
        assert entities[0].category == PIICategory.INSURANCE_ID

    def test_insurance_id(self) -> None:
        entities = _detect_insurance_ids("Insurance ID: AETNA-99812345")
        assert len(entities) == 1

    def test_policy_number(self) -> None:
        entities = _detect_insurance_ids("Policy Number: POL-2024-78901")
        assert len(entities) == 1

    def test_no_keyword_no_match(self) -> None:
        entities = _detect_insurance_ids("BCB-2847193")
        assert len(entities) == 0


# -----------------------------------------------------------------------
# detect_all
# -----------------------------------------------------------------------


class TestDetectAll:
    def test_multiple_categories(self) -> None:
        text = "SSN: 123-45-6789, email: a@b.com"
        entities = detect_all(text)
        cats = {e.category for e in entities}
        assert PIICategory.SSN in cats
        assert PIICategory.EMAIL in cats

    def test_category_filter(self) -> None:
        text = "SSN: 123-45-6789, email: a@b.com"
        entities = detect_all(text, categories={PIICategory.EMAIL})
        assert all(e.category == PIICategory.EMAIL for e in entities)

    def test_sorted_by_offset(self) -> None:
        text = "email: a@b.com then SSN 123-45-6789"
        entities = detect_all(text)
        offsets = [e.start for e in entities]
        assert offsets == sorted(offsets)

    def test_empty_text(self) -> None:
        entities = detect_all("")
        assert entities == []

    def test_no_pii(self) -> None:
        entities = detect_all("just a plain sentence")
        assert entities == []

    def test_all_detectors_registered(self) -> None:
        """Every regex-detectable category has a registered detector."""
        from agentward.sanitize.models import REGEX_CATEGORIES

        for cat in REGEX_CATEGORIES:
            assert cat in DETECTORS, f"Missing detector for {cat}"
