"""Regex-based PII detector.

Reuses Luhn validation from ``agentward.inspect.classifier`` and adds
patterns for phone numbers, email addresses, IP addresses, dates of birth,
passport numbers, driver's license numbers, bank routing numbers, and
mailing addresses.  All matches carry ``confidence=1.0``.
"""

from __future__ import annotations

import re
from typing import Callable

from agentward.inspect.classifier import _luhn_check
from agentward.sanitize.models import DetectedEntity, PIICategory

# -----------------------------------------------------------------------
# Pre-compiled patterns
# -----------------------------------------------------------------------

# Credit card: 13-19 digits with optional spaces/dashes, Luhn-validated.
_CREDIT_CARD_RE = re.compile(
    r"\b(?:\d[\ \-]*?){13,19}\b"
)

# SSN: 3-2-4 groups with optional dashes or spaces.
_SSN_RE = re.compile(r"\b(\d{3})[\ \-]?(\d{2})[\ \-]?(\d{4})\b")

# CVV/CVC: keyword-anchored 3-4 digits.
_CVV_RE = re.compile(
    r"\b(?:cvv|cvc|cvv2|security\s+code)\s*[:\s]\s*(\d{3,4})\b",
    re.IGNORECASE,
)

# Expiry date: keyword-anchored MM/YY or MM/YYYY.
_EXPIRY_RE = re.compile(
    r"\b(?:exp(?:iry)?(?:\s*date)?)\s*[:\s]\s*(\d{1,2}\s*[/-]\s*\d{2,4})\b",
    re.IGNORECASE,
)

# API keys: known provider prefixes.
_API_KEY_RE = re.compile(
    r"\b("
    r"sk-[a-zA-Z0-9\-_]{20,}"     # OpenAI: sk-..., sk-proj-..., sk-svcacct-...
    r"|ghp_[a-zA-Z0-9]{36}"       # GitHub PAT
    r"|xoxb-[a-zA-Z0-9\-]{20,}"   # Slack bot token
    r"|xoxp-[a-zA-Z0-9\-]{20,}"   # Slack user token
    r"|AKIA[A-Z0-9]{16}"          # AWS access key
    r")\b"
)

# Email addresses.
_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
)

# US/intl phone numbers: +1 (555) 123-4567, 555-123-4567, +44 20 7946 0958, etc.
_PHONE_RE = re.compile(
    r"(?<!\d)"  # not preceded by digit
    r"(?:\+\d{1,3}[\s.-]?)?"                        # optional country code
    r"(?:\(?\d{2,4}\)?[\s.-])?"                      # optional area code
    r"\d{3,4}[\s.-]\d{3,4}"                          # main number
    r"(?!\d)"   # not followed by digit
)

# IPv4 addresses.
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Date of birth: keyword-anchored date patterns.
_DOB_RE = re.compile(
    r"\b(?:d\.?o\.?b\.?|date\s+of\s+birth|birth\s*(?:date|day)|born)\s*[:\s]\s*"
    r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})",
    re.IGNORECASE,
)

# US passport numbers: 6-9 alphanumeric, keyword-anchored.
# Two patterns:
#   1. Tight: "passport #/no./number: AB1234567" (direct keyword→value)
#   2. Loose: "passport ... : AB1234567" (keyword, filler, colon, value)
_PASSPORT_RE = re.compile(
    r"\b(?:passport)\s*(?:#|no\.?|number)?\s*[:\s]\s*([A-Z][A-Z0-9]{5,8})\b"
    r"|\b(?:passport)\b.{0,50}?:\s*([A-Z][A-Z0-9]{5,8})\b",
    re.IGNORECASE,
)

# US driver's license: keyword-anchored alphanumeric, 4-13 chars.
_DL_RE = re.compile(
    r"\b(?:driver'?s?\s*(?:license|licence)|DL)\s*(?:#|no\.?|number)?\s*[:\s]\s*"
    r"([A-Z0-9]{4,13})\b",
    re.IGNORECASE,
)

# US ABA routing numbers: exactly 9 digits, keyword-anchored.
# Two patterns:
#   1. Tight: "routing #/no./number: 021000021" (direct keyword→value)
#   2. Loose: "routing ... : 021000021" (keyword, filler, colon, value)
_ROUTING_RE = re.compile(
    r"\b(?:routing)\s*(?:#|no\.?|number)?\s*[:\s]\s*(\d{9})\b"
    r"|\b(?:routing)\b.{0,40}?:\s*(\d{9})\b",
    re.IGNORECASE,
)

# US mailing address: heuristic — number + optional directional + street name + suffix,
# with optional trailing ", City, ST ZIPCODE" (captures full address line).
_ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+(?:[NSEW]\s+)?[A-Za-z][a-zA-Z]+(?:\s+[A-Za-z][a-zA-Z]+){0,3}\s+"
    r"(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court"
    r"|Way|Pl|Place|Cir|Circle)\b\.?"
    r"(?:,?\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?"  # optional city name
    r",?\s+[A-Z]{2}"                                   # state abbreviation
    r"(?:\s+\d{5}(?:-\d{4})?)?)?",                     # optional zip/zip+4
    re.IGNORECASE,
)

# Medical license number: keyword-anchored, format like "CA-MD-8827341".
_MEDICAL_LICENSE_RE = re.compile(
    r"\b(?:(?:medical\s+)?license|lic(?:ense)?)\s*(?:#|no\.?|number)?\s*[:\s]\s*"
    r"([A-Z]{1,3}[-]?[A-Z]{0,3}[-]?\d{4,10})\b",
    re.IGNORECASE,
)

# Insurance/member ID: keyword-anchored, format like "BCB-2847193".
_INSURANCE_ID_RE = re.compile(
    r"\b(?:member\s*(?:id|#)|insurance\s*(?:id|#)|subscriber\s*(?:id|#)"
    r"|policy\s*(?:id|#|number))\s*(?:#|no\.?|number)?\s*[:\s]\s*"
    r"([A-Z0-9][-A-Z0-9]{3,20})\b",
    re.IGNORECASE,
)

# Invalid SSN areas (same as classifier.py).
_INVALID_SSN_AREAS: frozenset[str] = frozenset({"000", "666"})


# -----------------------------------------------------------------------
# Individual detector functions
# -----------------------------------------------------------------------


def _detect_credit_cards(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _CREDIT_CARD_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[^0-9]", "", raw)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if _luhn_check(digits):
            entities.append(DetectedEntity(
                category=PIICategory.CREDIT_CARD,
                text=raw,
                start=m.start(),
                end=m.end(),
            ))
    return entities


def _detect_ssns(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _SSN_RE.finditer(text):
        area, group, serial = m.group(1), m.group(2), m.group(3)
        if area in _INVALID_SSN_AREAS:
            continue
        if 900 <= int(area) <= 999:
            continue
        if group == "00":
            continue
        if serial == "0000":
            continue
        entities.append(DetectedEntity(
            category=PIICategory.SSN,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_cvvs(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _CVV_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.CVV,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_expiry_dates(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _EXPIRY_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.EXPIRY_DATE,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_api_keys(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _API_KEY_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.API_KEY,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_emails(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _EMAIL_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.EMAIL,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_phones(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _PHONE_RE.finditer(text):
        raw = m.group(0)
        # Require at least 7 actual digits to reduce false positives.
        digit_count = sum(1 for c in raw if c.isdigit())
        if digit_count < 7:
            continue
        entities.append(DetectedEntity(
            category=PIICategory.PHONE,
            text=raw,
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_ip_addresses(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _IPV4_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.IP_ADDRESS,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_dob(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _DOB_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.DATE_OF_BIRTH,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_passports(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _PASSPORT_RE.finditer(text):
        # Two alternation branches: group(1) for tight match, group(2) for loose.
        val = m.group(1) or m.group(2)
        grp = 1 if m.group(1) else 2
        entities.append(DetectedEntity(
            category=PIICategory.PASSPORT,
            text=val,
            start=m.start(grp),
            end=m.end(grp),
        ))
    return entities


def _detect_drivers_licenses(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _DL_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.DRIVERS_LICENSE,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_routing_numbers(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _ROUTING_RE.finditer(text):
        # Two alternation branches: group(1) for tight match, group(2) for loose.
        val = m.group(1) or m.group(2)
        grp = 1 if m.group(1) else 2
        entities.append(DetectedEntity(
            category=PIICategory.BANK_ROUTING,
            text=val,
            start=m.start(grp),
            end=m.end(grp),
        ))
    return entities


def _detect_addresses(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _ADDRESS_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.ADDRESS,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_medical_licenses(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _MEDICAL_LICENSE_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.MEDICAL_LICENSE,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


def _detect_insurance_ids(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _INSURANCE_ID_RE.finditer(text):
        entities.append(DetectedEntity(
            category=PIICategory.INSURANCE_ID,
            text=m.group(0),
            start=m.start(),
            end=m.end(),
        ))
    return entities


# -----------------------------------------------------------------------
# Detector registry
# -----------------------------------------------------------------------

DETECTORS: dict[PIICategory, Callable[[str], list[DetectedEntity]]] = {
    PIICategory.CREDIT_CARD: _detect_credit_cards,
    PIICategory.SSN: _detect_ssns,
    PIICategory.CVV: _detect_cvvs,
    PIICategory.EXPIRY_DATE: _detect_expiry_dates,
    PIICategory.API_KEY: _detect_api_keys,
    PIICategory.EMAIL: _detect_emails,
    PIICategory.PHONE: _detect_phones,
    PIICategory.IP_ADDRESS: _detect_ip_addresses,
    PIICategory.DATE_OF_BIRTH: _detect_dob,
    PIICategory.PASSPORT: _detect_passports,
    PIICategory.DRIVERS_LICENSE: _detect_drivers_licenses,
    PIICategory.BANK_ROUTING: _detect_routing_numbers,
    PIICategory.ADDRESS: _detect_addresses,
    PIICategory.MEDICAL_LICENSE: _detect_medical_licenses,
    PIICategory.INSURANCE_ID: _detect_insurance_ids,
}


def detect_all(
    text: str,
    *,
    categories: set[PIICategory] | None = None,
) -> list[DetectedEntity]:
    """Run all applicable regex detectors on *text*.

    Args:
        text: The input text to scan.
        categories: Subset of categories to detect.  ``None`` means all
            regex-detectable categories.

    Returns:
        List of detected entities sorted by start offset.
    """
    active = categories if categories is not None else set(DETECTORS.keys())
    entities: list[DetectedEntity] = []
    for cat, fn in DETECTORS.items():
        if cat in active:
            entities.extend(fn(text))
    entities.sort(key=lambda e: e.start)
    return entities
