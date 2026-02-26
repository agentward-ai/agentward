#!/usr/bin/env python3
"""AgentWard Sanitize — standalone PII detection and redaction.

Self-contained script with zero external dependencies.  Can be used as a
Claude/OpenClaw skill or run directly from the command line.

Usage:
    python sanitize.py <file>                      # sanitize to stdout
    python sanitize.py <file> --output clean.txt   # write to file
    python sanitize.py <file> --json               # JSON with entity map
    python sanitize.py <file> --preview            # detect-only, no redaction
    python sanitize.py <file> --categories ssn,email
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable


# =====================================================================
# Models
# =====================================================================


class PIICategory(str, Enum):
    CREDIT_CARD = "credit_card"
    CVV = "cvv"
    EXPIRY_DATE = "expiry_date"
    BANK_ROUTING = "bank_routing"
    SSN = "ssn"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    API_KEY = "api_key"
    MEDICAL_LICENSE = "medical_license"
    INSURANCE_ID = "insurance_id"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    ADDRESS = "address"


@dataclass(frozen=True)
class DetectedEntity:
    category: PIICategory
    text: str
    start: int
    end: int
    confidence: float = 1.0


@dataclass
class SanitizeResult:
    original_text: str
    sanitized_text: str
    entities: list[DetectedEntity] = field(default_factory=list)
    entity_map: dict[str, str] = field(default_factory=dict)

    @property
    def has_pii(self) -> bool:
        return len(self.entities) > 0

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self.entities:
            counts[e.category.value] = counts.get(e.category.value, 0) + 1
        return counts


# =====================================================================
# Luhn algorithm (for credit card validation)
# =====================================================================


def _luhn_check(digits: str) -> bool:
    if not digits or not digits.isdigit():
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# =====================================================================
# Regex patterns
# =====================================================================

_CREDIT_CARD_RE = re.compile(r"\b(?:\d[\ \-]*?){13,19}\b")
_SSN_RE = re.compile(r"\b(\d{3})[\ \-]?(\d{2})[\ \-]?(\d{4})\b")
_CVV_RE = re.compile(r"\b(?:cvv|cvc|cvv2|security\s+code)\s*[:\s]\s*(\d{3,4})\b", re.I)
_EXPIRY_RE = re.compile(r"\b(?:exp(?:iry)?(?:\s*date)?)\s*[:\s]\s*(\d{1,2}\s*[/-]\s*\d{2,4})\b", re.I)
_API_KEY_RE = re.compile(
    r"\b(sk-[a-zA-Z0-9\-_]{20,}|ghp_[a-zA-Z0-9]{36}"
    r"|xoxb-[a-zA-Z0-9\-]{20,}|xoxp-[a-zA-Z0-9\-]{20,}"
    r"|AKIA[A-Z0-9]{16})\b"
)
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-])?\d{3,4}[\s.-]\d{3,4}(?!\d)"
)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOB_RE = re.compile(
    r"\b(?:d\.?o\.?b\.?|date\s+of\s+birth|birth\s*(?:date|day)|born)\s*[:\s]\s*"
    r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})",
    re.I,
)
_PASSPORT_RE = re.compile(
    r"\b(?:passport)\s*(?:#|no\.?|number)?\s*[:\s]\s*([A-Z][A-Z0-9]{5,8})\b"
    r"|\b(?:passport)\b.{0,50}?:\s*([A-Z][A-Z0-9]{5,8})\b",
    re.I,
)
_DL_RE = re.compile(
    r"\b(?:driver'?s?\s*(?:license|licence)|DL)\s*(?:#|no\.?|number)?\s*[:\s]\s*"
    r"([A-Z0-9]{4,13})\b",
    re.I,
)
_ROUTING_RE = re.compile(
    r"\b(?:routing)\s*(?:#|no\.?|number)?\s*[:\s]\s*(\d{9})\b"
    r"|\b(?:routing)\b.{0,40}?:\s*(\d{9})\b",
    re.I,
)
_ADDRESS_RE = re.compile(
    r"\b\d{1,6}\s+(?:[NSEW]\s+)?[A-Za-z][a-zA-Z]+(?:\s+[A-Za-z][a-zA-Z]+){0,3}\s+"
    r"(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Rd|Road|Ct|Court"
    r"|Way|Pl|Place|Cir|Circle)\b\.?"
    r"(?:,?\s+[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?"
    r",?\s+[A-Z]{2}"
    r"(?:\s+\d{5}(?:-\d{4})?)?)?",
    re.I,
)
_MEDICAL_LICENSE_RE = re.compile(
    r"\b(?:(?:medical\s+)?license|lic(?:ense)?)\s*(?:#|no\.?|number)?\s*[:\s]\s*"
    r"([A-Z]{1,3}[-]?[A-Z]{0,3}[-]?\d{4,10})\b",
    re.I,
)
_INSURANCE_ID_RE = re.compile(
    r"\b(?:member\s*(?:id|#)|insurance\s*(?:id|#)|subscriber\s*(?:id|#)"
    r"|policy\s*(?:id|#|number))\s*(?:#|no\.?|number)?\s*[:\s]\s*"
    r"([A-Z0-9][-A-Z0-9]{3,20})\b",
    re.I,
)

_INVALID_SSN_AREAS: frozenset[str] = frozenset({"000", "666"})


# =====================================================================
# Detector functions
# =====================================================================


def _detect_credit_cards(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _CREDIT_CARD_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[^0-9]", "", raw)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if _luhn_check(digits):
            entities.append(DetectedEntity(PIICategory.CREDIT_CARD, raw, m.start(), m.end()))
    return entities


def _detect_ssns(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _SSN_RE.finditer(text):
        area, group, serial = m.group(1), m.group(2), m.group(3)
        if area in _INVALID_SSN_AREAS or 900 <= int(area) <= 999:
            continue
        if group == "00" or serial == "0000":
            continue
        entities.append(DetectedEntity(PIICategory.SSN, m.group(0), m.start(), m.end()))
    return entities


def _detect_cvvs(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.CVV, m.group(0), m.start(), m.end())
        for m in _CVV_RE.finditer(text)
    ]


def _detect_expiry_dates(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.EXPIRY_DATE, m.group(0), m.start(), m.end())
        for m in _EXPIRY_RE.finditer(text)
    ]


def _detect_api_keys(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.API_KEY, m.group(0), m.start(), m.end())
        for m in _API_KEY_RE.finditer(text)
    ]


def _detect_emails(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.EMAIL, m.group(0), m.start(), m.end())
        for m in _EMAIL_RE.finditer(text)
    ]


def _detect_phones(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _PHONE_RE.finditer(text):
        raw = m.group(0)
        if sum(1 for c in raw if c.isdigit()) < 7:
            continue
        entities.append(DetectedEntity(PIICategory.PHONE, raw, m.start(), m.end()))
    return entities


def _detect_ip_addresses(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.IP_ADDRESS, m.group(0), m.start(), m.end())
        for m in _IPV4_RE.finditer(text)
    ]


def _detect_dob(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.DATE_OF_BIRTH, m.group(0), m.start(), m.end())
        for m in _DOB_RE.finditer(text)
    ]


def _detect_passports(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _PASSPORT_RE.finditer(text):
        val = m.group(1) or m.group(2)
        grp = 1 if m.group(1) else 2
        entities.append(DetectedEntity(PIICategory.PASSPORT, val, m.start(grp), m.end(grp)))
    return entities


def _detect_drivers_licenses(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.DRIVERS_LICENSE, m.group(0), m.start(), m.end())
        for m in _DL_RE.finditer(text)
    ]


def _detect_routing_numbers(text: str) -> list[DetectedEntity]:
    entities: list[DetectedEntity] = []
    for m in _ROUTING_RE.finditer(text):
        val = m.group(1) or m.group(2)
        grp = 1 if m.group(1) else 2
        entities.append(DetectedEntity(PIICategory.BANK_ROUTING, val, m.start(grp), m.end(grp)))
    return entities


def _detect_addresses(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.ADDRESS, m.group(0), m.start(), m.end())
        for m in _ADDRESS_RE.finditer(text)
    ]


def _detect_medical_licenses(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.MEDICAL_LICENSE, m.group(0), m.start(), m.end())
        for m in _MEDICAL_LICENSE_RE.finditer(text)
    ]


def _detect_insurance_ids(text: str) -> list[DetectedEntity]:
    return [
        DetectedEntity(PIICategory.INSURANCE_ID, m.group(0), m.start(), m.end())
        for m in _INSURANCE_ID_RE.finditer(text)
    ]


_DETECTORS: dict[PIICategory, Callable[[str], list[DetectedEntity]]] = {
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


# =====================================================================
# Engine
# =====================================================================


def _deduplicate_overlaps(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    """Remove overlapping entities, keeping the longer span."""
    if len(entities) <= 1:
        return entities
    result: list[DetectedEntity] = []
    for ent in entities:
        if result and ent.start < result[-1].end:
            prev = result[-1]
            if (ent.end - ent.start) > (prev.end - prev.start):
                result[-1] = ent
        else:
            result.append(ent)
    return result


def detect_all(
    text: str,
    categories: set[PIICategory] | None = None,
) -> list[DetectedEntity]:
    active = categories if categories is not None else set(_DETECTORS.keys())
    entities: list[DetectedEntity] = []
    for cat, fn in _DETECTORS.items():
        if cat in active:
            entities.extend(fn(text))
    entities.sort(key=lambda e: e.start)
    return _deduplicate_overlaps(entities)


def redact_text(
    text: str,
    entities: list[DetectedEntity],
) -> tuple[str, dict[str, str]]:
    if not entities:
        return text, {}

    seen: dict[tuple[PIICategory, str], int] = {}
    category_counters: dict[PIICategory, int] = {}
    entity_placeholders: dict[int, str] = {}

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

    entity_map: dict[str, str] = {}
    for idx, ent in enumerate(entities):
        ph = entity_placeholders[idx]
        if ph not in entity_map:
            entity_map[ph] = ent.text

    chunks: list[str] = []
    prev_end = 0
    for idx, ent in enumerate(entities):
        chunks.append(text[prev_end:ent.start])
        chunks.append(entity_placeholders[idx])
        prev_end = ent.end
    chunks.append(text[prev_end:])

    return "".join(chunks), entity_map


def sanitize_text(
    text: str,
    categories: set[PIICategory] | None = None,
) -> SanitizeResult:
    entities = detect_all(text, categories=categories)
    sanitized, entity_map = redact_text(text, entities)
    return SanitizeResult(
        original_text=text,
        sanitized_text=sanitized,
        entities=entities,
        entity_map=entity_map,
    )


def sanitize_file(
    path: Path,
    categories: set[PIICategory] | None = None,
) -> SanitizeResult:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    return sanitize_text(text, categories=categories)


# =====================================================================
# CLI
# =====================================================================


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AgentWard Sanitize — detect and redact PII from files.",
    )
    parser.add_argument("file", type=Path, help="File to sanitize")
    parser.add_argument("--output", "-o", type=Path, help="Write sanitized output to file")
    parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")
    parser.add_argument("--preview", action="store_true", help="Detect-only, no redaction")
    parser.add_argument(
        "--categories", "-c", type=str, default=None,
        help="Comma-separated PII categories to detect",
    )

    args = parser.parse_args()

    # Parse categories.
    cat_set: set[PIICategory] | None = None
    if args.categories:
        cat_set = set()
        for name in args.categories.split(","):
            name = name.strip().lower()
            try:
                cat_set.add(PIICategory(name))
            except ValueError:
                print(f"Warning: Unknown category '{name}', skipping.", file=sys.stderr)
        if not cat_set:
            print("Error: No valid categories specified.", file=sys.stderr)
            sys.exit(1)

    try:
        result = sanitize_file(args.file, categories=cat_set)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Preview mode.
    # Raw PII text is intentionally NOT printed — only category, offset,
    # length, and placeholder are shown.  This prevents leaking sensitive
    # data into LLM context when the output is captured by an agent.
    if args.preview:
        if not result.has_pii:
            print("No PII detected.")
            return
        print(f"Detected {len(result.entities)} PII entities:\n")
        cat_counters: dict[str, int] = {}
        for i, ent in enumerate(result.entities, 1):
            cat_key = ent.category.value.upper()
            cat_counters[cat_key] = cat_counters.get(cat_key, 0) + 1
            placeholder = f"[{cat_key}_{cat_counters[cat_key]}]"
            print(f"  {i}. [{ent.category.value}] {placeholder} (offset {ent.start}:{ent.end}, length {ent.end - ent.start})")
        return

    # JSON mode.
    # Stdout JSON intentionally omits raw PII values (entities[].text
    # and entity_map) to prevent leaking sensitive data into LLM context
    # when the output is captured by an agent.
    if args.json_output:
        data: dict[str, object] = {
            "file": str(args.file),
            "has_pii": result.has_pii,
            "entity_count": len(result.entities),
            "summary": result.summary,
            "entities": [
                {
                    "category": e.category.value,
                    "start": e.start,
                    "end": e.end,
                }
                for e in result.entities
            ],
            "sanitized_text": result.sanitized_text,
        }

        # Write the entity map (contains raw PII) to a sidecar file when
        # --output is specified.  This keeps it on disk and out of stdout.
        if args.output:
            map_path = args.output.with_suffix(".entity-map.json")
            map_data = {
                "entity_map": result.entity_map,
                "entities": [
                    {
                        "category": e.category.value,
                        "text": e.text,
                        "start": e.start,
                        "end": e.end,
                    }
                    for e in result.entities
                ],
            }
            map_path.parent.mkdir(parents=True, exist_ok=True)
            map_path.write_text(json.dumps(map_data, indent=2), encoding="utf-8")
            data["entity_map_file"] = str(map_path)
            print(
                f"Entity map written to {map_path} (contains raw PII — do not share)",
                file=sys.stderr,
            )

        print(json.dumps(data, indent=2))
        return

    # Default: write sanitized text.
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(result.sanitized_text, encoding="utf-8")
        print(
            f"Sanitized output written to {args.output}", file=sys.stderr,
        )
        if result.has_pii:
            print(
                f"  Redacted {len(result.entities)} entities "
                f"across {len({e.category for e in result.entities})} categories.",
                file=sys.stderr,
            )
    else:
        sys.stdout.write(result.sanitized_text)
        if not result.sanitized_text.endswith("\n"):
            sys.stdout.write("\n")


if __name__ == "__main__":
    main()
