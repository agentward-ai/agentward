"""Tier 1 sensitive content classifier — regex-based.

Scans tool call arguments for sensitive data patterns (credit cards, SSNs,
CVVs, API keys) and returns findings.  Pure functions, no I/O, no async.

This classifier runs at the LLM proxy interception point *after* the policy
engine has evaluated the tool call.  If a tool call is ALLOW/FLUSH/APPROVE
and the arguments contain sensitive data, the call is blocked before the
agent runtime sees it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator


# -----------------------------------------------------------------------
# Data structures
# -----------------------------------------------------------------------


class FindingType(str, Enum):
    """Types of sensitive data the classifier can detect."""

    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    CVV = "cvv"
    EXPIRY_DATE = "expiry_date"
    API_KEY = "api_key"


@dataclass(frozen=True)
class Finding:
    """A single instance of sensitive data found in tool call arguments.

    Attributes:
        finding_type: The category of sensitive data.
        matched_text: A redacted representation of the matched text.
        field_path: Dot-separated path to the field (e.g., "body.content").
    """

    finding_type: FindingType
    matched_text: str
    field_path: str


@dataclass(frozen=True)
class ClassificationResult:
    """Result of classifying tool call arguments.

    Attributes:
        has_sensitive_data: True if any sensitive data was found.
        findings: List of all findings.
    """

    has_sensitive_data: bool
    findings: list[Finding] = field(default_factory=list)


# -----------------------------------------------------------------------
# Pre-compiled regex patterns
# -----------------------------------------------------------------------

# Credit card: 13-19 digits possibly separated by spaces or dashes.
# Validated with Luhn checksum after extraction.
_CREDIT_CARD_RE = re.compile(
    r"\b"
    r"(?:\d[ -]*?){13,19}"
    r"\b"
)

# SSN: 3-2-4 digit groups with optional dashes or spaces.
_SSN_RE = re.compile(
    r"\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b"
)

# CVV/CVC: keyword followed by 3-4 digits.
_CVV_RE = re.compile(
    r"\b(?:cvv|cvc|cvv2|security\s+code)\s*[:\s]\s*(\d{3,4})\b",
    re.IGNORECASE,
)

# Expiry date: keyword followed by MM/YY or MM/YYYY.
_EXPIRY_RE = re.compile(
    r"\b(?:exp(?:iry)?(?:\s*date)?)\s*[:\s]\s*(\d{1,2}\s*[/-]\s*\d{2,4})\b",
    re.IGNORECASE,
)

# API keys: known provider prefixes with sufficient length.
_API_KEY_RE = re.compile(
    r"\b("
    r"sk-[a-zA-Z0-9]{20,}"          # OpenAI / Anthropic style
    r"|ghp_[a-zA-Z0-9]{36}"         # GitHub PAT
    r"|xoxb-[a-zA-Z0-9\-]{20,}"    # Slack bot token
    r"|xoxp-[a-zA-Z0-9\-]{20,}"    # Slack user token
    r"|AKIA[A-Z0-9]{16}"            # AWS access key
    r")\b"
)

# Invalid SSN area numbers (000, 666, 900-999).
_INVALID_SSN_AREAS = frozenset({"000", "666"})


# -----------------------------------------------------------------------
# Luhn algorithm
# -----------------------------------------------------------------------


def _luhn_check(digits: str) -> bool:
    """Validate a digit string using the Luhn algorithm.

    Args:
        digits: A string of digits (no spaces or dashes).

    Returns:
        True if the digit string passes the Luhn checksum.
    """
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


# -----------------------------------------------------------------------
# Redaction
# -----------------------------------------------------------------------


def _redact_card(digits: str) -> str:
    """Redact a credit card number, keeping first 4 and last 4 digits.

    Args:
        digits: The raw digit string (no separators).

    Returns:
        Redacted form like "4111 **** **** 1111".
    """
    if len(digits) <= 8:
        return "*" * len(digits)
    masked = digits[:4] + " " + "*" * (len(digits) - 8) + " " + digits[-4:]
    return masked


def _redact_ssn(area: str, group: str, serial: str) -> str:
    """Redact an SSN, keeping last 4 digits.

    Returns:
        Redacted form like "***-**-6789".
    """
    return f"***-**-{serial}"


# -----------------------------------------------------------------------
# Argument walker
# -----------------------------------------------------------------------


def _walk_arguments(
    obj: Any,
    path: str = "",
) -> Iterator[tuple[str, str]]:
    """Recursively yield (field_path, string_value) from nested structures.

    Handles dicts, lists, and converts non-string scalars to strings for
    scanning (e.g., an integer credit card number).

    Args:
        obj: The object to walk (dict, list, or scalar).
        path: The current dot-separated path prefix.

    Yields:
        (field_path, string_value) pairs for every leaf value.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _walk_arguments(value, child_path)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            child_path = f"{path}[{i}]" if path else f"[{i}]"
            yield from _walk_arguments(value, child_path)
    elif isinstance(obj, str):
        if obj:
            yield (path, obj)
    elif isinstance(obj, (int, float)):
        # Numbers might contain sensitive data (e.g., card number as int)
        yield (path, str(obj))


# -----------------------------------------------------------------------
# Individual detectors
# -----------------------------------------------------------------------


def _detect_credit_cards(text: str, field_path: str) -> list[Finding]:
    """Detect credit card numbers in text using regex + Luhn validation."""
    findings: list[Finding] = []
    for match in _CREDIT_CARD_RE.finditer(text):
        raw = match.group(0)
        digits = re.sub(r"[^0-9]", "", raw)
        if len(digits) < 13 or len(digits) > 19:
            continue
        if _luhn_check(digits):
            findings.append(
                Finding(
                    finding_type=FindingType.CREDIT_CARD,
                    matched_text=_redact_card(digits),
                    field_path=field_path,
                )
            )
    return findings


def _detect_ssns(text: str, field_path: str) -> list[Finding]:
    """Detect US Social Security Numbers in text."""
    findings: list[Finding] = []
    for match in _SSN_RE.finditer(text):
        area, group, serial = match.group(1), match.group(2), match.group(3)
        # Validate: area cannot be 000, 666, or 900-999
        if area in _INVALID_SSN_AREAS:
            continue
        if 900 <= int(area) <= 999:
            continue
        # Group cannot be 00
        if group == "00":
            continue
        # Serial cannot be 0000
        if serial == "0000":
            continue
        findings.append(
            Finding(
                finding_type=FindingType.SSN,
                matched_text=_redact_ssn(area, group, serial),
                field_path=field_path,
            )
        )
    return findings


def _detect_cvvs(text: str, field_path: str) -> list[Finding]:
    """Detect CVV/CVC codes in text (keyword-anchored)."""
    findings: list[Finding] = []
    for match in _CVV_RE.finditer(text):
        findings.append(
            Finding(
                finding_type=FindingType.CVV,
                matched_text="***",
                field_path=field_path,
            )
        )
    return findings


def _detect_expiry_dates(text: str, field_path: str) -> list[Finding]:
    """Detect payment card expiry dates in text (keyword-anchored)."""
    findings: list[Finding] = []
    for match in _EXPIRY_RE.finditer(text):
        findings.append(
            Finding(
                finding_type=FindingType.EXPIRY_DATE,
                matched_text="**/**",
                field_path=field_path,
            )
        )
    return findings


def _detect_api_keys(text: str, field_path: str) -> list[Finding]:
    """Detect API keys from known providers."""
    findings: list[Finding] = []
    for match in _API_KEY_RE.finditer(text):
        raw = match.group(1)
        # Redact: show prefix + last 4
        if len(raw) > 8:
            redacted = raw[:4] + "..." + raw[-4:]
        else:
            redacted = raw[:4] + "..."
        findings.append(
            Finding(
                finding_type=FindingType.API_KEY,
                matched_text=redacted,
                field_path=field_path,
            )
        )
    return findings


# -----------------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------------

# Map FindingType → detector function for easy filtering by enabled patterns.
_DETECTORS: dict[FindingType, Any] = {
    FindingType.CREDIT_CARD: _detect_credit_cards,
    FindingType.SSN: _detect_ssns,
    FindingType.CVV: _detect_cvvs,
    FindingType.EXPIRY_DATE: _detect_expiry_dates,
    FindingType.API_KEY: _detect_api_keys,
}


def redact_arguments(arguments: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    """Create a redacted copy of tool arguments based on classifier findings.

    Replaces the value at each finding's field_path with a redacted placeholder.
    Returns a deep copy — the original dict is not modified.

    Args:
        arguments: The original tool call arguments dict.
        findings: List of findings from classify_arguments().

    Returns:
        A new dict with sensitive values replaced by "[REDACTED:<type>]".
    """
    import copy

    redacted = copy.deepcopy(arguments)

    for finding in findings:
        _redact_at_path(redacted, finding.field_path, finding.finding_type.value)

    return redacted


def _redact_at_path(obj: Any, path: str, finding_type: str) -> None:
    """Replace the value at a dot-separated path with a redacted placeholder.

    Args:
        obj: The root object (dict or list) to modify in-place.
        path: Dot-separated path (e.g., "body.content" or "items[1]").
        finding_type: The type of finding for the placeholder text.
    """
    parts = _split_path(path)
    if not parts:
        return

    current = obj
    for part in parts[:-1]:
        if isinstance(current, dict):
            if part not in current:
                return
            current = current[part]
        elif isinstance(current, list):
            try:
                idx = int(part)
                current = current[idx]
            except (ValueError, IndexError):
                return
        else:
            return

    # Set the final value
    last = parts[-1]
    if isinstance(current, dict) and last in current:
        current[last] = f"[REDACTED:{finding_type}]"
    elif isinstance(current, list):
        try:
            idx = int(last)
            current[idx] = f"[REDACTED:{finding_type}]"
        except (ValueError, IndexError):
            pass


def _split_path(path: str) -> list[str]:
    """Split a field path into individual parts.

    Handles both dot notation ("a.b.c") and array notation ("a[0].b").

    Args:
        path: The dot-separated path string.

    Returns:
        List of path components.
    """
    parts: list[str] = []
    for segment in path.split("."):
        if not segment:
            continue
        # Handle array indices like "items[1]"
        if "[" in segment:
            before_bracket = segment[:segment.index("[")]
            if before_bracket:
                parts.append(before_bracket)
            # Extract all indices
            rest = segment[segment.index("["):]
            while rest.startswith("["):
                end = rest.index("]")
                parts.append(rest[1:end])
                rest = rest[end + 1:]
        else:
            parts.append(segment)
    return parts


def classify_arguments(
    arguments: dict[str, Any],
    *,
    enabled_patterns: list[str] | None = None,
) -> ClassificationResult:
    """Scan tool call arguments for sensitive data.

    Recursively walks all string values in the arguments dict and runs
    each enabled detector against the text.

    Args:
        arguments: The tool call arguments dict.
        enabled_patterns: List of FindingType values to check.
            If None, all patterns are enabled.

    Returns:
        A ClassificationResult with all findings.
    """
    # Resolve which detectors to run
    if enabled_patterns is not None:
        active_types = set()
        for p in enabled_patterns:
            try:
                active_types.add(FindingType(p))
            except ValueError:
                continue  # Unknown pattern name — skip
    else:
        active_types = set(_DETECTORS.keys())

    active_detectors = [
        _DETECTORS[ft] for ft in active_types if ft in _DETECTORS
    ]

    if not active_detectors:
        return ClassificationResult(has_sensitive_data=False)

    findings: list[Finding] = []
    for field_path, text in _walk_arguments(arguments):
        for detector in active_detectors:
            findings.extend(detector(text, field_path))

    return ClassificationResult(
        has_sensitive_data=len(findings) > 0,
        findings=findings,
    )
