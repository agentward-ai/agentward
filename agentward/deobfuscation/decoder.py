"""Deobfuscation pipeline — unwraps encoded/obfuscated argument values
before policy constraint evaluation.

Supports: Base64 (standard + URL-safe), Hex (escape/0x/plain),
URL-encoding (single + double), Unicode escapes, HTML entities,
ROT13, and reversed strings.
"""

from __future__ import annotations

import base64
import codecs
import html
import re
import unicodedata
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Decoded variant
# ---------------------------------------------------------------------------


@dataclass
class DecodedVariant:
    """A single decoded form of an argument value.

    Attributes:
        value: The decoded value.
        encoding: Which encoding was detected (e.g. "base64", "hex", "url").
        depth: Decode depth — 0 means original, 1 means first decode pass, etc.
        chain: List of encodings applied from outermost to innermost.
    """

    value: str
    encoding: str
    depth: int
    chain: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Base decoder ABC
# ---------------------------------------------------------------------------


class BaseDecoder(ABC):
    """Abstract base class for a single decoding strategy."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this decoder (e.g. 'base64', 'hex')."""

    @abstractmethod
    def detect(self, value: str) -> bool:
        """Return True if this decoder should be applied to *value*."""

    @abstractmethod
    def decode(self, value: str) -> str | None:
        """Decode *value*. Returns the decoded string or None on failure."""


# ---------------------------------------------------------------------------
# Base64 decoder
# ---------------------------------------------------------------------------

_B64_STANDARD_RE = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")
_B64_URLSAFE_RE = re.compile(r"^[A-Za-z0-9\-_]{8,}={0,2}$")
_PRINTABLE_RE = re.compile(r"^[\x09\x0a\x0d\x20-\x7e]+$")


def _is_printable_ascii(s: str) -> bool:
    """Return True if *s* contains only printable ASCII characters (tab, LF, CR, 0x20-0x7E)."""
    return bool(_PRINTABLE_RE.match(s))


class Base64Decoder(BaseDecoder):
    """Decode standard and URL-safe Base64."""

    @property
    def name(self) -> str:
        return "base64"

    def detect(self, value: str) -> bool:
        stripped = value.strip()
        if len(stripped) < 8:
            return False
        return bool(_B64_STANDARD_RE.match(stripped)) or bool(_B64_URLSAFE_RE.match(stripped))

    def decode(self, value: str) -> str | None:
        stripped = value.strip()
        # Pad to multiple of 4 if needed
        padded = stripped + "=" * ((4 - len(stripped) % 4) % 4)
        # Try standard base64 first
        for variant in (padded, padded.replace("-", "+").replace("_", "/")):
            try:
                raw = base64.b64decode(variant)
                text = raw.decode("utf-8")
                if _is_printable_ascii(text) and text != value:
                    return text
            except Exception:
                pass
        return None


# ---------------------------------------------------------------------------
# Hex decoder
# ---------------------------------------------------------------------------

_HEX_ESCAPE_RE = re.compile(r"^(?:\\x[0-9a-fA-F]{2})+$")
_HEX_0X_RE = re.compile(r"^0x([0-9a-fA-F]+)$")
_HEX_PLAIN_RE = re.compile(r"^[0-9a-fA-F]+$")


class HexDecoder(BaseDecoder):
    """Decode hex-encoded strings in escape, 0x-prefix, or plain forms."""

    @property
    def name(self) -> str:
        return "hex"

    def detect(self, value: str) -> bool:
        stripped = value.strip()
        if _HEX_ESCAPE_RE.match(stripped):
            return True
        if _HEX_0X_RE.match(stripped):
            return True
        # Plain hex: minimum 6 chars, even length, and result must be ASCII
        if len(stripped) >= 6 and len(stripped) % 2 == 0 and _HEX_PLAIN_RE.match(stripped):
            try:
                raw = bytes.fromhex(stripped)
                text = raw.decode("utf-8")
                return _is_printable_ascii(text) and text != stripped
            except Exception:
                return False
        return False

    def decode(self, value: str) -> str | None:
        stripped = value.strip()
        try:
            # \x41\x42 escape format
            if _HEX_ESCAPE_RE.match(stripped):
                # Strip \x prefixes and parse
                hex_bytes = bytes.fromhex(stripped.replace("\\x", ""))
                text = hex_bytes.decode("utf-8")
                return text if _is_printable_ascii(text) else None

            # 0x prefix format
            m = _HEX_0X_RE.match(stripped)
            if m:
                hex_str = m.group(1)
                if len(hex_str) % 2 != 0:
                    hex_str = "0" + hex_str
                hex_bytes = bytes.fromhex(hex_str)
                text = hex_bytes.decode("utf-8")
                return text if _is_printable_ascii(text) else None

            # Plain hex
            if _HEX_PLAIN_RE.match(stripped) and len(stripped) >= 6 and len(stripped) % 2 == 0:
                raw = bytes.fromhex(stripped)
                text = raw.decode("utf-8")
                if _is_printable_ascii(text) and text != stripped:
                    return text

        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# URL decoder
# ---------------------------------------------------------------------------

_PCT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


class URLDecoder(BaseDecoder):
    """Decode URL-percent-encoded strings, including double-encoded forms."""

    @property
    def name(self) -> str:
        return "url"

    def detect(self, value: str) -> bool:
        return bool(_PCT_ENCODED_RE.search(value))

    def decode(self, value: str) -> str | None:
        try:
            decoded = urllib.parse.unquote(value)
            if decoded == value:
                return None
            # Detect double-encoding: %252F → %2F → /
            if _PCT_ENCODED_RE.search(decoded):
                second = urllib.parse.unquote(decoded)
                if second != decoded:
                    return second
            return decoded
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Unicode escape decoder
# ---------------------------------------------------------------------------

_UNICODE_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}")
_HTML_ENTITY_DEC_RE = re.compile(r"&#\d+;")
_HTML_ENTITY_HEX_RE = re.compile(r"&#x[0-9a-fA-F]+;")


class UnicodeEscapeDecoder(BaseDecoder):
    """Decode \\uXXXX / \\UXXXXXXXX escape sequences and HTML character entities."""

    @property
    def name(self) -> str:
        return "unicode_escape"

    def detect(self, value: str) -> bool:
        if _UNICODE_ESCAPE_RE.search(value):
            return True
        if _HTML_ENTITY_DEC_RE.search(value) or _HTML_ENTITY_HEX_RE.search(value):
            return True
        return False

    def decode(self, value: str) -> str | None:
        try:
            # HTML entities first
            if _HTML_ENTITY_DEC_RE.search(value) or _HTML_ENTITY_HEX_RE.search(value):
                decoded = html.unescape(value)
                if decoded != value:
                    return decoded

            # \u / \U escape sequences
            if _UNICODE_ESCAPE_RE.search(value):
                decoded = value.encode("raw_unicode_escape").decode("unicode_escape")
                if decoded != value and _is_printable_ascii(decoded):
                    return decoded
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# ROT13 decoder
# ---------------------------------------------------------------------------

# Patterns that indicate a decoded value is semantically suspicious —
# not just any slash, but known dangerous paths or execution patterns.
_SUSPICIOUS_PATTERNS = [
    re.compile(r"https?://"),                  # URL
    re.compile(r"ftp://"),                     # FTP URL
    re.compile(r"\.\./"),                      # directory traversal
    re.compile(r"^[A-Za-z]:\\"),              # Windows path
    re.compile(r"/(?:bin|etc|tmp|usr|var|home|root|proc|dev|sys)/"),  # known Unix dirs
    re.compile(r"cmd\.exe|powershell", re.I), # Windows command executors
    re.compile(r"eval\(|exec\(|system\("),    # code execution
    re.compile(r"/etc/passwd|/etc/shadow|/etc/hosts"),  # specific sensitive files
]


def _contains_suspicious_patterns(value: str) -> bool:
    return any(p.search(value) for p in _SUSPICIOUS_PATTERNS)


class ROT13Decoder(BaseDecoder):
    """Decode ROT13-encoded strings — only flags if decoded form looks suspicious."""

    @property
    def name(self) -> str:
        return "rot13"

    def detect(self, value: str) -> bool:
        # Only trigger if the original does NOT look suspicious but decoded does
        if _contains_suspicious_patterns(value):
            return False
        decoded = codecs.decode(value, "rot_13")
        return _contains_suspicious_patterns(decoded)

    def decode(self, value: str) -> str | None:
        decoded = codecs.decode(value, "rot_13")
        if decoded != value:
            return decoded
        return None


# ---------------------------------------------------------------------------
# Reverse string decoder
# ---------------------------------------------------------------------------


class ReverseStringDecoder(BaseDecoder):
    """Decode reversed strings — only flags if reversed form looks suspicious."""

    @property
    def name(self) -> str:
        return "reverse"

    def detect(self, value: str) -> bool:
        # Only flag if original is not suspicious but reversed is
        if _contains_suspicious_patterns(value):
            return False
        reversed_val = value[::-1]
        return _contains_suspicious_patterns(reversed_val)

    def decode(self, value: str) -> str | None:
        reversed_val = value[::-1]
        if reversed_val != value:
            return reversed_val
        return None


# ---------------------------------------------------------------------------
# Deobfuscation pipeline
# ---------------------------------------------------------------------------

_DEFAULT_DECODERS: list[BaseDecoder] = [
    Base64Decoder(),
    HexDecoder(),
    URLDecoder(),
    UnicodeEscapeDecoder(),
    ROT13Decoder(),
    ReverseStringDecoder(),
]


class DeobfuscationPipeline:
    """Run a value through all registered decoders, recursively up to *max_depth*.

    Collects all unique decoded variants across all decoders. The list
    returned by :meth:`decode` always starts with the *original* value at
    depth 0 (so callers can always check every variant, including the raw).

    Args:
        decoders: List of :class:`BaseDecoder` instances.  Defaults to the
                  standard set (Base64, Hex, URL, Unicode, ROT13, Reverse).
        max_depth: Maximum recursive decode depth.  Prevents infinite loops
                   in pathological multi-layer encoding schemes.
    """

    def __init__(
        self,
        decoders: list[BaseDecoder] | None = None,
        max_depth: int = 5,
    ) -> None:
        self._decoders = decoders if decoders is not None else list(_DEFAULT_DECODERS)
        self._max_depth = max_depth

    def decode(self, value: str) -> list[DecodedVariant]:
        """Return all decoded variants of *value*, including the original.

        The original value is always first at depth 0. Subsequent entries
        represent decoded variants at increasing depths, with encoding chains
        tracking the full decode path.

        Args:
            value: The string value to decode.

        Returns:
            List of :class:`DecodedVariant` starting with the original.
        """
        original = DecodedVariant(value=value, encoding="original", depth=0, chain=[])
        seen_values: set[str] = {value}
        variants: list[DecodedVariant] = [original]

        self._recurse(value, depth=0, chain=[], seen=seen_values, variants=variants)
        return variants

    def _recurse(
        self,
        value: str,
        depth: int,
        chain: list[str],
        seen: set[str],
        variants: list[DecodedVariant],
    ) -> None:
        if depth >= self._max_depth:
            return

        for decoder in self._decoders:
            if not decoder.detect(value):
                continue
            decoded = decoder.decode(value)
            if decoded is None or decoded in seen:
                continue

            seen.add(decoded)
            new_chain = chain + [decoder.name]
            variant = DecodedVariant(
                value=decoded,
                encoding=decoder.name,
                depth=depth + 1,
                chain=new_chain,
            )
            variants.append(variant)
            # Recurse on the decoded value to detect multi-layer encoding
            self._recurse(decoded, depth + 1, new_chain, seen, variants)
