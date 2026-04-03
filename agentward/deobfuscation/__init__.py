"""Deobfuscation pipeline for AgentWard.

Unwraps encoded/obfuscated argument values before policy constraint evaluation,
defending against prompt injection via base64, hex, URL, unicode, ROT13, and
reversed-string encoding of malicious paths or commands.
"""

from agentward.deobfuscation.decoder import (
    Base64Decoder,
    BaseDecoder,
    DecodedVariant,
    DeobfuscationPipeline,
    EntropyAnalyzer,
    HexDecoder,
    ROT13Decoder,
    ReverseStringDecoder,
    URLDecoder,
    UnicodeEscapeDecoder,
    XORDecoder,
    _shannon_entropy,
    _printable_ratio,
)
from agentward.deobfuscation.middleware import (
    DeobfuscatedArgument,
    deobfuscate_arguments,
    get_all_values_for_arg,
)

__all__ = [
    "BaseDecoder",
    "Base64Decoder",
    "HexDecoder",
    "URLDecoder",
    "UnicodeEscapeDecoder",
    "ROT13Decoder",
    "ReverseStringDecoder",
    "XORDecoder",
    "EntropyAnalyzer",
    "DecodedVariant",
    "DeobfuscationPipeline",
    "DeobfuscatedArgument",
    "deobfuscate_arguments",
    "get_all_values_for_arg",
    "_shannon_entropy",
    "_printable_ratio",
]
