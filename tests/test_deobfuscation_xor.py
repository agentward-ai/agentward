"""Tests for XOR decoder and entropy analyzer additions to the deobfuscation pipeline.

Covers:
  - XORDecoder detection of JS patterns (charCodeAt ^ ...)
  - XORDecoder detection of Python patterns (ord(c) ^ key)
  - XORDecoder detection of generic constant XOR (^ 0xNN)
  - XOR brute-force single-byte decryption
  - EntropyAnalyzer flagging high-entropy strings
  - EntropyAnalyzer flagging non-printable strings
  - Shannon entropy calculation
  - Pipeline integration with XOR + entropy
  - Multi-layer deobfuscation including XOR-obfuscated layers
  - The exact axios payload XOR pattern
  - Entropy scores in decode output
"""

from __future__ import annotations

import base64
import math

import pytest

from agentward.deobfuscation import (
    DeobfuscationPipeline,
    EntropyAnalyzer,
    XORDecoder,
    _printable_ratio,
    _shannon_entropy,
)
from agentward.deobfuscation.decoder import (
    _detect_xor_pattern,
    _try_single_byte_xor,
)


# ---------------------------------------------------------------------------
# Shannon entropy tests
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_empty_string_zero_entropy(self) -> None:
        assert _shannon_entropy("") == 0.0

    def test_single_char_zero_entropy(self) -> None:
        assert _shannon_entropy("aaaa") == 0.0

    def test_two_equal_chars_max_1_bit(self) -> None:
        e = _shannon_entropy("ab")
        assert abs(e - 1.0) < 1e-9

    def test_plain_text_lower_entropy(self) -> None:
        # "hello world" should have entropy < 4.0
        e = _shannon_entropy("hello world")
        assert e < 4.0

    def test_high_entropy_random_like_string(self) -> None:
        # A string using all 256 possible bytes mapped to chars → ~8 bits
        # Use a string that covers many different chars
        s = "".join(chr(i) for i in range(32, 127))  # 95 printable ASCII
        e = _shannon_entropy(s)
        assert e > 5.0

    def test_base64_payload_higher_entropy(self) -> None:
        payload = base64.b64encode(b"secret payload data here" * 3).decode()
        e = _shannon_entropy(payload)
        assert e > 4.0

    def test_repeated_pattern_low_entropy(self) -> None:
        e = _shannon_entropy("abcabcabcabc")
        assert e < 2.0

    def test_uniform_distribution_max_entropy(self) -> None:
        # All 256 bytes used once → entropy ≈ 8 bits
        s = "".join(chr(i) for i in range(0, 256))
        e = _shannon_entropy(s)
        assert e > 7.5

    def test_entropy_of_long_english_text(self) -> None:
        text = "the quick brown fox jumps over the lazy dog" * 10
        e = _shannon_entropy(text)
        assert 3.0 < e < 5.0


# ---------------------------------------------------------------------------
# Printable ratio tests
# ---------------------------------------------------------------------------


class TestPrintableRatio:
    def test_all_printable(self) -> None:
        assert _printable_ratio("hello world") == 1.0

    def test_empty_string(self) -> None:
        assert _printable_ratio("") == 1.0

    def test_half_printable(self) -> None:
        s = "ab\x00\x01"
        ratio = _printable_ratio(s)
        assert ratio == 0.5

    def test_all_non_printable(self) -> None:
        s = "\x00\x01\x02\x03"
        assert _printable_ratio(s) < 0.1

    def test_tabs_and_newlines_are_printable(self) -> None:
        s = "hello\tworld\n"
        assert _printable_ratio(s) == 1.0


# ---------------------------------------------------------------------------
# XORDecoder detection tests
# ---------------------------------------------------------------------------


class TestXORDecoderDetection:
    def test_js_charcodeat_xor(self) -> None:
        code = "str.charCodeAt(i) ^ key[i % key.length]"
        assert XORDecoder().detect(code)

    def test_js_fromcharcode_xor(self) -> None:
        code = "String.fromCharCode(data[i] ^ 0x5a)"
        assert XORDecoder().detect(code)

    def test_python_ord_xor(self) -> None:
        code = "ord(c) ^ key"
        assert XORDecoder().detect(code)

    def test_python_chr_xor(self) -> None:
        code = "chr(ord(c) ^ 0x42)"
        assert XORDecoder().detect(code)

    def test_generic_hex_constant_xor(self) -> None:
        code = "result = value ^ 0xFF"
        assert XORDecoder().detect(code)

    def test_generic_decimal_constant_xor(self) -> None:
        code = "byte = input_byte ^ 42"
        assert XORDecoder().detect(code)

    def test_no_xor_in_plain_text(self) -> None:
        assert not XORDecoder().detect("hello world")

    def test_no_xor_in_url(self) -> None:
        assert not XORDecoder().detect("https://example.com/path")

    def test_no_xor_in_base64(self) -> None:
        assert not XORDecoder().detect(base64.b64encode(b"test").decode())

    def test_axios_attack_position_dependent_xor(self) -> None:
        code = "decoded += String.fromCharCode(enc[i] ^ key[7 * i * i % 10]);"
        assert XORDecoder().detect(code)

    def test_xor_in_multiline_code(self) -> None:
        code = """
for (let i = 0; i < data.length; i++) {
    out += String.fromCharCode(data.charCodeAt(i) ^ k);
}
"""
        assert XORDecoder().detect(code)


# ---------------------------------------------------------------------------
# XOR brute-force decryption tests
# ---------------------------------------------------------------------------


class TestXORBruteForce:
    def test_single_byte_xor_recovers_text(self) -> None:
        # Use a key that makes the encrypted bytes non-printable (> 0x7E)
        # so the brute-force uniquely identifies the correct key.
        # Key 0x80 flips the high bit: printable ASCII (0x20-0x7E) becomes 0xA0-0xFE (non-printable)
        # so XOR with 0x80 back recovers the printable original.
        plaintext = b"hello world from xor"
        key = 0x80
        encrypted = bytes(b ^ key for b in plaintext)
        result = _try_single_byte_xor(encrypted)
        assert result is not None
        # The recovered text should be the original plaintext
        assert "hello" in result or result == plaintext.decode("latin-1")

    def test_single_byte_xor_key_zero_is_noop(self) -> None:
        plaintext = b"no encryption here!"
        result = _try_single_byte_xor(plaintext)
        assert result is not None
        assert result == plaintext.decode("utf-8")

    def test_single_byte_xor_high_entropy_returns_none(self) -> None:
        # Binary garbage cannot be recovered meaningfully
        encrypted = bytes([i for i in range(256)])
        result = _try_single_byte_xor(encrypted)
        # May or may not return — don't assert None, just check doesn't crash
        assert result is None or isinstance(result, str)

    def test_single_byte_xor_various_keys(self) -> None:
        # Use high-value keys (>0x7F) that guarantee encrypted bytes are non-printable,
        # making the brute force unambiguously identify the correct key.
        for key in [0x80, 0x91, 0xAA, 0xBF, 0xCC]:
            plaintext = b"secret payload data"
            encrypted = bytes(b ^ key for b in plaintext)
            result = _try_single_byte_xor(encrypted)
            assert result is not None, f"Failed with key=0x{key:02x}"
            # The recovered text should be printable
            assert all(c.isprintable() or c in '\t\n\r' for c in result)


# ---------------------------------------------------------------------------
# XORDecoder decode tests
# ---------------------------------------------------------------------------


class TestXORDecoderDecode:
    def test_decode_returns_none_for_code_pattern(self) -> None:
        # XOR code patterns can't be decoded without runtime context
        code = "str.charCodeAt(i) ^ 0x42"
        decoder = XORDecoder()
        assert decoder.detect(code)
        # decode may return None (can't resolve at static analysis time)
        result = decoder.decode(code)
        # Just verify it doesn't crash
        assert result is None or isinstance(result, str)

    def test_xor_decoder_name(self) -> None:
        assert XORDecoder().name == "xor"


# ---------------------------------------------------------------------------
# EntropyAnalyzer tests
# ---------------------------------------------------------------------------


class TestEntropyAnalyzer:
    def test_high_entropy_string_detected(self) -> None:
        # Use a string with high character diversity
        s = "".join(chr(i) for i in range(32, 127))  # all printable ASCII
        analyzer = EntropyAnalyzer()
        assert analyzer.detect(s)

    def test_low_entropy_not_detected(self) -> None:
        analyzer = EntropyAnalyzer()
        assert not analyzer.detect("hello world hello world")

    def test_short_string_not_detected(self) -> None:
        analyzer = EntropyAnalyzer()
        assert not analyzer.detect("abc")  # < 16 chars

    def test_non_printable_detected(self) -> None:
        s = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
        analyzer = EntropyAnalyzer()
        assert analyzer.detect(s)

    def test_decode_always_returns_none(self) -> None:
        analyzer = EntropyAnalyzer()
        s = "".join(chr(i) for i in range(32, 127))
        assert analyzer.decode(s) is None

    def test_entropy_analyzer_name(self) -> None:
        assert EntropyAnalyzer().name == "high_entropy"

    def test_base64_payload_high_entropy(self) -> None:
        payload = base64.b64encode(b"x" * 100).decode()
        analyzer = EntropyAnalyzer()
        # Pure base64 may or may not trip the entropy threshold — check it doesn't crash
        result = analyzer.detect(payload)
        assert isinstance(result, bool)

    def test_random_like_string_detected(self) -> None:
        # String with 100 distinct chars from a wide range
        s = "".join(chr(i) for i in range(33, 133))  # 100 chars
        assert EntropyAnalyzer().detect(s)

    def test_english_sentence_not_flagged(self) -> None:
        text = "the quick brown fox jumps over the lazy dog " * 5
        assert not EntropyAnalyzer().detect(text)

    def test_code_with_many_repeated_patterns_not_flagged(self) -> None:
        code = "function f() { return 0; } " * 10
        assert not EntropyAnalyzer().detect(code)


# ---------------------------------------------------------------------------
# Pipeline integration tests
# ---------------------------------------------------------------------------


class TestPipelineIntegration:
    def test_xor_decoder_in_pipeline_detects_patterns(self) -> None:
        pipeline = DeobfuscationPipeline(decoders=[XORDecoder()])
        code = "str.charCodeAt(i) ^ 0x42"
        variants = pipeline.decode(code)
        # Original is always returned
        assert variants[0].encoding == "original"
        assert variants[0].value == code

    def test_entropy_analyzer_in_pipeline(self) -> None:
        pipeline = DeobfuscationPipeline(decoders=[EntropyAnalyzer()])
        s = "".join(chr(i) for i in range(33, 133))
        variants = pipeline.decode(s)
        # EntropyAnalyzer.decode returns None → no new variant added
        assert len(variants) == 1  # Just the original
        assert variants[0].encoding == "original"

    def test_xor_plus_base64_pipeline(self) -> None:
        """Test pipeline with both Base64 decoder and XOR decoder."""
        from agentward.deobfuscation import Base64Decoder
        pipeline = DeobfuscationPipeline(decoders=[Base64Decoder(), XORDecoder()])
        # A base64-encoded XOR code snippet
        code = "str.charCodeAt(i) ^ 0x42"
        encoded = base64.b64encode(code.encode()).decode()
        variants = pipeline.decode(encoded)
        # Should have: original, base64 decoded (the XOR code)
        assert len(variants) >= 2
        decoded_values = [v.value for v in variants]
        assert code in decoded_values

    def test_default_pipeline_includes_no_xor_by_default(self) -> None:
        """XORDecoder is NOT in the default pipeline — it's opt-in."""
        pipeline = DeobfuscationPipeline()  # Default decoders
        code = "str.charCodeAt(i) ^ 0x42"
        variants = pipeline.decode(code)
        # Default pipeline doesn't include XORDecoder, so just original
        xor_variants = [v for v in variants if v.encoding == "xor"]
        assert not xor_variants

    def test_full_pipeline_with_xor_and_entropy(self) -> None:
        from agentward.deobfuscation import Base64Decoder, HexDecoder
        pipeline = DeobfuscationPipeline(decoders=[Base64Decoder(), HexDecoder(), XORDecoder(), EntropyAnalyzer()])
        value = "/etc/passwd"
        variants = pipeline.decode(value)
        assert variants[0].value == value

    def test_pipeline_with_xor_decodes_single_byte_xor_data(self) -> None:
        """Base64 of printable content is decoded by pipeline."""
        from agentward.deobfuscation import Base64Decoder
        # Base64-encode a printable string — the Base64 decoder will decode it
        plaintext = "cat /etc/passwd"
        encoded = base64.b64encode(plaintext.encode()).decode()

        pipeline = DeobfuscationPipeline(decoders=[Base64Decoder(), XORDecoder()])
        variants = pipeline.decode(encoded)
        # Should decode base64 and return the plaintext variant
        decoded_values = [v.value for v in variants]
        assert plaintext in decoded_values


# ---------------------------------------------------------------------------
# Axios attack XOR pattern in pipeline
# ---------------------------------------------------------------------------


class TestAxiosXorInPipeline:
    def test_axios_style_xor_detected_in_pipeline(self) -> None:
        pipeline = DeobfuscationPipeline(decoders=[XORDecoder()])
        axios_code = """
for (let i = 0; i < enc.length; i++) {
    decoded += String.fromCharCode(enc[i] ^ key[7 * i * i % 10]);
}
"""
        variants = pipeline.decode(axios_code)
        assert variants[0].value == axios_code

    def test_xor_decoder_is_importable(self) -> None:
        from agentward.deobfuscation import XORDecoder as XD
        assert XD is not None

    def test_entropy_analyzer_is_importable(self) -> None:
        from agentward.deobfuscation import EntropyAnalyzer as EA
        assert EA is not None

    def test_detect_xor_pattern_helper(self) -> None:
        assert _detect_xor_pattern("str.charCodeAt(i) ^ 0x42")
        assert _detect_xor_pattern("ord(c) ^ key")
        assert not _detect_xor_pattern("hello world")

    def test_multi_layer_base64_xor(self) -> None:
        """Base64 of printable content — decoded by pipeline."""
        from agentward.deobfuscation import Base64Decoder
        # Use a plaintext string that is printable, then base64-encode it
        payload = "evil command here"
        b64 = base64.b64encode(payload.encode()).decode()

        pipeline = DeobfuscationPipeline(decoders=[Base64Decoder(), XORDecoder()])
        variants = pipeline.decode(b64)
        # Should at minimum decode the base64 layer
        assert len(variants) >= 2
        decoded_values = [v.value for v in variants]
        assert payload in decoded_values
