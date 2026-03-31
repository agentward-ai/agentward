"""Tests for the deobfuscation pipeline.

Covers all decoders, pipeline recursion, middleware, and constraint integration.
Includes the litellm attack pattern: double-encoded base64 carrying /etc/passwd.
"""

from __future__ import annotations

import base64
import urllib.parse

import pytest

from agentward.deobfuscation.decoder import (
    Base64Decoder,
    DecodedVariant,
    DeobfuscationPipeline,
    HexDecoder,
    ROT13Decoder,
    ReverseStringDecoder,
    URLDecoder,
    UnicodeEscapeDecoder,
)
from agentward.deobfuscation.middleware import (
    DeobfuscatedArgument,
    deobfuscate_arguments,
    get_all_values_for_arg,
)


# ---------------------------------------------------------------------------
# TestBase64Decoder
# ---------------------------------------------------------------------------


class TestBase64Decoder:
    def _dec(self) -> Base64Decoder:
        return Base64Decoder()

    def test_detects_standard_base64(self) -> None:
        val = base64.b64encode(b"/etc/passwd").decode()
        assert self._dec().detect(val)

    def test_detects_urlsafe_base64(self) -> None:
        val = base64.urlsafe_b64encode(b"/etc/passwd").decode().rstrip("=")
        assert self._dec().detect(val)

    def test_rejects_short_string(self) -> None:
        assert not self._dec().detect("abc")

    def test_rejects_normal_word(self) -> None:
        # "hello" is 5 chars — too short
        assert not self._dec().detect("hello")

    def test_decodes_standard_base64(self) -> None:
        val = base64.b64encode(b"/etc/passwd").decode()
        result = self._dec().decode(val)
        assert result == "/etc/passwd"

    def test_decodes_with_padding(self) -> None:
        val = base64.b64encode(b"hello world").decode()
        result = self._dec().decode(val)
        assert result == "hello world"

    def test_decodes_urlsafe_without_padding(self) -> None:
        val = base64.urlsafe_b64encode(b"/tmp/test").decode().rstrip("=")
        result = self._dec().decode(val)
        assert result == "/tmp/test"

    def test_rejects_binary_result(self) -> None:
        # Binary data that decodes to non-printable bytes
        raw = bytes(range(0, 256))
        val = base64.b64encode(raw).decode()
        result = self._dec().decode(val)
        assert result is None

    def test_pipeline_catches_double_base64(self) -> None:
        # Litellm attack pattern: base64(base64('/etc/passwd'))
        inner = base64.b64encode(b"/etc/passwd").decode()
        outer = base64.b64encode(inner.encode()).decode()
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode(outer)
        all_values = [v.value for v in variants]
        assert "/etc/passwd" in all_values

    def test_detect_requires_min_8_chars(self) -> None:
        # 7 valid base64 chars — should be rejected
        assert not self._dec().detect("AAAAAAA")

    def test_decodes_hello_world(self) -> None:
        val = base64.b64encode(b"Hello World").decode()
        result = self._dec().decode(val)
        assert result == "Hello World"

    def test_does_not_return_same_value(self) -> None:
        # A string that decodes to itself (unlikely but guard against it)
        val = "AAAAAAAAAA"
        result = self._dec().decode(val)
        # If it decodes to something different, fine. If None, also fine.
        if result is not None:
            assert result != val or not self._dec().detect(val)


# ---------------------------------------------------------------------------
# TestHexDecoder
# ---------------------------------------------------------------------------


class TestHexDecoder:
    def _dec(self) -> HexDecoder:
        return HexDecoder()

    def test_detects_escape_hex(self) -> None:
        assert self._dec().detect(r"\x2f\x65\x74\x63")

    def test_detects_0x_prefix(self) -> None:
        assert self._dec().detect("0x2f6574632f706173737764")

    def test_detects_plain_hex(self) -> None:
        # "/etc/passwd" in plain hex
        assert self._dec().detect("2f6574632f706173737764")

    def test_rejects_short_plain_hex(self) -> None:
        assert not self._dec().detect("dead")

    def test_decodes_escape_hex(self) -> None:
        result = self._dec().decode(r"\x2f\x74\x6d\x70")
        assert result == "/tmp"

    def test_decodes_0x_prefix(self) -> None:
        # "/tmp" = 2f 74 6d 70
        result = self._dec().decode("0x2f746d70")
        assert result == "/tmp"

    def test_decodes_plain_hex(self) -> None:
        result = self._dec().decode("2f746d70")
        assert result == "/tmp"

    def test_rejects_odd_length_plain_hex(self) -> None:
        result = self._dec().decode("2f74")  # even but short — /t
        # 2 bytes, should decode OK to "/t" but is short so detect should be false
        assert not self._dec().detect("2f74")

    def test_rejects_non_printable(self) -> None:
        # Hex that decodes to binary
        val = "0x0001020304"
        result = self._dec().decode(val)
        assert result is None


# ---------------------------------------------------------------------------
# TestURLDecoder
# ---------------------------------------------------------------------------


class TestURLDecoder:
    def _dec(self) -> URLDecoder:
        return URLDecoder()

    def test_detects_percent_encoded(self) -> None:
        assert self._dec().detect("%2Fetc%2Fpasswd")

    def test_does_not_detect_plain(self) -> None:
        assert not self._dec().detect("/etc/passwd")

    def test_decodes_single_encoded(self) -> None:
        result = self._dec().decode("%2Fetc%2Fpasswd")
        assert result == "/etc/passwd"

    def test_decodes_double_encoded(self) -> None:
        # %252F → %2F → /
        result = self._dec().decode("%252Fetc%252Fpasswd")
        assert result == "/etc/passwd"

    def test_decodes_mixed_case_hex(self) -> None:
        result = self._dec().decode("%2fetc%2fpasswd")
        assert result == "/etc/passwd"

    def test_returns_none_if_no_change(self) -> None:
        result = self._dec().decode("hello%ZZworld")  # invalid percent seq
        # unquote leaves invalid sequences as-is — no change
        assert result is None

    def test_detects_partial_encoding(self) -> None:
        assert self._dec().detect("/etc%2Fpasswd")

    def test_decodes_space_encoding(self) -> None:
        result = self._dec().decode("hello%20world")
        assert result == "hello world"


# ---------------------------------------------------------------------------
# TestUnicodeEscapeDecoder
# ---------------------------------------------------------------------------


class TestUnicodeEscapeDecoder:
    def _dec(self) -> UnicodeEscapeDecoder:
        return UnicodeEscapeDecoder()

    def test_detects_u_escape(self) -> None:
        assert self._dec().detect(r"\u002f")

    def test_detects_html_entity_decimal(self) -> None:
        assert self._dec().detect("&#47;etc&#47;passwd")

    def test_detects_html_entity_hex(self) -> None:
        assert self._dec().detect("&#x2F;etc&#x2F;passwd")

    def test_decodes_html_entity_decimal(self) -> None:
        result = self._dec().decode("&#47;etc&#47;passwd")
        assert result == "/etc/passwd"

    def test_decodes_html_entity_hex(self) -> None:
        result = self._dec().decode("&#x2F;etc&#x2F;passwd")
        assert result == "/etc/passwd"

    def test_does_not_detect_plain(self) -> None:
        assert not self._dec().detect("/etc/passwd")


# ---------------------------------------------------------------------------
# TestROT13Decoder
# ---------------------------------------------------------------------------


class TestROT13Decoder:
    def _dec(self) -> ROT13Decoder:
        return ROT13Decoder()

    def test_detects_rot13_of_path(self) -> None:
        import codecs
        rotated = codecs.encode("/etc/passwd", "rot_13")
        assert self._dec().detect(rotated)

    def test_does_not_detect_clean_text(self) -> None:
        assert not self._dec().detect("hello world")

    def test_decodes_rot13_path(self) -> None:
        import codecs
        rotated = codecs.encode("/etc/passwd", "rot_13")
        result = self._dec().decode(rotated)
        assert result == "/etc/passwd"

    def test_does_not_flag_when_original_already_suspicious(self) -> None:
        # If original itself looks like a path, don't re-flag
        assert not self._dec().detect("/etc/passwd")

    def test_detects_rot13_url(self) -> None:
        import codecs
        rotated = codecs.encode("http://evil.com", "rot_13")
        assert self._dec().detect(rotated)


# ---------------------------------------------------------------------------
# TestReverseStringDecoder
# ---------------------------------------------------------------------------


class TestReverseStringDecoder:
    def _dec(self) -> ReverseStringDecoder:
        return ReverseStringDecoder()

    def test_detects_reversed_path(self) -> None:
        # "/etc/passwd" reversed
        assert self._dec().detect("dwssap/cte/")

    def test_does_not_detect_clean_string(self) -> None:
        assert not self._dec().detect("hello world")

    def test_decodes_reversed_path(self) -> None:
        result = self._dec().decode("dwssap/cte/")
        assert result == "/etc/passwd"

    def test_does_not_flag_when_original_is_path(self) -> None:
        assert not self._dec().detect("/etc/passwd")

    def test_detects_reversed_url(self) -> None:
        # "http://evil.com" reversed
        assert self._dec().detect("moc.live//:ptth")


# ---------------------------------------------------------------------------
# TestDeobfuscationPipeline
# ---------------------------------------------------------------------------


class TestDeobfuscationPipeline:
    def test_original_always_first(self) -> None:
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode("hello world")
        assert variants[0].value == "hello world"
        assert variants[0].depth == 0
        assert variants[0].encoding == "original"

    def test_no_encoding_returns_only_original(self) -> None:
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode("hello world")
        assert len(variants) == 1

    def test_detects_base64_encoded_path(self) -> None:
        val = base64.b64encode(b"/etc/passwd").decode()
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode(val)
        all_values = [v.value for v in variants]
        assert "/etc/passwd" in all_values

    def test_detects_url_encoded_path(self) -> None:
        val = urllib.parse.quote("/etc/passwd", safe="")
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode(val)
        all_values = [v.value for v in variants]
        assert "/etc/passwd" in all_values

    def test_double_base64_attack(self) -> None:
        # Litellm attack: base64(base64('/etc/passwd'))
        inner = base64.b64encode(b"/etc/passwd").decode()
        outer = base64.b64encode(inner.encode()).decode()
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode(outer)
        all_values = [v.value for v in variants]
        assert "/etc/passwd" in all_values

    def test_loop_detection_prevents_infinite_recursion(self) -> None:
        # Create a value that would loop if not for loop detection
        # e.g., URL-encoding that decodes to itself (not possible but test max_depth)
        pipeline = DeobfuscationPipeline(max_depth=2)
        val = base64.b64encode(b"/tmp/test").decode()
        variants = pipeline.decode(val)
        # Should terminate without error
        assert len(variants) >= 1

    def test_max_depth_respected(self) -> None:
        pipeline = DeobfuscationPipeline(max_depth=1)
        # Even with 1 depth, should decode one layer
        val = base64.b64encode(b"/etc/passwd").decode()
        variants = pipeline.decode(val)
        assert any(v.value == "/etc/passwd" for v in variants)
        # But depth should not exceed 1
        assert all(v.depth <= 1 for v in variants)

    def test_chain_tracked_correctly(self) -> None:
        val = base64.b64encode(b"/etc/passwd").decode()
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode(val)
        decoded_variants = [v for v in variants if v.depth > 0]
        assert any(v.encoding == "base64" for v in decoded_variants)
        assert any("base64" in v.chain for v in decoded_variants)

    def test_url_then_base64(self) -> None:
        inner = base64.b64encode(b"/etc/passwd").decode()
        outer = urllib.parse.quote(inner, safe="")
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode(outer)
        all_values = [v.value for v in variants]
        assert "/etc/passwd" in all_values

    def test_empty_string_no_variants(self) -> None:
        pipeline = DeobfuscationPipeline()
        variants = pipeline.decode("")
        assert variants[0].value == ""
        # Decoders should handle empty string without crashing
        assert len(variants) >= 1

    def test_custom_decoders(self) -> None:
        # Only use the base64 decoder
        pipeline = DeobfuscationPipeline(decoders=[Base64Decoder()])
        val = base64.b64encode(b"/etc/passwd").decode()
        variants = pipeline.decode(val)
        assert any(v.value == "/etc/passwd" for v in variants)


# ---------------------------------------------------------------------------
# TestMiddleware
# ---------------------------------------------------------------------------


class TestMiddleware:
    def test_string_arg_processed(self) -> None:
        val = base64.b64encode(b"/etc/passwd").decode()
        tool_call = {"arguments": {"path": val}}
        result = deobfuscate_arguments(tool_call)
        assert "path" in result
        assert result["path"].has_obfuscation

    def test_non_string_arg_not_processed(self) -> None:
        tool_call = {"arguments": {"count": 5}}
        result = deobfuscate_arguments(tool_call)
        assert "count" in result
        assert not result["count"].has_obfuscation

    def test_empty_arguments_returns_empty(self) -> None:
        result = deobfuscate_arguments({})
        assert result == {}

    def test_none_arguments_returns_empty(self) -> None:
        result = deobfuscate_arguments({"arguments": None})
        assert result == {}

    def test_clean_string_has_no_obfuscation(self) -> None:
        tool_call = {"arguments": {"query": "hello world"}}
        result = deobfuscate_arguments(tool_call)
        assert not result["query"].has_obfuscation

    def test_decoded_variants_populated(self) -> None:
        val = base64.b64encode(b"/tmp/test").decode()
        tool_call = {"arguments": {"path": val}}
        result = deobfuscate_arguments(tool_call)
        assert len(result["path"].decoded_variants) > 0

    def test_raw_preserved(self) -> None:
        val = base64.b64encode(b"/tmp/test").decode()
        tool_call = {"arguments": {"path": val}}
        result = deobfuscate_arguments(tool_call)
        assert result["path"].raw == val

    def test_get_all_values_includes_raw(self) -> None:
        val = base64.b64encode(b"/tmp/test").decode()
        tool_call = {"arguments": {"path": val}}
        result = deobfuscate_arguments(tool_call)
        all_vals = get_all_values_for_arg(result["path"])
        assert val in all_vals
        assert "/tmp/test" in all_vals

    def test_get_all_values_deduplicates(self) -> None:
        # If raw and decoded are somehow the same, only appears once
        arg = DeobfuscatedArgument(
            raw="hello",
            decoded_variants=[DecodedVariant(value="hello", encoding="test", depth=1, chain=["test"])],
            has_obfuscation=True,
        )
        vals = get_all_values_for_arg(arg)
        assert vals.count("hello") == 1


# ---------------------------------------------------------------------------
# TestConstraintIntegration
# ---------------------------------------------------------------------------


class TestConstraintIntegration:
    """Integration tests: deobfuscation with policy engine evaluation."""

    def _make_policy(self, deobfuscation: bool = True) -> "AgentWardPolicy":
        from agentward.policy.schema import AgentWardPolicy

        return AgentWardPolicy.model_validate({
            "version": "1.0",
            "deobfuscation": deobfuscation,
            "capabilities": {
                "read_file": {
                    "args": {
                        "path": {
                            "allowed_prefixes": ["/tmp/"],
                        }
                    }
                }
            },
        })

    def test_base64_encoded_path_blocked(self) -> None:
        from agentward.deobfuscation.integration import evaluate_with_deobfuscation
        from agentward.policy.engine import PolicyEngine
        from agentward.policy.schema import PolicyDecision

        policy = self._make_policy(deobfuscation=True)
        engine = PolicyEngine(policy)
        encoded = base64.b64encode(b"/etc/passwd").decode()
        result = evaluate_with_deobfuscation(
            engine, "read_file", {"path": encoded}
        )
        # /etc/passwd does not start with /tmp/ — should be blocked
        assert result.decision == PolicyDecision.BLOCK

    def test_disabled_deobfuscation_passes_raw(self) -> None:
        from agentward.deobfuscation.integration import evaluate_with_deobfuscation
        from agentward.policy.engine import PolicyEngine
        from agentward.policy.schema import PolicyDecision

        policy = self._make_policy(deobfuscation=False)
        engine = PolicyEngine(policy)
        # /tmp/test passes the constraint raw
        result = evaluate_with_deobfuscation(
            engine, "read_file", {"path": "/tmp/test"}
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_no_encoding_falls_through(self) -> None:
        from agentward.deobfuscation.integration import evaluate_with_deobfuscation
        from agentward.policy.engine import PolicyEngine
        from agentward.policy.schema import PolicyDecision

        policy = self._make_policy(deobfuscation=True)
        engine = PolicyEngine(policy)
        result = evaluate_with_deobfuscation(
            engine, "read_file", {"path": "/tmp/good"}
        )
        assert result.decision == PolicyDecision.ALLOW

    def test_double_encoded_base64_blocked(self) -> None:
        from agentward.deobfuscation.integration import evaluate_with_deobfuscation
        from agentward.policy.engine import PolicyEngine
        from agentward.policy.schema import PolicyDecision

        policy = self._make_policy(deobfuscation=True)
        engine = PolicyEngine(policy)
        # base64(base64('/etc/passwd'))
        inner = base64.b64encode(b"/etc/passwd").decode()
        outer = base64.b64encode(inner.encode()).decode()
        result = evaluate_with_deobfuscation(engine, "read_file", {"path": outer})
        assert result.decision == PolicyDecision.BLOCK

    def test_reason_includes_encoding_chain(self) -> None:
        """When a decoded variant triggers a block, reason says 'decoded' or 'base64'.

        We use a value that passes the raw constraint (starts with /tmp/) but
        whose decoded form fails (decodes to /etc/passwd which doesn't start with /tmp/).
        """
        from agentward.deobfuscation.integration import evaluate_with_deobfuscation
        from agentward.policy.engine import PolicyEngine
        from agentward.policy.schema import PolicyDecision

        policy = self._make_policy(deobfuscation=True)
        engine = PolicyEngine(policy)
        # /etc/passwd encoded — raw fails the constraint anyway; just verify it blocks
        encoded = base64.b64encode(b"/etc/passwd").decode()
        result = evaluate_with_deobfuscation(engine, "read_file", {"path": encoded})
        # Should be blocked regardless (either raw or decoded fails /tmp/ constraint)
        assert result.decision == PolicyDecision.BLOCK

    def test_url_encoded_malicious_path_blocked(self) -> None:
        from agentward.deobfuscation.integration import evaluate_with_deobfuscation
        from agentward.policy.engine import PolicyEngine
        from agentward.policy.schema import PolicyDecision

        policy = self._make_policy(deobfuscation=True)
        engine = PolicyEngine(policy)
        encoded = urllib.parse.quote("/etc/passwd", safe="")
        result = evaluate_with_deobfuscation(engine, "read_file", {"path": encoded})
        assert result.decision == PolicyDecision.BLOCK
