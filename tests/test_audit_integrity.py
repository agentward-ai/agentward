"""Tests for the audit-log identity threading and HMAC chain.

Covers ``agentward/audit/integrity.py`` (chain primitives), the
``principal`` field injection in ``AuditLogger``, and ``audit-verify`` CLI
behavior end-to-end.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agentward.audit.integrity import (
    AuditChain,
    GENESIS_PREV_HASH,
    KEY_ENV_VAR,
    compute_hmac,
    hash_line,
    resolve_identity,
    verify_log,
)
from agentward.audit.logger import AuditLogger
from agentward.policy.engine import EvaluationResult
from agentward.policy.schema import PolicyDecision


# ---------------------------------------------------------------------------
# Identity resolution
# ---------------------------------------------------------------------------


class TestResolveIdentity:
    def test_explicit_value_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTWARD_PRINCIPAL", "env-user")
        monkeypatch.setenv("USER", "os-user")
        assert resolve_identity("explicit-user") == "explicit-user"

    def test_explicit_blank_falls_through(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AGENTWARD_PRINCIPAL", "env-user")
        assert resolve_identity("   ") == "env-user"

    def test_env_var_falls_through_to_os_user(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTWARD_PRINCIPAL", raising=False)
        monkeypatch.setenv("USER", "alice")
        assert resolve_identity(None) == "alice"

    def test_unknown_when_nothing_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AGENTWARD_PRINCIPAL", raising=False)
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("USERNAME", raising=False)
        assert resolve_identity(None) == "unknown"

    def test_strips_whitespace(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENTWARD_PRINCIPAL", "  alice@org  ")
        assert resolve_identity(None) == "alice@org"


# ---------------------------------------------------------------------------
# Chain primitives
# ---------------------------------------------------------------------------


class TestComputeHmac:
    def test_deterministic(self) -> None:
        entry = {"event": "tool_call", "tool": "read_file"}
        a = compute_hmac(entry, GENESIS_PREV_HASH, b"key")
        b = compute_hmac(entry, GENESIS_PREV_HASH, b"key")
        assert a == b

    def test_different_keys_different_hmacs(self) -> None:
        entry = {"event": "tool_call"}
        a = compute_hmac(entry, GENESIS_PREV_HASH, b"key-a")
        b = compute_hmac(entry, GENESIS_PREV_HASH, b"key-b")
        assert a != b

    def test_different_prev_hashes_different_hmacs(self) -> None:
        entry = {"event": "tool_call"}
        a = compute_hmac(entry, GENESIS_PREV_HASH, b"key")
        b = compute_hmac(entry, "abc123", b"key")
        assert a != b

    def test_hex_format(self) -> None:
        entry = {"event": "tool_call"}
        result = compute_hmac(entry, GENESIS_PREV_HASH, b"key")
        # SHA-256 hex digest = 64 chars
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


class TestHashLine:
    def test_deterministic(self) -> None:
        line = '{"event":"tool_call","tool":"read_file"}'
        assert hash_line(line) == hash_line(line)

    def test_distinct_for_distinct_inputs(self) -> None:
        assert hash_line("a") != hash_line("b")


# ---------------------------------------------------------------------------
# AuditChain stateful behavior
# ---------------------------------------------------------------------------


class TestAuditChain:
    def test_disabled_when_no_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(KEY_ENV_VAR, raising=False)
        chain = AuditChain()
        assert chain.enabled is False

    def test_enabled_with_env_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(KEY_ENV_VAR, "secret-key-value")
        chain = AuditChain()
        assert chain.enabled is True

    def test_enabled_with_explicit_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(KEY_ENV_VAR, raising=False)
        chain = AuditChain(key=b"explicit")
        assert chain.enabled is True

    def test_sign_is_noop_when_disabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(KEY_ENV_VAR, raising=False)
        chain = AuditChain()
        entry = {"event": "tool_call"}
        chain.sign(entry)
        assert "prev_hash" not in entry
        assert "hmac" not in entry

    def test_sign_adds_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(KEY_ENV_VAR, "key")
        chain = AuditChain()
        entry = {"event": "tool_call"}
        chain.sign(entry)
        assert "prev_hash" in entry
        assert "hmac" in entry
        assert entry["prev_hash"] == GENESIS_PREV_HASH
        assert len(entry["hmac"]) == 64

    def test_chain_advances(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(KEY_ENV_VAR, "key")
        chain = AuditChain()
        entry1 = {"event": "tool_call", "tool": "a"}
        entry2 = {"event": "tool_call", "tool": "b"}
        chain.sign(entry1)
        chain.sign(entry2)
        assert entry1["prev_hash"] == GENESIS_PREV_HASH
        # Second entry's prev_hash references entry1, not GENESIS
        assert entry2["prev_hash"] != GENESIS_PREV_HASH
        assert entry1["hmac"] != entry2["hmac"]

    def test_seeds_from_existing_log(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A second AuditChain on the same file continues the chain."""
        monkeypatch.setenv(KEY_ENV_VAR, "key")
        log = tmp_path / "audit.jsonl"

        # First chain: write one entry
        chain1 = AuditChain(existing_log_path=log)
        entry1 = {"event": "tool_call"}
        chain1.sign(entry1)
        log.write_text(json.dumps(entry1, sort_keys=True, separators=(",", ":")) + "\n")

        # Second chain seeded from the file should NOT use GENESIS
        chain2 = AuditChain(existing_log_path=log)
        entry2 = {"event": "tool_call"}
        chain2.sign(entry2)
        assert entry2["prev_hash"] != GENESIS_PREV_HASH


# ---------------------------------------------------------------------------
# verify_log end-to-end
# ---------------------------------------------------------------------------


def _write_chained_log(
    path: Path, entries: list[dict], key: bytes
) -> None:
    """Helper: write a list of entries through a real AuditChain."""
    chain = AuditChain(key=key)
    with path.open("w", encoding="utf-8") as f:
        for e in entries:
            chain.sign(e)
            # Match the canonical-JSON format the chain hashes against
            f.write(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n")


class TestVerifyLog:
    def test_clean_chain_verifies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        log = tmp_path / "audit.jsonl"
        _write_chained_log(
            log,
            [{"event": "tool_call", "n": i} for i in range(5)],
            b"key",
        )
        result = verify_log(log, key=b"key")
        assert result.ok is True
        assert result.signed_lines == 5
        assert result.unsigned_lines == 0
        assert result.first_break is None
        assert result.failures == []

    def test_modified_entry_breaks_chain(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "audit.jsonl"
        _write_chained_log(
            log,
            [{"event": "tool_call", "n": i} for i in range(5)],
            b"key",
        )
        # Tamper with the third line: change a value but keep length similar
        lines = log.read_text().splitlines()
        tampered_obj = json.loads(lines[2])
        tampered_obj["n"] = 99
        lines[2] = json.dumps(tampered_obj, sort_keys=True, separators=(",", ":"))
        log.write_text("\n".join(lines) + "\n")

        result = verify_log(log, key=b"key")
        assert result.ok is False
        assert result.first_break is not None
        # Either line 3 fails HMAC or line 4 fails prev_hash; either way break ≤ 4
        assert result.first_break <= 4

    def test_deleted_entry_breaks_chain(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "audit.jsonl"
        _write_chained_log(
            log,
            [{"event": "tool_call", "n": i} for i in range(5)],
            b"key",
        )
        # Delete line 3
        lines = log.read_text().splitlines()
        del lines[2]
        log.write_text("\n".join(lines) + "\n")

        result = verify_log(log, key=b"key")
        assert result.ok is False

    def test_unsigned_log_reports_zero_signed(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "audit.jsonl"
        # Write entries without signing
        with log.open("w", encoding="utf-8") as f:
            for i in range(3):
                f.write(json.dumps({"event": "tool_call", "n": i}) + "\n")

        result = verify_log(log, key=b"key")
        # Unsigned but nothing tampered → ok=True, signed=0
        assert result.ok is True
        assert result.signed_lines == 0
        assert result.unsigned_lines == 3

    def test_missing_file_returns_clean_empty(
        self, tmp_path: Path
    ) -> None:
        result = verify_log(tmp_path / "nonexistent.jsonl", key=b"key")
        assert result.total_lines == 0
        assert result.ok is True

    def test_signed_lines_without_key_fail(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "audit.jsonl"
        _write_chained_log(log, [{"event": "tool_call"}], b"key")
        result = verify_log(log, key=None)
        assert result.ok is False
        assert "no key supplied" in result.failures[0].reason

    def test_wrong_key_breaks_chain(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "audit.jsonl"
        _write_chained_log(log, [{"event": "tool_call"}], b"correct-key")
        result = verify_log(log, key=b"wrong-key")
        assert result.ok is False


# ---------------------------------------------------------------------------
# AuditLogger end-to-end with identity + chain
# ---------------------------------------------------------------------------


class TestAuditLoggerIdentity:
    def test_principal_in_every_entry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(KEY_ENV_VAR, raising=False)
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log, principal="alice@firm.example")
        try:
            logger.log_tool_call(
                tool_name="read_file",
                arguments={"path": "/tmp/x"},
                result=EvaluationResult(
                    decision=PolicyDecision.ALLOW,
                    reason="default allow",
                    skill=None,
                    resource=None,
                ),
            )
        finally:
            logger.close()

        line = log.read_text().strip()
        entry = json.loads(line)
        assert entry["principal"] == "alice@firm.example"
        assert entry["event"] == "tool_call"

    def test_principal_falls_back_to_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AGENTWARD_PRINCIPAL", "service-account-1")
        monkeypatch.delenv(KEY_ENV_VAR, raising=False)
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log)
        try:
            logger.log_shutdown("test")
        finally:
            logger.close()
        entry = json.loads(log.read_text().strip())
        assert entry["principal"] == "service-account-1"


class TestAuditLoggerChain:
    def test_unsigned_when_no_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(KEY_ENV_VAR, raising=False)
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log, principal="t")
        try:
            logger.log_shutdown("test")
        finally:
            logger.close()
        entry = json.loads(log.read_text().strip())
        assert "prev_hash" not in entry
        assert "hmac" not in entry

    def test_signed_when_key_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(KEY_ENV_VAR, "secret")
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log, principal="t")
        try:
            logger.log_shutdown("test")
        finally:
            logger.close()
        entry = json.loads(log.read_text().strip())
        assert "prev_hash" in entry
        assert "hmac" in entry
        assert entry["prev_hash"] == GENESIS_PREV_HASH

    def test_round_trip_verifies(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Write through the real logger, then verify through verify_log."""
        monkeypatch.setenv(KEY_ENV_VAR, "secret")
        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path=log, principal="t")
        try:
            for _ in range(3):
                logger.log_tool_call(
                    tool_name="read_file",
                    arguments={"path": "/tmp/x"},
                    result=EvaluationResult(
                        decision=PolicyDecision.ALLOW,
                        reason="ok",
                        skill=None,
                        resource=None,
                    ),
                )
            logger.log_shutdown("done")
        finally:
            logger.close()

        result = verify_log(log, key=b"secret")
        # Round-trip clean: writer formats are different from canonical JSON
        # (whitespace, key order) but verify_log re-parses to a dict and
        # canonicalises before checking — so the chain holds end-to-end.
        assert result.ok is True
        assert result.signed_lines == 4
        assert result.failures == []

    def test_round_trip_with_canonical_writer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Direct chain-and-write round trip in canonical JSON verifies clean."""
        monkeypatch.setenv(KEY_ENV_VAR, "secret")
        log = tmp_path / "audit.jsonl"
        chain = AuditChain()
        with log.open("w", encoding="utf-8") as f:
            for i in range(3):
                entry = {"event": "tool_call", "principal": "alice", "n": i}
                chain.sign(entry)
                f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")

        result = verify_log(log, key=b"secret")
        assert result.ok is True
        assert result.signed_lines == 3
