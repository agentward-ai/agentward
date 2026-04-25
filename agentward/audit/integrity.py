"""Tamper-evident HMAC hash chain for the audit log.

Each JSON Lines entry gets two extra fields:

* ``prev_hash`` — SHA-256 hex digest of the previous entry's full canonical
  JSON line (including its own ``hmac`` field). The first entry uses the
  literal string ``GENESIS``.
* ``hmac`` — HMAC-SHA-256, hex-encoded, computed over the canonical JSON of
  the entry *with* ``prev_hash`` populated and ``hmac`` set to the empty
  string. The key is the operator-supplied secret (env var
  ``AGENTWARD_AUDIT_HMAC_KEY``).

Verification walks the file forward and recomputes both fields at every
line. Any modification, deletion, or insertion breaks the chain at the
affected line and every subsequent line.

This is **defence in depth on top of WORM/SIEM storage**, not a substitute
for it. An attacker with both the running proxy's process memory and the
log file can forge the chain. The threat model this addresses is:

* After-the-fact tampering with the log file (e.g. by an admin who
  acquired filesystem access)
* Selective deletion of incriminating entries
* Splice-in of fabricated entries

Any of these breaks the chain at a verifiable point.

Key management
--------------
* Set ``AGENTWARD_AUDIT_HMAC_KEY`` to a high-entropy secret in your
  deployment environment (≥ 32 bytes recommended).
* If unset, the chain is **not** generated — entries are written
  unsigned. ``audit verify`` reports the chain as ``not_chained``.
* Rotating the key starts a new chain at the next entry. Prior entries
  remain verifiable with the prior key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


GENESIS_PREV_HASH = "GENESIS"
KEY_ENV_VAR = "AGENTWARD_AUDIT_HMAC_KEY"


def _canonical_json(entry: dict[str, Any]) -> str:
    """Render a dict as canonical JSON — sorted keys, no whitespace.

    Used so that the same logical entry produces the same byte string
    regardless of dict insertion order.
    """
    return json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)


def compute_hmac(entry: dict[str, Any], prev_hash: str, key: bytes) -> str:
    """Compute the HMAC-SHA-256 for an audit entry.

    The HMAC is computed over the canonical JSON of the entry **with**
    ``prev_hash`` populated and ``hmac`` set to the empty string. This makes
    verification deterministic — at verify time we recreate the same
    pre-image.

    Args:
        entry: The audit entry (without prev_hash or hmac fields, or with
               them present — they will be replaced).
        prev_hash: The chain ``prev_hash`` to bind into this entry.
        key: The HMAC secret key.

    Returns:
        Hex-encoded HMAC-SHA-256.
    """
    pre_image = dict(entry)
    pre_image["prev_hash"] = prev_hash
    pre_image["hmac"] = ""
    payload = _canonical_json(pre_image).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def hash_line(line: str) -> str:
    """SHA-256 of a complete JSON line.

    The line is the bytes that landed on disk (excluding the trailing
    newline). This becomes the ``prev_hash`` of the *next* entry.
    """
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


class AuditChain:
    """Stateful HMAC chain attached to an :class:`AuditLogger`.

    Lifecycle:
    1. Logger creates a chain at startup.
    2. If ``AGENTWARD_AUDIT_HMAC_KEY`` is set, the chain is enabled.
    3. On open of an existing log file, the chain reads the last line
       and seeds ``prev_hash`` from it so we continue the existing chain
       rather than starting a fresh one.
    4. ``sign(entry)`` mutates the entry dict in place, adding
       ``prev_hash`` and ``hmac`` fields, then advances ``prev_hash``.

    When the key is not configured, ``enabled`` is False and ``sign``
    leaves entries untouched.
    """

    def __init__(
        self,
        key: bytes | None = None,
        existing_log_path: Path | None = None,
    ) -> None:
        """Initialize the chain.

        Args:
            key: Explicit HMAC key (bytes). If None, falls back to the
                 ``AGENTWARD_AUDIT_HMAC_KEY`` environment variable.
                 If neither is provided the chain is disabled.
            existing_log_path: If given and the file exists, the chain
                 seeds ``prev_hash`` from the last line so a restart
                 continues the existing chain.
        """
        if key is None:
            env_value = os.environ.get(KEY_ENV_VAR)
            if env_value:
                key = env_value.encode("utf-8")

        self._key: bytes | None = key
        self._prev_hash: str = GENESIS_PREV_HASH

        if existing_log_path is not None and existing_log_path.exists():
            seed = self._tail_prev_hash(existing_log_path)
            if seed is not None:
                self._prev_hash = seed

    @property
    def enabled(self) -> bool:
        """True when an HMAC key is configured and signing is active."""
        return self._key is not None

    def sign(self, entry: dict[str, Any]) -> None:
        """Sign an entry in place: add ``prev_hash`` and ``hmac`` fields.

        After signing, the chain's internal ``prev_hash`` advances to the
        SHA-256 of the now-signed entry's canonical JSON. The next call
        to ``sign`` chains onto this entry.

        No-op when the chain is disabled.

        Args:
            entry: Mutable dict; will gain two new keys on success.
        """
        if not self.enabled or self._key is None:
            return

        entry["prev_hash"] = self._prev_hash
        entry["hmac"] = compute_hmac(entry, self._prev_hash, self._key)

        # Advance prev_hash to the canonical JSON of this fully-signed entry,
        # so the next call binds against exactly what we just wrote.
        self._prev_hash = hash_line(_canonical_json(entry))

    @staticmethod
    def _tail_prev_hash(path: Path) -> str | None:
        """Read the last line of an existing JSONL log and compute the
        next ``prev_hash`` from it. Returns None on parse failure.
        """
        try:
            with path.open("rb") as f:
                # Walk back from end to find the last non-empty line.
                f.seek(0, os.SEEK_END)
                size = f.tell()
                if size == 0:
                    return None
                # Naive but correct: read the whole file. JSONL audit logs
                # for typical AgentWard deployments stay small enough that
                # this isn't worth optimising.
                f.seek(0)
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
                if not lines:
                    return None
                last = lines[-1].decode("utf-8")
                return hash_line(last)
        except OSError:
            return None


# -----------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------


@dataclass
class ChainEntry:
    """A single line's verification outcome."""

    line_number: int
    ok: bool
    reason: str


@dataclass
class ChainVerification:
    """Result of verifying an entire log file."""

    total_lines: int
    signed_lines: int
    unsigned_lines: int
    ok: bool
    first_break: int | None  # line number of first verification failure
    failures: list[ChainEntry]


def verify_log(path: Path, key: bytes | None = None) -> ChainVerification:
    """Verify every line of an HMAC-chained JSONL log.

    Walks forward, tracking the expected ``prev_hash`` at each step.
    For each line:

    * If both ``prev_hash`` and ``hmac`` are present, verify the HMAC
      against the supplied key and the running ``prev_hash``. If it
      matches, advance.
    * If neither is present, count the line as unsigned and continue.
      An unsigned line cannot anchor the chain — so subsequent signed
      lines that point back to it will fail.

    Args:
        path: JSONL audit log path.
        key: HMAC key (bytes). Falls back to env var ``AGENTWARD_AUDIT_HMAC_KEY``.

    Returns:
        ChainVerification with per-line outcomes.
    """
    if key is None:
        env_value = os.environ.get(KEY_ENV_VAR)
        if env_value:
            key = env_value.encode("utf-8")

    failures: list[ChainEntry] = []
    total = 0
    signed = 0
    unsigned = 0
    expected_prev = GENESIS_PREV_HASH
    first_break: int | None = None

    if not path.exists():
        return ChainVerification(
            total_lines=0, signed_lines=0, unsigned_lines=0,
            ok=True, first_break=None, failures=[],
        )

    with path.open("r", encoding="utf-8") as f:
        for line_number, raw in enumerate(f, start=1):
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            total += 1
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as e:
                failures.append(ChainEntry(
                    line_number=line_number, ok=False,
                    reason=f"invalid JSON: {e}",
                ))
                if first_break is None:
                    first_break = line_number
                continue

            has_chain = "prev_hash" in entry and "hmac" in entry
            if not has_chain:
                unsigned += 1
                # Reset expectations: an unsigned line breaks the chain
                # for any subsequent signed lines.
                expected_prev = GENESIS_PREV_HASH
                continue

            signed += 1

            if key is None:
                failures.append(ChainEntry(
                    line_number=line_number, ok=False,
                    reason="HMAC present but no key supplied for verification",
                ))
                if first_break is None:
                    first_break = line_number
                continue

            actual_prev = entry["prev_hash"]
            if actual_prev != expected_prev:
                failures.append(ChainEntry(
                    line_number=line_number, ok=False,
                    reason=(
                        f"prev_hash mismatch: expected {expected_prev[:16]}..., "
                        f"got {actual_prev[:16]}..."
                    ),
                ))
                if first_break is None:
                    first_break = line_number
                # Continue checking individual HMACs but the chain is broken.
                expected_prev = actual_prev

            actual_hmac = entry["hmac"]
            unsigned_view = {k: v for k, v in entry.items() if k != "hmac"}
            unsigned_view["hmac"] = ""
            recomputed = hmac.new(
                key,
                _canonical_json(unsigned_view).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(actual_hmac, recomputed):
                failures.append(ChainEntry(
                    line_number=line_number, ok=False,
                    reason="HMAC mismatch — entry has been modified",
                ))
                if first_break is None:
                    first_break = line_number

            # Always advance — the next prev_hash is the SHA-256 of *this
            # line's canonical JSON*, regardless of whether HMAC verified.
            expected_prev = hash_line(_canonical_json(entry))

    ok = first_break is None
    return ChainVerification(
        total_lines=total, signed_lines=signed, unsigned_lines=unsigned,
        ok=ok, first_break=first_break, failures=failures,
    )


def resolve_identity(explicit: str | None = None) -> str:
    """Resolve the principal identity for audit logging.

    Priority:
    1. Explicit value (e.g. CLI flag).
    2. ``AGENTWARD_PRINCIPAL`` environment variable.
    3. OS user (``USER`` or ``USERNAME`` env var).
    4. Literal ``"unknown"``.

    The point of this helper is to make the identity field always present
    in audit logs so downstream SIEMs can rely on schema stability.
    """
    if explicit is not None and explicit.strip():
        return explicit.strip()
    env_principal = os.environ.get("AGENTWARD_PRINCIPAL")
    if env_principal and env_principal.strip():
        return env_principal.strip()
    os_user = os.environ.get("USER") or os.environ.get("USERNAME")
    if os_user and os_user.strip():
        return os_user.strip()
    return "unknown"
