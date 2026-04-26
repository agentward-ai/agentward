#!/usr/bin/env python3
"""Seed a signed audit log for the FlowTraders demo.

Writes an 8-entry HMAC-signed JSONL log to /tmp/agentward-comply-demo/
audit.jsonl representing a simulated trading-day morning. The HMAC key
is read from the AGENTWARD_AUDIT_HMAC_KEY environment variable.

Run from the repo root with the venv active:

    AGENTWARD_AUDIT_HMAC_KEY=flowtraders-demo-hmac-key-2026 \
        python3 scripts/seed-demo-audit-log.py

The output is deterministic given a fixed key — useful for rehearsing
the Evidence Pack demo and for unit-testing tamper detection on real
fixture data.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path


def main() -> int:
    # Defer the import so a missing AgentWard install fails with a
    # readable error rather than a stack trace.
    try:
        from agentward.audit.integrity import AuditChain
    except ImportError:
        sys.stderr.write(
            "agentward not importable. Activate the venv: "
            "`source .venv/bin/activate`.\n"
        )
        return 1

    key_env = os.environ.get("AGENTWARD_AUDIT_HMAC_KEY")
    if not key_env:
        sys.stderr.write(
            "AGENTWARD_AUDIT_HMAC_KEY is not set. Export it before running:\n"
            "    export AGENTWARD_AUDIT_HMAC_KEY=flowtraders-demo-hmac-key-2026\n"
        )
        return 1

    out_dir = Path("/tmp/agentward-comply-demo")
    out_dir.mkdir(exist_ok=True)
    out = out_dir / "audit.jsonl"

    # 8 entries — a representative trading-day morning slice.
    base = datetime(2026, 4, 25, 8, 30, 0, tzinfo=UTC)
    events: list[tuple[str, str, str]] = [
        ("market-data-feed",  "ALLOW",   "subscribe to ES/NQ futures"),
        ("trading-engine",    "ALLOW",   "read positions"),
        ("fix-gateway",       "APPROVE", "session-init to broker requires human approval"),
        ("trading-engine",    "ALLOW",   "submit BUY 100 ES limit"),
        ("trading-engine",    "BLOCK",   "size limit exceeded — 5000 ES rejected by capability constraint"),
        ("research-notebook", "ALLOW",   "read morning brief"),
        ("trading-engine",    "ALLOW",   "submit SELL 50 NQ limit"),
        ("fix-gateway",       "APPROVE", "session-close to broker requires human approval"),
    ]

    chain = AuditChain(key=key_env.encode("utf-8"))
    with out.open("w", encoding="utf-8") as f:
        for i, (skill, decision, reason) in enumerate(events):
            entry = {
                "ts": (base + timedelta(minutes=i * 3)).isoformat(timespec="seconds"),
                "event": "tool_call",
                "skill": skill,
                "decision": decision,
                "reason": reason,
                "actor": "trading-bot-1",
            }
            chain.sign(entry)
            f.write(json.dumps(entry) + "\n")

    print(f"wrote {len(events)} signed entries to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
