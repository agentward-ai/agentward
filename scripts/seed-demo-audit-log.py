#!/usr/bin/env python3
"""Seed a signed audit log for the FlowTraders demo.

Writes 8 deterministic HMAC-signed JSONL entries to
``/tmp/agentward-comply-demo/audit.jsonl``. The HMAC key is read from
the ``AGENTWARD_AUDIT_HMAC_KEY`` environment variable.

The 8 entries simulate a morning workflow performed by an AI research
assistant -- not by the firm's trading engine. AgentWard sits in the
AI-agent path; it never touches the trading hot path. The keystone
event in the timeline is line 5: the assistant tried to call
``submit_order`` on the trading skill and AgentWard blocked it,
because the policy explicitly denies write access on ``trading-engine``
to AI agents. Order submission is reserved for the algorithmic
trading runtime AgentWard does not proxy.

Run from the repo root with the venv active:

    AGENTWARD_AUDIT_HMAC_KEY=flowtraders-demo-hmac-key-2026 \
        python3 scripts/seed-demo-audit-log.py

The output is deterministic given a fixed key -- useful for rehearsing
the Evidence Pack demo and for unit-testing tamper detection on real
fixture data.

Note: all reason strings use plain ASCII (hyphens, not em-dashes) so
the on-disk JSON is human-readable without ``\\u2014`` escapes.
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

    # 8 entries -- a morning workflow performed by an AI research
    # assistant. Read-only / reporting actions, plus one BLOCK that
    # demonstrates AgentWard refusing to let the assistant cross into
    # the trading path. All reasons are plain ASCII to keep the on-disk
    # JSON readable without unicode escapes.
    base = datetime(2026, 4, 25, 8, 30, 0, tzinfo=UTC)
    actor = "research-assistant-v1"

    events: list[tuple[str, str, str, str]] = [
        # (skill, tool, decision, reason)
        (
            "market-data-feed", "list_symbols", "ALLOW",
            "Action 'read' on resource 'feed' is allowed for skill 'market-data-feed'.",
        ),
        (
            "trading-engine", "read_positions", "ALLOW",
            "Action 'read' on resource 'order' is allowed for skill 'trading-engine'.",
        ),
        (
            "research-notebook", "read_notebook", "ALLOW",
            "Action 'read' on resource 'file' is allowed for skill 'research-notebook'.",
        ),
        (
            "research-notebook", "append_note", "APPROVE",
            "Tool 'append_note' requires human approval before execution (write to file).",
        ),
        # ---- KEYSTONE BLOCK (line 5) ------------------------------------
        # The AI assistant attempted to submit an order via the trading
        # skill. The policy denies write access on trading-engine to AI
        # agents -- order submission is owned by the algorithmic trading
        # runtime, which AgentWard does not proxy. AgentWard kept the
        # agent out of the trading path.
        (
            "trading-engine", "submit_order", "BLOCK",
            "Action 'write' on resource 'order' is denied for skill 'trading-engine'. "
            "Tool 'submit_order' blocked.",
        ),
        # -------------------------------------------------------------------
        (
            "market-data-feed", "snapshot_book", "ALLOW",
            "Action 'read' on resource 'feed' is allowed for skill 'market-data-feed'.",
        ),
        (
            "trading-engine", "read_positions", "ALLOW",
            "Action 'read' on resource 'order' is allowed for skill 'trading-engine'.",
        ),
        (
            "research-notebook", "append_note", "APPROVE",
            "Tool 'append_note' requires human approval before execution (write to file).",
        ),
    ]

    chain = AuditChain(key=key_env.encode("utf-8"))
    with out.open("w", encoding="utf-8") as f:
        for i, (skill, tool, decision, reason) in enumerate(events):
            entry: dict[str, object] = {
                "ts": (base + timedelta(minutes=i * 3)).isoformat(timespec="seconds"),
                "event": "tool_call",
                "actor": actor,
                "skill": skill,
                "tool": tool,
                "decision": decision,
                "reason": reason,
            }
            chain.sign(entry)
            f.write(json.dumps(entry) + "\n")

    print(f"wrote {len(events)} signed entries to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
