#!/usr/bin/env python3
"""Seed a signed audit log for the FlowTraders demo.

Writes 8 deterministic HMAC-signed JSONL entries to
``/tmp/agentward-comply-demo/audit.jsonl``. The HMAC key is read from
the ``AGENTWARD_AUDIT_HMAC_KEY`` environment variable.

The 8 entries simulate a morning workflow performed by an AI research
assistant -- not by the firm's trading engine. AgentWard sits in the
AI-agent path; it never touches the trading hot path.

The keystone event in the timeline is line 5: the assistant attempted
to call ``append_note`` with a path *outside the configured research
scope* (``/etc/cron.d/exfil.sh``). AgentWard's policy attaches a
``must_start_with`` capability constraint to ``append_note``'s ``path``
argument. The constraint refused the call.

This is the canonical capability-scoping story:

  * The agent *should* be allowed to write -- writing notebooks is its
    job. Action-level permissions allow ``append_note`` in general.
  * But only within scope -- the ``must_start_with`` constraint pins
    every ``path`` argument to ``/Users/research/notebooks/``.
  * Even a prompt-injected agent cannot escape the scope, because the
    constraint is enforced *outside* the LLM's context window.

Field shape matches the production ``AuditLogger`` exactly:
``timestamp``, ``event``, ``tool``, ``arguments``, ``decision``,
``reason``, ``skill``, ``resource``, ``principal``, plus the HMAC chain
fields ``prev_hash`` / ``hmac``. All reason strings use plain ASCII so
the on-disk JSON is human-readable without ``\\u2014`` escapes.

Run from the repo root with the venv active::

    AGENTWARD_AUDIT_HMAC_KEY=flowtraders-demo-hmac-key-2026 \
        python3 scripts/seed-demo-audit-log.py

The output is deterministic given a fixed key -- useful for rehearsing
the Evidence Pack demo and for unit-testing tamper detection on real
fixture data.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Path-prefix that the policy's must_start_with capability constraint pins
# every append_note path argument to. The keystone BLOCK on line 5 is the
# agent attempting to write *outside* this prefix.
SCOPE_PREFIX = "/Users/research/notebooks/"


def main() -> int:
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

    base = datetime(2026, 4, 25, 8, 30, 0, tzinfo=UTC)
    principal = "research-assistant-v1"

    # 8 entries -- a morning workflow performed by an AI research
    # assistant. Read-only / reporting actions, two gated writes, plus
    # the keystone BLOCK on line 5: an attempt to write outside the
    # configured research scope, refused by a path-prefix capability
    # constraint.
    events: list[dict[str, object]] = [
        {
            "tool": "list_symbols",
            "skill": "market-data-feed",
            "resource": "feed",
            "arguments": {},
            "decision": "ALLOW",
            "reason": "Action 'read' on resource 'feed' is allowed for skill 'market-data-feed'.",
        },
        {
            "tool": "read_positions",
            "skill": "trading-engine",
            "resource": "order",
            "arguments": {},
            "decision": "ALLOW",
            "reason": "Action 'read' on resource 'order' is allowed for skill 'trading-engine'.",
        },
        {
            "tool": "read_notebook",
            "skill": "research-notebook",
            "resource": "file",
            "arguments": {"path": SCOPE_PREFIX + "momentum-strategy.ipynb"},
            "decision": "ALLOW",
            "reason": "Action 'read' on resource 'file' is allowed for skill 'research-notebook'.",
        },
        {
            "tool": "append_note",
            "skill": "research-notebook",
            "resource": "file",
            "arguments": {
                "path": SCOPE_PREFIX + "morning-brief.md",
                "content": "<redacted>",
            },
            "decision": "APPROVE",
            "reason": "Tool 'append_note' requires human approval before execution (write_file).",
        },
        # ---- KEYSTONE BLOCK (line 5) ------------------------------------
        # The AI assistant attempted to append a note *outside* the
        # configured research scope -- a path-prefix capability
        # constraint refused the call. The reason string is the exact
        # format AgentWard's capability engine produces.
        {
            "tool": "append_note",
            "skill": "research-notebook",
            "resource": "file",
            "arguments": {
                "path": "/etc/cron.d/exfil.sh",
                "content": "<redacted>",
            },
            "decision": "BLOCK",
            "reason": (
                f"BLOCKED [must_start_with]: Argument 'path' value "
                f"'/etc/cron.d/exfil.sh' must start with one of "
                f"['{SCOPE_PREFIX}']."
            ),
        },
        # -----------------------------------------------------------------
        {
            "tool": "snapshot_book",
            "skill": "market-data-feed",
            "resource": "feed",
            "arguments": {"symbol": "ES"},
            "decision": "ALLOW",
            "reason": "Action 'read' on resource 'feed' is allowed for skill 'market-data-feed'.",
        },
        {
            "tool": "read_positions",
            "skill": "trading-engine",
            "resource": "order",
            "arguments": {},
            "decision": "ALLOW",
            "reason": "Action 'read' on resource 'order' is allowed for skill 'trading-engine'.",
        },
        {
            "tool": "append_note",
            "skill": "research-notebook",
            "resource": "file",
            "arguments": {
                "path": SCOPE_PREFIX + "eod-summary.md",
                "content": "<redacted>",
            },
            "decision": "APPROVE",
            "reason": "Tool 'append_note' requires human approval before execution (write_file).",
        },
    ]

    chain = AuditChain(key=key_env.encode("utf-8"))
    with out.open("w", encoding="utf-8") as f:
        for i, event_data in enumerate(events):
            entry: dict[str, object] = {
                "timestamp": (
                    base + timedelta(minutes=i * 3)
                ).isoformat(timespec="seconds"),
                "event": "tool_call",
                "tool": event_data["tool"],
                "arguments": event_data["arguments"],
                "decision": event_data["decision"],
                "reason": event_data["reason"],
                "skill": event_data["skill"],
                "resource": event_data["resource"],
                "principal": principal,
            }
            chain.sign(entry)
            f.write(json.dumps(entry) + "\n")

    print(f"wrote {len(events)} signed entries to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
