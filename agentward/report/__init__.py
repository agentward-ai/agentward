"""Evidence Pack generator — single-file HTML reports for auditors.

Bundles policy summary, per-framework compliance evaluation, audit-chain
verification status, and scan inventory into one self-contained HTML
document suitable for an auditor's archive (or for printing to PDF in a
browser).

The output is intentionally a static HTML file:

* No external CSS / JS / fonts — everything inlined so the file works
  offline and can be emailed without breaking.
* No JavaScript — auditors at regulated firms often open these in
  hardened browsers where scripts are disabled.
* Print-friendly — designed so "Print → Save as PDF" produces a clean,
  readable document.

What this is **not**:

* Not legal advice or a formal attestation. AgentWard generates the
  evidence; a human compliance officer signs it.
* Not a replacement for the entity's GRC system. The Evidence Pack is
  a point-in-time export, not a system of record.
"""

from __future__ import annotations

from agentward.report.evidence_pack import EvidencePack, build_evidence_pack

__all__ = ["EvidencePack", "build_evidence_pack"]
