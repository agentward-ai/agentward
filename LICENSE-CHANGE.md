# License Change — Apache 2.0 → Business Source License 1.1

**Effective:** 2026-04-24
**Affects:** All commits from this date forward
**Reverts to:** Apache License 2.0 on **2028-04-24** (automatically, for every version)

---

## What changed

AgentWard's license has changed from **Apache License 2.0** to the **Business Source License 1.1 (BUSL 1.1)** with a Change Date of 2028-04-24 and a Change License of Apache 2.0.

Concretely, this means:

- **Existing commits stay Apache 2.0.** Anyone who has already cloned the repository, downloaded a release, or installed the package keeps Apache 2.0 rights to that exact code in perpetuity. The relicense applies only to commits authored after 2026-04-24.
- **New commits and releases are BUSL 1.1.** Source remains public. You can read it, fork it, build on it, modify it, and redistribute your modifications.
- **On 2028-04-24, every version published under BUSL 1.1 automatically converts to Apache 2.0.** This is built into the license itself — it is not a future promise that requires our cooperation.

---

## What you can do under BUSL 1.1

✅ **Use AgentWard for any internal purpose, free of charge.**
Run it inside your organization, on your infrastructure, against your AI agents. No commercial restriction.

✅ **Embed AgentWard inside your own products** — provided your product is not a hosted or managed offering that competes with OpenSafe Inc.'s paid version of AgentWard.

✅ **Modify AgentWard, fork it, contribute back.**
The full source remains public. Pull requests, security disclosures, and feature requests are welcome.

✅ **Use AgentWard for evaluation, research, security review, and academic work.** Without restriction.

## What you can't do under BUSL 1.1

❌ **Offer AgentWard to third parties as a hosted or embedded service that competes with OpenSafe Inc.'s commercial offering.**

In plain language: you can't take AgentWard and resell it as "Managed AgentWard" or bundle its core functionality (policy enforcement, runtime proxy, compliance evaluation) into a competing commercial product without a separate commercial license from OpenSafe Inc.

If you need to do that, [contact us](mailto:aditya@agentward.ai) — we offer commercial licenses.

---

## Why we made this change

AgentWard ships meaningful functionality — runtime policy enforcement, capability-pair chain analysis, multi-framework compliance evaluation (HIPAA, GDPR, SOX, PCI-DSS, DORA, MiFID II), data classification, approval workflows. Maintaining it well is a multi-year commitment.

Apache 2.0 allows any commercial vendor to take the entire codebase, host it as a managed service, and compete directly without contributing back. We've watched several recent precedents (Elastic vs AWS, MongoDB vs hyperscalers, HashiCorp vs Terraform-as-a-service vendors) and concluded the same competitive dynamics apply here.

BUSL 1.1 closes the "AWS hosting" loophole specifically. It does not restrict the developers, security teams, researchers, or enterprises actually using AgentWard. The change is targeted at one scenario: a commercial vendor taking the work and reselling it.

The 2-year Change Date is deliberately short. We commit, in the license itself, to releasing every version back to Apache 2.0 within two years — much faster than the 4-year industry norm (HashiCorp, MariaDB, Sentry).

---

## FAQ

**Is this still open-source?**
No, technically. BUSL 1.1 is *source-available*, not open-source per the OSI definition. We will accurately call AgentWard "source-available" going forward. The source is public, modification is allowed, redistribution is allowed for non-competing use — but the OSI bar specifically requires unrestricted commercial use, which BUSL does not grant.

**Can I keep using the Apache 2.0 version?**
Yes. Every commit prior to 2026-04-24 remains under Apache 2.0 forever. You can pin to that version, fork it, and continue using it on Apache 2.0 terms. You will not get our future updates under that license — but the existing functionality is yours, perpetually.

**What counts as a "competitive offering"?**
The license defines this in detail (see the LICENSE file). The short version: a paid product or managed service that significantly overlaps with OpenSafe Inc.'s paid offerings of AgentWard. Internal use inside any organization — including for-profit organizations — is explicitly *not* competitive. Embedding AgentWard inside your product is fine as long as your product isn't itself a paid competitor to AgentWard.

**Will the trademark also change?**
No. "AgentWard" remains the project name. OpenSafe Inc. holds the trademark.

**What if I'm a current contributor?**
Your past contributions remain under Apache 2.0 (we cannot retroactively relicense them, and we don't want to). Future contributions to this repository will be under BUSL 1.1 as part of the standard CLA. If you have questions about how this affects your past or future contributions, please open an issue.

**What if I'm an existing user with an active integration?**
Nothing breaks. Your right to use AgentWard for internal purposes — including inside a commercial product — is preserved. The only thing the license now blocks is reselling AgentWard's core functionality as a competing managed/hosted offering.

**How do I license commercial use that's not allowed by BUSL?**
Email aditya@agentward.ai. Commercial licenses are available for vendors who want to embed or resell AgentWard in scenarios that exceed the BUSL grant.

---

## Contact

- **License & commercial inquiries:** aditya@agentward.ai
- **Issues, contributions, feature requests:** [github.com/agentward-ai/agentward](https://github.com/agentward-ai/agentward)
- **Website:** [agentward.ai](https://agentward.ai)
