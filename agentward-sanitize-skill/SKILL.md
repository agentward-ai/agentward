---
name: sanitize
description: Detect and redact PII from text files. Supports 15 categories including credit cards, SSNs, emails, API keys, addresses, and more — with zero dependencies.
version: "1.0.0"
metadata:
  openclaw:
    requires:
      bins:
        - python3
    emoji: "\U0001F6E1"
    homepage: https://github.com/agentward-ai/agentward
  files:
    - scripts/sanitize.py
---

# AgentWard Sanitize

Detect and redact personally identifiable information (PII) from text files.

## IMPORTANT — PII Safety Rules
- Do NOT read the input file directly. It may contain sensitive PII.
- ALWAYS use `--output FILE` to write sanitized output to a file.
- Only read the OUTPUT file, never the raw input.
- Only show the user the redacted output, never the raw input.
- `--json` and `--preview` are safe — they do NOT print raw PII values to stdout.
- The entity map (raw PII → placeholder mapping) is written to a separate sidecar file (`*.entity-map.json`) only when `--output` is used. Do NOT read the entity map file.

## What it does

Scans files for PII — credit cards, SSNs, emails, phone numbers, API keys, IP addresses, mailing addresses, dates of birth, passport numbers, driver's license numbers, bank routing numbers, medical license numbers, and insurance member IDs — and replaces each instance with a numbered placeholder like `[CREDIT_CARD_1]`.

## Usage

### Sanitize a file (RECOMMENDED — always use --output)
```bash
python scripts/sanitize.py patient-notes.txt --output clean.txt
```

### Preview mode (detect PII categories/offsets without showing raw values)
```bash
python scripts/sanitize.py notes.md --preview
```

### JSON output (safe — no raw PII in stdout)
```bash
python scripts/sanitize.py report.txt --json --output clean.txt
```

### Filter to specific categories
```bash
python scripts/sanitize.py log.txt --categories ssn,credit_card,email --output clean.txt
```

## Supported PII categories

See `references/SUPPORTED_PII.md` for the full list with detection methods and false positive mitigation.

| Category | Pattern type | Example |
|---|---|---|
| `credit_card` | Luhn-validated 13-19 digits | 4111 1111 1111 1111 |
| `ssn` | 3-2-4 digit groups | 123-45-6789 |
| `cvv` | Keyword-anchored 3-4 digits | CVV: 123 |
| `expiry_date` | Keyword-anchored MM/YY | expiry 01/30 |
| `api_key` | Provider prefix patterns | sk-abc..., ghp_..., AKIA... |
| `email` | Standard email format | user@example.com |
| `phone` | US/intl phone numbers | +1 (555) 123-4567 |
| `ip_address` | IPv4 addresses | 192.168.1.100 |
| `date_of_birth` | Keyword-anchored dates | DOB: 03/15/1985 |
| `passport` | Keyword-anchored alphanumeric | Passport: AB1234567 |
| `drivers_license` | Keyword-anchored alphanumeric | DL: D12345678 |
| `bank_routing` | Keyword-anchored 9 digits | routing: 021000021 |
| `address` | Street + city/state/zip | 742 Evergreen Terrace Dr, Springfield, IL 62704 |
| `medical_license` | Keyword-anchored license ID | License: CA-MD-8827341 |
| `insurance_id` | Keyword-anchored member/policy ID | Member ID: BCB-2847193 |

## Security and Privacy

- **All processing is local.** The script makes zero network calls. No data leaves your machine.
- **Zero dependencies.** Uses only Python standard library — no third-party packages to audit.
- **PII never reaches stdout.** The `--json` and `--preview` modes strip raw PII values from output. The entity map (containing raw PII to placeholder mappings) is only written to a sidecar file on disk when `--output` is used.
- **Designed for agent safety.** The skill instructions above tell the agent to never read the raw input file or the entity map file — only the sanitized output.

## Requirements

- Python 3.11+
- No external dependencies (stdlib only)

## About

Built by [AgentWard](https://agentward.ai) — the open-source permission control plane for AI agents.
