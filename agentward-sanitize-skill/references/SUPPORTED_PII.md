# Supported PII Categories

## Financial

| Category | Description | Detection method | Example |
|---|---|---|---|
| `credit_card` | Credit/debit card numbers (Visa, Mastercard, Amex, etc.) | Regex + Luhn checksum | `4111 1111 1111 1111` |
| `cvv` | Card verification value (keyword-anchored) | Regex | `CVV: 123` |
| `expiry_date` | Card expiration date (keyword-anchored) | Regex | `exp: 01/30` |
| `bank_routing` | US ABA bank routing number (keyword-anchored) | Regex | `routing: 021000021` |

## Government IDs

| Category | Description | Detection method | Example |
|---|---|---|---|
| `ssn` | US Social Security Number (validated area/group/serial) | Regex | `123-45-6789` |
| `passport` | Passport number (keyword-anchored) | Regex | `Passport: AB1234567` |
| `drivers_license` | Driver's license number (keyword-anchored) | Regex | `DL: D12345678` |

## Credentials

| Category | Description | Detection method | Example |
|---|---|---|---|
| `api_key` | API keys from known providers | Regex (prefix match) | `sk-abc...`, `ghp_...`, `AKIA...` |

Supported providers: OpenAI/Anthropic (`sk-`, including `sk-proj-*` and `sk-svcacct-*`), GitHub (`ghp_`), Slack (`xoxb-`, `xoxp-`), AWS (`AKIA`).

## Healthcare / Professional

| Category | Description | Detection method | Example |
|---|---|---|---|
| `medical_license` | State medical license numbers (keyword-anchored) | Regex | `License: CA-MD-8827341` |
| `insurance_id` | Insurance member/policy IDs (keyword-anchored) | Regex | `Member ID: BCB-2847193` |

Keywords: license, medical license, member id, insurance id, subscriber id, policy number.

## Contact / Personal

| Category | Description | Detection method | Example |
|---|---|---|---|
| `email` | Email addresses | Regex | `user@example.com` |
| `phone` | Phone numbers (US and international) | Regex (7+ digits) | `+1 (555) 123-4567` |
| `ip_address` | IPv4 addresses | Regex | `192.168.1.100` |
| `date_of_birth` | Date of birth (keyword-anchored) | Regex | `DOB: 03/15/1985` |
| `address` | US mailing addresses (street + optional city/state/zip) | Regex | `742 Evergreen Terrace Dr, Springfield, IL 62704` |

## False positive mitigation

Several patterns use keyword-anchoring to reduce false positives:
- **CVV/expiry/DOB/passport/DL/routing/medical license/insurance ID**: Only matched when preceded by a keyword (e.g., "CVV:", "DOB:", "passport", "Member ID:").
- **SSN**: Area numbers 000, 666, and 900-999 are excluded per SSA rules. Group 00 and serial 0000 are excluded.
- **Credit card**: Luhn checksum validation eliminates random digit sequences.
- **Phone**: Requires 7+ actual digits to avoid matching short number sequences.
- **IP address**: Validates each octet is 0-255.
