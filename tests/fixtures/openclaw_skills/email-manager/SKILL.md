---
name: email-manager
description: Read and manage email using the himalaya CLI. Use for checking inbox, reading messages, and composing drafts.
homepage: https://github.com/pimalaya/himalaya
metadata:
  clawdbot:
    emoji: "\U0001f4e7"
    os:
      - darwin
      - linux
    requires:
      bins:
        - himalaya
      env:
        - IMAP_PASSWORD
    primaryEnv: IMAP_PASSWORD
    install:
      - id: brew
        kind: brew
        formula: himalaya
        bins:
          - himalaya
        label: Install himalaya (brew)
---

# Email Manager

Manage your email from the command line using himalaya.

## Usage

- `himalaya list` - List recent emails
- `himalaya read <id>` - Read a specific email
- `himalaya write` - Compose a new email
- `himalaya reply <id>` - Reply to an email
