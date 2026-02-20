---
name: api-client
description: Make API requests to external services. Requires API keys for authentication.
homepage: https://example.com/api-docs
metadata:
  clawdbot:
    emoji: "\U0001f310"
    os:
      - darwin
      - linux
      - win32
    requires:
      bins:
        - curl
      env:
        - API_KEY
        - API_SECRET
    primaryEnv: API_KEY
---

# API Client

Make authenticated HTTP requests to external APIs.

## Configuration

Set your API_KEY and API_SECRET environment variables.
