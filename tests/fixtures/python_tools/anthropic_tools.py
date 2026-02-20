"""Sample Anthropic Claude SDK tool definitions for testing."""

from anthropic import beta_tool


@beta_tool
def fetch_url(url: str, headers: dict | None = None) -> str:
    """Fetch content from a URL."""
    return ""
