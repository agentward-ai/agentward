"""Sample OpenAI Agents SDK tool definitions for testing."""

from agents import function_tool


@function_tool
def get_weather(location: str, unit: str = "celsius") -> str:
    """Get the current weather for a location."""
    return f"Weather in {location}"


@function_tool(name_override="search_web", description_override="Search the web for information")
def _internal_search(query: str) -> str:
    return f"Results for {query}"
