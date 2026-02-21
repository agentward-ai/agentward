"""Content extraction from tool responses for chain detection.

Extracts linkable content (URLs, file paths, commands) from tool response
data so the ChainTracker can detect when data flows from one tool's output
into another tool's input arguments.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

# --- Extraction patterns ---

_URL_PATTERN = re.compile(r"https?://[^\s\"'<>\]\)},]+")
_FILE_PATH_PATTERN = re.compile(
    r"(?:^|[\s\"'=:])("
    r"(?:/[\w.@:/-]+)"        # Unix absolute paths: /usr/bin/...
    r"|(?:~/[\w.@:/-]+)"      # Home-relative paths: ~/Documents/...
    r"|(?:[A-Z]:\\[\w.\\/-]+)" # Windows paths: C:\Users\...
    r")",
)
# Minimum path length to avoid matching single slashes or trivial fragments
_MIN_PATH_LENGTH = 5


@dataclass
class ExtractedContent:
    """Content extracted from a tool response for chain detection."""

    urls: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """Whether no content was extracted."""
        return not self.urls and not self.file_paths


def extract_content(data: Any) -> ExtractedContent:
    """Extract linkable content from a tool response.

    Recursively walks dicts, lists, and strings to find URLs and
    file paths that could be used in cross-tool chaining attacks.

    Args:
        data: The tool response data (typically a dict from JSON).

    Returns:
        Extracted content with deduplicated URLs and file paths.
    """
    urls: set[str] = set()
    file_paths: set[str] = set()

    _walk(data, urls, file_paths)

    return ExtractedContent(
        urls=sorted(urls),
        file_paths=sorted(file_paths),
    )


def content_matches_arguments(
    prior: ExtractedContent,
    arguments: dict[str, Any],
) -> list[str]:
    """Check if extracted content from a prior response appears in arguments.

    Serializes the arguments dict to a flat string, then checks if any
    extracted content string appears as a substring. This is intentionally
    simple — a substring match is sufficient to prove data flow.

    Args:
        prior: Content extracted from a prior tool response.
        arguments: The current tool call's arguments.

    Returns:
        List of matched content strings (empty if no match).
    """
    if prior.is_empty:
        return []

    # Serialize arguments to a flat string for substring matching
    try:
        args_str = json.dumps(arguments, default=str)
    except (TypeError, ValueError):
        return []

    matches: list[str] = []

    for url in prior.urls:
        if url in args_str:
            matches.append(url)

    for path in prior.file_paths:
        if path in args_str:
            matches.append(path)

    return matches


# --- Internal helpers ---


def _walk(
    data: Any,
    urls: set[str],
    file_paths: set[str],
) -> None:
    """Recursively extract content from a data structure."""
    if isinstance(data, str):
        _extract_from_string(data, urls, file_paths)
    elif isinstance(data, dict):
        for value in data.values():
            _walk(value, urls, file_paths)
    elif isinstance(data, (list, tuple)):
        for item in data:
            _walk(item, urls, file_paths)
    # Skip numbers, booleans, None — no linkable content


def _extract_from_string(
    text: str,
    urls: set[str],
    file_paths: set[str],
) -> None:
    """Extract URLs and file paths from a single string."""
    # URLs
    for match in _URL_PATTERN.finditer(text):
        url = match.group(0)
        # Strip trailing punctuation that's likely not part of the URL
        url = url.rstrip(".,;:!?)")
        if len(url) > 10:  # Skip trivially short matches
            urls.add(url)

    # File paths
    for match in _FILE_PATH_PATTERN.finditer(text):
        path = match.group(1).strip()
        if len(path) >= _MIN_PATH_LENGTH:
            file_paths.add(path)
