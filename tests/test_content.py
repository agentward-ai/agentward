"""Tests for content extraction from tool responses."""

from agentward.proxy.content import (
    ExtractedContent,
    content_matches_arguments,
    extract_content,
)


class TestExtractContent:
    """Tests for extract_content()."""

    def test_extract_urls_from_string(self) -> None:
        data = "Check out https://evil.com/payload and http://example.org/page"
        result = extract_content(data)
        assert "https://evil.com/payload" in result.urls
        assert "http://example.org/page" in result.urls

    def test_extract_urls_from_nested_dict(self) -> None:
        data = {
            "content": [
                {"type": "text", "text": "Visit https://attacker.com/inject"}
            ]
        }
        result = extract_content(data)
        assert "https://attacker.com/inject" in result.urls

    def test_extract_urls_from_list(self) -> None:
        data = ["https://a.com/1", "https://b.com/2"]
        result = extract_content(data)
        assert len(result.urls) == 2

    def test_extract_file_paths_unix(self) -> None:
        data = "Read the file at /etc/passwd and also /home/user/.ssh/id_rsa"
        result = extract_content(data)
        assert "/etc/passwd" in result.file_paths
        assert "/home/user/.ssh/id_rsa" in result.file_paths

    def test_extract_file_paths_home_relative(self) -> None:
        data = "Config at ~/Documents/secrets.txt"
        result = extract_content(data)
        assert "~/Documents/secrets.txt" in result.file_paths

    def test_no_extraction_from_numbers(self) -> None:
        data = {"count": 42, "active": True, "value": None}
        result = extract_content(data)
        assert result.is_empty

    def test_empty_string_returns_empty(self) -> None:
        result = extract_content("")
        assert result.is_empty

    def test_strips_trailing_punctuation_from_urls(self) -> None:
        data = "See https://example.com/page, for details."
        result = extract_content(data)
        assert "https://example.com/page" in result.urls
        # The trailing comma should be stripped
        assert not any(url.endswith(",") for url in result.urls)

    def test_deduplicates_urls(self) -> None:
        data = {
            "a": "https://dup.com/path",
            "b": "https://dup.com/path",
        }
        result = extract_content(data)
        assert result.urls.count("https://dup.com/path") == 1

    def test_short_paths_ignored(self) -> None:
        """Paths shorter than _MIN_PATH_LENGTH should be skipped."""
        data = "a /tmp value"  # /tmp is only 4 chars
        result = extract_content(data)
        assert "/tmp" not in result.file_paths


class TestContentMatchesArguments:
    """Tests for content_matches_arguments()."""

    def test_url_match_found(self) -> None:
        prior = ExtractedContent(
            urls=["https://evil.com/payload"],
            file_paths=[],
        )
        arguments = {"url": "https://evil.com/payload"}
        matches = content_matches_arguments(prior, arguments)
        assert "https://evil.com/payload" in matches

    def test_no_match(self) -> None:
        prior = ExtractedContent(
            urls=["https://evil.com/payload"],
            file_paths=[],
        )
        arguments = {"url": "https://safe.com/page"}
        matches = content_matches_arguments(prior, arguments)
        assert matches == []

    def test_file_path_match(self) -> None:
        prior = ExtractedContent(
            urls=[],
            file_paths=["/home/user/secrets.txt"],
        )
        arguments = {"path": "/home/user/secrets.txt"}
        matches = content_matches_arguments(prior, arguments)
        assert "/home/user/secrets.txt" in matches

    def test_nested_argument_match(self) -> None:
        """Content appears deep in nested arguments."""
        prior = ExtractedContent(
            urls=["https://evil.com/cmd"],
            file_paths=[],
        )
        arguments = {"config": {"targets": [{"url": "https://evil.com/cmd"}]}}
        matches = content_matches_arguments(prior, arguments)
        assert "https://evil.com/cmd" in matches

    def test_empty_prior_returns_empty(self) -> None:
        prior = ExtractedContent(urls=[], file_paths=[])
        arguments = {"anything": "whatever"}
        matches = content_matches_arguments(prior, arguments)
        assert matches == []
