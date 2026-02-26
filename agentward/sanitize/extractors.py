"""File content extractors.

Extracts plain text from supported file formats.  PDF extraction requires
``pypdf`` (``pip install agentward[sanitize]``).
"""

from __future__ import annotations

from pathlib import Path


def extract_text(path: Path) -> str:
    """Extract text content from a file.

    Supports:
      - ``.txt``, ``.md``, ``.csv``, ``.json``, ``.yaml``, ``.yml``,
        ``.log``, ``.xml``, ``.html``, ``.env`` — read as UTF-8 text.
      - ``.pdf`` — extracted via ``pypdf`` (requires optional dependency).

    Args:
        path: Path to the file.

    Returns:
        The extracted text content.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file format is unsupported.
        ImportError: If PDF extraction is requested but ``pypdf`` is missing.
    """
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    suffix = path.suffix.lower()

    if suffix == ".pdf":
        return _extract_pdf(path)

    # Plain text formats.
    text_suffixes = {
        ".txt", ".md", ".csv", ".json", ".yaml", ".yml",
        ".log", ".xml", ".html", ".htm", ".env", ".toml",
        ".ini", ".cfg", ".conf", ".tsv", ".rst",
    }
    if suffix in text_suffixes or suffix == "":
        return path.read_text(encoding="utf-8", errors="replace")

    raise ValueError(
        f"Unsupported file format: '{suffix}'. "
        f"Supported: {', '.join(sorted(text_suffixes | {'.pdf'}))}"
    )


def _extract_pdf(path: Path) -> str:
    """Extract text from a PDF file using pypdf.

    Args:
        path: Path to the PDF file.

    Returns:
        Concatenated text from all pages.

    Raises:
        ImportError: If pypdf is not installed.
    """
    try:
        from pypdf import PdfReader  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "pypdf is required for PDF text extraction. "
            "Install it with: pip install agentward[sanitize]"
        ) from exc

    reader = PdfReader(str(path))
    pages: list[str] = []
    for page in reader.pages:
        page_text = page.extract_text()
        if page_text:
            pages.append(page_text)
    return "\n\n".join(pages)
