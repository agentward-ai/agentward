"""Sample LangChain tool definitions for testing."""

from langchain_core.tools import tool, BaseTool


@tool
def search_database(query: str, limit: int = 10) -> str:
    """Search the internal database for records."""
    return f"Found records for {query}"


class FileReaderTool(BaseTool):
    name: str = "read_file"
    description: str = "Read contents of a file from disk"

    def _run(self, file_path: str) -> str:
        return ""
