"""Sample CrewAI tool definitions for testing."""

from crewai_tools import tool, BaseTool


@tool("Send Email")
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to the specified recipient."""
    return "sent"


class ShellExecutor(BaseTool):
    name: str = "execute_shell"
    description: str = "Execute a shell command and return output"

    def _run(self, command: str) -> str:
        return ""
