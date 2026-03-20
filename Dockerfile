FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY agentward/ ./agentward/

# Install agentward
RUN pip install --no-cache-dir .

# Run as MCP server over stdio for inspectability
ENTRYPOINT ["agentward-mcp-server"]
