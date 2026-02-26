#!/usr/bin/env bash
# smoke.sh — Quick validation that agentward works after install.
#
# Usage:
#   pip install -e .   # or pip install agentward
#   bash scripts/smoke.sh
#
# Also suitable for CI (GitHub Actions, etc.).

set -euo pipefail

echo "=== AgentWard Smoke Tests ==="
echo ""

# 1. Verify the package is importable
echo "Checking import..."
python -c "import agentward; print(f'  agentward {agentward.__version__} imported OK')"

# 2. Verify the CLI entrypoint loads
echo "Checking CLI entrypoint..."
python -c "from agentward.cli import app; print('  CLI app loaded OK')"

# 3. Run the smoke test suite
echo ""
echo "Running smoke test suite..."
echo ""
python -m pytest tests/test_smoke.py -v -x

echo ""
echo "=== All smoke tests passed ==="
