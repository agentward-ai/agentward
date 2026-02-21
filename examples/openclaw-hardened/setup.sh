#!/usr/bin/env bash
# setup.sh — Install the AgentWard hardened profile for OpenClaw.
#
# Idempotent: safe to run multiple times. Backs up existing configs
# before overwriting.
#
# Usage:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_SRC="${SCRIPT_DIR}/agentward.yaml"
MCP_SRC="${SCRIPT_DIR}/mcp.json"

CLAWDBOT_DIR="${HOME}/.clawdbot"
MCP_DEST="${CLAWDBOT_DIR}/mcp.json"
POLICY_DEST="${CLAWDBOT_DIR}/agentward.yaml"
BACKUP_SUFFIX="$(date +%Y%m%d_%H%M%S).bak"

# Colors (no-color fallback for non-interactive shells)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    DIM='\033[2m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' DIM='' BOLD='' NC=''
fi

err()  { echo -e "${RED}Error:${NC} $*" >&2; exit 1; }
info() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}$*${NC}"; }
dim()  { echo -e "${DIM}$*${NC}"; }

# ── Step 1: Check AgentWard is installed ──────────────────────────
if ! command -v agentward &>/dev/null; then
    err "agentward is not installed or not on PATH.\n\n  Install: pip install agentward\n  Docs:    https://agentward.ai"
fi

AGENTWARD_VERSION="$(agentward --version 2>&1 || true)"
info "Found ${AGENTWARD_VERSION}"

# ── Step 2: Check source files exist ─────────────────────────────
[ -f "${POLICY_SRC}" ] || err "Policy file not found: ${POLICY_SRC}"
[ -f "${MCP_SRC}" ]    || err "MCP config not found: ${MCP_SRC}"

# ── Step 3: Validate the policy loads correctly ──────────────────
dim "Validating policy..."
python3 -c "
from pathlib import Path
from agentward.policy.loader import load_policy
p = load_policy(Path('${POLICY_SRC}'))
print(f'  {len(p.skills)} skill(s), {len(p.skill_chaining)} chain rule(s), {len(p.require_approval)} approval gate(s)')
" || err "Policy validation failed. Fix ${POLICY_SRC} and re-run."

# ── Step 4: Ensure OpenClaw config directory exists ──────────────
if [ ! -d "${CLAWDBOT_DIR}" ]; then
    warn "OpenClaw config directory not found at ${CLAWDBOT_DIR}"
    warn "Creating it — install OpenClaw if you haven't already."
    mkdir -p "${CLAWDBOT_DIR}"
fi

# ── Step 5: Back up existing configs ─────────────────────────────
if [ -f "${MCP_DEST}" ]; then
    cp "${MCP_DEST}" "${MCP_DEST}.${BACKUP_SUFFIX}"
    dim "Backed up ${MCP_DEST} -> ${MCP_DEST}.${BACKUP_SUFFIX}"
fi

if [ -f "${POLICY_DEST}" ]; then
    cp "${POLICY_DEST}" "${POLICY_DEST}.${BACKUP_SUFFIX}"
    dim "Backed up ${POLICY_DEST} -> ${POLICY_DEST}.${BACKUP_SUFFIX}"
fi

# ── Step 6: Copy files into place ────────────────────────────────
cp "${POLICY_SRC}" "${POLICY_DEST}"
cp "${MCP_SRC}" "${MCP_DEST}"
info "Copied policy and MCP config to ${CLAWDBOT_DIR}/"

# ── Step 7: Run agentward setup for gateway mode ─────────────────
dim "Configuring OpenClaw gateway proxy..."
agentward setup --gateway openclaw --policy "${POLICY_DEST}" 2>&1 || true

# ── Step 8: Run scan to show risk profile ────────────────────────
echo ""
info "Scanning your OpenClaw skill set..."
echo ""
agentward scan 2>&1 || true

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}Done.${NC} Run ${BOLD}agentward map --policy ${POLICY_DEST}${NC} to visualize your permission graph."
