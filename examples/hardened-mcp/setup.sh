#!/usr/bin/env bash
# setup.sh — Install the AgentWard hardened MCP profile.
#
# Self-sufficient: works on any fresh machine with agentward + npx installed.
# Detects your MCP host (Claude Desktop, Cursor, VS Code, Claude Code),
# copies the policy and MCP config, then runs a scan.
#
# Idempotent: safe to run multiple times. Backs up existing configs.
#
# Usage:
#   chmod +x setup.sh && ./setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_SRC="${SCRIPT_DIR}/agentward.yaml"
TEMPLATE_SRC="${SCRIPT_DIR}/mcp.json.template"
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

# ── Step 1: Check prerequisites ───────────────────────────────────
if ! command -v agentward &>/dev/null; then
    # Check if agentward exists in common pip --user bin locations but isn't on PATH
    USER_BIN_CANDIDATES=(
        "${HOME}/Library/Python/3.13/bin"
        "${HOME}/Library/Python/3.12/bin"
        "${HOME}/Library/Python/3.11/bin"
        "${HOME}/.local/bin"
    )
    FOUND_AT=""
    for candidate in "${USER_BIN_CANDIDATES[@]}"; do
        if [ -f "${candidate}/agentward" ]; then
            FOUND_AT="${candidate}"
            break
        fi
    done

    if [ -n "${FOUND_AT}" ]; then
        err "agentward is installed but not on your PATH.\n\n  Quick fix (run this first):\n    export PATH=\"${FOUND_AT}:\$PATH\"\n\n  To make it permanent, add that line to your ~/.zshrc or ~/.bash_profile"
    else
        err "agentward is not installed.\n\n  Install:  pip install agentward\n  Docs:     https://agentward.ai"
    fi
fi

if ! command -v npx &>/dev/null; then
    err "npx is not installed (needed for MCP servers).\n\n  Install:  brew install node   (macOS)\n            apt install nodejs npm   (Linux)"
fi

AGENTWARD_VERSION="$(agentward --version 2>&1 || true)"
info "Found ${AGENTWARD_VERSION}"

# ── Step 2: Check source files exist ──────────────────────────────
[ -f "${POLICY_SRC}" ]   || err "Policy file not found: ${POLICY_SRC}"
[ -f "${TEMPLATE_SRC}" ] || err "MCP template not found: ${TEMPLATE_SRC}"

# ── Step 3: Validate the policy loads correctly ───────────────────
dim "Validating policy..."
python3 -c "
from pathlib import Path
from agentward.policy.loader import load_policy
p = load_policy(Path('${POLICY_SRC}'))
print(f'  {len(p.skills)} skill(s), {len(p.skill_chaining)} chain rule(s), {len(p.require_approval)} approval gate(s)')
" || err "Policy validation failed. Fix ${POLICY_SRC} and re-run."

# ── Step 4: Detect MCP host ──────────────────────────────────────
echo ""
info "Detecting MCP host..."

SYSTEM="$(uname -s)"
HOSTS=()
HOST_PATHS=()
HOST_DIRS=()

# Claude Desktop
if [ "${SYSTEM}" = "Darwin" ]; then
    CLAUDE_DIR="${HOME}/Library/Application Support/Claude"
elif [ "${SYSTEM}" = "Linux" ]; then
    CLAUDE_DIR="${HOME}/.config/Claude"
else
    CLAUDE_DIR="${APPDATA:-${HOME}/AppData/Roaming}/Claude"
fi
CLAUDE_CONFIG="${CLAUDE_DIR}/claude_desktop_config.json"

if [ -d "${CLAUDE_DIR}" ]; then
    HOSTS+=("Claude Desktop")
    HOST_PATHS+=("${CLAUDE_CONFIG}")
    HOST_DIRS+=("${CLAUDE_DIR}")
fi

# Cursor (global)
CURSOR_DIR="${HOME}/.cursor"
CURSOR_CONFIG="${CURSOR_DIR}/mcp.json"
if [ -d "${CURSOR_DIR}" ]; then
    HOSTS+=("Cursor")
    HOST_PATHS+=("${CURSOR_CONFIG}")
    HOST_DIRS+=("${CURSOR_DIR}")
fi

# Claude Code (project-level — always available)
HOSTS+=("Claude Code (current directory)")
HOST_PATHS+=("$(pwd)/.mcp.json")
HOST_DIRS+=("$(pwd)")

if [ ${#HOSTS[@]} -eq 0 ]; then
    err "No MCP hosts detected.\n\n  Install one of:\n    - Claude Desktop: https://claude.ai/download\n    - Cursor: https://cursor.com\n    - Claude Code: npm install -g @anthropic-ai/claude-code"
fi

# If only one real host detected (besides Claude Code fallback), use it.
# Otherwise ask the user.
CHOSEN_INDEX=0
if [ ${#HOSTS[@]} -gt 1 ]; then
    echo ""
    echo "  Available MCP hosts:"
    for i in "${!HOSTS[@]}"; do
        echo "    $((i + 1))) ${HOSTS[$i]}"
    done
    echo ""
    read -rp "  Which host? [1-${#HOSTS[@]}] (default: 1): " CHOICE
    CHOICE="${CHOICE:-1}"
    CHOSEN_INDEX=$((CHOICE - 1))

    if [ "${CHOSEN_INDEX}" -lt 0 ] || [ "${CHOSEN_INDEX}" -ge ${#HOSTS[@]} ]; then
        err "Invalid choice: ${CHOICE}"
    fi
fi

CHOSEN_HOST="${HOSTS[$CHOSEN_INDEX]}"
CHOSEN_CONFIG="${HOST_PATHS[$CHOSEN_INDEX]}"
CHOSEN_DIR="${HOST_DIRS[$CHOSEN_INDEX]}"

info "Installing into: ${CHOSEN_HOST}"
dim "  Config: ${CHOSEN_CONFIG}"

# ── Step 5: Copy policy to config directory ───────────────────────
POLICY_DEST="${CHOSEN_DIR}/agentward.yaml"
mkdir -p "${CHOSEN_DIR}"

if [ -f "${POLICY_DEST}" ]; then
    cp "${POLICY_DEST}" "${POLICY_DEST}.${BACKUP_SUFFIX}"
    dim "  Backed up existing policy → ${POLICY_DEST}.${BACKUP_SUFFIX}"
fi

cp "${POLICY_SRC}" "${POLICY_DEST}"
info "  Copied policy → ${POLICY_DEST}"

# ── Step 6: Generate MCP config from template ────────────────────
# Replace __HOME__ and __POLICY_PATH__ placeholders with real paths
MCP_CONFIG_CONTENT="$(sed \
    -e "s|__HOME__|${HOME}|g" \
    -e "s|__POLICY_PATH__|${POLICY_DEST}|g" \
    "${TEMPLATE_SRC}")"

if [ -f "${CHOSEN_CONFIG}" ]; then
    cp "${CHOSEN_CONFIG}" "${CHOSEN_CONFIG}.${BACKUP_SUFFIX}"
    dim "  Backed up existing config → ${CHOSEN_CONFIG}.${BACKUP_SUFFIX}"
fi

echo "${MCP_CONFIG_CONTENT}" > "${CHOSEN_CONFIG}"
info "  Wrote MCP config → ${CHOSEN_CONFIG}"

# ── Step 7: Run scan to verify ────────────────────────────────────
echo ""
info "Scanning your tools..."
echo ""
agentward scan "${CHOSEN_CONFIG}" 2>&1 || true

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}Done.${NC} AgentWard is now protecting your ${CHOSEN_HOST} MCP servers."
echo ""
echo -e "  Every tool call from ${CHOSEN_HOST} now routes through AgentWard."
echo -e "  Policy: ${BOLD}${POLICY_DEST}${NC}"
echo -e "  Config: ${BOLD}${CHOSEN_CONFIG}${NC}"
echo ""
echo -e "  ${DIM}Edit the policy:   ${NC}${BOLD}vim ${POLICY_DEST}${NC}"
echo -e "  ${DIM}Rescan:            ${NC}${BOLD}agentward scan ${CHOSEN_CONFIG}${NC}"
echo -e "  ${DIM}View permissions:  ${NC}${BOLD}agentward map ${CHOSEN_CONFIG} --policy ${POLICY_DEST}${NC}"
