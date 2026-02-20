#!/usr/bin/env node

/**
 * Thin wrapper that delegates to the Python agentward CLI.
 *
 * Resolves the venv-installed agentward binary and spawns it
 * with all arguments passed through. Stdio is inherited directly
 * so proxy mode (agentward inspect) works correctly.
 */

const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const VENV_PATH = path.join(os.homedir(), ".agentward", ".venv");

function findAgentward() {
  // Check venv first
  const venvBin =
    process.platform === "win32"
      ? path.join(VENV_PATH, "Scripts", "agentward.exe")
      : path.join(VENV_PATH, "bin", "agentward");

  if (fs.existsSync(venvBin)) {
    return venvBin;
  }

  // Fall back to PATH
  const whichCmd = process.platform === "win32" ? "where" : "which";
  try {
    const result = spawnSync(whichCmd, ["agentward"], {
      encoding: "utf-8",
      stdio: "pipe",
    });
    if (result.status === 0 && result.stdout.trim()) {
      return result.stdout.trim().split("\n")[0];
    }
  } catch {
    // Not found
  }

  return null;
}

const agentward = findAgentward();

if (!agentward) {
  console.error(
    "agentward: Python package not found.\n" +
      "\n" +
      "Run one of:\n" +
      "  npm rebuild agentward    (re-run post-install)\n" +
      "  pip install agentward    (install manually)\n"
  );
  process.exit(1);
}

// Pass all args through, inherit stdio for proxy mode
const args = process.argv.slice(2);
const result = spawnSync(agentward, args, {
  stdio: "inherit",
  env: process.env,
});

process.exit(result.status ?? 1);
