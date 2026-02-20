#!/usr/bin/env node

/**
 * Post-install script for the agentward npm package.
 *
 * Creates an isolated Python venv at ~/.agentward/.venv/ and installs
 * the agentward Python package into it. This keeps the Python dependency
 * contained and avoids polluting the user's system Python.
 */

const { execSync, spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const AGENTWARD_HOME = path.join(os.homedir(), ".agentward");
const VENV_PATH = path.join(AGENTWARD_HOME, ".venv");

function findPython() {
  for (const cmd of ["python3", "python"]) {
    try {
      const result = spawnSync(cmd, ["--version"], {
        encoding: "utf-8",
        stdio: "pipe",
      });
      if (result.status === 0) {
        // Check version >= 3.11
        const versionMatch = result.stdout.match(/Python (\d+)\.(\d+)/);
        if (versionMatch) {
          const major = parseInt(versionMatch[1], 10);
          const minor = parseInt(versionMatch[2], 10);
          if (major === 3 && minor >= 11) {
            return cmd;
          }
        }
      }
    } catch {
      // Command not found, try next
    }
  }
  return null;
}

function main() {
  console.log("agentward: Setting up Python environment...");

  const python = findPython();
  if (!python) {
    console.error(
      "\n" +
        "  agentward requires Python 3.11+\n" +
        "\n" +
        "  Install Python from https://python.org or via your package manager:\n" +
        "    macOS:   brew install python@3.13\n" +
        "    Ubuntu:  sudo apt install python3.13\n" +
        "    Windows: winget install Python.Python.3.13\n" +
        "\n" +
        "  Then run: npm rebuild agentward\n"
    );
    process.exit(1);
  }

  console.log(`  Using: ${python}`);

  // Create home directory
  if (!fs.existsSync(AGENTWARD_HOME)) {
    fs.mkdirSync(AGENTWARD_HOME, { recursive: true });
  }

  // Create venv if it doesn't exist
  if (!fs.existsSync(VENV_PATH)) {
    console.log(`  Creating venv at ${VENV_PATH}...`);
    try {
      execSync(`${python} -m venv "${VENV_PATH}"`, { stdio: "pipe" });
    } catch (err) {
      console.error(`  Failed to create venv: ${err.message}`);
      process.exit(1);
    }
  }

  // Install agentward into the venv
  const pip =
    process.platform === "win32"
      ? path.join(VENV_PATH, "Scripts", "pip")
      : path.join(VENV_PATH, "bin", "pip");

  console.log("  Installing agentward Python package...");
  try {
    execSync(`"${pip}" install --upgrade agentward`, {
      stdio: "inherit",
    });
  } catch (err) {
    console.error(`  Failed to install agentward: ${err.message}`);
    console.error("  You can install manually: pip install agentward");
    process.exit(1);
  }

  console.log("\n  agentward installed successfully!");
  console.log("  Run: agentward scan\n");
}

main();
