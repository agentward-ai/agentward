# AgentWard Demo — scan → configure → policy review
# Recorded with VHS (https://github.com/charmbracelet/vhs)

Output docs/demo.gif

Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 15
Set TypingSpeed 30ms

# Activate venv and clear
Hide
Type "source .venv/bin/activate && clear"
Enter
Sleep 1s
Show

# --- Step 1: Scan ---
Sleep 500ms
Type "echo '→ Step 1: Scan your tools for risks'"
Enter
Sleep 1.5s
Type "agentward scan tests/fixtures/openclaw_skills/"
Sleep 500ms
Enter
Sleep 8s

# --- Step 2: Configure ---
Sleep 1s
Type "echo ''"
Enter
Type "echo '→ Step 2: Generate a security policy'"
Enter
Sleep 1.5s
Type "agentward configure tests/fixtures/openclaw_skills/ -o /tmp/demo-policy.yaml"
Sleep 500ms
Enter
Sleep 6s

# --- Show generated policy ---
Sleep 1s
Type "echo ''"
Enter
Type "echo '→ Generated policy:'"
Enter
Sleep 1s
Type "cat /tmp/demo-policy.yaml"
Sleep 500ms
Enter
Sleep 4s

# --- Closing ---
Sleep 1s
Type "echo ''"
Enter
Type "echo '→ Step 3: Enforce at runtime with: agentward inspect --policy agentward.yaml'"
Enter
Sleep 1s
Type "echo '→ Every tool call is now evaluated. Blocked calls never reach the server.'"
Enter
Sleep 1s
Type "echo ''"
Enter
Type "echo '   pip install agentward  ·  github.com/agentward-ai/agentward'"
Enter
Sleep 4s
