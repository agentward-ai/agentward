import { useState, useEffect } from "react";

// ─── Shield Logo SVG ───
const ShieldLogo = ({ size = 40 }) => (
  <svg width={size} height={size} viewBox="0 0 48 48" fill="none">
    <path d="M24 4L6 12v12c0 11.1 7.7 21.5 18 24 10.3-2.5 18-12.9 18-24V12L24 4z" fill="#111" stroke="#00ff88" strokeWidth="2"/>
    <path d="M18 24l4 4 8-8" stroke="#00ff88" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" fill="none"/>
    <circle cx="24" cy="24" r="12" stroke="#00ff88" strokeWidth="1" strokeDasharray="3 3" opacity="0.4"/>
  </svg>
);

// ─── Animated Terminal ───
const Terminal = () => {
  const [lines, setLines] = useState([]);
  const terminalLines = [
    { text: "$ pip install agentward", type: "cmd", delay: 0 },
    { text: "$ agentward scan ~/", type: "cmd", delay: 600 },
    { text: "", type: "blank", delay: 900 },
    { text: "🔍 Auto-discovering tool sources...", type: "info", delay: 1100 },
    { text: "   Found: ~/.cursor/mcp.json (4 MCP servers)", type: "found", delay: 1400 },
    { text: "   Found: ~/projects/*.py (6 tool definitions)", type: "found", delay: 1700 },
    { text: "   Found: ~/.openclaw/skills/ (9 OpenClaw skills)", type: "found", delay: 2000 },
    { text: "", type: "blank", delay: 2200 },
    { text: "⚡ Enumerating live MCP servers...", type: "info", delay: 2400 },
    { text: "⚡ Scanning Python SDK tools (OpenAI, LangChain)...", type: "info", delay: 2700 },
    { text: "⚡ Analyzing OpenClaw skill permissions...", type: "info", delay: 3000 },
    { text: "", type: "blank", delay: 3200 },
    { text: "┌──────────────────────────────────────────────────────┐", type: "border", delay: 3400 },
    { text: "│  Source             Tool/Skill        Risk          │", type: "header", delay: 3500 },
    { text: "├──────────────────────────────────────────────────────┤", type: "border", delay: 3600 },
    { text: "│  MCP  filesystem    read,write,del    🔴 CRITICAL   │", type: "crit", delay: 3800 },
    { text: "│  MCP  slack         all-channels      ⚠ HIGH        │", type: "high", delay: 4000 },
    { text: "│  MCP  postgres      read,write        ⚠ MEDIUM      │", type: "medium", delay: 4200 },
    { text: "│  MCP  github        repos,issues      ✓ LOW         │", type: "low", delay: 4400 },
    { text: "│  Skill email-mgr    send,read,del     ⚠ HIGH        │", type: "high", delay: 4600 },
    { text: "│  Skill web-browser  navigate,js,dl    ⚠ HIGH        │", type: "high", delay: 4800 },
    { text: "│  Skill finance      read,network      🔴 CRITICAL   │", type: "crit", delay: 5000 },
    { text: "│  SDK  shell_exec    subprocess        🔴 CRITICAL   │", type: "crit", delay: 5200 },
    { text: "│  SDK  send_email    smtp,attachments   ⚠ HIGH       │", type: "high", delay: 5400 },
    { text: "└──────────────────────────────────────────────────────┘", type: "border", delay: 5600 },
    { text: "", type: "blank", delay: 5800 },
    { text: "⚠ Skill chain detected: email-mgr → web-browser", type: "chain", delay: 6000 },
    { text: "  Email content could leak via browsing", type: "chainwarn", delay: 6200 },
    { text: "", type: "blank", delay: 6400 },
    { text: "3 critical · 4 high · 1 medium · 1 low", type: "summary", delay: 6600 },
    { text: "→ Run `agentward configure` to generate policies", type: "action", delay: 7000 },
  ];

  useEffect(() => {
    setLines([]);
    const timeouts = terminalLines.map((line, i) =>
      setTimeout(() => setLines(prev => [...prev, line]), line.delay)
    );
    return () => timeouts.forEach(clearTimeout);
  }, []);

  const colors = {
    cmd: "#00ff88", info: "#888", found: "#5eead4", header: "#555",
    high: "#ff6b35", low: "#00ff88", medium: "#ffcc00", crit: "#ff3366",
    border: "#333", summary: "#fff", action: "#00ff88", blank: "transparent",
    chain: "#ff6b35", chainwarn: "#996633",
  };

  return (
    <div style={{
      background: "#0a0a0a", borderRadius: 12, padding: "20px 24px",
      fontFamily: "'JetBrains Mono', 'Fira Code', 'SF Mono', monospace",
      fontSize: 12.5, lineHeight: 1.65, overflow: "hidden", border: "1px solid #222",
      boxShadow: "0 8px 32px rgba(0,0,0,0.5)", maxWidth: 640, width: "100%",
    }}>
      <div style={{ display: "flex", gap: 6, marginBottom: 16 }}>
        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#ff5f57" }}/>
        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#febc2e" }}/>
        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#28c840" }}/>
      </div>
      <div style={{ maxHeight: 440, overflowY: "auto" }}>
        {lines.map((line, i) => (
          <div key={i} style={{
            color: colors[line.type] || "#ccc", whiteSpace: "pre",
            opacity: 0, animation: "fadeIn 0.25s ease forwards",
          }}>{line.text || "\u00A0"}</div>
        ))}
      </div>
      <div style={{ color: "#00ff88", opacity: lines.length >= terminalLines.length ? 1 : 0, transition: "opacity 0.3s" }}>
        <span style={{ opacity: 0.5 }}>$</span> <span style={{ animation: "blink 1s infinite" }}>▊</span>
      </div>
    </div>
  );
};

// ─── Architecture Diagram (embedded SVG from design) ───
const ArchitectureDiagram = () => (
  <div style={{
    background: "#0a0a0a", borderRadius: 12, padding: "0",
    maxWidth: 860, width: "100%", margin: "0 auto", overflow: "hidden",
  }}>
    <div dangerouslySetInnerHTML={{ __html: `
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800" font-family="'SF Mono', 'Fira Code', 'Consolas', monospace">
  <defs>
    <filter id="glow">
      <feGaussianBlur stdDeviation="3" result="blur"/>
      <feMerge>
        <feMergeNode in="blur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    <filter id="glow-strong">
      <feGaussianBlur stdDeviation="6" result="blur"/>
      <feMerge>
        <feMergeNode in="blur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    <marker id="arrow-green" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#00FF41"/>
    </marker>
    <marker id="arrow-red" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#FF3333"/>
    </marker>
    <marker id="arrow-dim" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#555"/>
    </marker>
  </defs>

  <!-- Background -->
  <rect width="1200" height="800" fill="#0a0a0a"/>

  <!-- Title -->
  <text x="600" y="40" text-anchor="middle" fill="#00FF41" font-size="22" font-weight="bold" filter="url(#glow)">AgentWard — Architecture</text>

  <!-- ==================== LAYER 1: Agent Hosts ==================== -->
  <text x="50" y="85" fill="#666" font-size="11" letter-spacing="3">AGENT HOSTS</text>

  <!-- Agent host boxes -->
  <g>
    <!-- Claude Desktop -->
    <rect x="50" y="95" width="155" height="42" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="127" y="121" text-anchor="middle" fill="#aaa" font-size="12">Claude Desktop</text>

    <!-- Claude Code -->
    <rect x="225" y="95" width="140" height="42" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="295" y="121" text-anchor="middle" fill="#aaa" font-size="12">Claude Code</text>

    <!-- Cursor -->
    <rect x="385" y="95" width="110" height="42" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="440" y="121" text-anchor="middle" fill="#aaa" font-size="12">Cursor</text>

    <!-- Windsurf -->
    <rect x="515" y="95" width="120" height="42" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="575" y="121" text-anchor="middle" fill="#aaa" font-size="12">Windsurf</text>

    <!-- VS Code -->
    <rect x="655" y="95" width="130" height="42" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="720" y="121" text-anchor="middle" fill="#aaa" font-size="12">VS Code</text>

    <!-- OpenClaw UI -->
    <rect x="805" y="95" width="145" height="42" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="877" y="121" text-anchor="middle" fill="#aaa" font-size="12">OpenClaw UI</text>

    <!-- API Clients -->
    <rect x="970" y="95" width="145" height="42" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
    <text x="1042" y="121" text-anchor="middle" fill="#aaa" font-size="12">API Clients</text>
  </g>

  <!-- Arrows from agents to AgentWard -->
  <!-- MCP stdio arrows (left 5 boxes) -->
  <line x1="127" y1="137" x2="127" y2="220" stroke="#555" stroke-width="1.5" marker-end="url(#arrow-dim)"/>
  <line x1="295" y1="137" x2="295" y2="220" stroke="#555" stroke-width="1.5" marker-end="url(#arrow-dim)"/>
  <line x1="440" y1="137" x2="440" y2="220" stroke="#555" stroke-width="1.5" marker-end="url(#arrow-dim)"/>
  <line x1="575" y1="137" x2="575" y2="220" stroke="#555" stroke-width="1.5" marker-end="url(#arrow-dim)"/>
  <line x1="720" y1="137" x2="720" y2="220" stroke="#555" stroke-width="1.5" marker-end="url(#arrow-dim)"/>

  <!-- HTTP arrows (right 2 boxes) -->
  <line x1="877" y1="137" x2="877" y2="220" stroke="#555" stroke-width="1.5" marker-end="url(#arrow-dim)"/>
  <line x1="1042" y1="137" x2="1042" y2="220" stroke="#555" stroke-width="1.5" marker-end="url(#arrow-dim)"/>

  <!-- Protocol labels -->
  <text x="400" y="185" text-anchor="middle" fill="#00FF41" font-size="10" opacity="0.7">JSON-RPC tools/call</text>
  <text x="950" y="185" text-anchor="middle" fill="#00FF41" font-size="10" opacity="0.7">POST /tools-invoke</text>

  <!-- ==================== LAYER 2: AgentWard ==================== -->
  <!-- Main green border box -->
  <rect x="30" y="210" width="1140" height="310" rx="6" fill="#0d1a0d" stroke="#00FF41" stroke-width="2" filter="url(#glow-strong)"/>

  <!-- AgentWard title bar -->
  <rect x="30" y="210" width="1140" height="40" rx="6" fill="#00FF41" opacity="0.15"/>
  <rect x="30" y="244" width="1140" height="6" fill="#0d1a0d"/>
  <text x="600" y="237" text-anchor="middle" fill="#00FF41" font-size="16" font-weight="bold" filter="url(#glow)">AGENTWARD — PERMISSION CONTROL PLANE</text>

  <!-- Proxy boxes -->
  <!-- Stdio Proxy -->
  <rect x="70" y="270" width="340" height="70" rx="4" fill="#111" stroke="#00FF41" stroke-width="1" opacity="0.8"/>
  <text x="240" y="295" text-anchor="middle" fill="#00FF41" font-size="14" font-weight="bold">Stdio Proxy</text>
  <text x="240" y="318" text-anchor="middle" fill="#668866" font-size="11">MCP JSON-RPC 2.0 over stdio</text>
  <text x="240" y="332" text-anchor="middle" fill="#668866" font-size="11">Subprocess management</text>

  <!-- HTTP Reverse Proxy -->
  <rect x="460" y="270" width="340" height="70" rx="4" fill="#111" stroke="#00FF41" stroke-width="1" opacity="0.8"/>
  <text x="630" y="295" text-anchor="middle" fill="#00FF41" font-size="14" font-weight="bold">HTTP Reverse Proxy</text>
  <text x="630" y="318" text-anchor="middle" fill="#668866" font-size="11">Gateway interception + WebSocket</text>
  <text x="630" y="332" text-anchor="middle" fill="#668866" font-size="11">passthrough for UI</text>

  <!-- Policy YAML file icon -->
  <rect x="860" y="270" width="270" height="70" rx="4" fill="#111" stroke="#444" stroke-width="1"/>
  <!-- File icon -->
  <polygon points="880,282 880,328 910,328 910,294 898,282" fill="none" stroke="#00FF41" stroke-width="1.5"/>
  <polyline points="898,282 898,294 910,294" fill="none" stroke="#00FF41" stroke-width="1.5"/>
  <text x="930" y="300" fill="#00FF41" font-size="13" font-weight="bold">agentward.yaml</text>
  <text x="930" y="318" fill="#668866" font-size="10">Declarative policy rules</text>

  <!-- Connecting line from YAML to Policy Engine -->
  <line x1="995" y1="340" x2="995" y2="370" stroke="#00FF41" stroke-width="1" stroke-dasharray="4,3" opacity="0.5"/>

  <!-- Policy Engine -->
  <rect x="70" y="370" width="530" height="65" rx="4" fill="#111" stroke="#00FF41" stroke-width="1.5"/>
  <text x="335" y="395" text-anchor="middle" fill="#00FF41" font-size="14" font-weight="bold">Policy Engine</text>

  <!-- Decision badges -->
  <rect x="105" y="408" width="80" height="22" rx="11" fill="#00FF41" opacity="0.2" stroke="#00FF41" stroke-width="1"/>
  <text x="145" y="423" text-anchor="middle" fill="#00FF41" font-size="11" font-weight="bold">ALLOW</text>

  <rect x="205" y="408" width="80" height="22" rx="11" fill="#FF3333" opacity="0.2" stroke="#FF3333" stroke-width="1"/>
  <text x="245" y="423" text-anchor="middle" fill="#FF3333" font-size="11" font-weight="bold">BLOCK</text>

  <rect x="305" y="408" width="90" height="22" rx="11" fill="#FFaa00" opacity="0.2" stroke="#FFaa00" stroke-width="1"/>
  <text x="350" y="423" text-anchor="middle" fill="#FFaa00" font-size="11" font-weight="bold">APPROVE</text>

  <rect x="415" y="408" width="65" height="22" rx="11" fill="#4488FF" opacity="0.2" stroke="#4488FF" stroke-width="1"/>
  <text x="447" y="423" text-anchor="middle" fill="#4488FF" font-size="11" font-weight="bold">LOG</text>

  <rect x="500" y="408" width="80" height="22" rx="11" fill="#aa44ff" opacity="0.2" stroke="#aa44ff" stroke-width="1"/>
  <text x="540" y="423" text-anchor="middle" fill="#aa44ff" font-size="11" font-weight="bold">REDACT</text>

  <!-- Connecting lines from proxies to engine -->
  <line x1="240" y1="340" x2="240" y2="370" stroke="#00FF41" stroke-width="1" stroke-dasharray="4,3" opacity="0.5"/>
  <line x1="630" y1="340" x2="500" y2="370" stroke="#00FF41" stroke-width="1" stroke-dasharray="4,3" opacity="0.5"/>

  <!-- Audit Logger -->
  <rect x="660" y="370" width="470" height="65" rx="4" fill="#111" stroke="#444" stroke-width="1"/>
  <text x="895" y="395" text-anchor="middle" fill="#ccc" font-size="14" font-weight="bold">Audit Logger</text>
  <text x="895" y="418" text-anchor="middle" fill="#668866" font-size="11">Structured JSON Lines  ·  Rich stderr output</text>
  <text x="895" y="432" text-anchor="middle" fill="#668866" font-size="11">Every decision logged with full context</text>

  <!-- Connecting line from engine to audit -->
  <line x1="600" y1="402" x2="660" y2="402" stroke="#444" stroke-width="1" stroke-dasharray="4,3"/>

  <!-- ==================== Decision Arrows ==================== -->

  <!-- ALLOW path (green) — left side -->
  <line x1="250" y1="520" x2="250" y2="600" stroke="#00FF41" stroke-width="2.5" marker-end="url(#arrow-green)" filter="url(#glow)"/>
  <rect x="195" y="548" width="110" height="24" rx="12" fill="#0a0a0a" stroke="#00FF41" stroke-width="1"/>
  <text x="250" y="565" text-anchor="middle" fill="#00FF41" font-size="12" font-weight="bold">✓ ALLOW</text>

  <!-- ALLOW path (green) — right side -->
  <line x1="800" y1="520" x2="800" y2="600" stroke="#00FF41" stroke-width="2.5" marker-end="url(#arrow-green)" filter="url(#glow)"/>
  <rect x="745" y="548" width="110" height="24" rx="12" fill="#0a0a0a" stroke="#00FF41" stroke-width="1"/>
  <text x="800" y="565" text-anchor="middle" fill="#00FF41" font-size="12" font-weight="bold">✓ ALLOW</text>

  <!-- BLOCK path (red) — center -->
  <line x1="530" y1="520" x2="530" y2="565" stroke="#FF3333" stroke-width="2.5"/>
  <!-- X symbol -->
  <line x1="515" y1="565" x2="545" y2="595" stroke="#FF3333" stroke-width="3"/>
  <line x1="545" y1="565" x2="515" y2="595" stroke="#FF3333" stroke-width="3"/>
  <rect x="480" y="548" width="100" height="24" rx="12" fill="#0a0a0a" stroke="#FF3333" stroke-width="1"/>
  <text x="530" y="565" text-anchor="middle" fill="#FF3333" font-size="12" font-weight="bold">✗ BLOCK</text>
  <text x="530" y="625" text-anchor="middle" fill="#FF3333" font-size="10" opacity="0.7">Call never reaches</text>
  <text x="530" y="640" text-anchor="middle" fill="#FF3333" font-size="10" opacity="0.7">tool servers</text>

  <!-- ==================== LAYER 3: Tool Servers ==================== -->
  <text x="50" y="660" fill="#666" font-size="11" letter-spacing="3">TOOL SERVERS</text>

  <!-- MCP Servers -->
  <rect x="70" y="670" width="400" height="55" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  <text x="270" y="695" text-anchor="middle" fill="#aaa" font-size="13" font-weight="bold">MCP Servers</text>
  <text x="270" y="714" text-anchor="middle" fill="#555" font-size="11">filesystem  ·  GitHub  ·  database  ·  Slack</text>

  <!-- OpenClaw Gateway -->
  <rect x="560" y="670" width="400" height="55" rx="4" fill="#1a1a1a" stroke="#333" stroke-width="1"/>
  <text x="760" y="695" text-anchor="middle" fill="#aaa" font-size="13" font-weight="bold">OpenClaw Gateway</text>
  <text x="760" y="714" text-anchor="middle" fill="#555" font-size="11">email  ·  calendar  ·  shell  ·  web browser</text>

  <!-- Transport labels on bottom -->
  <text x="270" y="745" text-anchor="middle" fill="#00FF41" font-size="10" opacity="0.5">stdio</text>
  <text x="760" y="745" text-anchor="middle" fill="#00FF41" font-size="10" opacity="0.5">HTTP / WebSocket</text>

  <!-- ==================== Footer ==================== -->
  <line x1="100" y1="768" x2="1100" y2="768" stroke="#222" stroke-width="1"/>
  <text x="600" y="790" text-anchor="middle" fill="#00FF41" font-size="12" opacity="0.6" filter="url(#glow)">Code-level enforcement outside the LLM context window — prompt injection can't override structural policies</text>

</svg>
    ` }} />
  </div>
);

// ─── Feature Stages ───
const stages = [
  { num: 1, icon: "🔍", title: "Scan", cmd: "agentward scan", status: "live",
    desc: "Auto-discover and map permissions across all tool sources — MCP servers, OpenClaw skills, Python SDK tools (OpenAI, LangChain, CrewAI). Risk-rated permission maps with use-case-aware recommendations." },
  { num: 2, icon: "⚙️", title: "Configure", cmd: "agentward configure", status: "live",
    desc: "Generate smart-default YAML policies from scan results. Detects use-case patterns (email+calendar, dev tools, finance) and tailors rules: approval gates, skill restrictions, chaining controls." },
  { num: 3, icon: "🔌", title: "Setup", cmd: "agentward setup", status: "live",
    desc: "Wire enforcement into your infrastructure. Wraps MCP server commands in agent host configs (Claude Desktop, Cursor, VS Code, Windsurf). Swaps OpenClaw gateway ports and patches LaunchAgent plists for HTTP proxy mode." },
  { num: 4, icon: "📋", title: "Comply", cmd: "agentward comply", status: "coming",
    desc: "Evaluate policies against HIPAA, SOX, GDPR, PCI-DSS. Generate compliance delta reports with exact config changes needed. Auto-fix mode produces compliant policy YAML." },
  { num: 5, icon: "🛡️", title: "Inspect", cmd: "agentward inspect", status: "live",
    desc: "Runtime MCP + HTTP proxy with live policy enforcement. Blocks, redacts, or flags tool calls. Skill chaining enforcement, human-in-the-loop approval gates, and structured audit trail." },
];

const compatList = [
  { name: "Claude Desktop", done: true },
  { name: "Claude Code", done: true },
  { name: "Cursor", done: true },
  { name: "Windsurf", done: true },
  { name: "VS Code", done: true },
  { name: "OpenClaw", done: true },
  { name: "OpenAI SDK", done: false },
  { name: "LangChain", done: false },
  { name: "CrewAI", done: false },
];

// ─── MAIN APP ───
export default function App() {
  const [copiedCmd, setCopiedCmd] = useState(false);
  const copyCmd = () => {
    navigator.clipboard?.writeText("pip install agentward");
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  return (
    <div style={{ background: "#0a0a0a", color: "#e0e0e0", fontFamily: "'Space Grotesk', 'Inter', system-ui, sans-serif", minHeight: "100vh" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes fadeIn { from { opacity:0; transform:translateY(3px) } to { opacity:1; transform:translateY(0) } }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        * { box-sizing:border-box; margin:0; padding:0; }
        ::selection { background:#00ff8840; }
        a { color:#00ff88; } a:hover { color:#00cc6a; }
      `}</style>

      {/* ─── TOP BRAND ─── */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:14, padding:"32px 20px 0" }}>
        <ShieldLogo size={48} />
        <span style={{ fontSize:28, fontWeight:700, color:"#fff", letterSpacing:"-0.5px" }}>AgentWard</span>
      </div>

      {/* ─── NAV ─── */}


      {/* ─── HERO ─── */}
      <div style={{ background:"linear-gradient(135deg, #00ff8808 0%, transparent 50%)", padding:"72px 20px 56px", textAlign:"center", maxWidth:800, margin:"0 auto" }}>
        <div style={{ display:"inline-block", padding:"4px 14px", borderRadius:20, background:"#00ff8812", border:"1px solid #00ff8825", marginBottom:24 }}>
          <span style={{ fontSize:12, fontWeight:600, color:"#00ff88", fontFamily:"'JetBrains Mono', monospace" }}>OPEN SOURCE · APACHE 2.0</span>
        </div>
        <h1 style={{ fontSize:"clamp(28px, 5vw, 46px)", fontWeight:700, lineHeight:1.15, color:"#fff", letterSpacing:"-1px", maxWidth:700, margin:"0 auto 20px" }}>
          Know what your AI agent's tools <span style={{ color:"#00ff88" }}>can actually access</span>
        </h1>
        <p style={{ fontSize:"clamp(16px, 2.5vw, 18px)", color:"#777", lineHeight:1.65, maxWidth:600, margin:"0 auto 36px" }}>
          The permission control plane for AI agents. Scan MCP servers, OpenClaw skills, and Python SDK tools. Enforce policies at runtime — in code, outside the LLM.
        </p>
        <div style={{ display:"flex", gap:12, justifyContent:"center", flexWrap:"wrap" }}>
          <button onClick={copyCmd} style={{ display:"flex", alignItems:"center", gap:10, padding:"14px 24px", borderRadius:10, background:"#111", border:"1px solid #222", cursor:"pointer", fontFamily:"'JetBrains Mono', monospace", fontSize:15, color:"#00ff88", fontWeight:500 }}>
            <span style={{ opacity:0.5 }}>$</span> pip install agentward
            <span style={{ fontSize:12, opacity:0.5, marginLeft:4 }}>{copiedCmd ? "✓ copied" : "⎘"}</span>
          </button>
          <a href="https://github.com/agentward-ai/agentward" target="_blank" rel="noopener" style={{ display:"flex", alignItems:"center", gap:10, padding:"14px 24px", borderRadius:10, background:"#00ff88", color:"#0a0a0a", textDecoration:"none", fontWeight:600, fontSize:15, border:"none" }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            Star on GitHub
          </a>
        </div>
      </div>

      {/* ─── METAPHOR ─── */}
      <div style={{ maxWidth:600, margin:"0 auto", padding:"24px 20px 0", textAlign:"center" }}>
        <div style={{ background:"#0d0d0d", border:"1px solid #1a1a1a", borderRadius:10, padding:"16px 24px", fontStyle:"italic", color:"#888", fontSize:14, lineHeight:1.7 }}>
          "Telling an agent <span style={{ color:"#ccc" }}>'don't touch the stove'</span> is a natural-language guardrail that can be circumvented. AgentWard puts a{" "}
          <span style={{ color:"#00ff88", fontStyle:"normal", fontWeight:600 }}>physical lock on the stove</span> — code-level enforcement that prompt injection can't override."
        </div>
      </div>

      {/* ─── TERMINAL DEMO ─── */}
      <div style={{ display:"flex", justifyContent:"center", padding:"0 20px 64px" }}>
        <Terminal />
      </div>

      {/* ─── THE PROBLEM ─── */}
      <section style={{ maxWidth:700, margin:"0 auto", padding:"0 20px 48px", textAlign:"center" }}>
        <div style={{ background:"#111", border:"1px solid #222", borderRadius:12, padding:"28px 32px" }}>
          <p style={{ fontSize:13, fontFamily:"'JetBrains Mono', monospace", color:"#00ff88", marginBottom:12, fontWeight:600 }}>THE PROBLEM</p>
          <p style={{ fontSize:16, lineHeight:1.7, color:"#ccc" }}>
            <strong style={{ color:"#fff" }}>26% of 31,000 AI agent skills contain vulnerabilities.</strong>{" "}
            230+ malicious skills found on ClawHub. OpenClaw has 140K+ GitHub stars and gives agents full computer control — but zero permission governance. Every existing tool only scans before installation, then walks away.
          </p>
          <p style={{ fontSize:16, lineHeight:1.7, color:"#ccc", marginTop:12 }}>
            <strong style={{ color:"#00ff88" }}>AgentWard does all four — across MCP servers, OpenClaw skills, and Python SDK tools.</strong>
          </p>
        </div>
      </section>



      {/* ─── ARCHITECTURE DIAGRAM ─── */}
      <section style={{ maxWidth:860, margin:"0 auto", padding:"0 20px 64px" }}>
        <ArchitectureDiagram />
      </section>

      {/* ─── QUICK START — agentward init ─── */}
      <section style={{ maxWidth:840, margin:"0 auto", padding:"0 20px 48px" }}>
        <h2 style={{ fontSize:24, fontWeight:700, color:"#fff", textAlign:"center", marginBottom:12 }}>One command to lock it down</h2>
        <p style={{ textAlign:"center", color:"#666", fontSize:14, marginBottom:28 }}>Scans your environment, generates a policy, wires enforcement, and starts the proxy — all in one step.</p>
        <div style={{ background:"linear-gradient(135deg,#0a1a0f,#111)", border:"1px solid #00ff8840", borderRadius:12, padding:"28px 28px 24px", position:"relative", overflow:"hidden" }}>
          <div style={{ position:"absolute", top:0, left:0, right:0, height:2, background:"linear-gradient(90deg,transparent,#00ff88,transparent)" }} />
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12, flexWrap:"wrap" }}>
            <span style={{ fontSize:28 }}>🚀</span>
            <span style={{ fontFamily:"monospace", fontSize:10, fontWeight:700, color:"#00ff88", background:"#00ff8820", padding:"3px 10px", borderRadius:4, border:"1px solid #00ff8830" }}>QUICK START</span>
            <h3 style={{ fontSize:20, fontWeight:700, color:"#fff", margin:0 }}>Init</h3>
          </div>
          <code style={{ fontFamily:"monospace", fontSize:13, color:"#00ff88", background:"#0a0a0a", padding:"6px 14px", borderRadius:6, display:"inline-block", marginBottom:14, border:"1px solid #00ff8830" }}>agentward init</code>
          <p style={{ fontSize:14, lineHeight:1.7, color:"#999", margin:0 }}>
            The recommended way to get started. Discovers your tools, shows a risk summary, generates a policy, wires enforcement into your agent host (MCP configs or OpenClaw gateway), and starts the runtime proxy — all interactively in one command. Everything{" "}
            <code style={{ fontFamily:"monospace", fontSize:12, color:"#00ff88", background:"#0a0a0a", padding:"1px 5px", borderRadius:3 }}>scan</code> +{" "}
            <code style={{ fontFamily:"monospace", fontSize:12, color:"#00ff88", background:"#0a0a0a", padding:"1px 5px", borderRadius:3 }}>configure</code> +{" "}
            <code style={{ fontFamily:"monospace", fontSize:12, color:"#00ff88", background:"#0a0a0a", padding:"1px 5px", borderRadius:3 }}>setup</code> +{" "}
            <code style={{ fontFamily:"monospace", fontSize:12, color:"#00ff88", background:"#0a0a0a", padding:"1px 5px", borderRadius:3 }}>inspect</code> does, in 10 seconds.
          </p>
        </div>
      </section>

      {/* ─── FIVE STAGES ─── */}
      <section style={{ maxWidth:840, margin:"0 auto", padding:"0 20px 64px" }}>
        <h2 style={{ fontSize:22, fontWeight:700, color:"#fff", textAlign:"center", marginBottom:12 }}>Or go step by step</h2>
        <p style={{ textAlign:"center", color:"#666", fontSize:14, marginBottom:28 }}>Five stages. Each command does one thing well.</p>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(240px, 1fr))", gap:16 }}>
          {stages.map(s => (
            <div key={s.num} style={{ background:"#111", border:`1px solid ${s.status==="coming"?"#ffcc0030":"#222"}`, borderRadius:12, padding:24, opacity:s.status==="coming"?0.75:1 }}>
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                <span style={{ fontSize:24 }}>{s.icon}</span>
                <span style={{ fontFamily:"monospace", fontSize:10, fontWeight:700, color:"#00ff88", background:"#00ff8815", padding:"2px 8px", borderRadius:4 }}>STAGE {s.num}</span>
                {s.status === "coming" && (
                  <span style={{ fontFamily:"monospace", fontSize:10, fontWeight:700, color:"#ffcc00", background:"#ffcc0015", padding:"2px 8px", borderRadius:4, border:"1px solid #ffcc0030" }}>COMING SOON</span>
                )}
                <h3 style={{ fontSize:17, fontWeight:700, color:"#fff" }}>{s.title}</h3>
              </div>
              <code style={{ fontFamily:"monospace", fontSize:12, color:s.status==="coming"?"#888":"#00ff88", background:"#0a0a0a", padding:"4px 10px", borderRadius:6, display:"inline-block", marginBottom:12, border:"1px solid #1a1a1a" }}>{s.cmd}</code>
              <p style={{ fontSize:13.5, lineHeight:1.6, color:"#888" }}>{s.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ─── POLICY YAML ─── */}
      <section style={{ maxWidth:620, margin:"0 auto", padding:"0 20px 64px" }}>
        <h2 style={{ fontSize:24, fontWeight:700, color:"#fff", textAlign:"center", marginBottom:12 }}>Human-readable policies</h2>
        <p style={{ textAlign:"center", color:"#777", fontSize:14, marginBottom:24 }}>YAML you can read, diff, and version control. Auto-generated from scan results.</p>
        <div style={{ background:"#0d0d0d", border:"1px solid #1a1a1a", borderRadius:12, padding:"20px 24px", fontFamily:"'JetBrains Mono', monospace", fontSize:12, lineHeight:1.8, color:"#888", overflowX:"auto" }}>
          <pre style={{ margin:0 }}>{`# agentward.yaml — auto-generated by agentward configure
version: "1.0"

skills:
  email-manager:
    gmail:
      read: true
      send: false         # 🚫 blocked — requires approval
      delete: false
    google_calendar:
      denied: true        # email skill has zero calendar access

  finance-tracker:
    gmail:
      read: true
      filters:
        only_from: ["chase.com", "amex.com"]
    network:
      outbound: false     # financial data NEVER leaves machine

  web-researcher:
    browser: { allowed: true }
    gmail:  { denied: true }
    filesystem: { denied: true }

skill_chaining:
  - email-manager cannot trigger web-researcher
  - finance-tracker cannot trigger any other skill
  - web-researcher cannot trigger shell-executor

require_approval:
  - send_email
  - delete_file
  - outbound_network_with_pii
  - shell_command_with_sudo`}</pre>
        </div>
      </section>

      {/* ─── COMPARISON TABLE ─── */}
      <section style={{ maxWidth:760, margin:"0 auto", padding:"0 20px 64px" }}>
        <h2 style={{ fontSize:24, fontWeight:700, color:"#fff", textAlign:"center", marginBottom:32 }}>Beyond scanning. Beyond prompts.</h2>
        <div style={{ overflowX:"auto" }}>
          <table style={{ width:"100%", borderCollapse:"collapse", fontFamily:"'JetBrains Mono', monospace", fontSize:12.5 }}>
            <thead><tr>
              {["Capability","Cisco","Caterpillar","Snyk","SecureClaw","AgentWard"].map((h,i) => (
                <th key={i} style={{ padding:"12px 12px", textAlign:"left", borderBottom:"2px solid #222", color:i===5?"#00ff88":"#555", fontWeight:700, fontSize:11, whiteSpace:"nowrap" }}>{h}</th>
              ))}
            </tr></thead>
            <tbody>
              {[
                ["Static Scanning","✓","✓","✓","✓","✓"],
                ["Runtime Enforcement","✗","✗","Proxy†","Plugin‡","✓"],
                ["Declarative Policy (YAML)","✗","✗","✗","✗","✓"],
                ["Skill Chaining Control","✗","✗","✗","✗","✓"],
                ["Compliance Mapping","✗","✗","✗","OWASP","Soon"],
                ["Data Flow Classification","✗","✗","PII†","✗","✓"],
                ["Structured Audit Trail","✗","✗","✗","✗","✓"],
                ["OpenClaw Skills","✓","✓","✓","✓","✓"],
                ["MCP + SDK + HTTP","~","~","MCP","OC","✓"],
              ].map((row,i) => (
                <tr key={i}>{row.map((cell,j) => (
                  <td key={j} style={{
                    padding:"10px 12px", borderBottom:"1px solid #1a1a1a", whiteSpace:"nowrap",
                    color: cell==="✓"?(j===5?"#00ff88":"#4ade80") : cell==="✗"?"#444" : cell==="~"?"#666" : cell==="Soon"?"#ffcc00" : cell==="OC"?"#666" : (cell.includes("†")||cell.includes("‡")||cell==="OWASP"||cell==="PII†")?"#ff6b35" : "#ccc",
                    fontWeight:j===0?500:400,
                  }}>{cell}</td>
                ))}</tr>
              ))}
            </tbody>
          </table>
          <p style={{ fontSize:11, color:"#444", marginTop:12, fontFamily:"'JetBrains Mono', monospace", lineHeight:1.7 }}>
            †Snyk mcp-scan proxy: guardrails via Invariant Labs API; PII detection in proxy mode.<br/>
            ‡SecureClaw: code-level plugin (51 audit checks) + behavioral skill (15 rules in LLM context, bypassable via prompt injection).
          </p>
        </div>
      </section>

      {/* ─── COMPATIBILITY ─── */}
      <section style={{ maxWidth:700, margin:"0 auto", padding:"0 20px 64px", textAlign:"center" }}>
        <p style={{ fontSize:12, fontWeight:600, color:"#555", marginBottom:16, letterSpacing:1, fontFamily:"'JetBrains Mono', monospace" }}>WORKS WITH</p>
        <div style={{ display:"flex", gap:10, justifyContent:"center", flexWrap:"wrap" }}>
          {compatList.map((c,i) => (
            <span key={i} style={{
              padding:"8px 16px", borderRadius:8, fontSize:13, fontWeight:500,
              background: c.done ? "#111" : "transparent",
              border: c.done ? "1px solid #1a1a1a" : "1px dashed #333",
              color: c.done ? "#ccc" : "#555",
              opacity: c.done ? 1 : 0.7,
            }}>
              {c.name}{!c.done && <span style={{ fontSize:9, marginLeft:6, color:"#555", fontFamily:"'JetBrains Mono', monospace" }}>SOON</span>}
            </span>
          ))}
        </div>
      </section>

      {/* ─── BOTTOM CTA ─── */}
      <section style={{ maxWidth:600, margin:"0 auto", padding:"60px 20px 80px", textAlign:"center", borderTop:"1px solid #1a1a1a" }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:12, marginBottom:12 }}>
          <ShieldLogo size={32} />
          <h2 style={{ fontSize:28, fontWeight:700, color:"#fff" }}>Stop trusting. Start verifying.</h2>
        </div>
        <p style={{ color:"#777", marginBottom:28, fontSize:15 }}>5 seconds to see what your AI agent's tools can actually do.</p>
        <div style={{ display:"flex", gap:12, justifyContent:"center", flexWrap:"wrap" }}>
          <button onClick={copyCmd} style={{ padding:"14px 24px", borderRadius:10, background:"#111", border:"1px solid #222", cursor:"pointer", fontFamily:"'JetBrains Mono', monospace", fontSize:14, color:"#00ff88", fontWeight:500 }}>$ pip install agentward</button>
          <a href="https://github.com/agentward-ai/agentward" target="_blank" rel="noopener" style={{ padding:"14px 24px", borderRadius:10, background:"#00ff88", color:"#0a0a0a", textDecoration:"none", fontWeight:600, fontSize:14, border:"none" }}>GitHub →</a>
        </div>
        <p style={{ marginTop:24, fontSize:12, color:"#555", fontFamily:"'JetBrains Mono', monospace" }}>Apache 2.0 · Python 3.11+ · No API key · Everything runs locally</p>
        <a href="mailto:hello@agentward.ai" style={{ display:"inline-block", marginTop:8, fontSize:13, color:"#00ff88", textDecoration:"none", fontFamily:"'JetBrains Mono', monospace", opacity:0.8 }}>hello@agentward.ai</a>
      </section>
    </div>
  );
}