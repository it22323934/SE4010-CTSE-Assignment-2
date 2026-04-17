import { useState, useEffect, useRef, useCallback } from "react";

// --- API Helper ---
const API_BASE = "/api";

async function startAudit(repoPath) {
  const isUrl = /^https?:\/\/|^git@/.test(repoPath.trim());
  const body = isUrl
    ? { repo_url: repoPath.trim() }
    : { repo_path: repoPath.trim() };

  const res = await fetch(`${API_BASE}/audit/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json();
    throw new Error(err.detail || "Failed to start audit");
  }
  return res.json();
}

async function pollAuditStatus(auditId) {
  const res = await fetch(`${API_BASE}/audit/${auditId}/status`);
  if (!res.ok) throw new Error("Failed to fetch status");
  return res.json();
}

async function downloadReport(auditId) {
  const res = await fetch(`${API_BASE}/audit/${auditId}/report`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Download failed" }));
    throw new Error(err.detail || "Download failed");
  }
  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  const disposition = res.headers.get("content-disposition");
  const filename = disposition
    ? disposition.split("filename=")[1]?.replace(/"/g, "") || "audit-report.md"
    : "audit-report.md";
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}

// --- GitHub Dark Theme Tokens ---
const gh = {
  bg: "#0d1117",
  bgOverlay: "#161b22",
  bgInset: "#010409",
  bgSubtle: "#1c2128",
  border: "#30363d",
  borderMuted: "#21262d",
  text: "#e6edf3",
  textMuted: "#8b949e",
  textSubtle: "#6e7681",
  green: "#3fb950",
  greenBg: "#12261e",
  blue: "#58a6ff",
  blueBg: "#0c2d6b",
  yellow: "#d29922",
  yellowBg: "#2e1800",
  red: "#f85149",
  redBg: "#3d1214",
  purple: "#bc8cff",
  purpleBg: "#1e103f",
  orange: "#db6d28",
  btnPrimary: "#238636",
  btnPrimaryHover: "#2ea043",
  btnSecondary: "#21262d",
  btnSecondaryHover: "#30363d",
};

// --- Icons (inline SVGs matching GitHub's Octicon style) ---
const Icons = {
  Check: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.75.75 0 0 1 1.06-1.06L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z" />
    </svg>
  ),
  X: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M3.72 3.72a.75.75 0 0 1 1.06 0L8 6.94l3.22-3.22a.75.75 0 1 1 1.06 1.06L9.06 8l3.22 3.22a.75.75 0 1 1-1.06 1.06L8 9.06l-3.22 3.22a.75.75 0 0 1-1.06-1.06L6.94 8 3.72 4.78a.75.75 0 0 1 0-1.06Z" />
    </svg>
  ),
  Dot: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <circle cx="8" cy="8" r="4" />
    </svg>
  ),
  Shield: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M7.467.133a1.75 1.75 0 0 1 1.066 0l5.25 1.68A1.75 1.75 0 0 1 15 3.48V7c0 1.566-.32 3.182-1.303 4.682-.983 1.498-2.585 2.813-5.032 3.855a1.7 1.7 0 0 1-1.33 0c-2.447-1.042-4.049-2.357-5.032-3.855C1.32 10.182 1 8.566 1 7V3.48a1.75 1.75 0 0 1 1.217-1.667Zm.61 1.429a.25.25 0 0 0-.153 0l-5.25 1.68a.25.25 0 0 0-.174.238V7c0 1.358.275 2.666 1.057 3.86.784 1.194 2.121 2.34 4.366 3.297a.2.2 0 0 0 .154 0c2.245-.956 3.582-2.104 4.366-3.298C13.225 9.666 13.5 8.36 13.5 7V3.48a.25.25 0 0 0-.174-.237l-5.25-1.68Z" />
    </svg>
  ),
  Code: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="m11.28 3.22 4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.749.749 0 0 1-1.275-.326.749.749 0 0 1 .215-.734L13.94 8l-3.72-3.72a.749.749 0 0 1 .326-1.275.749.749 0 0 1 .734.215Zm-6.56 0a.751.751 0 0 1 1.042.018.751.751 0 0 1 .018 1.042L2.06 8l3.72 3.72a.749.749 0 0 1-.326 1.275.749.749 0 0 1-.734-.215L.47 8.53a.75.75 0 0 1 0-1.06Z" />
    </svg>
  ),
  Gear: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M8 0a8.2 8.2 0 0 1 .701.031C9.444.095 9.99.645 10.16 1.29l.288 1.107c.018.066.079.158.212.224.231.114.454.243.668.386.123.082.233.09.3.071L12.7 2.77c.627-.2 1.314-.066 1.746.488.34.437.58.922.737 1.434.158.514.19 1.064.06 1.588l-.295 1.136a.348.348 0 0 0 .013.308c.13.228.244.464.34.708a.353.353 0 0 0 .243.187l1.107.288c.645.17 1.195.716 1.26 1.459a8.2 8.2 0 0 1 0 1.402c-.065.743-.615 1.289-1.26 1.459l-1.107.288a.353.353 0 0 0-.243.187 6 6 0 0 1-.34.708.348.348 0 0 0-.013.308l.295 1.136c.13.524.098 1.074-.06 1.588a3.5 3.5 0 0 1-.737 1.434c-.432.554-1.12.687-1.746.488l-1.072-.307a.348.348 0 0 0-.3.071 6 6 0 0 1-.668.386c-.133.066-.194.158-.212.224l-.288 1.107c-.17.645-.716 1.195-1.459 1.26a8.1 8.1 0 0 1-1.402 0c-.743-.065-1.289-.615-1.459-1.26l-.288-1.107a.352.352 0 0 0-.212-.224 6 6 0 0 1-.668-.386.348.348 0 0 0-.3-.071l-1.072.307c-.627.2-1.314.066-1.746-.488a3.5 3.5 0 0 1-.737-1.434 3.5 3.5 0 0 1 .06-1.588l.295-1.136a.348.348 0 0 0-.013-.308 6 6 0 0 1-.34-.708.353.353 0 0 0-.243-.187L1.29 10.16c-.645-.17-1.195-.716-1.26-1.459a8.2 8.2 0 0 1 0-1.402c.065-.743.615-1.289 1.26-1.459l1.107-.288a.353.353 0 0 0 .243-.187 6 6 0 0 1 .34-.708.348.348 0 0 0 .013-.308L2.614 3.213c-.13-.524-.098-1.074.06-1.588.158-.512.398-.997.737-1.434C3.843.637 4.53.504 5.157.704l1.072.307c.067.019.177.011.3-.071.214-.143.437-.272.668-.386.133-.066.194-.158.212-.224l.288-1.107C7.711.645 8.257.095 9 .03A8.2 8.2 0 0 1 8 0ZM5.5 8a2.5 2.5 0 1 0 5 0 2.5 2.5 0 0 0-5 0Z" />
    </svg>
  ),
  Play: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Zm4.879-2.773 4.264 2.559a.25.25 0 0 1 0 .428l-4.264 2.559A.25.25 0 0 1 6 10.559V5.442a.25.25 0 0 1 .379-.215Z" />
    </svg>
  ),
  File: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M2 1.75C2 .784 2.784 0 3.75 0h6.586c.464 0 .909.184 1.237.513l2.914 2.914c.329.328.513.773.513 1.237v9.586A1.75 1.75 0 0 1 13.25 16h-9.5A1.75 1.75 0 0 1 2 14.25Zm1.75-.25a.25.25 0 0 0-.25.25v12.5c0 .138.112.25.25.25h9.5a.25.25 0 0 0 .25-.25V6h-2.75A1.75 1.75 0 0 1 9 4.25V1.5Zm6.75.062V4.25c0 .138.112.25.25.25h2.688l-.011-.013-2.914-2.914-.013-.011Z" />
    </svg>
  ),
  Repo: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M2 2.5A2.5 2.5 0 0 1 4.5 0h8.75a.75.75 0 0 1 .75.75v12.5a.75.75 0 0 1-.75.75h-2.5a.75.75 0 0 1 0-1.5h1.75v-2h-8a1 1 0 0 0-.714 1.7.75.75 0 1 1-1.072 1.05A2.495 2.495 0 0 1 2 11.5Zm10.5-1h-8a1 1 0 0 0-1 1v6.708A2.486 2.486 0 0 1 4.5 9h8ZM5 12.25a.25.25 0 0 1 .25-.25h3.5a.25.25 0 0 1 .25.25v3.25a.25.25 0 0 1-.4.2l-1.45-1.087a.25.25 0 0 0-.3 0L5.4 15.7a.25.25 0 0 1-.4-.2Z" />
    </svg>
  ),
  Chevron: ({ open }) => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" style={{ transform: open ? "rotate(90deg)" : "rotate(0deg)", transition: "transform 0.15s ease" }}>
      <path d="M6.22 3.22a.75.75 0 0 1 1.06 0l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.751.751 0 0 1-1.042-.018.751.751 0 0 1-.018-1.042L9.94 8 6.22 4.28a.75.75 0 0 1 0-1.06Z" />
    </svg>
  ),
  Clock: () => (
    <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
      <path d="M8 0a8 8 0 1 1 0 16A8 8 0 0 1 8 0ZM1.5 8a6.5 6.5 0 1 0 13 0 6.5 6.5 0 0 0-13 0Zm7-3.25v2.992l2.028.812a.75.75 0 0 1-.557 1.392l-2.5-1A.751.751 0 0 1 7 8.25v-3.5a.75.75 0 0 1 1.5 0Z" />
    </svg>
  ),
  Alert: () => (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
      <path d="M6.457 1.047c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0 1 14.082 15H1.918a1.75 1.75 0 0 1-1.543-2.575ZM8 5a.75.75 0 0 0-.75.75v2.5a.75.75 0 0 0 1.5 0v-2.5A.75.75 0 0 0 8 5Zm0 9a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z" />
    </svg>
  ),
};

// --- Spinner Component ---
const Spinner = ({ size = 16 }) => (
  <svg width={size} height={size} viewBox="0 0 16 16" style={{ animation: "ghSpin 1s linear infinite" }}>
    <circle cx="8" cy="8" r="6" fill="none" stroke={gh.yellow} strokeWidth="2" strokeDasharray="28" strokeDashoffset="8" strokeLinecap="round" />
  </svg>
);

// --- Workflow Step Definitions ---
const WORKFLOW_STEPS = [
  { id: "orchestrator_plan", label: "Orchestrator · Plan Audit", agent: "Orchestrator", model: "llama3:8b", icon: "Gear", description: "Analyzing repository structure, detecting language and framework, prioritizing files by change frequency." },
  { id: "code_quality", label: "Code Quality · Analysis", agent: "Code Quality", model: "deepseek-coder-v2:16b", icon: "Code", description: "Parsing ASTs, calculating cyclomatic complexity, detecting code smells and structural issues." },
  { id: "security", label: "Security · Vulnerability Scan", agent: "Security", model: "llama3:8b", icon: "Shield", description: "Scanning for hardcoded secrets, SQL injection, command injection, checking Git history." },
  { id: "merge_findings", label: "Orchestrator · Merge & Cross-Reference", agent: "Orchestrator", model: "llama3:8b", icon: "Gear", description: "Deduplicating findings, escalating cross-referenced issues, building merged report." },
  { id: "refactoring", label: "Refactoring · Generate Fix Plan", agent: "Refactoring", model: "deepseek-coder-v2:16b", icon: "File", description: "Generating prioritized refactoring plan with before/after code and dependency ordering." },
];

// --- Severity Badge ---
const SeverityBadge = ({ severity }) => {
  const colors = {
    critical: { bg: gh.redBg, text: gh.red, border: `${gh.red}40` },
    high: { bg: gh.yellowBg, text: gh.orange, border: `${gh.orange}40` },
    medium: { bg: gh.yellowBg, text: gh.yellow, border: `${gh.yellow}40` },
    low: { bg: gh.blueBg, text: gh.blue, border: `${gh.blue}40` },
  };
  const c = colors[severity] || colors.medium;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", padding: "1px 8px", borderRadius: "2em", fontSize: "12px", fontWeight: 500, fontFamily: "'SF Mono', 'Cascadia Code', 'Fira Code', monospace", background: c.bg, color: c.text, border: `1px solid ${c.border}`, lineHeight: "20px" }}>
      {severity}
    </span>
  );
};

// --- Workflow Step Component (GitHub Actions-style) ---
const WorkflowStep = ({ step, status, duration, isLast, logs, isExpanded, onToggle, findingsCount, toolCalls }) => {
  const Icon = Icons[step.icon] || Icons.Gear;
  const borderColor = status === "completed" ? gh.green : status === "running" ? gh.yellow : status === "failed" ? gh.red : gh.border;
  const connectorColor = status === "completed" ? `${gh.green}50` : gh.border;

  const formatDuration = (ms) => {
    if (!ms) return null;
    if (ms < 1000) return `${ms}ms`;
    const s = (ms / 1000).toFixed(1);
    return `${s}s`;
  };

  return (
    <div style={{ position: "relative" }}>
      {/* Vertical connector line */}
      {!isLast && (
        <div style={{ position: "absolute", left: 19, top: 40, bottom: 0, width: 2, background: connectorColor, zIndex: 0 }} />
      )}
      <div onClick={onToggle} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 16px", cursor: "pointer", borderRadius: 6, background: status === "running" ? `${gh.yellow}08` : "transparent", transition: "background 0.15s ease", position: "relative", zIndex: 1 }}
        onMouseEnter={(e) => { if (status !== "running") e.currentTarget.style.background = gh.bgSubtle; }}
        onMouseLeave={(e) => { if (status !== "running") e.currentTarget.style.background = status === "running" ? `${gh.yellow}08` : "transparent"; }}>
        {/* Node circle */}
        <div style={{ width: 40, height: 40, borderRadius: "50%", border: `2px solid ${borderColor}`, display: "flex", alignItems: "center", justifyContent: "center", background: gh.bgOverlay, flexShrink: 0 }}>
          {status === "running" ? <Spinner size={18} /> : status === "completed" ? <span style={{ color: gh.green }}><Icons.Check /></span> : status === "failed" ? <span style={{ color: gh.red }}><Icons.X /></span> : <span style={{ color: gh.textSubtle }}><Icon /></span>}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
            <span style={{ fontSize: 14, fontWeight: 600, color: gh.text }}>{step.label}</span>
            <span style={{ fontSize: 11, fontFamily: "'SF Mono', 'Cascadia Code', monospace", color: gh.textSubtle, background: gh.bgSubtle, padding: "1px 6px", borderRadius: 4 }}>{step.model}</span>
            {findingsCount > 0 && status === "completed" && (
              <span style={{ fontSize: 11, fontFamily: "'SF Mono', 'Cascadia Code', monospace", color: gh.orange, background: gh.yellowBg, padding: "1px 6px", borderRadius: 4, border: `1px solid ${gh.orange}30` }}>
                {findingsCount} finding{findingsCount !== 1 ? "s" : ""}
              </span>
            )}
          </div>
          <span style={{ fontSize: 12, color: gh.textMuted, marginTop: 2, display: "block" }}>{step.description}</span>
          {/* Tool calls badges when running or completed */}
          {toolCalls && toolCalls.length > 0 && (
            <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
              {[...new Set(toolCalls)].map((tool, i) => (
                <span key={i} style={{ fontSize: 10, fontFamily: "'SF Mono', 'Cascadia Code', monospace", color: gh.blue, background: gh.blueBg, padding: "1px 5px", borderRadius: 3, border: `1px solid ${gh.blue}30` }}>
                  {tool}
                </span>
              ))}
            </div>
          )}
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
          {duration && (
            <span style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 12, color: gh.textMuted, fontFamily: "'SF Mono', 'Cascadia Code', monospace" }}>
              <Icons.Clock /> {formatDuration(duration)}
            </span>
          )}
          {status === "running" && (
            <span style={{ fontSize: 11, color: gh.yellow, fontWeight: 500 }}>In Progress</span>
          )}
          {(logs && logs.length > 0) && <span style={{ color: gh.textSubtle }}><Icons.Chevron open={isExpanded} /></span>}
        </div>
      </div>

      {/* Expanded execution log */}
      {isExpanded && logs && logs.length > 0 && (
        <div style={{ marginLeft: 56, marginTop: 4, marginBottom: 12, background: gh.bgInset, border: `1px solid ${gh.border}`, borderRadius: 6, overflow: "hidden" }}>
          <div style={{ padding: "8px 12px", borderBottom: `1px solid ${gh.border}`, display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: gh.textMuted }}>
            <Icons.File /> Agent Execution Log — {logs.length} entries
          </div>
          <div style={{ padding: "8px 0", fontFamily: "'SF Mono', 'Cascadia Code', 'Fira Code', monospace", fontSize: 12, lineHeight: "22px", maxHeight: 300, overflowY: "auto" }}>
            {logs.map((line, i) => {
              let color = gh.textMuted;
              if (line.startsWith("[tool]")) color = gh.blue;
              else if (line.startsWith("[llm]")) color = gh.purple;
              else if (line.startsWith("[state]")) color = gh.green;
              else if (line.startsWith("[plan]")) color = gh.yellow;
              else if (line.startsWith("[merge]")) color = gh.orange;
              else if (line.startsWith("[error]")) color = gh.red;
              else if (line.startsWith("[read]")) color = gh.textMuted;
              return (
                <div key={i} style={{ padding: "0 16px", display: "flex", gap: 8 }}>
                  <span style={{ color: gh.textSubtle, userSelect: "none", width: 20, textAlign: "right", flexShrink: 0 }}>{i + 1}</span>
                  <span style={{ color, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{line}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

// --- Findings Table ---
const FindingsTable = ({ findings, title }) => {
  const [expanded, setExpanded] = useState(null);
  return (
    <div style={{ border: `1px solid ${gh.border}`, borderRadius: 6, overflow: "hidden" }}>
      <div style={{ padding: "12px 16px", background: gh.bgSubtle, borderBottom: `1px solid ${gh.border}`, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <span style={{ fontSize: 14, fontWeight: 600, color: gh.text }}>{title}</span>
        <span style={{ fontSize: 12, color: gh.textMuted }}>{findings.length} findings</span>
      </div>
      {findings.length === 0 && (
        <div style={{ padding: 20, textAlign: "center", color: gh.textMuted, fontSize: 13 }}>No findings detected</div>
      )}
      {findings.map((f, i) => (
        <div key={f.id || i} style={{ borderBottom: i < findings.length - 1 ? `1px solid ${gh.border}` : "none" }}>
          <div onClick={() => setExpanded(expanded === i ? null : i)} style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 16px", cursor: "pointer", transition: "background 0.1s" }}
            onMouseEnter={e => e.currentTarget.style.background = gh.bgSubtle}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
            <span style={{ color: gh.textSubtle, flexShrink: 0 }}><Icons.Chevron open={expanded === i} /></span>
            <SeverityBadge severity={f.severity || (f.priority <= 2 ? "critical" : f.priority <= 3 ? "high" : "medium")} />
            <span style={{ fontSize: 13, fontFamily: "'SF Mono', 'Cascadia Code', monospace", color: gh.blue, flexShrink: 0 }}>{f.id || `REF-${f.priority}`}</span>
            <span style={{ fontSize: 13, color: gh.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", flex: 1 }}>{f.title || f.description}</span>
            <span style={{ fontSize: 12, fontFamily: "'SF Mono', 'Cascadia Code', monospace", color: gh.textMuted, flexShrink: 0 }}>{f.file?.split("/").pop()}</span>
          </div>
          {expanded === i && (
            <div style={{ padding: "12px 16px 12px 56px", background: gh.bgInset, borderTop: `1px solid ${gh.border}`, fontSize: 13, lineHeight: "20px" }}>
              <div style={{ color: gh.textMuted, marginBottom: 4 }}>
                <span style={{ color: gh.textSubtle }}>File: </span>
                <span style={{ fontFamily: "'SF Mono', 'Cascadia Code', monospace", color: gh.blue }}>{f.file}</span>
                {f.line_start && <span style={{ color: gh.textSubtle }}> L{f.line_start}{f.line_end ? `-${f.line_end}` : ""}</span>}
              </div>
              <div style={{ color: gh.text, marginBottom: 8 }}>{f.description || f.changes_summary}</div>
              {f.suggestion && <div style={{ color: gh.green, fontSize: 12 }}>💡 {f.suggestion}</div>}
              {f.attack_vector && <div style={{ color: gh.red, fontSize: 12, marginTop: 4 }}>⚠ {f.attack_vector}</div>}
              {f.cwe_id && <span style={{ display: "inline-block", marginTop: 6, fontSize: 11, fontFamily: "'SF Mono', 'Cascadia Code', monospace", padding: "1px 6px", borderRadius: 4, background: gh.bgSubtle, color: gh.textMuted, border: `1px solid ${gh.border}` }}>{f.cwe_id}</span>}
              {f.finding_refs && <div style={{ marginTop: 6, fontSize: 12, color: gh.textMuted }}>Addresses: {f.finding_refs.map(r => <span key={r} style={{ fontFamily: "monospace", color: gh.purple, marginRight: 6 }}>{r}</span>)}</div>}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

// --- Summary Cards ---
const SummaryCard = ({ label, value, color, icon: IconComp }) => (
  <div style={{ flex: 1, minWidth: 120, background: gh.bgOverlay, border: `1px solid ${gh.border}`, borderRadius: 6, padding: "14px 16px", display: "flex", alignItems: "center", gap: 12 }}>
    <div style={{ width: 32, height: 32, borderRadius: 6, background: `${color}18`, display: "flex", alignItems: "center", justifyContent: "center", color }}><IconComp /></div>
    <div>
      <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "'SF Mono', 'Cascadia Code', monospace", lineHeight: 1 }}>{value}</div>
      <div style={{ fontSize: 11, color: gh.textMuted, marginTop: 2, textTransform: "uppercase", letterSpacing: "0.5px" }}>{label}</div>
    </div>
  </div>
);

// --- Tab Button ---
const TabBtn = ({ label, active, onClick }) => (
  <button onClick={onClick} style={{ padding: "8px 16px", fontSize: 13, fontWeight: active ? 600 : 400, color: active ? gh.text : gh.textMuted, background: "none", border: "none", borderBottom: active ? `2px solid ${gh.orange}` : "2px solid transparent", cursor: "pointer", transition: "all 0.15s" }}>
    {label}
  </button>
);

// --- Main App ---
export default function CodeSentinelUI() {
  const [repoPath, setRepoPath] = useState("");
  const [isRunning, setIsRunning] = useState(false);
  const [isComplete, setIsComplete] = useState(false);
  const [stepStatuses, setStepStatuses] = useState({});
  const [stepDurations, setStepDurations] = useState({});
  const [stepFindingsCounts, setStepFindingsCounts] = useState({});
  const [stepToolCalls, setStepToolCalls] = useState({});
  const [expandedStep, setExpandedStep] = useState(null);
  const [activeTab, setActiveTab] = useState("workflow");
  const [stepLogs, setStepLogs] = useState({});
  const [auditId, setAuditId] = useState(null);
  const [findings, setFindings] = useState({ code_quality: [], security: [], refactoring: [] });
  const [errorMsg, setErrorMsg] = useState(null);
  const [elapsedTime, setElapsedTime] = useState(0);
  const pollRef = useRef(null);
  const timerRef = useRef(null);

  // Process steps data from backend status response
  const processStepsData = useCallback((steps, currentStep) => {
    const statuses = {};
    const durations = {};
    const findingsCounts = {};
    const toolCallsMap = {};
    const logsMap = {};

    for (const [stepId, stepData] of Object.entries(steps || {})) {
      if (typeof stepData === "string") {
        // Legacy format: just a status string
        statuses[stepId] = stepData;
      } else if (typeof stepData === "object" && stepData !== null) {
        statuses[stepId] = stepData.status || "pending";
        durations[stepId] = stepData.duration_ms || null;
        findingsCounts[stepId] = stepData.findings_count || 0;
        toolCallsMap[stepId] = stepData.tool_calls || [];
        logsMap[stepId] = stepData.logs || [];
      }
    }

    // Ensure current step shows as running if backend says so
    if (currentStep && !statuses[currentStep]) {
      statuses[currentStep] = "running";
    }

    setStepStatuses(statuses);
    setStepDurations(durations);
    setStepFindingsCounts(findingsCounts);
    setStepToolCalls(toolCallsMap);
    setStepLogs(logsMap);
  }, []);

  const runAudit = useCallback(async () => {
    if (isRunning || !repoPath.trim()) return;

    setIsRunning(true);
    setIsComplete(false);
    setStepStatuses({});
    setStepDurations({});
    setStepFindingsCounts({});
    setStepToolCalls({});
    setExpandedStep(null);
    setStepLogs({});
    setActiveTab("workflow");
    setFindings({ code_quality: [], security: [], refactoring: [] });
    setErrorMsg(null);
    setElapsedTime(0);

    // Start elapsed timer
    const startTs = Date.now();
    timerRef.current = setInterval(() => {
      setElapsedTime(Math.floor((Date.now() - startTs) / 1000));
    }, 1000);

    try {
      const result = await startAudit(repoPath);
      const id = result.audit_id;
      setAuditId(id);

      // Poll for real-time step progress from backend
      pollRef.current = setInterval(async () => {
        try {
          const status = await pollAuditStatus(id);

          // Update step progress from backend data
          processStepsData(status.steps, status.current_step);

          if (status.status === "completed") {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);

            // Process final step data
            processStepsData(status.steps, null);

            // Build detailed logs from agent_traces if available
            if (status.agent_traces && status.agent_traces.length > 0) {
              const traceLogs = {};
              for (const trace of status.agent_traces) {
                const agent = trace.agent || "unknown";
                const stepId = agent === "orchestrator" ? "orchestrator_plan"
                  : agent === "orchestrator_merge" ? "merge_findings" : agent;
                if (!traceLogs[stepId]) traceLogs[stepId] = [];
                for (const tc of (trace.tool_calls || [])) {
                  traceLogs[stepId].push(`[tool] ${tc.tool} → ${JSON.stringify(tc.params).slice(0, 100)}`);
                }
                if (trace.input_summary) {
                  traceLogs[stepId].push(`[plan] ${trace.input_summary}`);
                }
                if (trace.output_summary) {
                  traceLogs[stepId].push(`[state] ${trace.output_summary}`);
                }
                if (trace.duration_ms) {
                  traceLogs[stepId].push(`[state] Completed in ${trace.duration_ms}ms`);
                }
                if (trace.error) {
                  traceLogs[stepId].push(`[error] ${trace.error}`);
                }
              }
              // Merge trace logs with step logs (step logs take priority)
              setStepLogs(prev => {
                const merged = { ...traceLogs };
                for (const [k, v] of Object.entries(prev)) {
                  if (v && v.length > 0) merged[k] = v;
                }
                return merged;
              });
            }

            if (status.findings) {
              setFindings({
                code_quality: status.findings.code_quality || [],
                security: status.findings.security || [],
                refactoring: status.findings.refactoring || [],
              });
            }

            setIsRunning(false);
            setIsComplete(true);
          } else if (status.status === "failed") {
            clearInterval(pollRef.current);
            clearInterval(timerRef.current);
            setIsRunning(false);
            setErrorMsg(status.error || "Audit failed");

            // Mark remaining pending steps as failed
            const stepIds = WORKFLOW_STEPS.map(s => s.id);
            const failedStatuses = {};
            stepIds.forEach(s => {
              const current = status.steps?.[s];
              if (current && typeof current === "object") {
                failedStatuses[s] = current.status === "completed" ? "completed" : "failed";
              } else {
                failedStatuses[s] = "failed";
              }
            });
            setStepStatuses(failedStatuses);
          }
        } catch (_pollErr) {
          // Keep polling on transient errors
        }
      }, 1500);

    } catch (err) {
      clearInterval(timerRef.current);
      setIsRunning(false);
      setErrorMsg(err.message);
    }
  }, [isRunning, repoPath, processStepsData]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, []);

  const allFindings = [...findings.code_quality, ...findings.security];
  const totalFindings = allFindings.length;
  const criticalCount = allFindings.filter(f => f.severity === "critical").length;
  const highCount = allFindings.filter(f => f.severity === "high").length;

  const formatElapsed = (s) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`;
  };

  return (
    <div style={{ fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif", background: gh.bg, color: gh.text, minHeight: "100vh", padding: 0 }}>
      <style>{`
        @keyframes ghSpin { to { transform: rotate(360deg); } }
        @keyframes ghPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: ${gh.bgInset}; }
        ::-webkit-scrollbar-thumb { background: ${gh.border}; border-radius: 3px; }
        input:focus { outline: none; border-color: ${gh.blue} !important; box-shadow: 0 0 0 3px ${gh.blue}30 !important; }
      `}</style>

      {/* Header */}
      <div style={{ borderBottom: `1px solid ${gh.border}`, background: gh.bgOverlay, padding: "12px 24px", display: "flex", alignItems: "center", gap: 12 }}>
        <span style={{ color: gh.text }}><Icons.Shield /></span>
        <span style={{ fontSize: 16, fontWeight: 600, color: gh.text }}>CodeSentinel</span>
        <span style={{ fontSize: 12, color: gh.textMuted, fontFamily: "'SF Mono', 'Cascadia Code', monospace", background: gh.bgSubtle, padding: "2px 8px", borderRadius: "2em", border: `1px solid ${gh.border}` }}>v1.0.0</span>
        <div style={{ flex: 1 }} />
        {isComplete && (
          <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, fontWeight: 500, color: gh.green }}>
            <Icons.Check /> Audit Complete
          </span>
        )}
        {isRunning && (
          <span style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: gh.yellow, animation: "ghPulse 2s ease-in-out infinite" }}>
            <Spinner size={14} /> Running · {formatElapsed(elapsedTime)}
          </span>
        )}
      </div>

      {/* Main Content */}
      <div style={{ maxWidth: 960, margin: "0 auto", padding: "24px 16px" }}>
        {/* Error Banner */}
        {errorMsg && (
          <div style={{ background: gh.redBg, border: `1px solid ${gh.red}40`, borderRadius: 6, padding: "10px 16px", marginBottom: 16, display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ color: gh.red }}><Icons.X /></span>
            <span style={{ color: gh.red, fontSize: 13 }}>{errorMsg}</span>
          </div>
        )}

        {/* Input Section */}
        <div style={{ background: gh.bgOverlay, border: `1px solid ${gh.border}`, borderRadius: 6, padding: 20, marginBottom: 20 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14 }}>
            <span style={{ color: gh.textMuted }}><Icons.Repo /></span>
            <span style={{ fontSize: 14, fontWeight: 600 }}>Repository</span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input type="text" placeholder="https://github.com/owner/repo  or  /path/to/local/repo" value={repoPath} onChange={e => setRepoPath(e.target.value)}
              onKeyDown={e => { if (e.key === "Enter") runAudit(); }}
              style={{ flex: 1, padding: "6px 12px", fontSize: 13, fontFamily: "'SF Mono', 'Cascadia Code', monospace", background: gh.bgInset, color: gh.text, border: `1px solid ${gh.border}`, borderRadius: 6, transition: "border-color 0.15s, box-shadow 0.15s" }} />
            <button onClick={runAudit} disabled={isRunning || !repoPath.trim()}
              style={{ display: "flex", alignItems: "center", gap: 6, padding: "6px 16px", fontSize: 13, fontWeight: 600, color: "#fff", background: isRunning ? gh.btnSecondary : gh.btnPrimary, border: `1px solid ${isRunning ? gh.border : "rgba(240,246,252,0.1)"}`, borderRadius: 6, cursor: isRunning ? "not-allowed" : "pointer", transition: "background 0.15s", opacity: isRunning ? 0.6 : 1 }}
              onMouseEnter={e => { if (!isRunning) e.currentTarget.style.background = gh.btnPrimaryHover; }}
              onMouseLeave={e => { if (!isRunning) e.currentTarget.style.background = isRunning ? gh.btnSecondary : gh.btnPrimary; }}>
              <Icons.Play /> Run Audit
            </button>
          </div>
        </div>

        {/* Summary Cards + Download */}
        {isComplete && (
          <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
            <SummaryCard label="Total Findings" value={totalFindings} color={gh.blue} icon={Icons.Alert} />
            <SummaryCard label="Critical" value={criticalCount} color={gh.red} icon={Icons.Shield} />
            <SummaryCard label="High" value={highCount} color={gh.orange} icon={Icons.Alert} />
            <SummaryCard label="Refactoring Actions" value={findings.refactoring.length} color={gh.green} icon={Icons.Code} />
          </div>
        )}

        {/* Tabs */}
        {(isRunning || isComplete) && (
          <>
            <div style={{ borderBottom: `1px solid ${gh.border}`, marginBottom: 20, display: "flex", gap: 0, alignItems: "center" }}>
              <TabBtn label="Workflow" active={activeTab === "workflow"} onClick={() => setActiveTab("workflow")} />
              {isComplete && <TabBtn label="Code Quality" active={activeTab === "quality"} onClick={() => setActiveTab("quality")} />}
              {isComplete && <TabBtn label="Security" active={activeTab === "security"} onClick={() => setActiveTab("security")} />}
              {isComplete && <TabBtn label="Refactoring Plan" active={activeTab === "refactoring"} onClick={() => setActiveTab("refactoring")} />}
              {isComplete && auditId && (
                <div style={{ marginLeft: "auto" }}>
                  <button onClick={() => downloadReport(auditId)}
                    style={{ display: "flex", alignItems: "center", gap: 6, padding: "5px 12px", fontSize: 12, fontWeight: 500, color: gh.text, background: gh.btnSecondary, border: `1px solid ${gh.border}`, borderRadius: 6, cursor: "pointer", transition: "background 0.15s" }}
                    onMouseEnter={e => e.currentTarget.style.background = gh.btnSecondaryHover}
                    onMouseLeave={e => e.currentTarget.style.background = gh.btnSecondary}>
                    <Icons.File /> Download Report
                  </button>
                </div>
              )}
            </div>

            {/* Workflow Tab */}
            {activeTab === "workflow" && (
              <div style={{ background: gh.bgOverlay, border: `1px solid ${gh.border}`, borderRadius: 6, padding: "12px 0" }}>
                <div style={{ padding: "4px 16px 12px", borderBottom: `1px solid ${gh.border}`, display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <span style={{ fontSize: 14, fontWeight: 600 }}>Audit Pipeline</span>
                  <span style={{ fontSize: 12, color: gh.textMuted }}>·</span>
                  <span style={{ fontSize: 12, color: gh.textMuted }}>{Object.values(stepStatuses).filter(s => s === "completed").length}/{WORKFLOW_STEPS.length} steps</span>
                  {isRunning && <span style={{ fontSize: 12, color: gh.yellow, marginLeft: 8 }}>{formatElapsed(elapsedTime)}</span>}
                </div>
                {WORKFLOW_STEPS.map((step, i) => (
                  <WorkflowStep key={step.id} step={step}
                    status={stepStatuses[step.id] || "pending"}
                    duration={stepDurations[step.id]}
                    findingsCount={stepFindingsCounts[step.id]}
                    toolCalls={stepToolCalls[step.id]}
                    isLast={i === WORKFLOW_STEPS.length - 1}
                    logs={stepLogs[step.id]}
                    isExpanded={expandedStep === step.id}
                    onToggle={() => setExpandedStep(expandedStep === step.id ? null : step.id)} />
                ))}
              </div>
            )}

            {/* Findings Tabs */}
            {activeTab === "quality" && <FindingsTable findings={findings.code_quality} title="Code Quality Findings" />}
            {activeTab === "security" && <FindingsTable findings={findings.security} title="Security Vulnerabilities" />}
            {activeTab === "refactoring" && <FindingsTable findings={findings.refactoring} title="Prioritized Refactoring Plan" />}
          </>
        )}

        {/* Empty State */}
        {!isRunning && !isComplete && !errorMsg && (
          <div style={{ textAlign: "center", padding: "60px 20px", color: gh.textMuted }}>
            <div style={{ fontSize: 48, marginBottom: 16, opacity: 0.3 }}><Icons.Shield /></div>
            <div style={{ fontSize: 20, fontWeight: 600, color: gh.text, marginBottom: 8 }}>No audit results yet</div>
            <div style={{ fontSize: 14, maxWidth: 400, margin: "0 auto" }}>Enter a repository path and click <strong style={{ color: gh.green }}>Run Audit</strong> to start a multi-agent code analysis.</div>
          </div>
        )}
      </div>
    </div>
  );
}
