"use client";

import { useRenderToolCall } from "@copilotkit/react-core";

/* Couleurs de sévérité — cohérentes avec le dashboard Splunk */
const SEV: Record<string, { bg: string; fg: string; label: string }> = {
  critical: { bg: "#3a0d0d", fg: "#ff5b5b", label: "CRITIQUE" },
  high: { bg: "#3a230d", fg: "#ff9d3c", label: "ÉLEVÉ" },
  medium: { bg: "#3a350d", fg: "#ffe03c", label: "MOYEN" },
  low: { bg: "#0d3a25", fg: "#3cff9d", label: "FAIBLE" },
  informational: { bg: "#0d233a", fg: "#3cb4ff", label: "INFO" },
  unknown: { bg: "#26262e", fg: "#aaa", label: "?" },
};

function Sev({ s }: { s: string }) {
  const c = SEV[s] ?? SEV.unknown;
  return (
    <span style={{ background: c.bg, color: c.fg, padding: "2px 8px", borderRadius: 6, fontSize: 11, fontWeight: 700, letterSpacing: 0.5 }}>
      {c.label}
    </span>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ border: "1px solid #2a2a35", borderRadius: 12, padding: 16, margin: "8px 0", background: "#16161e" }}>
      <div style={{ fontSize: 13, color: "#8a8a9a", marginBottom: 10, textTransform: "uppercase", letterSpacing: 1 }}>{title}</div>
      {children}
    </div>
  );
}

const Running = ({ label }: { label: string }) => (
  <div style={{ padding: 12, color: "#3cb4ff" }} className="animate-pulse">⏳ {label}…</div>
);

/* Enregistre tous les renderers d'outils forensiques. Rendu vide lui-même. */
export function ForensicRenderers() {
  // 1. Techniques d'attaque (kill-chain MITRE)
  useRenderToolCall({
    name: "find_attack_techniques",
    render: ({ result, status }) => {
      if (status === "executing") return <Running label="Recherche des techniques d'attaque" />;
      const rows = result?.techniques ?? [];
      if (!rows.length) return <></>;
      return (
        <Card title={`Kill-chain détectée — ${rows.length} techniques MITRE`}>
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {rows.map((r: any, i: number) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 13 }}>
                <Sev s={r.severity} />
                <code style={{ color: "#e0e0ff" }}>{r.rule}</code>
                <span style={{ color: "#6cf", fontFamily: "monospace", fontSize: 11 }}>{r.mitre}</span>
                <span style={{ color: "#999", fontSize: 12 }}>{r.description}</span>
              </div>
            ))}
          </div>
        </Card>
      );
    },
  });

  // 2. Triage par sévérité / MITRE
  useRenderToolCall({
    name: "triage_summary",
    render: ({ result, status }) => {
      if (status === "executing") return <Running label="Triage des détections" />;
      const rows = result?.triage ?? [];
      if (!rows.length) return <></>;
      return (
        <Card title="Triage par sévérité & technique">
          <table style={{ width: "100%", fontSize: 13, borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ color: "#8a8a9a", textAlign: "left" }}>
                <th style={{ padding: 4 }}>Sévérité</th><th>MITRE</th><th>Détections</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r: any, i: number) => (
                <tr key={i} style={{ borderTop: "1px solid #2a2a35" }}>
                  <td style={{ padding: 4 }}><Sev s={r.severity} /></td>
                  <td style={{ color: "#6cf", fontFamily: "monospace", fontSize: 11 }}>{r.mitre || "—"}</td>
                  <td style={{ color: "#e0e0ff", fontWeight: 700 }}>{r.detections}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      );
    },
  });

  // 3. Investigation processus
  useRenderToolCall({
    name: "investigate_process",
    render: ({ args, result, status }) => {
      if (status === "executing") return <Running label={`Recherche de ${args?.process_name ?? "processus"}`} />;
      const rows = result?.instances ?? [];
      return (
        <Card title={`Processus — ${result?.process_name ?? args?.process_name}`}>
          {rows.length === 0 ? (
            <div style={{ color: "#999" }}>Aucune instance trouvée en mémoire.</div>
          ) : (
            <table style={{ width: "100%", fontSize: 13, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ color: "#8a8a9a", textAlign: "left" }}>
                  <th style={{ padding: 4 }}>PID</th><th>PPID</th><th>Création</th><th>Session</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r: any, i: number) => (
                  <tr key={i} style={{ borderTop: "1px solid #2a2a35" }}>
                    <td style={{ padding: 4, color: "#ff9d3c", fontWeight: 700 }}>{r.pid}</td>
                    <td style={{ color: "#e0e0ff" }}>{r.ppid}</td>
                    <td style={{ color: "#999", fontFamily: "monospace", fontSize: 11 }}>{r.create_time}</td>
                    <td style={{ color: "#e0e0ff" }}>{r.session_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      );
    },
  });

  // 5. Triage IA natif Splunk (| ai)
  useRenderToolCall({
    name: "ai_triage",
    render: ({ result, status }) => {
      if (status === "executing")
        return <Running label="Analyse IA via | ai (Splunk AI Toolkit → Claude)" />;
      const text = result?.ai_analysis;
      if (!text || typeof text !== "string") return <></>;
      return (
        <div style={{ border: "1px solid #4a2a6a", borderRadius: 12, padding: 16, margin: "8px 0", background: "#1a1426" }}>
          <div style={{ fontSize: 12, color: "#b48aff", marginBottom: 8, textTransform: "uppercase", letterSpacing: 1 }}>
            ✦ Triage IA natif Splunk — commande | ai
          </div>
          <pre style={{ whiteSpace: "pre-wrap", fontFamily: "inherit", fontSize: 13, color: "#e0d8ff", margin: 0, lineHeight: 1.5 }}>
            {text}
          </pre>
        </div>
      );
    },
  });

  // 4. Chronologie de l'attaque
  useRenderToolCall({
    name: "attack_timeline",
    render: ({ result, status }) => {
      if (status === "executing") return <Running label="Reconstruction de la chronologie" />;
      const rows = (result?.timeline ?? []).slice(0, 40);
      if (!rows.length) return <></>;
      return (
        <Card title={`Chronologie de l'attaque — ${result?.timeline?.length ?? 0} événements`}>
          <div style={{ display: "flex", flexDirection: "column", gap: 4, maxHeight: 320, overflowY: "auto" }}>
            {rows.map((r: any, i: number) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 12, borderLeft: `2px solid ${r.kind === "detection" ? "#ff5b5b" : "#3a506b"}`, paddingLeft: 10 }}>
                <span style={{ color: "#777", fontFamily: "monospace" }}>{r._time?.slice(0, 19).replace("T", " ")}</span>
                <span style={{ color: r.kind === "detection" ? "#ff9d3c" : "#9cf" }}>{r.artifact}</span>
                {r.mitre ? <span style={{ color: "#6cf", fontFamily: "monospace", fontSize: 10 }}>{r.mitre}</span> : null}
              </div>
            ))}
          </div>
        </Card>
      );
    },
  });

  return null;
}
