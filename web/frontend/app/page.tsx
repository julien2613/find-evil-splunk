"use client";

import { CopilotSidebar } from "@copilotkit/react-ui";
import { useCopilotChatSuggestions } from "@copilotkit/react-core";
import { ForensicRenderers } from "../components/ForensicRenderers";

function Suggestions() {
  useCopilotChatSuggestions({
    instructions:
      "Propose des questions d'investigation forensique : évaluer la compromission, lister les techniques MITRE, pivoter sur powershell.exe, reconstruire la timeline.",
  });
  return null;
}

export default function Page() {
  return (
    <main style={{ minHeight: "100vh", background: "#0d0d12", color: "#e0e0ff" }}>
      <ForensicRenderers />
      <Suggestions />

      <header style={{ padding: "32px 48px", borderBottom: "1px solid #1f1f2a" }}>
        <div style={{ fontSize: 13, color: "#ff5b5b", letterSpacing: 2, fontWeight: 700 }}>
          ● INCIDENT — DOMAIN CONTROLLER COMPROMIS
        </div>
        <h1 style={{ fontSize: 34, margin: "8px 0 4px" }}>Find Evil — Forensic Agent</h1>
        <p style={{ color: "#8a8a9a", maxWidth: 720 }}>
          Investigation forensique mémoire d'un contrôleur de domaine Windows Server 2016
          (scénario SRL-2018). L'agent Claude interroge Splunk via le{" "}
          <strong style={{ color: "#9cf" }}>Splunk MCP Server</strong> et rend ses découvertes
          en UI générative. Ouvre le panneau pour lancer l'investigation.
        </p>
      </header>

      <section style={{ padding: "32px 48px", display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 16 }}>
        {[
          { k: "Image mémoire", v: "base-dc-memory.img", s: "5 Go · Win Server 2016 DC" },
          { k: "Détections", v: "15 règles YARA", s: "kill-chain APT mappée MITRE" },
          { k: "Processus", v: "124 analysés", s: "Volatility3 psscan" },
          { k: "Outils MCP", v: "4 forensiques", s: "via Splunk MCP Server" },
        ].map((c) => (
          <div key={c.k} style={{ border: "1px solid #1f1f2a", borderRadius: 12, padding: 20, background: "#13131a" }}>
            <div style={{ color: "#8a8a9a", fontSize: 12, textTransform: "uppercase", letterSpacing: 1 }}>{c.k}</div>
            <div style={{ fontSize: 22, fontWeight: 700, margin: "6px 0" }}>{c.v}</div>
            <div style={{ color: "#6a6a7a", fontSize: 12 }}>{c.s}</div>
          </div>
        ))}
      </section>

      <CopilotSidebar
        defaultOpen
        labels={{
          title: "Agent forensique",
          initial:
            "Bonjour. Je suis l'agent d'investigation. Demandez-moi par exemple : **« Ce contrôleur de domaine est-il compromis ? »**",
        }}
      />
    </main>
  );
}
