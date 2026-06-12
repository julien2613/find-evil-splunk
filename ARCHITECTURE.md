# Architecture — Find Evil : Agentic Memory Forensics

> Diagramme d'architecture requis par le hackathon : interaction avec Splunk,
> intégration des modèles/agents IA, et flux de données entre services.
> Projet recentré sur l'**agent officiel Splunk** (`splunklib.ai`).

## Vue d'ensemble

```mermaid
flowchart TB
    subgraph EV["1 · Évidence"]
        IMG["base-dc-memory.img<br/>DC Windows Server 2016 — SRL-2018 (5 Go)"]
        YARA["YARA-X<br/>apt_detection_rules.yar (15 règles APT)"]
        VOL["Volatility3<br/>windows.psscan (124 processus)"]
        IMG --> YARA & VOL
    end

    subgraph SPL["2 · Splunk Enterprise (local) — plan de données"]
        HEC["HTTP Event Collector :8088"]
        IDX["index=forensics<br/>forensics:process · forensics:yara_hit · forensics:incident"]
        DASH["Dashboards (Splunk Web :8000)<br/>SOC Incidents · AI Investigation · A2UI Native · Command Center"]
        HEC --> IDX --> DASH
    end

    subgraph MCP["3 · Plan de contrôle"]
        SRV["Splunk MCP Server (officiel, app 7931)<br/>/services/mcp :8089"]
        TOOLS["5 outils forensiques custom<br/>find_attack_techniques · triage_summary<br/>investigate_process · attack_timeline · ai_triage"]
        AITK["Splunk AI Toolkit — commande | ai<br/>(connexion LLM 'claude')"]
        SRV --> TOOLS
        TOOLS -. "ai_triage" .-> AITK
    end

    subgraph AGENT["4 · Agent officiel Splunk (splunklib.ai)"]
        SDK["Agentic Splunk SDK + Claude<br/>find_evil/bin/forensic_agent_sdk.py"]
        A2AGENT["A2UI : find_evil/bin/a2ui_agent.py<br/>sortie structurée -> A2UI v0.9"]
        REACT["renderer React @splunk/react-ui<br/>vue A2UI Native"]
        SDK --> A2AGENT --> REACT
    end

    subgraph WF["5 · Workflow SOC automatisé"]
        ALERT["Alerte planifiée (savedsearches.conf)<br/>détecte YARA critique -> | ai -> collect"]
    end

    YARA & VOL -->|"ingest_to_splunk.py (HEC)"| HEC
    TOOLS <-->|"SPL sûr (safe-SPL)"| IDX
    AITK -->|"| ai prompt"| LLM["LLM Claude (Anthropic)"]
    SDK <-->|"auto-discovery / tools/call"| SRV
    ALERT -->|"incident notable"| IDX
    SDK -->|rapport| OUT["verdict + kill-chain MITRE + remédiation"]
```

## Flux de données

1. **Extraction** — `yara_scan.py` (YARA-X) et `vol_extract.py` (Volatility3) → artefacts JSON.
2. **Ingestion** — `ingest_to_splunk.py` pousse les artefacts dans l'index `forensics` via HEC.
3. **Exposition** — le **Splunk MCP Server** officiel expose 5 outils forensiques custom (SPL sûr).
4. **Agent officiel** — l'**Agentic Splunk SDK** (`splunklib.ai`) se connecte au service Splunk,
   **auto-découvre les outils du MCP Server**, raisonne avec Claude, et produit :
   - un **verdict texte** (`forensic_agent_sdk.py`), ou
   - une **sortie A2UI v0.9** (`a2ui_agent.py`) rendue en composants `@splunk/react-ui`.
5. **IA dans le SPL** — l'outil `ai_triage` exécute la commande **`| ai`** de l'AI Toolkit (LLM natif SPL).
6. **Workflow SOC** — une alerte planifiée détecte les détections critiques, lance le triage IA
   (`| ai`) et écrit un **incident notable** (`forensics:incident`) → dashboard *SOC Incidents*.

## Capacités Splunk AI

| Capacité | Composant |
|---|---|
| **Splunk MCP Server** (officiel) | `/services/mcp` + 5 outils custom |
| **Splunk AI Toolkit** (`\| ai`) | outil `forensics_ai_triage` + workflow |
| **Agentic Splunk SDK** (`splunklib.ai`) | agent officiel (texte + A2UI) |

## Ports & services (local)

| Service | Port |
|---|---|
| Splunk Web | 8000 |
| Splunk management / MCP (`/services/mcp`) | 8089 |
| HTTP Event Collector | 8088 |
