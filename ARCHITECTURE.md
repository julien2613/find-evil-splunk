# Architecture — Find Evil : Agentic Memory Forensics

> Diagramme d'architecture requis par le hackathon : interaction avec Splunk,
> intégration des modèles/agents IA, et flux de données entre services.

## Vue d'ensemble

```mermaid
flowchart TB
    subgraph EV["1 · Couche Évidence"]
        IMG["base-dc-memory.img<br/>DC Windows Server 2016 — SRL-2018 (5 Go)"]
        YARA["YARA-X<br/>apt_detection_rules.yar (15 règles APT)"]
        VOL["Volatility3<br/>windows.psscan (124 processus)"]
        IMG --> YARA & VOL
    end

    subgraph SPL["2 · Splunk Enterprise (local) — plan de données"]
        HEC["HTTP Event Collector :8088"]
        IDX["index=forensics<br/>sourcetypes : forensics:process · forensics:yara_hit"]
        DASH["Dashboards (Splunk Web :8000)<br/>Command Center · AI Investigation · A2UI"]
        HEC --> IDX --> DASH
    end

    subgraph MCP["3 · Plan de contrôle agentique"]
        SRV["Splunk MCP Server (officiel, app 7931)<br/>/services/mcp :8089"]
        TOOLS["5 outils forensiques custom<br/>find_attack_techniques · triage_summary<br/>investigate_process · attack_timeline · ai_triage"]
        AITK["Splunk AI Toolkit — commande | ai<br/>(connexion LLM 'claude')"]
        SRV --> TOOLS
        TOOLS -. "ai_triage" .-> AITK
    end

    subgraph AI["4 · Agents & UI"]
        ADK["Agent ADK (Claude via LiteLLM)<br/>FastAPI/AG-UI :8800"]
        FE["Frontend CopilotKit (UI générative) :3000"]
        CLI["agent_investigate.py (client CLI)"]
        A2["Serveur A2UI :8801<br/>+ renderer React @splunk/react-ui"]
    end

    YARA & VOL -->|"ingest_to_splunk.py (HEC)"| HEC
    TOOLS <-->|"SPL sûr (safe-SPL)"| IDX
    AITK -->|"| ai prompt"| LLM["LLM Claude (Anthropic)"]
    ADK <-->|"tools/call (JSON-RPC)"| SRV
    CLI <-->|"tools/call"| SRV
    A2 <-->|"tools/call"| SRV
    FE <-->|"AG-UI / SSE"| ADK
    ADK -->|"rapport"| OUT["Verdict + kill-chain MITRE + remédiation"]
    A2 -->|"A2UI JSONL"| DASH
```

## Flux de données (séquence)

1. **Extraction** — `yara_scan.py` (YARA-X) et `vol_extract.sh` (Volatility3) analysent
   l'image mémoire → artefacts JSON (détections + processus).
2. **Ingestion** — `ingest_to_splunk.py` pousse les artefacts dans l'index `forensics`
   via le **HTTP Event Collector**, en préservant l'heure réelle des événements
   (`_time` = heure de création des processus / d'acquisition).
3. **Exposition** — le **Splunk MCP Server** officiel expose 5 outils forensiques
   custom (enregistrés via `/services/mcp_tools`), qui traduisent des intentions
   d'investigation en **SPL sûr** (whitelist safe-SPL) contre l'index `forensics`.
4. **Raisonnement IA — 2 chemins** :
   - **Dans Splunk** : l'outil `ai_triage` exécute la commande **`| ai`** de l'AI
     Toolkit → envoie les détections au LLM Claude → verdict natif SPL.
   - **Agent** : l'**agent ADK (Claude)** appelle les outils via `tools/call`
     (JSON-RPC), orchestre l'investigation et produit un rapport d'incident MITRE.
5. **Restitution** — trois surfaces : frontend **CopilotKit** (UI générative via
   AG-UI), **dashboards Splunk** (Command Center, AI Investigation), et rendu
   **A2UI** en composants React natifs Splunk (`@splunk/react-ui`).

## Capacités Splunk AI utilisées

| Capacité | Rôle | Composant |
|---|---|---|
| **Splunk MCP Server** (officiel) | Plan de contrôle de l'agent | `/services/mcp` |
| **Outils MCP custom** | 5 outils forensiques métier | `forensic_mcp_tools.json` |
| **Splunk AI Toolkit** (`\| ai`) | Raisonnement IA natif SPL | `forensics_ai_triage` |

## Ports & services (local)

| Service | Port |
|---|---|
| Splunk Web | 8000 |
| Splunk management / MCP (`/services/mcp`) | 8089 |
| HTTP Event Collector | 8088 |
| Agent ADK (AG-UI) | 8800 |
| Serveur A2UI | 8801 |
| Frontend CopilotKit | 3000 |
