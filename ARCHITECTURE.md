# Architecture — Find Evil: Agentic Memory Forensics

> Architecture diagram required by the hackathon: interaction with Splunk,
> integration of AI models/agents, and data flow between services.
> Project refocused on the **official Splunk agent** (`splunklib.ai`).

## Overview

```mermaid
flowchart TB
    subgraph EV["1 · Evidence"]
        IMG["base-dc-memory.img<br/>DC Windows Server 2016 — SRL-2018 (5 GB)"]
        YARA["YARA-X<br/>apt_detection_rules.yar (15 APT rules)"]
        VOL["Volatility3<br/>windows.psscan (124 processes)"]
        IMG --> YARA & VOL
    end

    subgraph SPL["2 · Splunk Enterprise (local) — data plane"]
        HEC["HTTP Event Collector :8088"]
        IDX["index=forensics<br/>forensics:process · forensics:yara_hit · forensics:incident"]
        DASH["Dashboards (Splunk Web :8000)<br/>SOC Incidents · AI Investigation · A2UI Native · Command Center"]
        HEC --> IDX --> DASH
    end

    subgraph MCP["3 · Control plane"]
        SRV["Splunk MCP Server (official, app 7931)<br/>/services/mcp :8089"]
        TOOLS["5 custom forensic tools<br/>find_attack_techniques · triage_summary<br/>investigate_process · attack_timeline · ai_triage"]
        AITK["Splunk AI Toolkit — | ai command<br/>(LLM connection 'claude')"]
        SRV --> TOOLS
        TOOLS -. "ai_triage" .-> AITK
    end

    subgraph AGENT["4 · Official Splunk agent (splunklib.ai)"]
        SDK["Agentic Splunk SDK + Claude<br/>find_evil/bin/forensic_agent_sdk.py"]
        A2AGENT["A2UI: find_evil/bin/a2ui_agent.py<br/>structured output -> A2UI v0.9"]
        REACT["React renderer @splunk/react-ui<br/>A2UI Native view"]
        SDK --> A2AGENT --> REACT
    end

    subgraph WF["5 · Automated SOC workflow"]
        ALERT["Scheduled alert (savedsearches.conf)<br/>detects critical YARA -> | ai -> collect"]
    end

    YARA & VOL -->|"ingest_to_splunk.py (splunk-sdk)"| HEC
    TOOLS <-->|"safe SPL (safe-SPL)"| IDX
    AITK -->|"| ai prompt"| LLM["LLM Claude (Anthropic)"]
    SDK <-->|"auto-discovery / tools/call"| SRV
    ALERT -->|"notable incident"| IDX
    SDK -->|report| OUT["verdict + MITRE kill-chain + remediation"]
```

## Data flow

1. **Extraction** — `yara_scan.py` (YARA-X) and `vol_extract.py` (Volatility3) → JSON artifacts.
2. **Ingestion** — `ingest_to_splunk.py` pushes the artifacts into the `forensics` index via the SDK (index.attached_socket) + props.conf.
3. **Exposure** — the official **Splunk MCP Server** exposes 5 custom forensic tools (safe SPL).
4. **Official agent** — the **Agentic Splunk SDK** (`splunklib.ai`) connects to the Splunk service,
   **auto-discovers the MCP Server tools**, reasons with Claude, and produces:
   - a **text verdict** (`forensic_agent_sdk.py`), or
   - an **A2UI v0.9 output** (`a2ui_agent.py`) rendered as `@splunk/react-ui` components.
5. **AI inside SPL** — the `ai_triage` tool runs the AI Toolkit's **`| ai`** command (LLM native to SPL).
6. **SOC workflow** — a scheduled alert detects the critical detections, launches AI triage
   (`| ai`) and writes a **notable incident** (`forensics:incident`) → *SOC Incidents* dashboard.

## Splunk AI capabilities

| Capability | Component |
|---|---|
| **Splunk MCP Server** (official) | `/services/mcp` + 5 custom tools |
| **Splunk AI Toolkit** (`\| ai`) | `forensics_ai_triage` tool + workflow |
| **Agentic Splunk SDK** (`splunklib.ai`) | official agent (text + A2UI) |

## Ports & services (local)

| Service | Port |
|---|---|
| Splunk Web | 8000 |
| Splunk management / MCP (`/services/mcp`) | 8089 |
| HTTP Event Collector | 8088 |
