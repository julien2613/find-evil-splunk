"""Agent forensique ADK — piloté par Claude, outillé par le Splunk MCP Server.

Chaque function tool ci-dessous est un appel `tools/call` vers le serveur MCP
officiel de Splunk. L'agent orchestre ces outils pour investiguer une image
mémoire de contrôleur de domaine et restitue des résultats structurés que le
frontend CopilotKit rend en UI générative (composants forensiques).

Modèle : Claude via LiteLLM (ANTHROPIC_API_KEY requise).
Lancement : uvicorn agent:app --port 8000   (ou python agent.py)
"""
import os
from pathlib import Path

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from ag_ui_adk import ADKAgent, AGUIToolset, add_adk_fastapi_endpoint
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from mcp_client import SplunkMCP

# Charge la clé Anthropic depuis l'env, sinon depuis le fichier gitignoré du repo.
if not os.environ.get("ANTHROPIC_API_KEY"):
    _key_file = Path(__file__).resolve().parents[2] / ".anthropic_key"
    if _key_file.exists():
        os.environ["ANTHROPIC_API_KEY"] = _key_file.read_text().strip()

_mcp = SplunkMCP()
MODEL = os.environ.get("FORENSIC_AGENT_MODEL", "anthropic/claude-sonnet-4-6")


# --- Function tools : chacun passe par le Splunk MCP Server ---

def find_attack_techniques() -> dict:
    """Liste toutes les techniques d'attaque détectées (règles YARA) sur l'image
    mémoire, triées par sévérité, avec leur identifiant MITRE ATT&CK.
    À utiliser en premier pour évaluer si la machine est compromise."""
    return {"techniques": _mcp.call_tool("forensics_find_attack_techniques")}


def triage_summary() -> dict:
    """Résumé de triage : nombre de détections par sévérité et par technique
    MITRE. Donne l'ampleur et la nature de la compromission."""
    return {"triage": _mcp.call_tool("forensics_triage_summary")}


def investigate_process(process_name: str) -> dict:
    """Recherche un processus par nom dans l'image mémoire du contrôleur de domaine.

    Args:
        process_name: nom du processus (ex. powershell.exe, cmd.exe, ntdsutil.exe).
    """
    return {
        "process_name": process_name,
        "instances": _mcp.call_tool(
            "forensics_investigate_process", {"process_name": process_name}
        ),
    }


def attack_timeline() -> dict:
    """Chronologie unifiée de l'attaque : processus et détections YARA fusionnés
    sur un axe temporel, avec technique MITRE et sévérité."""
    return {"timeline": _mcp.call_tool("forensics_attack_timeline")}


def ai_triage() -> dict:
    """Triage IA natif Splunk : fait analyser les détections YARA par Claude via la
    commande `| ai` du Splunk AI Toolkit (exécutée dans Splunk). Retourne un verdict
    de compromission, la kill-chain MITRE résumée et des recommandations. À utiliser
    pour une synthèse d'incident raisonnée directement dans le moteur Splunk."""
    rows = _mcp.call_tool("forensics_ai_triage")
    analysis = ""
    for r in rows:
        for k, v in r.items():
            if "ai_result" in k:
                analysis = v
    return {"ai_analysis": analysis or rows}


INSTRUCTION = """Tu es un analyste forensique senior spécialisé en réponse à incident.

Tu investigues une image mémoire d'un contrôleur de domaine Windows Server 2016
(scénario SRL-2018) en interrogeant Splunk via tes outils. Ces outils passent par
le Splunk MCP Server et exécutent du SPL sûr contre l'index forensics.

Méthode d'investigation :
1. Commence par `triage_summary` et `find_attack_techniques` pour la vue d'ensemble.
2. Pivote sur les processus suspects avec `investigate_process` (powershell.exe,
   cmd.exe, wmic.exe, ntdsutil.exe).
3. Reconstruis le déroulé avec `attack_timeline`.
4. Conclus par un verdict clair (COMPROMIS / SUSPECT / RAS), la kill-chain MITRE,
   et des recommandations de remédiation concrètes.

Réponds en français, de façon concise et actionnable. Cite toujours les techniques
MITRE ATT&CK (T-codes). Ne fabrique jamais de données : appuie-toi uniquement sur
les résultats des outils."""

forensic_agent = LlmAgent(
    name="forensic_agent",
    model=LiteLlm(model=MODEL),
    instruction=INSTRUCTION,
    tools=[
        find_attack_techniques,
        triage_summary,
        investigate_process,
        attack_timeline,
        ai_triage,
        AGUIToolset(),
    ],
)

adk_agent = ADKAgent(
    adk_agent=forensic_agent,
    app_name="find_evil",
    user_id="analyst",
)

app = FastAPI(title="Find Evil — Forensic Agent")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
add_adk_fastapi_endpoint(app, adk_agent, path="/")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("AGENT_PORT", "8800")))
