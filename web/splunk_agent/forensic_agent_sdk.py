"""Agent forensique natif Splunk — basé sur l'Agentic Splunk SDK (splunklib.ai).

Contrairement à l'agent ADK (web/agent), celui-ci utilise le SDK officiel Splunk :
il se connecte au service Splunk et **auto-découvre les outils du Splunk MCP Server**
(nos 5 outils forensiques), puis raisonne avec Claude — dans le respect du RBAC.

Prérequis :
    pip install "splunk-sdk[ai]"
    export ANTHROPIC_API_KEY=...        (sinon lu depuis ../../.anthropic_key)
    export SPLUNK_USERNAME=julien
    export SPLUNK_PASSWORD=...           (sinon lu depuis ../../.splunk_pass)

Usage :
    python forensic_agent_sdk.py "Ce contrôleur de domaine est-il compromis ?"
"""
import asyncio
import os
import sys
from pathlib import Path

from splunklib.client import connect
from splunklib.ai import Agent, AnthropicModel
from splunklib.ai.messages import HumanMessage
from splunklib.ai.tool_settings import ToolSettings, RemoteToolSettings, ToolAllowlist

REPO = Path(__file__).resolve().parents[2]

# Nos 5 outils forensiques exposés par le Splunk MCP Server.
FORENSIC_TOOLS = [
    "forensics_find_attack_techniques",
    "forensics_triage_summary",
    "forensics_investigate_process",
    "forensics_attack_timeline",
    "forensics_ai_triage",
]

SYSTEM_PROMPT = """Tu es un analyste forensique senior en réponse à incident.
Tu investigues une image mémoire d'un contrôleur de domaine Windows Server 2016
(scénario SRL-2018) en utilisant tes outils, qui interrogent Splunk.

Méthode : commence par le triage et les techniques d'attaque, pivote sur les
processus suspects, reconstruis la chronologie. Conclus par un verdict clair
(COMPROMIS / SUSPECT / RAS), la kill-chain MITRE ATT&CK et des recommandations.
Réponds en français, concis, en citant les techniques MITRE (T-codes)."""


def _secret(env_name, file_name):
    val = os.environ.get(env_name)
    if val:
        return val.strip()
    f = REPO / file_name
    if f.exists():
        return f.read_text().strip()
    return None


async def main():
    question = sys.argv[1] if len(sys.argv) > 1 else "Ce contrôleur de domaine est-il compromis ?"

    anthropic_key = _secret("ANTHROPIC_API_KEY", ".anthropic_key")
    splunk_user = os.environ.get("SPLUNK_USERNAME", "julien")
    splunk_pass = _secret("SPLUNK_PASSWORD", ".splunk_pass")
    if not anthropic_key:
        sys.exit("ANTHROPIC_API_KEY manquante (env ou .anthropic_key)")
    if not splunk_pass:
        sys.exit("SPLUNK_PASSWORD manquante (env ou .splunk_pass)")

    # 1. Connexion au service Splunk (auth = RBAC de l'utilisateur)
    service = connect(
        scheme="https",
        host=os.environ.get("SPLUNK_HOST", "localhost"),
        port=int(os.environ.get("SPLUNK_PORT", "8089")),
        username=splunk_user,
        password=splunk_pass,
        autologin=True,
        verify=False,
    )

    # 2. Modèle Claude (provider-agnostic)
    model = AnthropicModel(
        model=os.environ.get("FORENSIC_SDK_MODEL", "claude-sonnet-4-6"),
        api_key=anthropic_key,
        base_url="https://api.anthropic.com",
    )

    # 3. Agent qui auto-découvre nos outils forensiques sur le MCP Server
    async with Agent(
        model=model,
        service=service,
        system_prompt=SYSTEM_PROMPT,
        tool_settings=ToolSettings(
            local=None,
            remote=RemoteToolSettings(allowlist=ToolAllowlist(names=FORENSIC_TOOLS)),
        ),
    ) as agent:
        print(f"[Agent Splunk SDK] Question : {question}\n")
        result = await agent.invoke([HumanMessage(content=question)])
        print(result.final_message.content)


if __name__ == "__main__":
    asyncio.run(main())
