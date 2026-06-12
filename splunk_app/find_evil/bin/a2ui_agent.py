"""Intégration A2UI × Agentic Splunk SDK.

L'agent officiel `splunklib.ai` investigue l'image mémoire via les outils du Splunk
MCP Server, puis **structure son verdict** (output_schema pydantic). On convertit cette
sortie structurée au format **A2UI** (https://a2ui.org) et on l'écrit dans le static de
l'app, où la vue React native (a2ui_native) la rend en composants @splunk/react-ui.

Pipeline : Agent SDK (tools MCP) -> structured_output -> A2UI JSONL -> render React Splunk.

Lancement :
    SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
      python /Applications/Splunk/etc/apps/find_evil/bin/a2ui_agent.py
"""
import os
import sys

_LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
sys.path.insert(0, os.path.abspath(_LIB))

import asyncio
import json
from pathlib import Path
from typing import List, Literal

from pydantic import BaseModel, Field

from splunklib.client import connect
from splunklib.ai import Agent, AnthropicModel
from splunklib.ai.messages import HumanMessage
from splunklib.ai.tool_settings import ToolSettings, RemoteToolSettings, ToolAllowlist

REPO = Path("/Users/julientaste/testsplunk")
STATIC = Path("/Applications/Splunk/etc/apps/find_evil/appserver/static/forensic_report.a2ui.json")
VERSION, SURFACE = "v0.9", "forensic"

# Outils sans paramètre row_limit (Anthropic strict refuse les contraintes min/max
# sur les entiers que le row_limiter du MCP Server injecterait).
FORENSIC_TOOLS = [
    "forensics_find_attack_techniques", "forensics_triage_summary", "forensics_ai_triage",
]


# --- Schéma de sortie structurée de l'agent ---
class Technique(BaseModel):
    signature: str = Field(description="Nom de la signature YARA détectée (CIM)")
    severity: Literal["critical", "high", "medium", "low", "informational"]
    mitre: str = Field(description="Identifiant(s) MITRE ATT&CK, ex. T1003.003")
    description: str = Field(description="Description courte de la technique")


class ForensicReport(BaseModel):
    verdict: Literal["COMPROMIS", "SUSPECT", "RAS"]
    techniques: List[Technique] = Field(description="Techniques d'attaque détectées, triées par sévérité")
    analysis: str = Field(description="Synthèse d'analyste en Markdown : kill-chain et raisonnement")
    recommendations: List[str] = Field(description="3 à 5 actions de remédiation prioritaires")


SYSTEM_PROMPT = """Tu es un analyste forensique senior. Tu DOIS d'abord appeler tes outils
(au minimum forensics_find_attack_techniques ET forensics_triage_summary) pour collecter les
détections — n'émets JAMAIS de conclusion avant d'avoir les résultats des outils. Ensuite,
renvoie un rapport structuré : verdict, techniques MITRE (toutes celles renvoyées par l'outil),
analyse Markdown, recommandations. Appuie-toi UNIQUEMENT sur les résultats des outils."""


def _secret(env, fname):
    v = os.environ.get(env)
    if v:
        return v.strip()
    f = REPO / fname
    return f.read_text().strip() if f.exists() else None


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def to_a2ui(report: ForensicReport) -> str:
    """Convertit le rapport en A2UI JSONL selon le pattern idiomatique : séparation
    structure (updateComponents + bindings {path}) / état (updateDataModel), et
    templates de List pour les tableaux (ChildList {componentId, path})."""
    techs = sorted(report.techniques, key=lambda t: SEV_RANK.get(t.severity, 5))
    crit = sum(1 for t in techs if t.severity == "critical")
    high = sum(1 for t in techs if t.severity == "high")

    # --- État : data model (RFC 6901). Chaînes prêtes à l'affichage. ---
    data = {
        "verdict": f"Verdict : {report.verdict}",
        "kpi_critical": f"Critiques : {crit}",
        "kpi_high": f"Élevées : {high}",
        "kpi_total": f"Techniques : {len(techs)}",
        "analysis": report.analysis,
        "techniques": [
            {"label": f"**[{t.severity.upper()}]** {t.signature} — `{t.mitre}` — {t.description}"}
            for t in techs
        ],
        "recommendations": [{"text": f"{i+1}. {r}"} for i, r in enumerate(report.recommendations)],
    }

    # --- Structure : composants liés au data model par {path}, templates de List. ---
    comps = [
        {"id": "root", "component": "Column",
         "children": ["title", "verdict_card", "kpi_row", "tech_heading", "tech_list",
                      "ai_heading", "ai_card", "reco_heading", "reco_list"]},
        {"id": "title", "component": "Text", "variant": "h1",
         "text": "Find Evil — Rapport d'incident (A2UI × Splunk SDK)"},
        {"id": "verdict_card", "component": "Card", "child": "verdict_text"},
        {"id": "verdict_text", "component": "Text", "variant": "h2", "text": {"path": "/verdict"}},
        {"id": "kpi_row", "component": "Row", "children": ["kpi_c", "kpi_h", "kpi_t"]},
        {"id": "kpi_c", "component": "Card", "child": "kpi_c_t"},
        {"id": "kpi_c_t", "component": "Text", "text": {"path": "/kpi_critical"}},
        {"id": "kpi_h", "component": "Card", "child": "kpi_h_t"},
        {"id": "kpi_h_t", "component": "Text", "text": {"path": "/kpi_high"}},
        {"id": "kpi_t", "component": "Card", "child": "kpi_t_t"},
        {"id": "kpi_t_t", "component": "Text", "text": {"path": "/kpi_total"}},
        {"id": "tech_heading", "component": "Text", "variant": "h2", "text": "Kill-chain MITRE ATT&CK"},
        # Template de List : une carte par item de /techniques, paths scopés à l'item.
        {"id": "tech_list", "component": "List",
         "children": {"componentId": "tech_tmpl", "path": "/techniques"}},
        {"id": "tech_tmpl", "component": "Card", "child": "tech_tmpl_t"},
        {"id": "tech_tmpl_t", "component": "Text", "variant": "body", "text": {"path": "/label"}},
        {"id": "ai_heading", "component": "Text", "variant": "h2", "text": "Analyse de l'agent"},
        {"id": "ai_card", "component": "Card", "child": "ai_text"},
        {"id": "ai_text", "component": "Text", "variant": "body", "text": {"path": "/analysis"}},
        {"id": "reco_heading", "component": "Text", "variant": "h2", "text": "Recommandations"},
        {"id": "reco_list", "component": "List",
         "children": {"componentId": "reco_tmpl", "path": "/recommendations"}},
        {"id": "reco_tmpl", "component": "Card", "child": "reco_tmpl_t"},
        {"id": "reco_tmpl_t", "component": "Text", "text": {"path": "/text"}},
    ]

    lines = [
        json.dumps({"version": VERSION, "createSurface": {"surfaceId": SURFACE,
                    "catalogId": "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"}}),
        json.dumps({"version": VERSION, "updateComponents": {"surfaceId": SURFACE,
                    "components": comps}}, ensure_ascii=False),
        json.dumps({"version": VERSION, "updateDataModel": {"surfaceId": SURFACE,
                    "path": "/", "value": data}}, ensure_ascii=False),
    ]
    return "\n".join(lines)


async def main():
    anthropic_key = _secret("ANTHROPIC_API_KEY", ".anthropic_key")
    splunk_pass = _secret("SPLUNK_PASSWORD", ".splunk_pass")
    if not anthropic_key or not splunk_pass:
        sys.exit("Manque ANTHROPIC_API_KEY ou SPLUNK_PASSWORD")

    service = connect(scheme="https", host="localhost", port=8089,
                      username=os.environ.get("SPLUNK_USERNAME", "julien"),
                      password=splunk_pass, autologin=True, verify=False)
    model = AnthropicModel(model=os.environ.get("FORENSIC_SDK_MODEL", "claude-sonnet-4-6"),
                           api_key=anthropic_key, base_url="https://api.anthropic.com")

    async with Agent(
        model=model, service=service, system_prompt=SYSTEM_PROMPT,
        output_schema=ForensicReport,
        tool_settings=ToolSettings(local=None,
            remote=RemoteToolSettings(allowlist=ToolAllowlist(names=FORENSIC_TOOLS))),
    ) as agent:
        print("[A2UI × Splunk SDK] investigation en cours…")
        result = await agent.invoke([HumanMessage(
            content="Appelle d'abord forensics_find_attack_techniques et forensics_triage_summary, "
                    "puis produis le rapport d'incident structuré à partir de leurs résultats.")])
        report: ForensicReport = result.structured_output
        print(f"  verdict={report.verdict} | {len(report.techniques)} techniques | "
              f"{len(report.recommendations)} recommandations")
        a2ui = to_a2ui(report)
        STATIC.write_text(a2ui)
        print(f"  A2UI écrit ({len(a2ui)} octets) -> {STATIC}")
        print("  Rendu : http://localhost:8000/en-US/app/find_evil/a2ui_native")


if __name__ == "__main__":
    asyncio.run(main())
