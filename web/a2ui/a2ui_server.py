"""Serveur A2UI — émet un rapport forensique au format A2UI (Agent-to-UI) JSONL.

Le rapport est construit à partir des outils du Splunk MCP Server (détections YARA
+ triage IA via | ai). Les messages A2UI (createSurface / updateComponents) sont
rendus par l'app Splunk (vue A2UI) qui mappe les composants abstraits en HTML.

Lancement : uvicorn a2ui_server:app --port 8801
Endpoint  : GET /a2ui/forensic_report  -> A2UI JSONL (text/plain)
"""
import json
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from mcp_client import SplunkMCP  # noqa: E402

_mcp = SplunkMCP()
VERSION = "v0.9"
SURFACE = "forensic"

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "unknown": 5}


def _msg(obj):
    return json.dumps(obj, ensure_ascii=False)


def build_a2ui():
    """Construit le flux A2UI JSONL du rapport forensique."""
    techniques = _mcp.call_tool("forensics_find_attack_techniques")
    techniques.sort(key=lambda r: SEV_RANK.get(r.get("severity", "unknown"), 5))
    crit = [t for t in techniques if t.get("severity") == "critical"]
    high = [t for t in techniques if t.get("severity") == "high"]

    # Texte d'analyse IA via | ai (Splunk AI Toolkit)
    ai_rows = _mcp.call_tool("forensics_ai_triage")
    ai_text = ""
    for r in ai_rows:
        for k, v in r.items():
            if "ai_result" in k:
                ai_text = v
    if not ai_text:
        ai_text = "Analyse IA indisponible."

    verdict = "COMPROMIS" if crit else ("SUSPECT" if high else "RAS")

    lines = []
    # 1. Création de la surface
    lines.append(_msg({
        "version": VERSION,
        "createSurface": {
            "surfaceId": SURFACE,
            "catalogId": "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json",
        },
    }))

    components = []
    root_children = ["title", "verdict_card", "kpi_row", "tech_heading", "tech_list", "ai_heading", "ai_card"]
    components.append({"id": "root", "component": "Column", "children": root_children})

    components.append({"id": "title", "component": "Text", "variant": "h1",
                       "text": "Find Evil — Rapport d'incident (A2UI)"})

    components.append({"id": "verdict_card", "component": "Card", "child": "verdict_text"})
    components.append({"id": "verdict_text", "component": "Text", "variant": "h2",
                       "text": f"Verdict : {verdict}"})

    # KPI row
    components.append({"id": "kpi_row", "component": "Row", "children": ["kpi_crit", "kpi_high", "kpi_total"]})
    components.append({"id": "kpi_crit", "component": "Card", "child": "kpi_crit_t"})
    components.append({"id": "kpi_crit_t", "component": "Text", "text": f"Critiques : {len(crit)}"})
    components.append({"id": "kpi_high", "component": "Card", "child": "kpi_high_t"})
    components.append({"id": "kpi_high_t", "component": "Text", "text": f"Élevées : {len(high)}"})
    components.append({"id": "kpi_total", "component": "Card", "child": "kpi_total_t"})
    components.append({"id": "kpi_total_t", "component": "Text", "text": f"Détections : {len(techniques)}"})

    # Techniques list
    components.append({"id": "tech_heading", "component": "Text", "variant": "h2",
                       "text": "Kill-chain MITRE ATT&CK"})
    tech_ids = []
    for i, t in enumerate(techniques):
        rid = f"tech_{i}"
        tid = f"{rid}_t"
        tech_ids.append(rid)
        label = f"[{t.get('severity','').upper()}] {t.get('rule','')} — {t.get('mitre','')} — {t.get('description','')}"
        components.append({"id": rid, "component": "Card", "child": tid})
        components.append({"id": tid, "component": "Text", "text": label,
                           "severity": t.get("severity", "unknown")})
    components.append({"id": "tech_list", "component": "List", "children": tech_ids})

    # AI analysis
    components.append({"id": "ai_heading", "component": "Text", "variant": "h2",
                       "text": "Analyse IA (| ai → Claude, via Splunk AI Toolkit)"})
    components.append({"id": "ai_card", "component": "Card", "child": "ai_text"})
    components.append({"id": "ai_text", "component": "Text", "variant": "markdown", "text": ai_text})

    lines.append(_msg({
        "version": VERSION,
        "updateComponents": {"surfaceId": SURFACE, "root": "root", "components": components},
    }))
    return "\n".join(lines)


app = FastAPI(title="Find Evil — A2UI Server")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_methods=["*"],
    allow_headers=["*"],
)


_RENDERER_HTML = (
    Path(__file__).resolve().parents[1]
    / ".." / "splunk_app" / "find_evil" / "appserver" / "static" / "a2ui_report.html"
)


@app.get("/", response_class=HTMLResponse)
def renderer():
    """Sert le renderer A2UI (même origine que l'endpoint -> pas de souci CSP/CORS)."""
    html = _RENDERER_HTML.resolve().read_text()
    # Le renderer fetch la même origine quand servi ici
    html = html.replace(
        'params.get("src") || "http://localhost:8801/a2ui/forensic_report"',
        'params.get("src") || "/a2ui/forensic_report"',
    )
    return html


@app.get("/a2ui/forensic_report", response_class=PlainTextResponse)
def forensic_report():
    return build_a2ui()


@app.get("/health", response_class=PlainTextResponse)
def health():
    return "ok"


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8801)
