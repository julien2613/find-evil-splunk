"""Enriched A2UI catalog (information-first) — shared by the splunklib.ai agent
(a2ui_agent.py) and the deterministic generator (gen_a2ui.py).

Each builder produces an A2UI JSONL document (createSurface + updateComponents +
updateDataModel) consumed by the React renderer `a2ui_app.jsx`, which maps the
components to dense @splunk/react-ui controls:
  VerdictBadge · KpiRow · SeverityBar · TechniqueTable (severity chips) ·
  RecommendationList · LolbinBars · IncidentList · Collapsible.
"""
import json
import re

VERSION = "v0.9"
CATALOG = "https://a2ui.org/specification/v0_9/catalogs/basic/catalog.json"
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _doc(surface, comps, data):
    return "\n".join([
        json.dumps({"version": VERSION, "createSurface": {"surfaceId": surface, "catalogId": CATALOG}}),
        json.dumps({"version": VERSION, "updateComponents": {"surfaceId": surface, "components": comps}},
                   ensure_ascii=False),
        json.dumps({"version": VERSION, "updateDataModel": {"surfaceId": surface, "path": "/", "value": data}},
                   ensure_ascii=False),
    ])


# --- Parsing helpers (to rebuild structured data) ---

def parse_tech_label(label):
    """'**[CRITICAL]** Sig — `T1003` — desc' -> structured dict."""
    m = re.match(r"\*\*\[(\w+)\]\*\*\s*(.+?)\s*—\s*`([^`]*)`\s*—\s*(.+)", label, re.S)
    if not m:
        return {"signature": label, "severity": "unknown", "mitre": "", "description": ""}
    return {"severity": m.group(1).lower(), "signature": m.group(2).strip(),
            "mitre": m.group(3).strip(), "description": m.group(4).strip()}


def parse_reco(text):
    """'1. **[PRIORITY 1 — Immediate]** text' -> {priority, horizon, text}."""
    t = re.sub(r"^\s*(\d+)[\.\)]\s*", "", text)
    num = re.match(r"^\s*(\d+)", text)
    priority = f"P{num.group(1)}" if num else None
    horizon = None
    mb = re.match(r"\*\*\[([^\]]+)\]\*\*\s*(.*)", t, re.S)
    if mb:
        bracket, t = mb.group(1), mb.group(2).strip()
        parts = re.split(r"[—\-–]", bracket, maxsplit=1)
        horizon = parts[1].strip() if len(parts) > 1 else bracket.strip()
    t = t.replace("**", "")
    return {"priority": priority or "•", "horizon": horizon, "text": t.strip()}


def severity_counts(techniques):
    counts = {}
    for t in techniques:
        counts[t["severity"]] = counts.get(t["severity"], 0) + 1
    order = ["critical", "high", "medium", "low", "informational"]
    return [{"sev": s, "count": counts[s]} for s in order if s in counts]


# --- Builders ---

def build_forensic(surface, *, verdict, summary, analysis, techniques, recommendations,
                   extra_kpis=None):
    techs = sorted(techniques, key=lambda t: SEV_RANK.get(t["severity"], 5))
    crit = sum(1 for t in techs if t["severity"] == "critical")
    high = sum(1 for t in techs if t["severity"] == "high")
    kpis = [
        {"label": "Critical", "value": crit, "tone": "critical"},
        {"label": "High", "value": high, "tone": "high"},
        {"label": "Techniques", "value": len(techs), "tone": "neutral"},
    ] + (extra_kpis or [])
    data = {
        "verdict": verdict, "summary": summary, "analysis": analysis,
        "kpis": kpis, "severity": severity_counts(techs),
        "techniques": techs, "recommendations": [parse_reco(r) for r in recommendations],
    }
    comps = [
        {"id": "root", "component": "Column", "children": [
            "title", "verdict", "kpis", "sev_h", "sev", "tech_h", "tech", "reco_h", "reco", "analysis"]},
        {"id": "title", "component": "Text", "variant": "h2",
         "text": "Incident report — splunklib.ai agent → A2UI"},
        {"id": "verdict", "component": "VerdictBadge",
         "verdict": {"path": "/verdict"}, "summary": {"path": "/summary"}},
        {"id": "kpis", "component": "KpiRow", "path": "/kpis"},
        {"id": "sev_h", "component": "Text", "variant": "h3", "text": "Severity breakdown"},
        {"id": "sev", "component": "SeverityBar", "path": "/severity"},
        {"id": "tech_h", "component": "Text", "variant": "h3", "text": "MITRE ATT&CK kill-chain"},
        {"id": "tech", "component": "TechniqueTable", "path": "/techniques"},
        {"id": "reco_h", "component": "Text", "variant": "h3", "text": "Remediation recommendations"},
        {"id": "reco", "component": "RecommendationList", "path": "/recommendations"},
        {"id": "analysis", "component": "Collapsible",
         "title": "Detailed agent analysis (kill-chain & reasoning)", "text": {"path": "/analysis"}},
    ]
    return _doc(surface, comps, data)


def build_command(surface, *, verdict, summary, kpis, severity, techniques, lolbins):
    data = {"verdict": verdict, "summary": summary, "kpis": kpis,
            "severity": severity, "techniques": techniques, "lolbins": lolbins}
    comps = [
        {"id": "root", "component": "Column", "children": [
            "title", "verdict", "kpis", "sev_h", "sev", "tech_h", "tech", "lol_h", "lol"]},
        {"id": "title", "component": "Text", "variant": "h2",
         "text": "Forensic Command Center — compromised DC (SRL-2018)"},
        {"id": "verdict", "component": "VerdictBadge",
         "verdict": {"path": "/verdict"}, "summary": {"path": "/summary"}},
        {"id": "kpis", "component": "KpiRow", "path": "/kpis"},
        {"id": "sev_h", "component": "Text", "variant": "h3", "text": "Detections by severity"},
        {"id": "sev", "component": "SeverityBar", "path": "/severity"},
        {"id": "tech_h", "component": "Text", "variant": "h3", "text": "Detected MITRE ATT&CK kill-chain"},
        {"id": "tech", "component": "TechniqueTable", "path": "/techniques"},
        {"id": "lol_h", "component": "Text", "variant": "h3", "text": "Attack tools (LOLBins) in memory"},
        {"id": "lol", "component": "LolbinBars", "path": "/lolbins"},
    ]
    return _doc(surface, comps, data)


def build_incidents(surface, *, incidents):
    data = {"incidents": incidents}
    comps = [
        {"id": "root", "component": "Column", "children": ["title", "list"]},
        {"id": "title", "component": "Text", "variant": "h2",
         "text": "SOC incidents — automated AI triage"},
        {"id": "list", "component": "IncidentList", "path": "/incidents"},
    ]
    return _doc(surface, comps, data)
