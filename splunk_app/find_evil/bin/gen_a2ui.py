"""Génère les snapshots A2UI des dashboards à partir de Splunk (déterministe, sans LLM).

Produit, dans appserver/static, trois documents A2UI rendus par a2ui_app.jsx :
  - forensic_report.a2ui.json : verdict + kill-chain + reco (réutilise l'analyse de l'agent)
  - command.a2ui.json         : vue d'ensemble (KPIs, sévérité, techniques, LOLBins)
  - incidents.a2ui.json       : incidents SOC (triage IA)

Lancement :
    SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
      python /Applications/Splunk/etc/apps/find_evil/bin/gen_a2ui.py
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

_LIB = os.path.join(os.path.dirname(__file__), "..", "lib")
sys.path.insert(0, os.path.abspath(_LIB))

import splunklib.results as sr
from splunklib.client import connect

import a2ui_catalog as cat

STATIC = Path("/Applications/Splunk/etc/apps/find_evil/appserver/static")
REPO = Path("/Users/julientaste/testsplunk")
LOLBINS = ("powershell.exe", "cmd.exe", "wmic.exe", "ntdsutil.exe", "psexec.exe",
           "bitsadmin.exe", "certutil.exe")


def _secret(env, fname):
    v = os.environ.get(env)
    if v:
        return v.strip()
    f = REPO / fname
    return f.read_text().strip() if f.exists() else None


def oneshot(service, query):
    reader = sr.JSONResultsReader(service.jobs.oneshot(
        query, output_mode="json", count=0, earliest_time="0", latest_time="now"))
    return [dict(r) for r in reader if isinstance(r, dict)]


def read_existing_forensic():
    """Récupère verdict/analyse/techniques/reco du snapshot agent existant."""
    f = STATIC / "forensic_report.a2ui.json"
    if not f.exists():
        return None
    data = {}
    for line in f.read_text().splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if "updateDataModel" in msg:
            data = msg["updateDataModel"].get("value", {})
    if not data:
        return None
    techs = data.get("techniques", [])
    # Compat : ancien format (label string) OU nouveau (déjà structuré)
    if techs and "label" in techs[0]:
        techs = [cat.parse_tech_label(t["label"]) for t in techs]
    recos = data.get("recommendations", [])
    recos = [r["text"] if isinstance(r, dict) and "text" in r else (r.get("text") if isinstance(r, dict) else r)
             for r in recos]
    return {
        "verdict": str(data.get("verdict", "COMPROMIS")).replace("Verdict :", "").strip(),
        "analysis": data.get("analysis", ""),
        "techniques": techs,
        "recommendations": [r for r in recos if r],
    }


def gen_forensic(service):
    base = read_existing_forensic()
    techs = oneshot(service, "search index=forensics sourcetype=forensics:yara_hit "
                    "| sort severity | table signature severity mitre description")
    techs = [{"signature": t.get("signature", ""), "severity": t.get("severity", "unknown"),
              "mitre": t.get("mitre", ""), "description": t.get("description", "")} for t in techs]
    if base and base["techniques"]:
        techs = base["techniques"]  # techniques de l'agent (déjà triées/annotées)
    procs = oneshot(service, "search index=forensics sourcetype=forensics:process "
                    "| stats dc(process_id) as p")
    nproc = int(procs[0]["p"]) if procs else 0
    crit = sum(1 for t in techs if t["severity"] == "critical")
    high = sum(1 for t in techs if t["severity"] == "high")
    verdict = (base or {}).get("verdict") or "COMPROMIS"
    summary = (f"{crit} détections critiques, {high} élevées — {len(techs)} techniques MITRE "
               f"sur le contrôleur de domaine ({nproc} processus analysés).")
    analysis = (base or {}).get("analysis") or "Analyse non disponible — lancer bin/a2ui_agent.py."
    recos = (base or {}).get("recommendations") or []
    doc = cat.build_forensic("forensic", verdict=verdict, summary=summary, analysis=analysis,
                             techniques=techs, recommendations=recos,
                             extra_kpis=[{"label": "Processus", "value": nproc, "tone": "info"}])
    (STATIC / "forensic_report.a2ui.json").write_text(doc)
    print(f"  forensic : verdict={verdict} | {len(techs)} techniques | {nproc} processus")


def gen_command(service):
    techs = oneshot(service, "search index=forensics sourcetype=forensics:yara_hit "
                    "| eval r=case(severity=\"critical\",1,severity=\"high\",2,severity=\"medium\",3,"
                    "severity=\"low\",4,1=1,5) | sort r | table signature severity mitre description")
    techs = [{"signature": t.get("signature", ""), "severity": t.get("severity", "unknown"),
              "mitre": t.get("mitre", ""), "description": t.get("description", "")} for t in techs]
    procs = oneshot(service, "search index=forensics sourcetype=forensics:process | stats dc(process_id) as p")
    nproc = int(procs[0]["p"]) if procs else 0
    lol = oneshot(service, "search index=forensics sourcetype=forensics:process process_name IN "
                  "(" + ",".join('"%s"' % n for n in LOLBINS) + ") | stats count by process_name | sort -count")
    lolbins = [{"name": r.get("process_name", ""), "count": int(r.get("count", 0))} for r in lol]
    crit = sum(1 for t in techs if t["severity"] == "critical")
    high = sum(1 for t in techs if t["severity"] == "high")
    kpis = [
        {"label": "Critiques", "value": crit, "tone": "critical"},
        {"label": "Élevées", "value": high, "tone": "high"},
        {"label": "Techniques", "value": len(techs), "tone": "neutral"},
        {"label": "Processus", "value": nproc, "tone": "info"},
    ]
    summary = ("Contrôleur de domaine Windows Server 2016 — exfiltration d'identifiants Active "
               "Directory (NTDS.dit + Mimikatz). Investigation pilotable par agent via Splunk MCP Server.")
    doc = cat.build_command("command", verdict="COMPROMIS", summary=summary, kpis=kpis,
                            severity=cat.severity_counts(techs), techniques=techs, lolbins=lolbins)
    (STATIC / "command.a2ui.json").write_text(doc)
    print(f"  command  : {crit} crit, {high} high | {len(lolbins)} LOLBins | {nproc} processus")


def gen_incidents(service):
    rows = oneshot(service, "search index=forensics sourcetype=forensics:incident "
                   "| sort -_time | table _time verdict critical_count high_count ai_analysis")
    incidents = []
    for r in rows:
        ts = r.get("_time", "")
        try:
            tlabel = datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
        except (ValueError, TypeError):
            tlabel = str(ts)
        incidents.append({
            "time": tlabel, "verdict": r.get("verdict", "?"),
            "critical": int(r.get("critical_count", 0) or 0),
            "high": int(r.get("high_count", 0) or 0),
            "analysis": r.get("ai_analysis", ""),
        })
    doc = cat.build_incidents("incidents", incidents=incidents)
    (STATIC / "incidents.a2ui.json").write_text(doc)
    print(f"  incidents: {len(incidents)} incident(s)")


def main():
    pwd = _secret("SPLUNK_PASSWORD", ".splunk_pass")
    if not pwd:
        sys.exit("Manque SPLUNK_PASSWORD")
    service = connect(scheme="https", host="localhost", port=8089,
                      username=os.environ.get("SPLUNK_USERNAME", "julien"),
                      password=pwd, autologin=True, verify=False)
    print("[gen_a2ui] génération des snapshots A2UI…")
    gen_forensic(service)
    gen_command(service)
    gen_incidents(service)
    print("OK — snapshots écrits dans", STATIC)


if __name__ == "__main__":
    main()
