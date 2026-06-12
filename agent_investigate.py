#!/usr/bin/env python3
"""Agent d'investigation forensique piloté par le Splunk MCP Server.

Se connecte au serveur MCP officiel (JSON-RPC sur /services/mcp), appelle les
outils forensiques custom comme le ferait un agent LLM, puis génère un rapport
d'incident structuré (Markdown + JSON) avec mapping MITRE ATT&CK.

Usage:
    python agent_investigate.py            # rapport complet
    python agent_investigate.py --json     # sortie JSON brute
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = Path(__file__).parent
MCP_URL = "https://localhost:8089/services/mcp"
TOKEN = (BASE / ".mcp_token").read_text().strip()
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

# Ordre de sévérité MITRE pour le tri du récit
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "unknown": 5}


class MCPClient:
    """Client JSON-RPC minimal pour le Splunk MCP Server."""

    def __init__(self):
        self._id = 0

    def _rpc(self, method, params=None):
        self._id += 1
        resp = requests.post(
            MCP_URL,
            headers=HEADERS,
            json={"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}},
            verify=False,
            timeout=60,
        )
        resp.raise_for_status()
        # La réponse peut être en SSE (text/event-stream) ou JSON brut
        data = None
        for line in resp.text.splitlines():
            line = line[5:].strip() if line.startswith("data:") else line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
        if data is None:
            raise RuntimeError(f"Réponse MCP illisible: {resp.text[:200]}")
        if "error" in data:
            raise RuntimeError(f"Erreur MCP ({method}): {data['error']}")
        return data.get("result", {})

    def initialize(self):
        return self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "forensic-agent", "version": "1.0"},
        })

    def list_tools(self):
        return self._rpc("tools/list").get("tools", [])

    def call(self, name, arguments=None):
        result = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        for c in result.get("content", []):
            if c.get("type") == "text":
                try:
                    return json.loads(c["text"]).get("results", [])
                except json.JSONDecodeError:
                    return c["text"]
        return []


def investigate():
    """Déroule l'investigation comme un agent : triage → pivot → timeline."""
    mcp = MCPClient()
    mcp.initialize()
    tools = {t["name"] for t in mcp.list_tools()}

    findings = {}
    # 1. Vue d'ensemble des techniques d'attaque détectées
    findings["techniques"] = mcp.call("forensics_find_attack_techniques")
    # 2. Triage par sévérité / MITRE
    findings["triage"] = mcp.call("forensics_triage_summary")
    # 3. Pivot sur les outils d'attaque clés vus dans les détections
    findings["processes"] = {}
    for proc in ("powershell.exe", "cmd.exe", "wmic.exe", "ntdsutil.exe"):
        rows = mcp.call("forensics_investigate_process", {"process_name": proc})
        if rows:
            findings["processes"][proc] = rows
    # 4. Chronologie
    findings["timeline"] = mcp.call("forensics_attack_timeline")
    findings["_tools_used"] = sorted(t for t in tools if t.startswith("forensics_"))
    return findings


def build_report(f):
    techniques = sorted(
        f["techniques"], key=lambda r: SEV_RANK.get(r.get("severity", "unknown"), 5)
    )
    crit = [t for t in techniques if t.get("severity") == "critical"]
    high = [t for t in techniques if t.get("severity") == "high"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    L = []
    L.append("# Rapport d'incident — base-dc-memory.img")
    L.append("")
    L.append(f"**Généré le :** {now}  ")
    L.append("**Cible :** Contrôleur de domaine Windows Server 2016 (scénario SRL-2018)  ")
    L.append("**Méthode :** Agent d'investigation via Splunk MCP Server (outils forensiques custom)  ")
    L.append(f"**Outils MCP utilisés :** {', '.join(f['_tools_used'])}")
    L.append("")
    verdict = "COMPROMIS" if crit else ("SUSPECT" if high else "RAS")
    L.append(f"## Verdict : **{verdict}**")
    L.append("")
    L.append(
        f"L'agent a identifié **{len(crit)} détection(s) critique(s)** et "
        f"**{len(high)} détection(s) élevée(s)** sur le contrôleur de domaine. "
        "La chaîne d'attaque correspond à une exfiltration d'identifiants Active Directory."
    )
    L.append("")
    L.append("## Kill-chain détectée (MITRE ATT&CK)")
    L.append("")
    L.append("| Sévérité | Règle | MITRE | Description |")
    L.append("|---|---|---|---|")
    for t in techniques:
        L.append(
            f"| {t.get('severity','')} | `{t.get('rule','')}` | "
            f"{t.get('mitre','')} | {t.get('description','')} |"
        )
    L.append("")
    L.append("## Processus suspects identifiés")
    L.append("")
    if f["processes"]:
        L.append("| Processus | PID | PPID | Création | Session |")
        L.append("|---|---|---|---|---|")
        for proc, rows in f["processes"].items():
            for r in rows:
                L.append(
                    f"| {r.get('process_name','')} | {r.get('pid','')} | "
                    f"{r.get('ppid','')} | {r.get('create_time','')} | {r.get('session_id','')} |"
                )
    else:
        L.append("_Aucun des outils d'attaque ciblés n'a été trouvé en mémoire vive._")
    L.append("")
    L.append("## Recommandations")
    L.append("")
    L.append("1. **Isoler** le contrôleur de domaine du réseau immédiatement.")
    L.append("2. **Réinitialiser** krbtgt (deux fois) et tous les comptes privilégiés — NTDS.dit est compromis.")
    L.append("3. **Rechercher** une propagation latérale via PsExec/WMI vers les autres hôtes.")
    L.append("4. **Conserver** l'image mémoire et les logs comme preuves.")
    L.append("")
    L.append("---")
    L.append("*Rapport produit automatiquement par l'agent forensique — Splunk Agentic Ops Hackathon.*")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="sortie JSON brute")
    args = ap.parse_args()

    findings = investigate()
    out_dir = BASE / "artifacts"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "incident_findings.json").write_text(json.dumps(findings, indent=2, ensure_ascii=False))

    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
        return

    report = build_report(findings)
    report_path = out_dir / "incident_report.md"
    report_path.write_text(report)
    print(report)
    print(f"\n[Rapport écrit dans {report_path}]", file=sys.stderr)


if __name__ == "__main__":
    main()
