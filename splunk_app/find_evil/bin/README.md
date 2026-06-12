# Agent forensique natif Splunk (splunklib.ai)

`forensic_agent_sdk.py` utilise l'**Agentic Splunk SDK** officiel (`splunklib.ai`,
SDK Python 3.0) : il se connecte au service Splunk, **auto-découvre les outils du
Splunk MCP Server** (nos 5 outils forensiques) et raisonne avec Claude — RBAC respecté.

## Déploiement (pattern app Splunk : SDK vendorisé dans lib/)
```bash
cd $SPLUNK_HOME/etc/apps/find_evil
pip install --target=lib "splunk-sdk[ai,anthropic]"   # ~93 Mo, non committé
```

## Lancement
```bash
export ANTHROPIC_API_KEY=...        # ou ../../.anthropic_key
SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
  python bin/forensic_agent_sdk.py "Ce DC est-il compromis ?"
```
Sortie : liste des outils auto-découverts + verdict (COMPROMIS) + kill-chain MITRE.
