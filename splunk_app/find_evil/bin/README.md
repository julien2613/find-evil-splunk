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

## A2UI × Splunk SDK (`a2ui_agent.py`)

Intègre **A2UI** (https://a2ui.org) avec l'Agentic Splunk SDK : l'agent investigue via
les outils MCP, renvoie une **sortie structurée** (`output_schema` pydantic), convertie
en **A2UI JSONL** et écrite dans `appserver/static/forensic_report.a2ui.json`. La vue
**A2UI Native** la rend en composants `@splunk/react-ui`.

Pipeline : Agent SDK (tools MCP) → structured_output → A2UI → render React Splunk.

```bash
SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
  python bin/a2ui_agent.py
# -> verdict + A2UI écrit ; rendu sur /app/find_evil/a2ui_native
```
> N.B. : allowlist limitée aux outils sans `row_limit` (Anthropic strict refuse les
> contraintes min/max sur les entiers).
