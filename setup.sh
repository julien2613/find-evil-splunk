#!/bin/bash
# Reproducible setup — forensics index, HEC, and forensic MCP tools.
# Prerequisites: local Splunk Enterprise + Splunk_MCP_Server app installed.
# Usage: SPLUNK_AUTH='user:pass' ./setup.sh
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/Applications/Splunk}"
MGMT="https://localhost:8089"
AUTH="${SPLUNK_AUTH:?Export SPLUNK_AUTH='user:pass' before running}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "==> 1. Deploying the versioned TA forensics_ingest (index + sourcetypes)"
# Single source of truth: the repo's TA (indexes.conf + props.conf + app.conf).
# Ingestion is done via the Python SDK (ingest_to_splunk.py) — no HEC.
cp -R "$HERE/splunk_app/forensics_ingest/." "$SPLUNK_HOME/etc/apps/forensics_ingest/"
echo "    TA deployed (props.conf index-time settings apply on restart)"

echo "==> 2. Restarting Splunk (apply index/HEC changes)"
"$SPLUNK_HOME/bin/splunk" restart > /dev/null
sleep 5

echo "==> 3. Token MCP (audience=mcp)"
curl -sk -u "$AUTH" -X POST "$MGMT/services/admin/token-auth/tokens_auth?output_mode=json" -d disabled=0 >/dev/null 2>&1 || true
TOK=$(curl -sk -u "$AUTH" -X POST "$MGMT/services/authorization/tokens?output_mode=json" \
  -d name="${AUTH%%:*}" --data-urlencode "audience=mcp" --data-urlencode "expires_on=+30d" \
  | python3 -c "import sys,json;e=json.load(sys.stdin).get('entry',[]);print(e[0]['content']['token'] if e else '')")
[ -n "$TOK" ] && echo "$TOK" > "$HERE/.mcp_token" && chmod 600 "$HERE/.mcp_token" && echo "    MCP token created (len ${#TOK})"

echo "==> 4. Registering the forensic MCP tools"
# Merges the 4 SPL tools + the ai_triage tool (| ai) into a single batch.
python3 - "$HERE" <<'PY'
import json, sys
here = sys.argv[1]
base = json.load(open(f"{here}/forensic_mcp_tools.json"))
ai = json.load(open(f"{here}/forensic_ai_tool.json"))
base["tools"].extend(ai["tools"])
json.dump(base, open(f"{here}/forensic_mcp_tools_all.json", "w"), ensure_ascii=False, indent=2)
PY
curl -sk -u "$AUTH" -X POST "$MGMT/services/mcp_tools?output_mode=json" \
  -H "Content-Type: application/json" --data-binary @"$HERE/forensic_mcp_tools_all.json" | python3 -m json.tool

echo "==> 5. Enabling the tools (ai_triage requires the AI Toolkit — see AI_TOOLKIT_SETUP.md)"
for name in find_attack_techniques investigate_process attack_timeline triage_summary ai_triage; do
  tid="forensics:forensics_${name}"
  curl -sk -u "$AUTH" -X POST "$MGMT/services/mcp_tools?output_mode=json" \
    -H "Content-Type: application/json" \
    -d "{\"tool_id\":\"$tid\",\"tool_name\":\"forensics_${name}\",\"enabled\":true}" >/dev/null
  echo "    enabled: forensics_${name}"
done

echo "==> Setup complete. Index 'forensics' + HEC + 4 MCP tools ready."
