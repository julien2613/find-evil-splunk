#!/bin/bash
# Setup reproductible — index forensics, HEC, et outils MCP forensiques.
# Prérequis : Splunk Enterprise local + app Splunk_MCP_Server installée.
# Usage : SPLUNK_AUTH='user:pass' ./setup.sh
set -euo pipefail

SPLUNK_HOME="${SPLUNK_HOME:-/Applications/Splunk}"
MGMT="https://localhost:8089"
AUTH="${SPLUNK_AUTH:?Exporter SPLUNK_AUTH='user:pass' avant de lancer}"
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "==> 1. App forensics_ingest (index + HEC)"
APP="$SPLUNK_HOME/etc/apps/forensics_ingest/local"
mkdir -p "$APP/../metadata" "$APP"
HEC_TOKEN="$(cat "$HERE/.hec_token" 2>/dev/null || uuidgen | tr 'A-Z' 'a-z')"
echo "$HEC_TOKEN" > "$HERE/.hec_token"; chmod 600 "$HERE/.hec_token"

cat > "$APP/indexes.conf" <<EOF
[forensics]
homePath = \$SPLUNK_DB/forensics/db
coldPath = \$SPLUNK_DB/forensics/colddb
thawedPath = \$SPLUNK_DB/forensics/thaweddb
maxTotalDataSizeMB = 10240
frozenTimePeriodInSecs = 315360000
EOF

cat > "$APP/inputs.conf" <<EOF
[http]
disabled = 0
enableSSL = 1

[http://forensics_hec]
disabled = 0
token = $HEC_TOKEN
index = forensics
indexes = forensics
sourcetype = forensics:event
EOF
echo "    HEC token: $HEC_TOKEN"

# props.conf : parsing JSON + _time depuis event_time (évidence 2018 -> MAX_DAYS_AGO).
# Requis par l'ingestion via le SDK (index.attached_socket) — voir ingest_to_splunk.py.
cat > "$APP/props.conf" <<'EOF'
[forensics:process]
INDEXED_EXTRACTIONS = json
TIMESTAMP_FIELDS = event_time
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%z
MAX_DAYS_AGO = 4000
KV_MODE = none
AUTO_KV_JSON = false

[forensics:yara_hit]
INDEXED_EXTRACTIONS = json
TIMESTAMP_FIELDS = event_time
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%z
MAX_DAYS_AGO = 4000
KV_MODE = none
AUTO_KV_JSON = false
EOF

echo "==> 2. Redémarrage Splunk (prise en compte index/HEC)"
"$SPLUNK_HOME/bin/splunk" restart > /dev/null
sleep 5

echo "==> 3. Token MCP (audience=mcp)"
curl -sk -u "$AUTH" -X POST "$MGMT/services/admin/token-auth/tokens_auth?output_mode=json" -d disabled=0 >/dev/null 2>&1 || true
TOK=$(curl -sk -u "$AUTH" -X POST "$MGMT/services/authorization/tokens?output_mode=json" \
  -d name="${AUTH%%:*}" --data-urlencode "audience=mcp" --data-urlencode "expires_on=+30d" \
  | python3 -c "import sys,json;e=json.load(sys.stdin).get('entry',[]);print(e[0]['content']['token'] if e else '')")
[ -n "$TOK" ] && echo "$TOK" > "$HERE/.mcp_token" && chmod 600 "$HERE/.mcp_token" && echo "    Token MCP créé (len ${#TOK})"

echo "==> 4. Enregistrement des outils MCP forensiques"
# Fusionne les 4 outils SPL + l'outil ai_triage (| ai) en un seul batch.
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

echo "==> 5. Activation des outils (ai_triage nécessite le AI Toolkit — voir AI_TOOLKIT_SETUP.md)"
for name in find_attack_techniques investigate_process attack_timeline triage_summary ai_triage; do
  tid="forensics:forensics_${name}"
  curl -sk -u "$AUTH" -X POST "$MGMT/services/mcp_tools?output_mode=json" \
    -H "Content-Type: application/json" \
    -d "{\"tool_id\":\"$tid\",\"tool_name\":\"forensics_${name}\",\"enabled\":true}" >/dev/null
  echo "    activé: forensics_${name}"
done

echo "==> Setup terminé. Index 'forensics' + HEC + 4 outils MCP prêts."
