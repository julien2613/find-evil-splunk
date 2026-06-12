#!/bin/bash
# Lance le backend agent (port 8800) + le frontend CopilotKit (port 3000).
# Prérequis : ANTHROPIC_API_KEY exportée, Splunk + MCP Server actifs, setup.sh joué.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

: "${ANTHROPIC_API_KEY:?Exporter ANTHROPIC_API_KEY avant de lancer (clé du modèle agent)}"

echo "==> Backend agent ADK (port 8800)"
cd "$HERE/agent"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
.venv/bin/python -m uvicorn agent:app --host 0.0.0.0 --port 8800 &
AGENT_PID=$!

echo "==> Frontend CopilotKit (port 3000)"
cd "$HERE/frontend"
[ -d node_modules ] || npm install
COPILOTKIT_TELEMETRY_DISABLED=true npm run dev &
WEB_PID=$!

trap 'kill $AGENT_PID $WEB_PID 2>/dev/null' INT TERM
echo ""
echo "  Agent  : http://localhost:8800/"
echo "  UI     : http://localhost:3000/"
echo "  Ctrl+C pour tout arrêter."
wait
