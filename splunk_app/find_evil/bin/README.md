# Native Splunk forensic agent (splunklib.ai)

`forensic_agent_sdk.py` uses the official **Agentic Splunk SDK** (`splunklib.ai`,
Python SDK 3.0): it connects to the Splunk service, **auto-discovers the tools of the
Splunk MCP Server** (our 5 forensic tools) and reasons with Claude — RBAC enforced.

## Deployment (Splunk app pattern: SDK vendored in lib/)
```bash
cd $SPLUNK_HOME/etc/apps/find_evil
pip install --target=lib "splunk-sdk[ai,anthropic]"   # ~93 MB, not committed
```

## Run
```bash
export ANTHROPIC_API_KEY=...        # or ../../.anthropic_key
SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
  python bin/forensic_agent_sdk.py "Is this DC compromised?"
```
Output: list of auto-discovered tools + verdict (COMPROMISED) + MITRE kill-chain.

## A2UI × Splunk SDK (`a2ui_agent.py`)

Integrates **A2UI** (https://a2ui.org) with the Agentic Splunk SDK: the agent investigates via
the MCP tools, returns a **structured output** (pydantic `output_schema`), converted
to **A2UI JSONL** and written to `appserver/static/forensic_report.a2ui.json`. The
**A2UI Native** view renders it as `@splunk/react-ui` components.

Pipeline: SDK Agent (MCP tools) → structured_output → A2UI → render React Splunk.

```bash
SPLUNK_HOME=/Applications/Splunk SPLUNK_PASSWORD=... \
  python bin/a2ui_agent.py
# -> verdict + A2UI written; rendered at /app/find_evil/a2ui_native
```
> N.B.: allowlist limited to tools without `row_limit` (Anthropic strict refuses
> min/max constraints on integers).
