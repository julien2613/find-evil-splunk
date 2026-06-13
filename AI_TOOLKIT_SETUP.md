# Splunk AI Toolkit setup (`| ai` command)

Find Evil uses the **`| ai`** SPL command of the Splunk AI Toolkit to make a model reason **directly inside the Splunk search engine**.

This is one of the two AI paths in the project (the other is the official `splunklib.ai` Agent that talks to Claude via the Anthropic API and auto-discovers our MCP tools). The `| ai` path is what enables:

- The `forensics_ai_triage` MCP tool (the agent or an analyst can ask for an AI verdict from inside Splunk).
- The **fully automated SOC workflow** (`Find Evil - Auto Triage Workflow` saved search) that detects critical YARA hits, runs `| ai` for verdict + kill-chain + recommendations, and writes a `forensics:incident` with zero manual steps.

On **local Splunk Enterprise on macOS Apple Silicon**, getting `| ai` running is non-trivial. The steps below are the exact procedure that worked on this machine.

> **Important**: The four A2UI dashboards themselves render **pre-built snapshots** (`forensic_report.a2ui.json`, `command.a2ui.json`, etc.). They do **not** require `| ai` at view time. Only the `ai_triage` MCP tool and the scheduled SOC alert need the AI Toolkit configured.


## 1. Install the AI Toolkit
- Splunkbase **app 2890** → `Splunk_ML_Toolkit` in `etc/apps/`.

## 2. Install the Python engine (PSC) — exact variant
- Splunkbase **app 2882**, the **macOS Apple Silicon (arm64)** variant.
- Unpacks under `Splunk_SA_Scientific_Python_darwin_arm64` (the name `| ai` requires).
- ⚠️ **Linux/Intel builds do not work**: Python binaries are compiled per platform.

### Remove the macOS quarantine (otherwise SIGKILL)
The embedded Python is unsigned → Gatekeeper kills it (`error code 9`). Fix:
```bash
xattr -dr com.apple.quarantine \
  /Applications/Splunk/etc/apps/Splunk_SA_Scientific_Python_darwin_arm64
```
Then restart Splunk.

## 3. Grant the capability to the user
The `| ai` command requires `apply_ai_commander_command`, which is absent from the `admin` role.
Add the **`mltk_admin`** role to the user (Settings → Users), or grant the
`apply_ai_commander_command` / `edit_ai_commander_config` / `list_ai_commander_config`
capabilities to the desired role. The SOC saved search must be **owned by a user with this role**
(the workflow dispatches `| ai`).

## 4. Create the LLM connection (UI)
In **AI Toolkit → Connections** (`/app/Splunk_ML_Toolkit/connections`):
- Provider **Anthropic**, model `claude-sonnet-4-5-20250929`
- Access Token = `sk-ant-…` key, endpoint `https://api.anthropic.com/v1/messages`
- Name the connection **`claude`** (referenced by `forensics_ai_triage` and the SOC workflow).

> The Connections page only lists the providers once PSC is installed **and** the role is granted.
> Without that, only "Custom" appears.

## 5. Verify
```spl
| makeresults | ai connection="claude" prompt="say hello"
```
Should return a model response. After that, both the `forensics_ai_triage` MCP tool and the scheduled SOC workflow will work.

## 6. Ownership of the automated SOC alert (important)

The saved search `Find Evil - Auto Triage Workflow` (in `find_evil/default/savedsearches.conf`) dispatches `| ai` on a schedule.

It **must be owned by (or run as) a user who has the `apply_ai_commander_command` capability** (typically by assigning the `mltk_admin` role).

After installing the app via Terraform or manually, you usually need to fix the owner/ACL:

```bash
curl -sk -u admin:password -X POST \
  "https://localhost:8089/servicesNS/nobody/find_evil/saved/searches/Find%20Evil%20-%20Auto%20Triage%20Workflow/acl" \
  -d owner=julien -d sharing=app
```

---

**Summary of the two AI paths in Find Evil**

- **splunklib.ai Agent path** (`forensic_agent_sdk.py` / `a2ui_agent.py`): Uses the official Agentic SDK + direct Anthropic calls + auto-discovery of our 5 MCP tools. Produces text or A2UI. Runs as a script that connects to Splunk.
- **`| ai` inside SPL path**: LLM reasoning happens inside the Splunk search process. Powers the `ai_triage` tool exposed to the MCP Server and (crucially) the hands-off scheduled SOC workflow that creates `forensics:incident` events.

Both ultimately feed the same A2UI dashboards and the same `forensics` index.
