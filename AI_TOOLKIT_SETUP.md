# Splunk AI Toolkit setup (`| ai` command)

Find Evil uses the **`| ai`** SPL command of the Splunk AI Toolkit to make a model reason
**inside the search engine**. On **local Splunk Enterprise** (macOS Apple Silicon), getting it
running requires the steps below — all discovered and validated on this machine.

## Where `| ai` is used
- **`forensics_ai_triage`** MCP tool — aggregates the YARA detections and asks Claude, via `| ai`,
  for a verdict + kill-chain + remediation, all from one SPL pipeline (see [`../forensic_ai_tool.json`](forensic_ai_tool.json)).
- **Automated SOC workflow** — the scheduled saved search `Find Evil - Auto Triage Workflow`
  detects critical detections, runs `| ai`, and writes a notable `forensics:incident`.

> The **dashboards** render pre-built **A2UI snapshots** (`@splunk/react-ui` controls), not a live
> `| ai` panel — so viewing the dashboards does not require `| ai`. It is the **workflow** and the
> **`ai_triage` tool** that need the setup below.

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
Should return a model response. After that, the `forensics_ai_triage` MCP tool and the SOC
workflow both work.

> Note: this `| ai` setup is the Splunk AI Toolkit path. The `splunklib.ai` **agent**
> (`bin/a2ui_agent.py`, `bin/forensic_agent_sdk.py`) talks to Claude through the Anthropic API
> directly and does not depend on the AI Toolkit.
