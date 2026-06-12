# Splunk AI Toolkit setup (`| ai` command)

The `forensics_ai_triage` tool relies on the **`| ai`** SPL command of the Splunk AI
Toolkit. On **local Splunk Enterprise** (macOS Apple Silicon), getting it running
requires four steps — all discovered and validated on this machine.

## 1. Install the AI Toolkit
- Splunkbase **app 2890** → `Splunk_ML_Toolkit` in `etc/apps/`.

## 2. Install the Python engine (PSC) — exact variant
- Splunkbase **app 2882**, the **macOS Apple Silicon (arm64)** variant.
- Unpacks under `Splunk_SA_Scientific_Python_darwin_arm64` (the name `| ai` requires).
- ⚠️ **Linux/Intel do not work**: Python binaries are compiled per platform.

### Remove the macOS quarantine (otherwise SIGKILL)
The embedded Python is unsigned → Gatekeeper kills it (`error code 9`). Fix:
```bash
xattr -dr com.apple.quarantine \
  /Applications/Splunk/etc/apps/Splunk_SA_Scientific_Python_darwin_arm64
```
Then restart Splunk.

## 3. Grant the capability to the user
The `| ai` command requires `apply_ai_commander_command`, which is absent from the `admin` role.
Add the **`mltk_admin`** role to the user (Settings → Users), or grant
the `apply_ai_commander_command` / `edit_ai_commander_config` /
`list_ai_commander_config` capabilities to the desired role.

## 4. Create the LLM connection (UI)
In **AI Toolkit → Connections** (`/app/Splunk_ML_Toolkit/connections`):
- Provider **Anthropic**, model `claude-sonnet-4-5-20250929`
- Access Token = `sk-ant-…` key, endpoint `https://api.anthropic.com/v1/messages`
- Name the connection **`claude`** (referenced by the `forensics_ai_triage` tool).

> The Connections page only shows the providers once PSC is installed **and** the
> role is granted. Without that, only "Custom" appears.

## 5. Verify
```spl
| makeresults | ai connection="claude" prompt="say hello"
```
Should return a response from the model. After that, the `forensics_ai_triage` MCP tool
works (see `../forensic_ai_tool.json`).
