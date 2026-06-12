# Find Evil — Terraform delivery

Deploy the **Find Evil** forensic application to a running Splunk instance as code,
using the official [Splunk Terraform provider](https://registry.terraform.io/providers/splunk/splunk/latest).

`terraform apply` will:

1. **Package** `splunk_app/find_evil` and `splunk_app/forensics_ingest` into `dist/*.spl`
   (via `package.py`, triggered automatically when any app source file changes).
2. **Install** both apps with `splunk_apps_local`:
   - `forensics_ingest` — provisions the `forensics` index (`indexes.conf`, 10-year
     retention so the 2018 memory snapshot is never frozen) plus the CIM-aligned
     sourcetype props.
   - `find_evil` — A2UI → `@splunk/react-ui` dashboards, MCP forensic tools, the
     `splunklib.ai` agent, and the automated SOC triage workflow.

## What it provisions vs. prerequisites

| Provisioned by Terraform | Manual prerequisite |
|---|---|
| `forensics` index | Splunk Enterprise running and reachable |
| `forensics_ingest` TA (sourcetype props) | [Splunk MCP Server](https://splunkbase.splunk.com/app/7931) installed |
| `find_evil` app (dashboards, tools, agent, workflow) | [AI Toolkit](https://splunkbase.splunk.com/app/2890) + an LLM connection named `claude` — see [`../AI_TOOLKIT_SETUP.md`](../AI_TOOLKIT_SETUP.md) |

Terraform deploys the **configuration and apps**, not the **data**. After `apply`,
ingest the forensic events and (optionally) generate the A2UI snapshots:

```bash
# from the repo root
python ingest_to_splunk.py --host localhost --port 8089
SPLUNK_PASSWORD=… python splunk_app/find_evil/bin/gen_a2ui.py
```

## Usage

```bash
cd terraform
export SPLUNK_USERNAME=julien
export SPLUNK_PASSWORD='********'      # the provider reads these automatically

terraform init
terraform plan
terraform apply
```

Outputs include direct links to the four dashboards.

### Requirements

- Terraform >= 1.0 and `python3` on the machine running Terraform.
- Because `splunk_apps_local` reads the `.spl` path on the **Splunk server**, run
  Terraform on the same host as Splunk (the default for local dev). For a remote
  Splunk, copy `dist/*.spl` to the server and point `name` at that server-side path.

### The `| ai` workflow owner

The bundled `Find Evil - Auto Triage Workflow` saved search runs the `| ai` command,
which requires the `mltk_admin` role. Grant your dispatching user that role (and set
the saved search owner accordingly) once after install — this is an AI Toolkit
permission, not something the provider manages. See [`../AI_TOOLKIT_SETUP.md`](../AI_TOOLKIT_SETUP.md).

## Files

| File | Purpose |
|---|---|
| `versions.tf` | Provider requirements (`splunk/splunk`, `hashicorp/null`) |
| `variables.tf` | Inputs (URL, credentials, index sizing/retention) |
| `main.tf` | Provider, packaging, index, app installs |
| `outputs.tf` | Index name, installed apps, dashboard links |
| `package.py` | Builds `dist/*.spl` from the app sources |
| `terraform.tfvars.example` | Sample variable values |
