# Test the deployment on a clean Splunk (Docker)

Spin up a **fresh** Splunk Enterprise in a container and deploy Find Evil into it with the
Terraform module — proving the whole thing installs from scratch, not just on the dev machine.

## Prerequisites
- **Docker** (daemon running). On macOS, [Colima](https://github.com/abiosoft/colima) is a
  lightweight option: `brew install colima docker docker-compose && colima start`.
- **Terraform** and **python3** (already used by the module).

> The `splunk/splunk` image is **amd64-only**. On Apple Silicon it runs under emulation —
> it works, but the first start takes ~5–10 minutes and is CPU-heavy.

## Run
```bash
# 1. Build the .spl archives (bind-mounted into the container at /spl)
python3 ../terraform/package.py

# 2. Start a clean Splunk (different host ports so it won't clash with a local Splunk)
export SPLUNK_PASSWORD='Changeme123'        # >= 8 chars
docker compose up -d
docker compose logs -f splunk               # wait for "Ansible playbook complete" / healthy

# 3. Deploy with Terraform against the container
cd ../terraform
terraform init
SPLUNK_USERNAME=admin SPLUNK_PASSWORD="$SPLUNK_PASSWORD" \
  terraform apply -auto-approve \
    -var splunk_url=localhost:18089 \
    -var splunk_web_url=http://localhost:18000 \
    -var spl_dir=/spl

# 4. Open the app — the A2UI dashboards render the bundled snapshots (populated even
#    with an empty index, since they read JSON snapshots, not live searches)
open http://localhost:18000        # login: admin / $SPLUNK_PASSWORD
#   → App: Find Evil → Forensic Command Center, A2UI Native, AI Investigation, SOC Incidents

# 5. Tear down
cd ../docker && docker compose down -v
```

## What this validates
- The `forensics_ingest` TA installs and **creates the `forensics` index** on a clean instance.
- The `find_evil` app installs and its **4 A2UI dashboards render** (verdict, KPIs, MITRE
  table, LOLBins, incidents) from the bundled `*.a2ui.json` snapshots.
- The Terraform module is **portable** (uses `-var spl_dir=/spl` so `splunk_apps_local` reads
  the archives from the bind mount, not a host-specific path).

## What it does NOT cover (by design)
- The **MCP Server** and **AI Toolkit** Splunkbase apps are not in the base image, so the
  live `splunklib.ai` agent and the `| ai` SOC workflow don't run here. Those are validated
  on the full local install (see `../AI_TOOLKIT_SETUP.md`). To ingest data into the container
  too, run `python3 ../ingest_to_splunk.py --host localhost --port 18089` after step 3.
