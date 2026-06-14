# Find Evil — Splunk delivery as code.
# Provisions the forensics index and installs the two apps (TA + Find Evil) into a
# running Splunk instance, using the official Splunk Terraform provider.

provider "splunk" {
  url                  = var.splunk_url
  username             = var.splunk_username
  password             = var.splunk_password
  insecure_skip_verify = true
}

locals {
  app_src = {
    find_evil        = "${path.module}/../splunk_app/find_evil"
    forensics_ingest = "${path.module}/../splunk_app/forensics_ingest"
  }
  # Where splunkd reads the .spl from. Defaults to the host dist/ dir; override via
  # var.spl_dir for a remote/containerized Splunk (e.g. /spl when bind-mounted).
  spl_dir = coalesce(var.spl_dir, abspath("${path.module}/dist"))
}

# Build the .spl archives from the app sources before installing. The trigger hashes
# every source file, so a change to any app file repackages and reinstalls on apply.
resource "null_resource" "package" {
  triggers = {
    find_evil = sha1(join("", [
      for f in sort(fileset(local.app_src.find_evil, "**")) :
      filesha1("${local.app_src.find_evil}/${f}")
    ]))
    forensics_ingest = sha1(join("", [
      for f in sort(fileset(local.app_src.forensics_ingest, "**")) :
      filesha1("${local.app_src.forensics_ingest}/${f}")
    ]))
  }

  provisioner "local-exec" {
    command = "python3 ${path.module}/package.py"
  }
}

# Ingestion add-on: provisions the `forensics` index (indexes.conf) and the
# CIM-aligned sourcetype props (forensics:process, forensics:yara_hit, forensics:incident).
resource "splunk_apps_local" "forensics_ingest" {
  name             = "${local.spl_dir}/forensics_ingest.spl"
  filename         = true
  explicit_appname = "forensics_ingest"
  update           = true

  depends_on = [null_resource.package]
}

# Main app: A2UI → @splunk/react-ui dashboards, MCP forensic tools, the splunklib.ai
# agent and the automated SOC triage workflow (savedsearches.conf).
# Installed after the TA so the forensics index exists before its searches load.
resource "splunk_apps_local" "find_evil" {
  name             = "${local.spl_dir}/find_evil.spl"
  filename         = true
  explicit_appname = "find_evil"
  update           = true

  depends_on = [
    null_resource.package,
    splunk_apps_local.forensics_ingest,
  ]
}
