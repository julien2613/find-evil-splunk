output "index_name" {
  description = "The forensics index (provisioned by the forensics_ingest TA)."
  value       = var.index_name
}

output "installed_apps" {
  description = "Apps installed into Splunk."
  value       = [splunk_apps_local.forensics_ingest.name, splunk_apps_local.find_evil.name]
}

output "dashboards" {
  description = "Direct links to the Find Evil dashboards."
  value = {
    command_center   = "${var.splunk_web_url}/en-US/app/find_evil/forensic_command_center"
    a2ui_native      = "${var.splunk_web_url}/en-US/app/find_evil/a2ui_native"
    ai_investigation = "${var.splunk_web_url}/en-US/app/find_evil/ai_investigation"
    soc_incidents    = "${var.splunk_web_url}/en-US/app/find_evil/soc_incidents"
  }
}
