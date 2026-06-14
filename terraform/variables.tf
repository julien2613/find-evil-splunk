variable "splunk_url" {
  description = "Splunk management endpoint (splunkd REST), host:port. https:// is assumed."
  type        = string
  default     = "localhost:8089"
}

variable "splunk_web_url" {
  description = "Splunk Web base URL, used only to build the dashboard links in outputs."
  type        = string
  default     = "http://localhost:8000"
}

variable "splunk_username" {
  description = "Splunk admin user. Leave null to read the SPLUNK_USERNAME environment variable."
  type        = string
  default     = null
}

variable "splunk_password" {
  description = "Splunk admin password. Prefer the SPLUNK_PASSWORD environment variable over committing this."
  type        = string
  sensitive   = true
  default     = null
}

variable "index_name" {
  description = "Name of the forensic index. Provisioned by the forensics_ingest TA (indexes.conf); must match that stanza."
  type        = string
  default     = "forensics"
}

variable "spl_dir" {
  description = "Directory (readable by the Splunk server) holding the packaged .spl archives. Override for a remote/containerized Splunk where the path differs from the host (e.g. /spl when bind-mounted)."
  type        = string
  default     = null
}
