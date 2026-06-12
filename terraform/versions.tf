terraform {
  required_version = ">= 1.0"

  required_providers {
    splunk = {
      source  = "splunk/splunk"
      version = "~> 1.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}
