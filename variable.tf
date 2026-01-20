variable "zotel_installer_s3" {
  type = string
  default = "s3://vaas-prod-artifacts/otel-artifacts/zotelagent_1.6.0_p2_b3278_rhel.sh"
}

variable "zotel_installer_name" {
  type = string
  default = "zotelagent_1.6.0_p2_b3278_rhel.sh"
}

variable "zotel_service_group" {
  type = string
  default = "vault_as_a_service"
}

variable "zotel_ingest_host" {
  type = string
  default = "observability2-dev-ingest.zscaler.com"
}

variable "zotel_ingest_token" {
  type = string
  sensitive = true
}