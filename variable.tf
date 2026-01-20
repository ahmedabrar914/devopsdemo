variable "zotel_install_dir" {
  type    = string
  default = "/sc"
}

variable "zotel_installer_s3_uri" {
  type = string
}

variable "zotel_installer_name" {
  type    = string
  default = "zotelagent_1.6.0_p2_b3278_rhel.sh"
}

variable "zotel_service_group" {
  type    = string
  default = "vault_as_a_service"
}

variable "zotel_ingest_host" {
  type = string
}

variable "zotel_ingest_token" {
  type      = string
  sensitive = true
}