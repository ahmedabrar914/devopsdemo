variable "enable_vault_release_downloader" {
  type    = bool
  default = false
}

variable "vault_release_downloader_function_name" {
  type = string
}

variable "vault_release_downloader_runtime" {
  type    = string
  default = "python3.12"
}

variable "vault_release_downloader_timeout" {
  type    = number
  default = 300
}

variable "vault_release_downloader_memory_size" {
  type    = number
  default = 1024
}

variable "vault_release_downloader_bucket_name" {
  type = string
}

variable "vault_release_downloader_integrity_table" {
  type = string
}

variable "vault_release_downloader_quarantine_prefix" {
  type    = string
  default = "vault"
}

variable "vault_release_downloader_arch" {
  type    = string
  default = "linux_amd64"
}

variable "vault_release_downloader_retention_days" {
  type    = number
  default = 30
}

variable "vault_release_downloader_object_lock_mode" {
  type    = string
  default = "GOVERNANCE"
}

variable "vault_release_downloader_schedule_expression" {
  type    = string
  default = "rate(1 day)"
}