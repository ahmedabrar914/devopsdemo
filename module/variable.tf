variable "enable_vault_batch_token_rotator" {
  description = "Enable creation of Vault DR batch token rotator lambda"
  type        = bool
  default     = false
}

variable "vault_batch_token_rotator_function_name" {
  type    = string
  default = "vault-dr-batch-token-rotator"
}

variable "vault_batch_token_rotator_runtime" {
  type    = string
  default = "python3.12"
}

variable "vault_batch_token_rotator_timeout" {
  type    = number
  default = 60
}

variable "vault_batch_token_rotator_memory_size" {
  type    = number
  default = 256
}

variable "vault_batch_token_rotator_log_level" {
  type    = string
  default = "INFO"
}

variable "vault_batch_token_rotator_log_retention_in_days" {
  type    = number
  default = 14
}

variable "vault_batch_token_ttl" {
  type    = string
  default = "71h"
}

variable "vault_batch_token_policy_name" {
  type    = string
  default = "dr-secondary-promotion"
}

variable "vault_batch_token_role_name" {
  type    = string
  default = "failover-handler"
}

variable "vault_batch_token_schedule_expression" {
  type    = string
  default = null
}

variable "vault_root_token_secret_id" {
  type = string
}

variable "rotated_token_secret_id" {
  type = string
}

variable "vault_root_token_json_key" {
  type    = string
  default = "root_token"
}

variable "vault_ca_secret_json_key" {
  type    = string
  default = ""
}

variable "vault_batch_token_http_timeout_seconds" {
  type    = string
  default = "10"
}

variable "vault_batch_token_http_connect_timeout_seconds" {
  type    = string
  default = "5"
}

variable "vault_batch_token_http_max_retries" {
  type    = string
  default = "3"
}

##admin

variable "enable_vault_admin_token_rotator" {
  type    = bool
  default = false
}

variable "vault_admin_token_rotator_function_name" {
  type = string
}

variable "vault_admin_token_rotator_runtime" {
  type    = string
  default = "python3.12"
}

variable "vault_admin_token_rotator_timeout" {
  type    = number
  default = 60
}

variable "vault_admin_token_rotator_memory_size" {
  type    = number
  default = 256
}

variable "vault_admin_token_rotator_log_level" {
  type    = string
  default = "INFO"
}

variable "vault_admin_token_rotator_log_retention_in_days" {
  type    = number
  default = 14
}

variable "vault_admin_token_ttl" {
  type    = string
  default = "32d"
}

variable "vault_admin_token_policy_name" {
  type = string
}

variable "vault_admin_token_role_name" {
  type = string
}

variable "vault_admin_token_schedule_expression" {
  type    = string
  default = null
}

variable "admin_rotated_token_secret_id" {
  type = string
}

variable "vault_admin_token_http_timeout_seconds" {
  type    = string
  default = "10"
}

variable "vault_admin_token_http_connect_timeout_seconds" {
  type    = string
  default = "5"
}

variable "vault_admin_token_http_max_retries" {
  type    = string
  default = "3"
}

variable "vault_admin_token_renewable" {
  type    = string
  default = "true"
}

variable "vault_admin_token_explicit_max_ttl" {
  type    = string
  default = "32d"
}