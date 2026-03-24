variable "aws_region" {
  type = string
}

variable "function_name" {
  type = string
}

variable "runtime" {
  type    = string
  default = "python3.12"
}

variable "timeout" {
  type    = number
  default = 60
}

variable "memory_size" {
  type    = number
  default = 256
}

variable "subnet_ids" {
  type = list(string)
}

variable "security_group_ids" {
  type = list(string)
}

variable "vault_primary_addr" {
  type = string
}

variable "vault_ca_secret_id" {
  type = string
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

variable "policy_name" {
  type    = string
  default = "dr-secondary-promotion"
}

variable "role_name" {
  type    = string
  default = "failover-handler"
}

variable "batch_token_ttl" {
  type    = string
  default = "71h"
}

variable "http_timeout_seconds" {
  type    = string
  default = "10"
}

variable "http_connect_timeout_seconds" {
  type    = string
  default = "5"
}

variable "http_max_retries" {
  type    = string
  default = "3"
}

variable "log_level" {
  type    = string
  default = "INFO"
}

variable "log_retention_in_days" {
  type    = number
  default = 14
}

variable "schedule_expression" {
  type    = string
  default = null
}