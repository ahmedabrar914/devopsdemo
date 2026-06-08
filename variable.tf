variable "lambda_name" {
  type = string
}

variable "runtime" {
  type    = string
  default = "python3.12"
}

variable "timeout" {
  type    = number
  default = 300
}

variable "memory_size" {
  type    = number
  default = 1024
}

variable "bucket_name" {
  type = string
}

variable "dynamodb_table_name" {
  type = string
}

variable "quarantine_prefix" {
  type    = string
  default = "vault"
}

variable "arch" {
  type    = string
  default = "linux_amd64"
}

variable "retention_days" {
  type    = number
  default = 30
}

variable "object_lock_mode" {
  type    = string
  default = "GOVERNANCE"
}

variable "schedule_expression" {
  type    = string
  default = "rate(1 day)"
}