variable "bucket_name" {
  type = string
}

variable "vault_role_arn" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}