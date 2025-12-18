variable "region" {
  type = string
}

variable "name_prefix" {
  type = string
}

variable "env" {
  type = string
}

# IAM Role Vault will use to write snapshots (EC2 instance role or EKS IRSA role ARN)
variable "vault_role_arn" {
  type        = string
  description = "IAM role ARN used by Vault for S3 snapshot access"
}

variable "snapshot_bucket_name" {
  type        = string
  description = "Globally unique S3 bucket name"
}

variable "tags" {
  type    = map(string)
  default = {}
}