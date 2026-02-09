variable "source_bucket_name" { type = string }
variable "source_bucket_arn"  { type = string }
variable "source_kms_key_arn" { type = string }

variable "replica_bucket_name" { type = string }

variable "replication_prefix" {
  type    = string
  default = "vault/raft-snapshots/"
}

variable "replica_object_lock_mode" {
  type    = string
  default = "GOVERNANCE"
}

variable "replica_object_lock_days" {
  type    = number
  default = 30
}

variable "tags" {
  type    = map(string)
  default = {}
}