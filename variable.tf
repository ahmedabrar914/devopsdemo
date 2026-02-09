variable "replica_region" {
  type        = string
  description = "DR region for S3 snapshot replica"
}

variable "replica_bucket_name" {
  type        = string
  description = "Replica bucket name in replica_region"
}

variable "replication_prefix" {
  type        = string
  description = "Only replicate this prefix"
  default     = "vault/raft-snapshots/"
}

variable "replica_object_lock_mode" {
  type        = string
  default     = "GOVERNANCE"
}

variable "replica_object_lock_days" {
  type        = number
  default     = 30
}