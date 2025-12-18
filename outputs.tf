output "snapshot_bucket_name" {
  value = module.vault_snapshots_bucket.bucket_name
}

output "snapshot_bucket_arn" {
  value = module.vault_snapshots_bucket.bucket_arn
}