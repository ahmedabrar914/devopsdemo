module "s3_vault_snapshots_replica" {
  source = "./modules/s3_vault_snapshots_replica"

  providers = {
    aws    = aws
    aws.dr = aws.dr
  }

  source_bucket_name = module.s3_vault_snapshots.snapshot_bucket_name
  source_bucket_arn  = module.s3_vault_snapshots.snapshot_bucket_arn
  source_kms_key_arn = module.s3_vault_snapshots.kms_key_arn

  replica_bucket_name = var.replica_bucket_name
  replication_prefix  = var.replication_prefix

  replica_object_lock_mode = var.replica_object_lock_mode
  replica_object_lock_days = var.replica_object_lock_days

  tags = var.tags
}