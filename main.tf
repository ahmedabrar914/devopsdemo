module "vault_snapshots_bucket" {
  source = "./modules/s3_vault_snapshots"

  bucket_name    = var.snapshot_bucket_name
  vault_role_arn = var.vault_role_arn

  tags = merge(
    {
      Environment = var.env
      Project     = var.name_prefix
    },
    var.tags
  )
}