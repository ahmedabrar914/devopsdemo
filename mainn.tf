module "vault_release_downloader" {
  count  = var.enable_vault_release_downloader ? 1 : 0
  source = "../../../modules/vault-release-downloader"

  lambda_name = var.vault_release_downloader_function_name
  runtime     = var.vault_release_downloader_runtime
  timeout     = var.vault_release_downloader_timeout
  memory_size = var.vault_release_downloader_memory_size

  bucket_name         = var.vault_release_downloader_bucket_name
  dynamodb_table_name = var.vault_release_downloader_integrity_table

  quarantine_prefix = var.vault_release_downloader_quarantine_prefix
  arch              = var.vault_release_downloader_arch
  retention_days    = var.vault_release_downloader_retention_days
  object_lock_mode  = var.vault_release_downloader_object_lock_mode

  schedule_expression = var.vault_release_downloader_schedule_expression
}