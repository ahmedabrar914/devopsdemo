# Lambda for Vault Release Downloader
enable_vault_release_downloader = true

vault_release_downloader_function_name = "vault-release-dwnl"
vault_release_downloader_runtime       = "python3.12"
vault_release_downloader_timeout       = 300
vault_release_downloader_memory_size   = 1024

vault_release_downloader_bucket_name     = "vault-quarantine-prod-usw2"
vault_release_downloader_integrity_table = "vault-artifact-integrity"

vault_release_downloader_quarantine_prefix = "vault"
vault_release_downloader_arch              = "linux_amd64"
vault_release_downloader_retention_days    = 30
vault_release_downloader_object_lock_mode  = "GOVERNANCE"

vault_release_downloader_schedule_expression = "rate(1 day)"