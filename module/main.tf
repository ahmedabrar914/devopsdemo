module "vault_batch_token_rotator" {
  count  = var.enable_vault_batch_token_rotator ? 1 : 0
  source = "./modules/lambda_vault_batch_token_rotator"

  aws_region    = var.region
  function_name = var.vault_batch_token_rotator_function_name

  runtime     = var.vault_batch_token_rotator_runtime
  timeout     = var.vault_batch_token_rotator_timeout
  memory_size = var.vault_batch_token_rotator_memory_size

  log_level             = var.vault_batch_token_rotator_log_level
  log_retention_in_days = var.vault_batch_token_rotator_log_retention_in_days
  schedule_expression   = var.vault_batch_token_schedule_expression

  vault_primary_addr         = "https://${var.vault_fqdn}:8200"
  vault_ca_secret_id         = var.sm_vault_tls_ca_bundle
  vault_root_token_secret_id = var.vault_root_token_secret_id
  rotated_token_secret_id    = var.rotated_token_secret_id

  vault_root_token_json_key = var.vault_root_token_json_key
  vault_ca_secret_json_key  = var.vault_ca_secret_json_key

  policy_name     = var.vault_batch_token_policy_name
  role_name       = var.vault_batch_token_role_name
  batch_token_ttl = var.vault_batch_token_ttl

  http_timeout_seconds         = var.vault_batch_token_http_timeout_seconds
  http_connect_timeout_seconds = var.vault_batch_token_http_connect_timeout_seconds
  http_max_retries             = var.vault_batch_token_http_max_retries

  subnet_ids = module.vpc.private_subnet_ids

  security_group_ids = [
    aws_security_group.vault_batch_token_lambda_sg.id
  ]
}