resource "aws_security_group" "vault_batch_token_lambda" {
  count       = var.enable_vault_batch_token_rotator ? 1 : 0
  name        = "${var.name_prefix}-vault-batch-token-lambda-sg"
  description = "Security group for Vault batch token rotator lambda"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-vault-batch-token-lambda-sg"
    Env  = var.env
  }
}

resource "aws_security_group_rule" "allow_lambda_to_vault_8200" {
  count                    = var.enable_vault_batch_token_rotator ? 1 : 0
  type                     = "ingress"
  security_group_id        = var.vault_server_security_group_id
  from_port                = 8200
  to_port                  = 8200
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vault_batch_token_lambda[0].id
  description              = "Allow Vault batch token lambda to reach Vault API"
}




module "sg" {
  source = "./modules/sg"

  name_prefix = var.name_prefix
  vpc_id      = module.vpc.vpc_id

  # keep your existing sg module inputs here

  enable_vault_batch_token_lambda_sg       = var.enable_vault_batch_token_rotator
  vault_batch_token_lambda_egress_cidr_blocks = ["0.0.0.0/0"]

  enable_lambda_to_vault_ingress_rule = var.enable_vault_batch_token_rotator

  # Replace this with the ACTUAL vault SG ID source from your stack
  vault_security_group_id = module.aws_vault_hvd.vault_security_group_id
}

module "vault_batch_token_rotator" {
  count  = var.enable_vault_batch_token_rotator ? 1 : 0
  source = "./modules/lambda"

  aws_region    = var.region
  function_name = var.vault_batch_token_rotator_function_name

  runtime     = var.vault_batch_token_rotator_runtime
  timeout     = var.vault_batch_token_rotator_timeout
  memory_size = var.vault_batch_token_rotator_memory_size

  log_level             = var.vault_batch_token_rotator_log_level
  log_retention_in_days = var.vault_batch_token_rotator_log_retention_in_days
  schedule_expression   = var.vault_batch_token_schedule_expression

  vault_primary_addr         = "https://${var.vault_fqdn}:8200"
  vault_root_token_secret_id = var.vault_root_token_secret_id
  rotated_token_secret_id    = var.rotated_token_secret_id

  vault_root_token_json_key = var.vault_root_token_json_key

  policy_name     = var.vault_batch_token_policy_name
  role_name       = var.vault_batch_token_role_name
  batch_token_ttl = var.vault_batch_token_ttl

  http_timeout_seconds         = var.vault_batch_token_http_timeout_seconds
  http_connect_timeout_seconds = var.vault_batch_token_http_connect_timeout_seconds
  http_max_retries             = var.vault_batch_token_http_max_retries

  subnet_ids = module.vault_vpc.private_subnet_ids

  security_group_ids = [
    module.vault_core[0].vault_sg_id
  ]
}
