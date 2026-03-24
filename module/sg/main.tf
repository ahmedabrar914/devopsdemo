resource "aws_security_group" "vault_batch_token_lambda" {
  count       = var.enable_vault_batch_token_lambda_sg ? 1 : 0
  description = "Vault batch token rotator lambda security group"
  name        = "${var.name_prefix}-vault-batch-token-lambda-sg"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name_prefix}-vault-batch-token-lambda-sg"
  }
}