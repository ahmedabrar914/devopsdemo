resource "aws_security_group" "vault_batch_token_lambda" {
  count       = var.enable_vault_batch_token_lambda_sg ? 1 : 0
  description = "Vault batch token rotator lambda security group"
  name        = "${var.name_prefix}-vault-batch-token-lambda-sg"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.name_prefix}-vault-batch-token-lambda-sg"
  }
}

resource "aws_security_group_rule" "vault_batch_token_lambda_egress_all" {
  count             = var.enable_vault_batch_token_lambda_sg ? 1 : 0
  type              = "egress"
  security_group_id = aws_security_group.vault_batch_token_lambda[0].id
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = var.vault_batch_token_lambda_egress_cidr_blocks
  description       = "Allow lambda outbound traffic"
}

resource "aws_security_group_rule" "allow_lambda_to_vault_8200" {
  count                    = var.enable_lambda_to_vault_ingress_rule && var.vault_security_group_id != null ? 1 : 0
  type                     = "ingress"
  security_group_id        = var.vault_security_group_id
  from_port                = 8200
  to_port                  = 8200
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.vault_batch_token_lambda[0].id
  description              = "Allow Vault batch token lambda to reach Vault API"
}

