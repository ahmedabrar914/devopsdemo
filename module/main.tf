resource "aws_security_group" "vault_batch_token_lambda_sg" {
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