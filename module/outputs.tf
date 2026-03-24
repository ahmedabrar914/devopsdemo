output "vault_batch_token_rotator_function_name" {
  value = var.enable_vault_batch_token_rotator ? module.vault_batch_token_rotator[0].function_name : null
}

output "vault_batch_token_rotator_function_arn" {
  value = var.enable_vault_batch_token_rotator ? module.vault_batch_token_rotator[0].function_arn : null
}

output "vault_batch_token_lambda_sg_id" {
  value = aws_security_group.vault_batch_token_lambda_sg.id
}