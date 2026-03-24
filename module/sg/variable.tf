variable "enable_vault_batch_token_lambda_sg" {
  description = "Enable security group for Vault batch token rotator lambda"
  type        = bool
  default     = false
}

variable "vault_batch_token_lambda_egress_cidr_blocks" {
  description = "CIDR blocks allowed for lambda egress"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "enable_lambda_to_vault_ingress_rule" {
  description = "Enable ingress rule from lambda SG to Vault SG on 8200"
  type        = bool
  default     = false
}

variable "vault_security_group_id" {
  description = "Vault security group ID to allow lambda access into"
  type        = string
  default     = null
}