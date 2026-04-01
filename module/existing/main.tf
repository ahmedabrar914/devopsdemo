#------------------------------------------------------------------------------
# Vault VPC
#------------------------------------------------------------------------------
module "vault_vpc" {
  source = "./modules/vpc"

  name_prefix                     = var.name_prefix
  vpc_cidr_block                  = var.vpc_cidr_block
  region                          = var.region
  azs                             = var.azs
  enable_nat_gateway              = var.enable_nat_gateway
  ami_bastion                     = var.ami_bastion
  bastion_iam_instance_profile    = module.vault_vpc_iam.bastion_iam_instance_profile
  bastion_host_security_group_id  = module.vault_vpc_sg.bastion_host_security_group_id
  ssm_endpoints_security_group_id = module.vault_vpc_sg.ssm_endpoints_security_group_id
  tags = {
    Environment = var.env
    Project     = var.name_prefix
  }
}
