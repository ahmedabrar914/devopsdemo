# Security resources for App Connector instances

# Use existing Security Group for App Connector instances
data "aws_security_group" "app_connector_sg" {
  name   = "${var.name_prefix}-ac-sg"
  vpc_id = var.vpc_id
}

# Add data source to get VPC CIDR block
data "aws_vpc" "selected" {
  id = var.vpc_id
}


# Add inbound rule to allow all intra-VPC traffic (similar to Cloud Connector service SG)
resource "aws_security_group_rule" "allow_vpc_traffic" {
  count = var.enable_ssm_access ? 1 : 0
  
  type              = "ingress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = [data.aws_vpc.selected.cidr_block]
  description       = "Allow all intra-VPC traffic"
  
  security_group_id = data.aws_security_group.app_connector_sg.id
}

# Add inbound rule for health check probe (similar to Cloud Connector service SG)
resource "aws_security_group_rule" "allow_health_check" {
  count = var.enable_ssm_access ? 1 : 0
  
  type              = "ingress"
  from_port         = 80 # Using port 80 as a default health check port
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = [data.aws_vpc.selected.cidr_block]
  description       = "Allow health check probe from VPC"
  
  security_group_id = data.aws_security_group.app_connector_sg.id
}

# Add inbound rule for HTTPS from VPC (similar to Cloud Connector service SG)
resource "aws_security_group_rule" "allow_https_from_vpc" {
  count = var.enable_ssm_access ? 1 : 0
  
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = [data.aws_vpc.selected.cidr_block]
  description       = "Allow HTTPS from VPC"
  
  security_group_id = data.aws_security_group.app_connector_sg.id
}

# Allow SSH access from the Bastion host
resource "aws_security_group_rule" "allow_ssh_from_bastion" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.bastion_sg.id
  description              = "Allow SSH from Bastion host"
  
  security_group_id = data.aws_security_group.app_connector_sg.id
}
