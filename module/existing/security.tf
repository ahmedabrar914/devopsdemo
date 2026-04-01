#------------------------------------------------------------------------------
# Bastion Host SG Resources
#------------------------------------------------------------------------------
resource "aws_security_group" "ssm_endpoints" {
  description = "SSM Endpoints Security Group"
  name        = "${var.name_prefix}-ssm-endpoints"
  vpc_id      = var.vpc_id
  tags = {
    Name = "${var.name_prefix}-ssm-endpoints"
  }
}

resource "aws_security_group_rule" "ssm_ingress_from_private_subnet" {
  for_each          = local.ssm_ingress_rules
  type              = "ingress"
  security_group_id = aws_security_group.ssm_endpoints.id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  cidr_blocks       = each.value.cidr_blocks
  description       = each.value.description
}

resource "aws_security_group_rule" "bastion_ingress_ssm" {
  for_each                 = local.bastion_ingress_ssm_rules
  type                     = "ingress"
  security_group_id        = aws_security_group.ssm_endpoints.id
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  protocol                 = each.value.protocol
  source_security_group_id = each.value.source_security_group_id
  description              = each.value.description
}

resource "aws_security_group_rule" "allow_bastion_to_ssm" {
  for_each                 = local.bastion_to_ssm_rules
  type                     = "ingress"
  security_group_id        = aws_security_group.ssm_endpoints.id
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  protocol                 = each.value.protocol
  source_security_group_id = each.value.source_security_group_id
  description              = each.value.description
}

resource "aws_security_group" "bastion" {
  description = "Bastion Host Security Group"
  name        = "${var.name_prefix}-bastion-instance-sg"
  vpc_id      = var.vpc_id
  tags = {
    Name = "${var.name_prefix}-bastion-instance-sg"
  }
}

resource "aws_security_group_rule" "bastion_ingress_self" {
  for_each          = local.bastion_self_ingress_rules
  type              = "ingress"
  security_group_id = aws_security_group.bastion.id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  self              = each.value.self
  description       = each.value.description
}

resource "aws_security_group_rule" "allow_ssm_from_bastion" {
  for_each                 = local.bastion_egress_ssm_rules
  type                     = "egress"
  security_group_id        = aws_security_group.bastion.id
  from_port                = each.value.from_port
  to_port                  = each.value.to_port
  protocol                 = each.value.protocol
  source_security_group_id = each.value.source_security_group_id
  description              = each.value.description
}

resource "aws_security_group_rule" "bastion_egress_dns_udp" {
  for_each          = local.bastion_egress_dns_udp_rules
  type              = "egress"
  security_group_id = aws_security_group.bastion.id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  cidr_blocks       = each.value.cidr_blocks
  description       = each.value.description
}

resource "aws_security_group_rule" "bastion_egress_dns_tcp" {
  for_each          = local.bastion_egress_dns_tcp_rules
  type              = "egress"
  security_group_id = aws_security_group.bastion.id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  cidr_blocks       = each.value.cidr_blocks
  description       = each.value.description
}
