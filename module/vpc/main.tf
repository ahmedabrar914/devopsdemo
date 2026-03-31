#------------------------------------------------------------------------------
# Bastion Host
#------------------------------------------------------------------------------
data "aws_ami" "bastion" {
  most_recent = true
  owners      = var.bastion_host_ami_owners
  filter {
    name   = "name"
    values = [var.bastion_instance_ami_name_filter]
  }
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_endpoint_type   = "Interface"
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.ssm"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private[0].id]
  security_group_ids  = [var.ssm_endpoints_security_group_id]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ssm-vpc-endpoint"
  })

}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_endpoint_type   = "Interface"
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.ssmmessages"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private[0].id]
  security_group_ids  = [var.ssm_endpoints_security_group_id]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ssmmessages-vpc-endpoint"
  })

}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_endpoint_type   = "Interface"
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.ec2messages"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.private[0].id]
  security_group_ids  = [var.ssm_endpoints_security_group_id]

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ec2messages-vpc-endpoint"
  })
}

resource "aws_instance" "bastion" {
  subnet_id              = aws_subnet.private[0].id
  ami                    = var.ami_bastion
  instance_type          = "t3.micro"
  iam_instance_profile   = var.bastion_iam_instance_profile
  vpc_security_group_ids = [var.bastion_host_security_group_id]

  root_block_device {
    encrypted = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-bastion-box"
  })
}
