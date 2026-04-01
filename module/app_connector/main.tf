# Main configuration for Zscaler App Connector deployment

# Terraform and provider configuration
terraform {
  required_version = ">= 1.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Locate latest App Connector AMI by product code
data "aws_ami" "app_connector" {
  most_recent = true

  filter {
    name   = "product-code"
    values = ["by1wc5269g0048ix2nqvr0362"] # Zscaler App Connector product code
  }

  owners = ["aws-marketplace"]
}

# Create key pair if provided
resource "aws_key_pair" "app_connector_key" {
  count      = var.ec2_key_pair != null ? 1 : 0
  key_name   = "${var.name_prefix}-key"
  public_key = var.ec2_key_pair
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-key"
      Owner = var.owner_tag
    }
  )
}

# User data template for App Connector provisioning
data "template_file" "app_connector_userdata" {
  template = file("${path.module}/userdata.tpl")
  
  vars = {
    zpa_provisioning_key = var.zpa_provisioning_key
  }
}

# Local file for reference (optional)
resource "local_file" "app_connector_userdata_file" {
  content  = data.template_file.app_connector_userdata.rendered
  filename = "${path.module}/app_connector_userdata.sh"
}

# App Connector EC2 instances
resource "aws_instance" "app_connector" {
  count = var.ac_count
  
  ami                    = data.aws_ami.app_connector.id
  instance_type          = var.ac_instance_type
  subnet_id              = element(var.private_subnet_ids, count.index % length(var.private_subnet_ids))
  vpc_security_group_ids = [data.aws_security_group.app_connector_sg.id]
  key_name               = var.ec2_key_pair != null ? aws_key_pair.app_connector_key[0].key_name : null
  user_data              = data.template_file.app_connector_userdata.rendered
  
  iam_instance_profile = var.reuse_iam ? aws_iam_instance_profile.app_connector_profile[0].name : aws_iam_instance_profile.app_connector_profile[count.index].name
  
  # Enable IMDSv2 as required in the documentation
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 64
    delete_on_termination = true
    encrypted             = true
    
    tags = merge(
      var.tags,
      {
        Name = "${var.name_prefix}-app-connector-${count.index + 1}-root"
        Owner = var.owner_tag
      }
    )
  }
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-app-connector-${count.index + 1}"
      Owner = var.owner_tag
    }
  )
  
  # Ensure the instance is created before destroying the old one
  lifecycle {
    create_before_destroy = true
  }
}
