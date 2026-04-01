# Outputs for Zscaler App Connector deployment

# App Connector instance IDs
output "app_connector_instance_ids" {
  description = "IDs of the App Connector instances"
  value       = aws_instance.app_connector[*].id
}

# App Connector private IPs
output "app_connector_private_ips" {
  description = "Private IP addresses of the App Connector instances"
  value       = aws_instance.app_connector[*].private_ip
}

# Security group IDs
output "security_group_ids" {
  description = "IDs of the security groups created for App Connector instances"
  value       = [data.aws_security_group.app_connector_sg.id]
}

# IAM role ARNs
output "iam_role_arns" {
  description = "ARNs of the IAM roles created for App Connector instances"
  value       = aws_iam_role.app_connector_role[*].arn
}

# SSM access policy ARN (if enabled)
output "ssm_access_policy_arn" {
  description = "ARN of the SSM access policy for App Connector instances"
  value       = var.enable_ssm_access ? data.aws_iam_policy.ssm_access_policy.arn : null
}

# App Connector AMI ID
output "app_connector_ami_id" {
  description = "ID of the App Connector AMI used"
  value       = data.aws_ami.app_connector.id
}

# App Connector AMI name
output "app_connector_ami_name" {
  description = "Name of the App Connector AMI used"
  value       = data.aws_ami.app_connector.name
}

# SSM connection command (direct to App Connectors - legacy method)
output "ssm_connection_commands" {
  description = "AWS CLI commands to connect to the App Connector instances via SSM (legacy method)"
  value = [
    for i in range(var.ac_count) :
    "aws ssm start-session --target ${aws_instance.app_connector[i].id} --region ${var.region}"
  ]
}

# Bastion host outputs
output "bastion_instance_id" {
  description = "ID of the bastion host instance"
  value       = aws_instance.bastion.id
}

# SSM connection command for bastion
output "bastion_ssm_connection_command" {
  description = "AWS CLI command to connect to the bastion host via SSM"
  value       = "aws ssm start-session --target ${aws_instance.bastion.id} --region ${var.region}"
}

# SSH commands to connect from bastion to app connectors
output "ssh_commands_from_bastion" {
  description = "SSH commands to connect from bastion to app connector instances"
  value = [
    for i in range(var.ac_count) :
    "ssh ec2-user@${aws_instance.app_connector[i].private_ip} -i ~/.ssh/id_rsa"
  ]
}

# Full connection instructions
output "connection_instructions" {
  description = "Instructions for connecting to app connector instances through the bastion host"
  value = <<-EOT
    To connect to app connector instances through the bastion host:
    
    1. Connect to the bastion host using SSM:
       aws ssm start-session --target ${aws_instance.bastion.id} --region ${var.region}
    
    2. From the bastion host, connect to an app connector instance:
       ${join("\n       ", [for i in range(var.ac_count) : "ssh ec2-user@${aws_instance.app_connector[i].private_ip} -i ~/.ssh/id_rsa  # App Connector ${i + 1}"])}
    
    Note: You may need to generate an SSH key on the bastion host if one doesn't exist.
  EOT
}
