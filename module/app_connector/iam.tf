# IAM resources for App Connector instances

# Get current AWS account ID
data "aws_caller_identity" "current" {}

# App Connector IAM Role
resource "aws_iam_role" "app_connector_role" {
  count = var.reuse_iam ? 1 : var.ac_count
  
  name = var.reuse_iam ? "${var.name_prefix}-ac-role" : "${var.name_prefix}-ac-role-${count.index + 1}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Effect = "Allow",
      Sid = ""
    }]
  })

  tags = merge(
    var.tags,
    {
      Name = var.reuse_iam ? "${var.name_prefix}-ac-role" : "${var.name_prefix}-ac-role-${count.index + 1}"
      Owner = var.owner_tag
    }
  )
}

# We're removing the AWS managed policy and relying on our custom policy instead

# Add custom inline policy for SSM Session Manager
resource "aws_iam_role_policy" "ssm_session_manager_policy" {
  count  = var.enable_ssm_access ? (var.reuse_iam ? 1 : var.ac_count) : 0
  name   = "SSMSessionManagerPolicy"
  role   = aws_iam_role.app_connector_role[count.index].name
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "ssmmessages:OpenDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:CreateControlChannel",
          "ssm:UpdateInstanceInformation"
        ],
        Effect   = "Allow",
        Resource = "*",
        Sid      = "CCPermitSSMSessionManager"
      }
    ]
  })
}

# Create instance profile
resource "aws_iam_instance_profile" "app_connector_profile" {
  count = var.reuse_iam ? 1 : var.ac_count
  
  name = var.reuse_iam ? "${var.name_prefix}-ac-profile" : "${var.name_prefix}-ac-profile-${count.index + 1}"
  role = aws_iam_role.app_connector_role[count.index].name
  
  tags = merge(
    var.tags,
    {
      Name = var.reuse_iam ? "${var.name_prefix}-ac-profile" : "${var.name_prefix}-ac-profile-${count.index + 1}"
      Owner = var.owner_tag
    }
  )
}

# Use existing SSM access policy
data "aws_iam_policy" "ssm_access_policy" {
  name = "${var.name_prefix}-ssm-access-policy"
}

# Add a new policy to allow SSH access from the bastion host
resource "aws_iam_role_policy" "app_connector_ssh_policy" {
  count  = var.reuse_iam ? 1 : var.ac_count
  name   = "SSHAccessFromBastionPolicy"
  role   = aws_iam_role.app_connector_role[count.index].name
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "ec2:DescribeInstances",
          "ec2-instance-connect:SendSSHPublicKey"
        ],
        Effect   = "Allow",
        Resource = "*",
        Sid      = "AllowSSHFromBastion"
      }
    ]
  })
}

# Add a policy to allow the bastion to assume a role to connect to app connectors
resource "aws_iam_policy" "bastion_to_app_connector_policy" {
  name        = "${var.name_prefix}-bastion-to-ac-policy"
  description = "Policy to allow bastion host to connect to app connector instances"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "ssm:StartSession",
          "ssm:TerminateSession",
          "ssm:ResumeSession",
          "ssm:DescribeSessions",
          "ssm:GetConnectionStatus"
        ],
        Effect   = "Allow",
        Resource = [
          "arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*",
          "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:document/AWS-StartSSHSession"
        ],
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Name": [
              for i in range(var.ac_count) : "${var.name_prefix}-app-connector-${i + 1}"
            ]
          }
        }
      }
    ]
  })
  
  tags = merge(
    var.tags,
    {
      Name = "${var.name_prefix}-bastion-to-ac-policy"
      Owner = var.owner_tag
    }
  )
}

# Attach the policy to the bastion role
resource "aws_iam_role_policy_attachment" "bastion_to_app_connector_attachment" {
  role       = aws_iam_role.bastion_role.name
  policy_arn = aws_iam_policy.bastion_to_app_connector_policy.arn
}

# Output information about the SSO role policy attachment
# Note: We don't directly attach the policy to the SSO role as it's likely managed outside Terraform
output "sso_policy_attachment_instructions" {
  value = var.enable_ssm_access ? "To grant SSO administrators access to App Connector instances via SSM, manually attach the policy '${data.aws_iam_policy.ssm_access_policy.arn}' to the SSO role '${var.sso_admin_role_name}'." : "SSM access is disabled. No policy needs to be attached."
}
