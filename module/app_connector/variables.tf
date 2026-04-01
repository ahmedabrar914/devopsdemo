# Variables for Zscaler App Connector deployment

# Basic configuration
variable "name_prefix" {
  description = "Prefix to use for resource names"
  type        = string
  validation {
    condition     = length(var.name_prefix) <= 12
    error_message = "Variable name_prefix must be 12 or less characters."
  }
}

variable "region" {
  description = "AWS region where resources will be created"
  type        = string
}

variable "owner_tag" {
  description = "Value for the owner tag"
  type        = string
  default     = "app-connector-admin"
}

variable "tags" {
  description = "Additional tags to apply to resources"
  type        = map(string)
  default     = {}
}

# Network configuration (existing resources)
variable "vpc_id" {
  description = "ID of the existing VPC where resources will be created"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs where App Connectors will be deployed"
  type        = list(string)
}

# App Connector configuration
variable "ac_count" {
  description = "Number of App Connector instances to deploy"
  type        = number
  default     = 2
}

variable "ac_instance_type" {
  description = "EC2 instance type for App Connector"
  type        = string
  default     = "m5a.xlarge"
  validation {
    condition = (
      var.ac_instance_type == "t3.xlarge" ||
      var.ac_instance_type == "m5a.xlarge" ||
      var.ac_instance_type == "t2.micro" # Only for testing with Amazon Linux 2
    )
    error_message = "Input ac_instance_type must be set to an approved VM instance type."
  }
}

variable "zpa_provisioning_key" {
  description = "ZPA provisioning key for App Connector"
  type        = string
  sensitive   = true
}

variable "ec2_key_pair" {
  description = "Name of the EC2 key pair to use for instances (optional)"
  type        = string
  default     = null
}

# Security configuration
variable "enable_ssm_access" {
  description = "Enable AWS Systems Manager access to instances"
  type        = bool
  default     = true
}

variable "sso_admin_role_name" {
  description = "Name of the SSO Administrator role that should have access to App Connector instances"
  type        = string
  default     = "AWSReservedSSO_AdministratorAccess_3f57aaaad5b5200e"
}

variable "reuse_security_group" {
  description = "Whether to create one security group for all instances or one per instance"
  type        = bool
  default     = true
}

variable "reuse_iam" {
  description = "Whether to create one IAM role for all instances or one per instance"
  type        = bool
  default     = true
}

# Bastion host configuration
variable "bastion_subnet_id" {
  description = "ID of the public subnet where the bastion host will be deployed"
  type        = string
  default     = "subnet-04d5d23279a7657d8"  # Default to first subnet you provided
}

variable "bastion_instance_type" {
  description = "EC2 instance type for the bastion host"
  type        = string
  default     = "t3.micro"
}

variable "bastion_key_name" {
  description = "Name of the EC2 key pair to use for the bastion host"
  type        = string
  default     = null
}

variable "bastion_allowed_cidr" {
  description = "CIDR blocks allowed to connect to the bastion host via SSM"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Consider restricting this in production
}
