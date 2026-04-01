variable "name_prefix" {
  description = "A prefix to be added to the names of all created resources."
  type        = string
  default     = "vault"
}

variable "region" {
  type        = string
  description = "Name of the region"
}

variable "env" {
  type        = string
  default     = "staging"
  description = "Name of the region"
}

variable "tags" {
  description = "A map of tags to add to all resources."
  type        = map(string)
  default     = {}
}

variable "vpc_cidr_block" {
  description = "The CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "ami_bastion" {
  description = "Bastion AMI ID."
  type        = string
}

variable "vpc_enable_dns_support" {
  description = "Enable DNS support in the VPC."
  type        = bool
  default     = true
}

variable "vpc_enable_dns_hostnames" {
  description = "Enable DNS hostnames in the VPC."
  type        = bool
  default     = true
}

variable "azs" {
  description = "A list of Availability Zones to use for subnets."
  type        = list(string)
}

variable "public_subnet_cidrs" {
  description = "A list of CIDR blocks for public subnets. Must match the number of AZs."
  type        = list(string)
  default     = []
}

variable "private_subnet_cidrs" {
  description = "A list of CIDR blocks for private subnets. Must match the number of AZs."
  type        = list(string)
  default     = []
}

variable "subnet_map_public_ip_on_launch" {
  description = "Specify true to indicate that instances launched into the public subnet receive a public IP address."
  type        = bool
  default     = false
}

variable "enable_nat_gateway" {
  description = "Set to true to create a NAT Gateway for outbound internet access from private subnets."
  type        = bool
  default     = false
}

variable "single_nat_gateway" {
  description = "Set to true to create a single NAT Gateway. If false, a NAT Gateway will be created in each AZ with a private subnet."
  type        = bool
  default     = false
}

variable "enable_nat_instance" {
  description = "Set to true to create a NAT Instance. Ignored if enable_nat_gateway is true."
  type        = bool
  default     = false
}

variable "nat_instance_type" {
  description = "The instance type to use for the NAT instance."
  type        = string
  default     = "t3.micro"
}

variable "nat_instance_ami_id" {
  description = "The AMI ID for the NAT instance. If null, latest Amazon Linux 2 will be used. Ensure it's configured for NAT."
  type        = string
  default     = null
}

variable "nat_instance_key_name" {
  description = "The EC2 Key Pair name for the NAT instance (for SSH access if needed)."
  type        = string
  default     = null
}

variable "bastion_instance_ami_name_filter" {
  description = "The AMI filter to use for the bastion host's AMI."
  type        = string
  default     = "al2023-ami-2023*-x86_64"
}

variable "bastion_host_ami_owners" {
  description = "The list of owners used to select the AMI."
  type        = list(string)
  default     = ["amazon"]
}

variable "bastion_iam_instance_profile" {
  description = "Bastion Host IAM Instance profile."
  type        = string
}

variable "bastion_host_security_group_id" {
  description = "Bastion Host SG."
  type        = string
}

variable "ssm_endpoints_security_group_id" {
  description = "Bastion Host SG."
  type        = string
}
