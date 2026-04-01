output "vpc_id" {
  description = "The ID of the VPC."
  value       = aws_vpc.main.id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC."
  value       = aws_vpc.main.cidr_block
}

output "vpc_default_security_group_id" {
  description = "The ID of the default security group for the VPC."
  value       = aws_vpc.main.default_security_group_id
}

output "public_subnet_ids" {
  description = "A list of IDs of the public subnets."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "A list of IDs of the private subnets."
  value       = aws_subnet.private[*].id
}

output "public_route_table_ids" {
  description = "The ID of the public route table."
  value       = aws_route_table.public[*].id
}

output "private_route_table_ids" {
  description = "A list of IDs of the private route tables."
  value       = aws_route_table.private[*].id
}

output "internet_gateway_id" {
  description = "The ID of the Internet Gateway."
  value       = aws_internet_gateway.main.id
}

output "nat_gateway_public_ips" {
  description = "List of public Elastic IP addresses allocated to the NAT Gateways."
  value       = var.enable_nat_gateway ? aws_eip.nat_gateway[*].public_ip : null
}

output "nat_gateway_ids" {
  description = "List of IDs of the NAT Gateways."
  value       = var.enable_nat_gateway ? aws_nat_gateway.main[*].id : null
}

output "bastion_host_instance_id" {
  value = aws_instance.bastion.id
}

output "private_subnet_cidr" {
  value = element(local.private_subnet_cidrs, 0)
}
