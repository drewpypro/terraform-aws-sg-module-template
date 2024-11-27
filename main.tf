provider "aws" {
  region = "us-east-1"
}

locals {
  security_groups_path = "${path.module}/security-groups"
}

# Read JSON files for each security group
data "local_file" "security_groups" {
  for_each = fileset(local.security_groups_path, "*.json")

  filename = "${local.security_groups_path}/${each.value}"
}

# Create security groups and rules based on JSON files
resource "aws_security_group" "sg" {
  for_each = data.local_file.security_groups

  name        = each.key
  description = "Security group for ${each.key}"
  vpc_id      = module.vpc.vpc_id

  dynamic "ingress" {
    for_each = [for rule in jsondecode(each.value.content) : rule if rule.direction == "ingress"]
    content {
      from_port                = ingress.value.from_port
      to_port                  = ingress.value.to_port
      protocol                 = ingress.value.ip_protocol
      cidr_blocks              = ingress.value.cidr_ipv4 != null ? [ingress.value.cidr_ipv4] : []
      ipv6_cidr_blocks         = ingress.value.cidr_ipv6 != null ? [ingress.value.cidr_ipv6] : []
      security_groups          = ingress.value.referenced_security_group_id != null ? [ingress.value.referenced_security_group_id] : []
      self                     = ingress.value.self_rule
    }
  }

  dynamic "egress" {
    for_each = [for rule in jsondecode(each.value.content) : rule if rule.direction == "egress"]
    content {
      from_port                = egress.value.from_port
      to_port                  = egress.value.to_port
      protocol                 = egress.value.ip_protocol
      cidr_blocks              = egress.value.cidr_ipv4 != null ? [egress.value.cidr_ipv4] : []
      ipv6_cidr_blocks         = egress.value.cidr_ipv6 != null ? [egress.value.cidr_ipv6] : []
      security_groups          = egress.value.referenced_security_group_id != null ? [egress.value.referenced_security_group_id] : []
      self                     = egress.value.self_rule
    }
  }
}
