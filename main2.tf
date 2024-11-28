provider "aws" {
  region = var.aws_region
}

locals {
  # Load ingress rules from JSON files
  ingress_rule_files = fileset(path.module, "sg_rules/ingress/*.json")
  ingress_rules = flatten([
    for file in local.ingress_rule_files : jsondecode(file("${path.module}/${file}"))
  ])

  # Load egress rules from JSON files
  egress_rule_files = fileset(path.module, "sg_rules/egress/*.json")
  egress_rules = flatten([
    for file in local.egress_rule_files : jsondecode(file("${path.module}/${file}"))
  ])

  # Collect all unique security group names from ingress and egress rules
  security_group_names = distinct(concat(
    [for rule in local.ingress_rules : rule.name],
    [for rule in local.egress_rules : rule.name]
  ))
}

# Create security groups
resource "aws_security_group" "sgs" {
  for_each = toset(local.security_group_names)

  name        = each.value
  description = "Managed by Terraform"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = each.value
      }
}


# Create ingress rules
resource "aws_vpc_security_group_ingress_rule" "ingress" {
  for_each = { for rule in local.ingress_rules : "${rule.name}-${rule.from_port}-${rule.to_port}-ingress" => rule }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = lookup(each.value, "referenced_security_group_id", null) != null ? aws_security_group.sgs[each.value.referenced_security_group_id].id : null
}

# Create egress rules
resource "aws_vpc_security_group_egress_rule" "egress" {
  for_each = { for rule in local.egress_rules : "${rule.name}-${rule.from_port}-${rule.to_port}-egress" => rule }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = lookup(each.value, "referenced_security_group_id", null) != null ? aws_security_group.sgs[each.value.referenced_security_group_id].id : null
}