# Security Groups and Rules Configuration
locals {
  security_group_configs = {
    for filename in fileset(path.module, "rulesets/*.json") :
    basename(trimsuffix(filename, ".json")) => jsondecode(file(filename))
  }
}

# Create Security Groups
resource "aws_security_group" "this" {
  for_each = local.security_group_configs

  name        = each.key
  description = "Security group for ${each.key}"
  vpc_id      = module.vpc.vpc_id

  # Handle self-referential rules if self_rule is true
  dynamic "ingress" {
    for_each = try(each.value.self_rule, "") == "yes" ? [1] : []
    content {
      from_port = 0
      to_port   = 0
      protocol  = "-1"
      self      = true
    }
  }

  dynamic "egress" {
    for_each = try(each.value.self_rule, "") == "yes" ? [1] : []
    content {
      from_port = 0
      to_port   = 0
      protocol  = "-1"
      self      = true
    }
  }

  tags = {
    Name = each.key
  }
}

# Create Ingress Rules
resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = {
    for entry in flatten([
      for sg_name, sg_config in local.security_group_configs :
      [
        for rule in try(sg_config.rules.ingress, []) : {
          sg_name     = sg_name
          rule        = rule
          unique_key  = "${sg_name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}"
        }
      ]
    ]) : entry.unique_key => entry
  }

  security_group_id = aws_security_group.this[each.value.sg_name].id
  
  from_port   = try(each.value.rule.from_port, null)
  to_port     = try(each.value.rule.to_port, null)
  ip_protocol = each.value.rule.ip_protocol
  
  cidr_ipv4              = try(each.value.rule.cidr_ipv4, null)
  cidr_ipv6              = try(each.value.rule.cidr_ipv6, null)
  referenced_security_group_id = try(
    aws_security_group.this[each.value.rule.referenced_security_group_id].id,
    null
  )
}

# Create Egress Rules
resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = {
    for entry in flatten([
      for sg_name, sg_config in local.security_group_configs :
      [
        for rule in try(sg_config.rules.egress, []) : {
          sg_name     = sg_name
          rule        = rule
          unique_key  = "${sg_name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}"
        }
      ]
    ]) : entry.unique_key => entry
  }

  security_group_id = aws_security_group.this[each.value.sg_name].id
  
  from_port   = try(each.value.rule.from_port, null)
  to_port     = try(each.value.rule.to_port, null)
  ip_protocol = each.value.rule.ip_protocol
  
  cidr_ipv4              = try(each.value.rule.cidr_ipv4, null)
  cidr_ipv6              = try(each.value.rule.cidr_ipv6, null)
  referenced_security_group_id = try(
    aws_security_group.this[each.value.rule.referenced_security_group_id].id,
    null
  )
}