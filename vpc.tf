locals {
  # Read all JSON files in the security-groups directory
  security_group_files = fileset(path.module, "security-groups/*.json")
  security_groups = {
    for filename in local.security_group_files :
    basename(trim(filename, ".json")) => jsondecode(file(filename))
  }
}

# Create security groups
resource "aws_security_group" "this" {
  for_each = local.security_groups
  
  name        = each.value.name
  description = "Security group for ${each.value.name}"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = each.value.name
  }

  # Add self-referential rule if specified
  dynamic "ingress" {
    for_each = each.value.self_rule ? [1] : []
    content {
      from_port = 0
      to_port   = 0
      protocol  = "-1"
      self      = true
    }
  }

  dynamic "egress" {
    for_each = each.value.self_rule ? [1] : []
    content {
      from_port = 0
      to_port   = 0
      protocol  = "-1"
      self      = true
    }
  }
}

# Create ingress rules
resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = {
    for rule in flatten([
      for sg_name, sg in local.security_groups : [
        for rule in sg.rules :
        merge(rule, {
          sg_name = sg_name
          rule_id = "${sg_name}-${rule.direction}-${coalesce(rule.from_port, "all")}"
        })
        if rule.direction == "ingress"
      ]
    ]) : rule.rule_id => rule
  }

  security_group_id = aws_security_group.this[each.value.sg_name].id
  
  from_port   = try(each.value.from_port, null)
  to_port     = try(each.value.to_port, null)
  ip_protocol = each.value.ip_protocol
  
  dynamic "referenced_security_group_id" {
    for_each = try([each.value.referenced_security_group_id], [])
    content {
      id = aws_security_group.this[referenced_security_group_id.value].id
    }
  }

  cidr_ipv4 = try(each.value.cidr_ipv4, null)
  cidr_ipv6 = try(each.value.cidr_ipv6, null)
}

# Create egress rules
resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = {
    for rule in flatten([
      for sg_name, sg in local.security_groups : [
        for rule in sg.rules :
        merge(rule, {
          sg_name = sg_name
          rule_id = "${sg_name}-${rule.direction}-${coalesce(rule.from_port, "all")}"
        })
        if rule.direction == "egress"
      ]
    ]) : rule.rule_id => rule
  }

  security_group_id = aws_security_group.this[each.value.sg_name].id
  
  from_port   = try(each.value.from_port, null)
  to_port     = try(each.value.to_port, null)
  ip_protocol = each.value.ip_protocol
  
  dynamic "referenced_security_group_id" {
    for_each = try([each.value.referenced_security_group_id], [])
    content {
      id = aws_security_group.this[referenced_security_group_id.value].id
    }
  }

  cidr_ipv4 = try(each.value.cidr_ipv4, null)
  cidr_ipv6 = try(each.value.cidr_ipv6, null)
}