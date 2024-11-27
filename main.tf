# Use a local block for dynamic fileset loading
locals {
  security_group_files = fileset("${path.module}/security_groups", "*.json")
}

# Loop through JSON files to create security groups
resource "aws_security_group" "security_groups" {
  for_each = { for file in local.security_group_files : file => jsondecode(file("${path.module}/security_groups/${file}")) }

  name        = each.value.aws_security_group
  description = "Security group for ${each.key}"
  vpc_id      = module.vpc.vpc_id
}

# Loop through rules in each security group and create them
resource "aws_security_group_rule" "rules" {
  for_each = flatten([
    for sg_file in local.security_group_files : [
      for rule in jsondecode(file("${path.module}/security_groups/${sg_file}")).rules : {
        sg_id = aws_security_group.security_groups[sg_file].id
        rule  = rule
      }
    ]
  ])

  security_group_id = each.value.sg_id
  type              = each.value.rule.direction
  from_port         = each.value.rule.from_port
  to_port           = each.value.rule.to_port
  protocol          = each.value.rule.ip_protocol

  # Dynamically assign CIDR blocks or referenced security groups
  cidr_blocks              = each.value.rule.cidr_ipv4 != null ? [each.value.rule.cidr_ipv4] : []
  ipv6_cidr_blocks         = each.value.rule.cidr_ipv6 != null ? [each.value.rule.cidr_ipv6] : []
  source_security_group_id = each.value.rule.referenced_security_group_id != null ? aws_security_group.security_groups[each.value.rule.referenced_security_group_id].id : null
}
