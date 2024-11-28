provider "aws" {
  region = var.aws_region
}

locals {
  # Define security groups as a map
  security_groups = {
    "app1-lambda"         = "app1-lambda"
    "app2-lambda"         = "app2-lambda"
    "cluster-endpoint"    = "cluster-endpoint"
    "dms"                 = "dms"
    "efs-mount-endpoint"  = "efs-mount-endpoint"
    "elasti-cache"        = "elasti-cache"
    "internet-istio-nodes" = "internet-istio-nodes"
    "internet-nlb"        = "internet-nlb"
    "istio-nodes"         = "istio-nodes"
    "msk"                 = "msk"
    "nlb"                 = "nlb"
    "opensearch"          = "opensearch"
    "rds"                 = "rds"
    "worker-nodes"        = "worker-nodes"
  }

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
}

# Create security groups
resource "aws_security_group" "sgs" {
  for_each = local.security_groups

  name        = each.value
  description = "Managed by Terraform"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = each.value
  }
}


# Create ingress rules
resource "aws_vpc_security_group_ingress_rule" "ingress" {
  for_each = { for i, rule in local.ingress_rules : "${rule.name}-${rule.from_port}-${rule.to_port}-ingress-${i}" => rule }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = lookup(each.value, "referenced_security_group_id", null) != null ? aws_security_group.sgs[lookup(local.security_groups, each.value.referenced_security_group_id)].id : null

  depends_on = [aws_security_group.sgs]
}

# Create egress rules
resource "aws_vpc_security_group_egress_rule" "egress" {
  for_each = { for i, rule in local.egress_rules : "${rule.name}-${rule.from_port}-${rule.to_port}-egress-${i}" => rule }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = lookup(each.value, "referenced_security_group_id", null) != null ? aws_security_group.sgs[lookup(local.security_groups, each.value.referenced_security_group_id)].id : null

  depends_on = [aws_security_group.sgs]
}