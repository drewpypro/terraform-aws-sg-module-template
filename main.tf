provider "aws" {
  region = var.aws_region
}

locals {
  # Define security groups as a map
  security_groups = {
    "app1_lambda"          = "app1_lambda"
    "app2_lambda"          = "app2_lambda"
    "cluster_endpoint"     = "cluster_endpoint"
    "dms"                  = "dms"
    "efs_mount_endpoint"   = "efs_mount_endpoint"
    "elasti_cache"         = "elasti_cache"
    "internet_istio_nodes" = "internet_istio_nodes"
    "internet_nlb"         = "internet_nlb"
    "istio_nodes"          = "istio_nodes"
    "msk"                  = "msk"
    "nlb"                  = "nlb"
    "opensearch"           = "opensearch"
    "rds"                  = "rds"
    "worker_nodes"         = "worker_nodes"
    "sg1"                  = "sg1"
  }

  # Get all ingress rule files and decode them
  ingress_files = fileset(path.module, "./sg_rules/ingress/*.json")
  ingress_rules = flatten([
    for file in local.ingress_files : jsondecode(file("${path.module}/${file}"))
  ])

  # Get all egress rule files and decode them
  egress_files = fileset(path.module, "./sg_rules/egress/*.json")
  egress_rules = flatten([
    for file in local.egress_files : jsondecode(file("${path.module}/${file}"))
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
  for_each = { for i, rule in local.ingress_rules : "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.referenced_security_group_id}-ingress" => rule }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = lookup(each.value, "referenced_security_group_id", null) != null ? aws_security_group.sgs[each.value.referenced_security_group_id].id : null

  depends_on = [aws_security_group.sgs]
}

# Create egress rules
resource "aws_vpc_security_group_egress_rule" "egress" {
  for_each = { for i, rule in local.egress_rules : "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.referenced_security_group_id}-egress" => rule }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = lookup(each.value, "referenced_security_group_id", null) != null ? aws_security_group.sgs[each.value.referenced_security_group_id].id : null

  depends_on = [aws_security_group.sgs]
}