provider "aws" {
  region = var.aws_region
}

locals {
  # Define security groups as a map
  security_groups = {
    "app1_lambda"               = "app1_lambda"
    "app2_lambda"               = "app2_lambda"
    "cluster_endpoint"          = "cluster_endpoint"
    "dms"                       = "dms"
    "efs_mount_endpoint"        = "efs_mount_endpoint"
    "elasti_cache"              = "elasti_cache"
    "internet_istio_nodes"      = "internet_istio_nodes"
    "internet_nlb"              = "internet_nlb"
    "istio_nodes"               = "istio_nodes"
    "msk"                       = "msk"
    "nlb"                       = "nlb"
    "opensearch"                = "opensearch"
    "rds"                       = "rds"
    "worker_nodes"              = "worker_nodes"
    "vpce_autoscaling"          = "vpce_autoscaling"
    "vpce_dms"                  = "vpce_dms"
    "vpce_ec2"                  = "vpce_ec2"
    "vpce_ec2messages"          = "vpce_ec2messages"
    "vpce_efs"                  = "vpce_efs"
    "vpce_eks"                  = "vpce_eks"
    "vpce_elasticache"          = "vpce_elasticache"
    "vpce_elasticloadbalancing" = "vpce_elasticloadbalancing"
    "vpce_kms"                  = "vpce_kms"
    "vpce_lambda"               = "vpce_lambda"
    "vpce_logs"                 = "vpce_logs"
    "vpce_monitoring"           = "vpce_monitoring"
    "vpce_rds"                  = "vpce_rds"
    "vpce_s3"                   = "vpce_s3"
    "vpce_sns"                  = "vpce_sns"
    "vpce_sqs"                  = "vpce_sqs"
    "vpce_sts"                  = "vpce_sts"
    "vpce_ssm"                  = "vpce_ssm"
    "vpce_ssmmessages"          = "vpce_ssmmessages"
    "vpce_sts"                  = "vpce_sts"

  }

  # Get all rule files and decode them
  rule_files = fileset(path.module, "./sg_rules/*.json")
  rules = flatten([
    for file in local.rule_files : jsondecode(file("${path.module}/${file}"))
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

output "security_group_ids" {
  value = {
    for name, sg in aws_security_group.sgs :
    name => sg.id
  }
  description = "Map of all security group names to their IDs"
}

# Create ingress rules for referenced_security_group_id
resource "aws_vpc_security_group_ingress_rule" "ingress_referenced" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.referenced_security_group_id}-ingress"
    => rule if rule.referenced_security_group_id != "null" && rule.cidr_ipv4 == "null"
  }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = aws_security_group.sgs[each.value.referenced_security_group_id].id
  description                  = each.value.business_justification
}

# Create ingress rules for cidr_ipv4
resource "aws_vpc_security_group_ingress_rule" "ingress_cidr_ipv4" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv4}-ingress"
    => rule if rule.cidr_ipv4 != "null" && rule.referenced_security_group_id == "null"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = tonumber(each.value.from_port)
  to_port           = tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.business_justification
}

# Create ingress rules for cidr_ipv4
resource "aws_vpc_security_group_ingress_rule" "ingress_cidr_ipv6" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv6}-ingress"
    => rule if rule.cidr_ipv6 != "null" && rule.referenced_security_group_id == "null"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = tonumber(each.value.from_port)
  to_port           = tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv6         = each.value.cidr_ipv6
  description       = each.value.business_justification
}

# Create egress rules for referenced_security_group_id
resource "aws_vpc_security_group_egress_rule" "egress_referenced" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.referenced_security_group_id}-egress"
    => rule if rule.referenced_security_group_id != "null" && rule.cidr_ipv4 == "null"
  }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = tonumber(each.value.from_port)
  to_port                      = tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = aws_security_group.sgs[each.value.referenced_security_group_id].id
  description                  = each.value.business_justification
}

# Create egress rules for cidr_ipv4
resource "aws_vpc_security_group_egress_rule" "egress_cidr" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv4}-egress"
    => rule if rule.cidr_ipv4 != "null" && rule.referenced_security_group_id == "null"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = tonumber(each.value.from_port)
  to_port           = tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.business_justification
}

# Create egress rules for cidr_ipv4
resource "aws_vpc_security_group_egress_rule" "egress_cidr_ipv6" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv6}-egress"
    => rule if rule.cidr_ipv6 != "null" && rule.referenced_security_group_id == "null"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = tonumber(each.value.from_port)
  to_port           = tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv6         = each.value.cidr_ipv6
  description       = each.value.business_justification
}