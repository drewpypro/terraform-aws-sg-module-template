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
    "rds_db"                    = "rds_db"
    "worker_nodes"              = "worker_nodes"
    "autoscaling"               = "autoscaling"
    "dms"                       = "dms"
    "ec2"                       = "ec2"
    "ec2messages"               = "ec2messages"
    "efs"                       = "efs"
    "eks"                       = "eks"
    "elasticache"               = "elasticache"
    "elasticloadbalancing"      = "elasticloadbalancing"
    "kms"                       = "kms"
    "lambda"                    = "lambda"
    "logs"                      = "logs"
    "monitoring"                = "monitoring"
    "rds"                       = "rds"
    "s3"                        = "s3"
    "sns"                       = "sns"
    "sqs"                       = "sqs"
    "sts"                       = "sts"
    "ssm"                       = "ssm"
    "ssmmessages"               = "ssmmessages"
    "sts"                       = "sts"
    "ec2_test_sg"               = "ec2_test_sg"
    "ecr.api"                   = "ecr.api"
    "ecr.dkr"                   = "ecr.dkr"
  }

  # Load prefix list id DB
  prefix_lists = jsondecode(file("${path.module}/prefix_lists.json"))

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
  vpc_id      = var.vpc_id

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
    => rule if rule.referenced_security_group_id != "null" && rule.cidr_ipv4 == "null" && rule.direction == "ingress"
  }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = each.value.ip_protocol == "-1" ? null : tonumber(each.value.from_port)
  to_port                      = each.value.ip_protocol == "-1" ? null : tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = aws_security_group.sgs[each.value.referenced_security_group_id].id
  description                  = each.value.business_justification
}

# Create ingress rules for cidr_ipv4
resource "aws_vpc_security_group_ingress_rule" "ingress_cidr_ipv4" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv4}-ingress"
    => rule if rule.cidr_ipv4 != "null" && rule.referenced_security_group_id == "null" && rule.direction == "ingress"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = each.value.ip_protocol == "-1" ? null : tonumber(each.value.from_port)
  to_port           = each.value.ip_protocol == "-1" ? null : tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.business_justification
}

# Create ingress rules for cidr_ipv4
resource "aws_vpc_security_group_ingress_rule" "ingress_cidr_ipv6" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv6}-ingress"
    => rule if rule.cidr_ipv6 != "null" && rule.referenced_security_group_id == "null" && rule.direction == "ingress"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = each.value.ip_protocol == "-1" ? null : tonumber(each.value.from_port)
  to_port           = each.value.ip_protocol == "-1" ? null : tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv6         = each.value.cidr_ipv6
  description       = each.value.business_justification
}

# Create egress rules for referenced_security_group_id
resource "aws_vpc_security_group_egress_rule" "egress_referenced" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.referenced_security_group_id}-egress"
    => rule if rule.referenced_security_group_id != "null" && rule.cidr_ipv4 == "null" && rule.direction == "egress"
  }

  security_group_id            = aws_security_group.sgs[each.value.name].id
  from_port                    = each.value.ip_protocol == "-1" ? null : tonumber(each.value.from_port)
  to_port                      = each.value.ip_protocol == "-1" ? null : tonumber(each.value.to_port)
  ip_protocol                  = each.value.ip_protocol
  referenced_security_group_id = aws_security_group.sgs[each.value.referenced_security_group_id].id
  description                  = each.value.business_justification
}

# Create egress rules for cidr_ipv4
resource "aws_vpc_security_group_egress_rule" "egress_cidr" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv4}-egress"
    => rule if rule.cidr_ipv4 != "null" && rule.referenced_security_group_id == "null" && rule.direction == "egress"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = each.value.ip_protocol == "-1" ? null : tonumber(each.value.from_port)
  to_port           = each.value.ip_protocol == "-1" ? null : tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.business_justification
}

# Create egress rules for cidr_ipv4
resource "aws_vpc_security_group_egress_rule" "egress_cidr_ipv6" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.cidr_ipv6}-egress"
    => rule if rule.cidr_ipv6 != "null" && rule.referenced_security_group_id == "null" && rule.direction == "egress"
  }

  security_group_id = aws_security_group.sgs[each.value.name].id
  from_port         = each.value.ip_protocol == "-1" ? null : tonumber(each.value.from_port)
  to_port           = each.value.ip_protocol == "-1" ? null : tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  cidr_ipv6         = each.value.cidr_ipv6
  description       = each.value.business_justification
}

# Lookup prefix list IDs dynamically based on aws_region
resource "aws_vpc_security_group_egress_rule" "egress_prefix_list" {
  for_each = {
    for i, rule in local.rules :
    "${rule.name}-${rule.from_port}-${rule.to_port}-${rule.ip_protocol}-${rule.prefix_list_id}-egress"
    => rule if rule.prefix_list_id != "null" && rule.referenced_security_group_id == "null" && rule.direction == "egress"
  }

  security_group_id = aws_security_group.sgs[each.value.security_group_id].id
  from_port         = each.value.ip_protocol == "-1" ? null : tonumber(each.value.from_port)
  to_port           = each.value.ip_protocol == "-1" ? null : tonumber(each.value.to_port)
  ip_protocol       = each.value.ip_protocol
  prefix_list_id    = lookup(local.prefix_lists[var.aws_region], "com.amazonaws.${var.aws_region}.${each.value.prefix_list_id}", null)
  description       = each.value.business_justification
}
