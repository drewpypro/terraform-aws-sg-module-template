# terraform-aws-security-group-eks-module

# Requirements
- Vending Repo calls module from TFE to build a set of security-groups for a given account running an aligned eks cluster template. 
- Each resource (or clustered resource) gets a single SG applied to it. 
- VPCE has a separate SG per vpc endpoint eni. 
- each module provides outputs of sg-id's, and each module gets inputs of all module sg-id outputs. 
- each module has resource "aws_security_group_rule" that only creates the security-group and separate "aws_security_vpc_security_group_ingress/egress" rule resources that reference security-group id's that are exported from other modules in the same repo
- SG rules use "referenced_sg_ids" for connectivity between components within the VPC. 
- cidr_ipv4 & cidr_ipv6, can also be used if needed. 
- self_rules are aligned per resource type and dataflow declared. 
- Should implement DRY (dont repeat yourself)
- Should support ability to use custom rules for a given temlpate (if required) 

```
terraform-aws-security-group-eks-module/
├── main.tf
├── variables.tf
├── modules/
│   ├── security_groups/
│   │   ├── istio-sg/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   ├── worker-node-sg/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   ├── vpce-sg/
│   │   │   ├── main.tf
│   │   │   ├── variables.tf
│   │   └── (other SG submodules...)
└── README.md
```

# Vending Account Usage

```
variables "services" {
  description "authorized services that require vpc endpoint security groups"
  type = list(string)
  default = [ "ec2", "ssm", "sts", "rds"]
}

module "eks-sg-template" {
  source = "./tfe/aws/terraform-aws-security-group-eks-module/"
  vpc_id   = aws_vpc.test_vpc.id
  services = var.services
  name = var.name
}
```
