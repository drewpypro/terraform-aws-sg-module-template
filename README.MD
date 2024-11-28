# terraform-aws-security-group-eks-module

![Success](./img/successful_test1.png)

# Overview
- Generate AWS security-group configuration in a single module using json files converted from traditional csv dataflow templates. 
- Python manages state of json files used for Terraform to build rules. 


# Requirements
- Define firewall rules in firewall_rules.csv
- Run rule_conversion.py (for first time or after making changes to firewall_rules.csv)
- Terraform apply

```
terraform-aws-sg-module-template/
├── main.tf
├── providers.tf
├── variables.tf
├── sg_rules/
│   ├── egress/
│   │   ├── aws_security_group.sgs[each.value.name]-egress.json
│   │   ├── ...
│   ├── ingress/
│   │   ├── aws_security_group.sgs[each.value.name]-ingress.json
│   │   ├── ...
└── README.md
```

# TO DO

- Incorporate per service [vpce-sg-module](https://github.com/drewpypro/aws-vpce-policy-tester/tree/main/modulev2)
- Incorporate cidr_ipv4 and cidr_ipv6 leveraging list variables. 
- Incorporate into [aws-eks-drewpy](https://github.com/drewpypro/aws-eks-drewpy)