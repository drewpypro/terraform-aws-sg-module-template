# terraform-aws-security-group-module-template
- [Overview](#overview)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [Prerequisites](#prerequisites)
- [TO DO](#to-do)
- [Scripts](#scripts)
- [Test Cases](tests/README.MD#test-cases)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)

# Overview
- Generate AWS security-group configuration in a single module using json files converted from traditional csv dataflow templates
- Python manages state of json files used for Terraform to build rules

# Project Structure
```
terraform-aws-sg-module-template/
├── main.tf
├── providers.tf
├── variables.tf
├── sg_rules/
│   ├── aws_security_group.sgs[each.value.name].json
├── firewall_rules.csv
├── rule_conversion.py
└── README.md
```

# Usage
- Define firewall rules in [firewall_rules.csv](https://github.com/drewpypro/terraform-aws-sg-module-template/blob/main/firewall_rules.csv)
- Run [rule_conversion.py](https://github.com/drewpypro/terraform-aws-sg-module-template/blob/main/rule_conversion.py)
- Terraform apply

## Prerequisites
```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
BUCKET_ACCESS_KEY_ID
BUCKET_ENDPOINT
BUCKET_KEY
BUCKET_NAME
BUCKET_SECRET_ACCESS_KEY
```

# TO DO

- Make conversion script remove files (if SG is deleted)
- Incorporate into [aws-eks-drewpy](https://github.com/drewpypro/aws-eks-drewpy)
- Make mermaid better
- Custom Rules (If this is being used as a shared template module)

# Scripts

## Security Group Rules Validator and Generator [rule_conversion.py](https://github.com/drewpypro/terraform-aws-sg-module-template/rule_conversion.py)
- This script automates the validation and generation of json rules used for AWS Security Group modules. 
  1. Reads firewall_rules.csv
  2. Performs Validation
    **All fields must be present and valid**
    **IPv4/IPv6 validation**
    **Multiple input detection (referenced_security_group_id, cidr_ipv4, cidr_ipv6)**
    **Duplicate rule detection**
  3. Converts rules into JSON format used in [terraform-aws-sg-module-template](https://github.com/drewpypro/terraform-aws-sg-module-template)
  4. Maintains state and empties rules for removed security groups. 

# Contributing

- Fork the repository.
- Create a new branch for your feature or bugfix.
- Make your changes and test them thoroughly.
- Submit a pull request for review.

# Disclaimer

This project is provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. Use this project at your own risk. The maintainers of this repository are not responsible for any damage or issues arising from its use.

# License

This project is licensed under the MIT License. This means you are free to use, modify, and distribute the code as long as credit is given to the original author.

```
Copyright (c) 2025 drewpypro

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```
 