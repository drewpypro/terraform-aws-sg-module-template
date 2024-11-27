variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "services" {
  description = "List of services requiring VPC endpoint security groups"
  type        = list(string)
  default     = ["ec2", "ssm"]
}

variable "referenced_sg_ids" {
  description = "Map of referenced SG IDs for inter-service communication"
  type        = map(string)
  default     = {}
}


variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24"]
}
