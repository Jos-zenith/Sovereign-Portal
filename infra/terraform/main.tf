# VICT Sovereign Infrastructure - AWS Graviton Deployment
# Region: India (Mumbai/Hyderabad)

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
  
  default_tags {
    tags = {
      Project     = "VICT-Sovereign-FaaS"
      Compliance  = "DPDP-RBI"
      DataRegion  = "India"
      ManagedBy   = "Terraform"
    }
  }
}

# Variables
variable "region" {
  description = "AWS region for deployment (India only)"
  type        = string
  default     = "ap-south-1" # Mumbai
  
  validation {
    condition     = contains(["ap-south-1", "ap-south-2"], var.region)
    error_message = "Region must be in India: ap-south-1 (Mumbai) or ap-south-2 (Hyderabad)"
  }
}

variable "instance_type" {
  description = "Graviton instance type"
  type        = string
  default     = "t4g.medium" # 2 vCPU, 4GB RAM
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "evidence_retention_days" {
  description = "Immutable retention period for forensic evidence"
  type        = number
  default     = 30

  validation {
    condition     = var.evidence_retention_days >= 7
    error_message = "Evidence retention must be at least 7 days for audit readiness."
  }
}

variable "foreign_cache_ttl_hours" {
  description = "TTL for non-sovereign ephemeral cache (RBI cap: 24h)"
  type        = number
  default     = 24

  validation {
    condition     = var.foreign_cache_ttl_hours > 0 && var.foreign_cache_ttl_hours <= 24
    error_message = "foreign_cache_ttl_hours must be between 1 and 24."
  }
}

# VPC Configuration
resource "aws_vpc" "vict_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "vict-sovereign-vpc"
  }
}

# Private Subnet (for VICT runtime)
resource "aws_subnet" "vict_private" {
  vpc_id            = aws_vpc.vict_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.region}a"
  
  tags = {
    Name = "vict-private-subnet"
    Type = "Isolated"
  }
}

# Public Subnet (for NAT/Load Balancer)
resource "aws_subnet" "vict_public" {
  vpc_id                  = aws_vpc.vict_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "vict-public-subnet"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "vict_igw" {
  vpc_id = aws_vpc.vict_vpc.id
  
  tags = {
    Name = "vict-igw"
  }
}

# Security Group for VICT Gateway
resource "aws_security_group" "vict_gateway" {
  name        = "vict-gateway-sg"
  description = "Security group for VICT Consent Gateway"
  vpc_id      = aws_vpc.vict_vpc.id
  
  # Inbound: HTTPS only
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS traffic"
  }
  
  # Inbound: HTTP (redirect to HTTPS)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP redirect"
  }
  
  # Outbound: India region only (example)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
    description = "Internal VPC only"
  }
  
  tags = {
    Name = "vict-gateway-sg"
  }
}

# EC2 Instance - VICT Graviton Server
resource "aws_instance" "vict_server" {
  ami           = data.aws_ami.ubuntu_arm64.id
  instance_type = var.instance_type
  subnet_id     = aws_subnet.vict_private.id
  
  vpc_security_group_ids = [aws_security_group.vict_gateway.id]
  
  # Encrypted root volume
  root_block_device {
    volume_size           = 50
    volume_type           = "gp3"
    encrypted             = true
    delete_on_termination = true
  }
  
  # IMDSv2 required
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  
  user_data = file("${path.module}/scripts/bootstrap.sh")
  
  tags = {
    Name        = "vict-graviton-server"
    Role        = "FaaS-Runtime"
    DataSovereign = "true"
  }
}

# Data source: Latest Ubuntu ARM64 AMI
data "aws_ami" "ubuntu_arm64" {
  most_recent = true
  owners      = ["099720109477"] # Canonical
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*"]
  }
  
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Immutable evidence bucket for forensic traces (DPDP 72-hour reporting support)
resource "aws_s3_bucket" "vict_evidence" {
  bucket_prefix       = "vict-evidence-"
  object_lock_enabled = true

  tags = {
    Name        = "vict-evidence-immutable"
    DataClass   = "forensic-evidence"
    Sovereignty = "india-only"
  }
}

resource "aws_s3_bucket_versioning" "vict_evidence" {
  bucket = aws_s3_bucket.vict_evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "vict_evidence" {
  bucket = aws_s3_bucket.vict_evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vict_evidence" {
  bucket = aws_s3_bucket.vict_evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vict_evidence" {
  bucket                  = aws_s3_bucket.vict_evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Ephemeral cache for temporary foreign processing with strict 24h purge
resource "aws_s3_bucket" "vict_foreign_ephemeral_cache" {
  bucket_prefix = "vict-foreign-cache-"

  tags = {
    Name        = "vict-foreign-ephemeral-cache"
    DataClass   = "ephemeral"
    Sovereignty = "ttl-purged"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vict_foreign_ephemeral_cache" {
  bucket = aws_s3_bucket.vict_foreign_ephemeral_cache.id

  rule {
    id     = "delete-within-rbi-window"
    status = "Enabled"

    filter {}

    expiration {
      days = ceil(var.foreign_cache_ttl_hours / 24)
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vict_foreign_ephemeral_cache" {
  bucket = aws_s3_bucket.vict_foreign_ephemeral_cache.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vict_foreign_ephemeral_cache" {
  bucket                  = aws_s3_bucket.vict_foreign_ephemeral_cache.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Outputs
output "vpc_id" {
  value       = aws_vpc.vict_vpc.id
  description = "VPC ID for VICT deployment"
}

output "instance_id" {
  value       = aws_instance.vict_server.id
  description = "EC2 Instance ID"
}

output "instance_private_ip" {
  value       = aws_instance.vict_server.private_ip
  description = "Private IP of VICT server (India region)"
}

output "deployment_region" {
  value       = var.region
  description = "AWS region where VICT is deployed"
}

output "evidence_bucket_name" {
  value       = aws_s3_bucket.vict_evidence.bucket
  description = "Immutable forensic evidence bucket"
}

output "foreign_ephemeral_cache_bucket_name" {
  value       = aws_s3_bucket.vict_foreign_ephemeral_cache.bucket
  description = "Ephemeral cache bucket with max 24h lifecycle"
}
