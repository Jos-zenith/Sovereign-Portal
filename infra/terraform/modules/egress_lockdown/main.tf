# VICT egress lockdown: application subnets reach the internet only through the VICT egress proxy.
#
# Three independent layers, so one later misconfiguration does not reopen a path:
#   1. Route table: app subnets have no route to an internet gateway or NAT gateway.
#   2. Network ACL: app subnets may only send and receive traffic inside the VPC.
#   3. Security groups: app instances may only connect to the proxy (plus listed internal
#      destinations); the proxy may only open TCP 443 outbound.
#
# All three are free AWS features. See README.md for what this does not cover (DNS).

terraform {
  required_version = ">= 1.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "vpc_id" {
  description = "VPC holding the application and the proxy"
  type        = string
}

variable "app_subnet_ids" {
  description = "Subnets running LSP application code. They lose all direct internet access."
  type        = list(string)
}

variable "proxy_port" {
  description = "Port the VICT egress proxy listens on"
  type        = number
  default     = 3128
}

variable "internal_egress_cidrs" {
  description = "In-VPC ranges app instances may still reach directly, e.g. the database or consent authority"
  type        = list(string)
  default     = []
}

variable "enable_s3_gateway_endpoint" {
  description = "Let app subnets reach S3 through a gateway endpoint, limited to buckets in this account. Free."
  type        = bool
  default     = false
}

variable "s3_read_only_external_arns" {
  description = "Objects in other accounts' buckets the app may read but never write, e.g. [\"arn:aws:s3:::al2023-repos-ap-south-1-*/*\"]"
  type        = list(string)
  default     = []
}

variable "interface_endpoint_services" {
  description = "AWS services to reach through interface endpoints, limited to this account, e.g. [\"sqs\", \"logs\"]. AWS bills each one hourly per subnet."
  type        = list(string)
  default     = []
}

variable "endpoint_subnet_ids" {
  description = "Subnets for interface endpoints, at most one per availability zone. Defaults to app_subnet_ids."
  type        = list(string)
  default     = []
}

data "aws_vpc" "this" {
  id = var.vpc_id
}

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_ec2_managed_prefix_list" "s3" {
  count = var.enable_s3_gateway_endpoint ? 1 : 0
  name  = "com.amazonaws.${data.aws_region.current.name}.s3"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  s3_cidrs   = var.enable_s3_gateway_endpoint ? sort([for entry in data.aws_ec2_managed_prefix_list.s3[0].entries : entry.cidr]) : []

  # An endpoint without a policy reaches every account's resources, including an
  # attacker's bucket or queue. Both conditions are needed: PrincipalAccount stops
  # credentials from another account, ResourceAccount stops writes to its resources.
  own_account_only = {
    Sid       = "OwnAccountOnly"
    Effect    = "Allow"
    Principal = "*"
    Action    = "*"
    Resource  = "*"
    Condition = {
      StringEquals = {
        "aws:PrincipalAccount" = local.account_id
        "aws:ResourceAccount"  = local.account_id
      }
    }
  }

  s3_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([local.own_account_only], length(var.s3_read_only_external_arns) == 0 ? [] : [{
      Sid       = "ReadOnlyListedObjects"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject"]
      Resource  = var.s3_read_only_external_arns
      Condition = { StringEquals = { "aws:PrincipalAccount" = local.account_id } }
    }])
  })

  interface_endpoint_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [local.own_account_only]
  })
}

# Layer 1: no way out by routing. Only the implicit local route exists.
resource "aws_route_table" "app_isolated" {
  vpc_id = var.vpc_id

  tags = {
    Name = "vict-app-isolated"
    Role = "egress-lockdown"
  }
}

resource "aws_route_table_association" "app_isolated" {
  for_each       = toset(var.app_subnet_ids)
  subnet_id      = each.value
  route_table_id = aws_route_table.app_isolated.id
}

# Layer 2: subnet-level allow-list. Stateless, so return traffic is allowed explicitly.
resource "aws_network_acl" "app" {
  vpc_id     = var.vpc_id
  subnet_ids = var.app_subnet_ids

  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = data.aws_vpc.this.cidr_block
    from_port  = 0
    to_port    = 0
  }

  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = data.aws_vpc.this.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # S3 gateway endpoint traffic goes to S3's public ranges, so it needs its own
  # rules: HTTPS out, and replies back. Only when the endpoint is enabled.
  dynamic "egress" {
    for_each = local.s3_cidrs
    content {
      rule_no    = 200 + egress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = egress.value
      from_port  = 443
      to_port    = 443
    }
  }

  dynamic "ingress" {
    for_each = local.s3_cidrs
    content {
      rule_no    = 200 + ingress.key
      protocol   = "tcp"
      action     = "allow"
      cidr_block = ingress.value
      from_port  = 1024
      to_port    = 65535
    }
  }

  tags = {
    Name = "vict-app-vpc-only"
    Role = "egress-lockdown"
  }
}

# Layer 3: instance-level rules.
resource "aws_security_group" "app_egress" {
  name        = "vict-app-egress"
  description = "LSP app instances: outbound only to the VICT egress proxy and listed internal ranges"
  vpc_id      = var.vpc_id

  tags = {
    Name = "vict-app-egress"
    Role = "egress-lockdown"
  }
}

resource "aws_security_group" "proxy" {
  name        = "vict-egress-proxy"
  description = "VICT egress proxy: CONNECT from app instances, TCP 443 out"
  vpc_id      = var.vpc_id

  tags = {
    Name = "vict-egress-proxy"
    Role = "egress-lockdown"
  }
}

resource "aws_vpc_security_group_egress_rule" "app_to_proxy" {
  security_group_id            = aws_security_group.app_egress.id
  referenced_security_group_id = aws_security_group.proxy.id
  ip_protocol                  = "tcp"
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  description                  = "CONNECT to the VICT egress proxy"
}

resource "aws_vpc_security_group_egress_rule" "app_internal" {
  for_each          = toset(var.internal_egress_cidrs)
  security_group_id = aws_security_group.app_egress.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 0
  to_port           = 65535
  description       = "Listed internal destination"
}

resource "aws_vpc_security_group_ingress_rule" "proxy_from_app" {
  security_group_id            = aws_security_group.proxy.id
  referenced_security_group_id = aws_security_group.app_egress.id
  ip_protocol                  = "tcp"
  from_port                    = var.proxy_port
  to_port                      = var.proxy_port
  description                  = "CONNECT requests from app instances"
}

resource "aws_vpc_security_group_egress_rule" "proxy_https_out" {
  security_group_id = aws_security_group.proxy.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "TLS to allow-listed hosts; the proxy enforces the host list"
}

resource "aws_vpc_security_group_egress_rule" "proxy_internal" {
  security_group_id = aws_security_group.proxy.id
  cidr_ipv4         = data.aws_vpc.this.cidr_block
  ip_protocol       = "tcp"
  from_port         = 0
  to_port           = 65535
  description       = "Consent authority and audit storage inside the VPC"
}

# AWS services without an internet path. Every endpoint carries an own-account policy.

resource "aws_vpc_endpoint" "s3" {
  count             = var.enable_s3_gateway_endpoint ? 1 : 0
  vpc_id            = var.vpc_id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.app_isolated.id]
  policy            = local.s3_endpoint_policy

  tags = {
    Name = "vict-s3-own-account"
    Role = "egress-lockdown"
  }
}

resource "aws_vpc_security_group_egress_rule" "app_to_s3" {
  count             = var.enable_s3_gateway_endpoint ? 1 : 0
  security_group_id = aws_security_group.app_egress.id
  prefix_list_id    = aws_vpc_endpoint.s3[0].prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "S3 through the gateway endpoint; its policy limits it to this account"
}

resource "aws_security_group" "endpoints" {
  count       = length(var.interface_endpoint_services) > 0 ? 1 : 0
  name        = "vict-aws-endpoints"
  description = "Interface endpoints: HTTPS from app instances only"
  vpc_id      = var.vpc_id

  tags = {
    Name = "vict-aws-endpoints"
    Role = "egress-lockdown"
  }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_from_app" {
  count                        = length(var.interface_endpoint_services) > 0 ? 1 : 0
  security_group_id            = aws_security_group.endpoints[0].id
  referenced_security_group_id = aws_security_group.app_egress.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "HTTPS from app instances"
}

resource "aws_vpc_security_group_egress_rule" "app_to_endpoints" {
  count                        = length(var.interface_endpoint_services) > 0 ? 1 : 0
  security_group_id            = aws_security_group.app_egress.id
  referenced_security_group_id = aws_security_group.endpoints[0].id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
  description                  = "AWS interface endpoints, limited to this account by policy"
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(var.interface_endpoint_services)
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = length(var.endpoint_subnet_ids) > 0 ? var.endpoint_subnet_ids : var.app_subnet_ids
  security_group_ids  = [aws_security_group.endpoints[0].id]
  private_dns_enabled = true
  policy              = local.interface_endpoint_policy

  tags = {
    Name = "vict-${each.value}-own-account"
    Role = "egress-lockdown"
  }
}

output "s3_endpoint_id" {
  value = var.enable_s3_gateway_endpoint ? aws_vpc_endpoint.s3[0].id : null
}

output "app_security_group_id" {
  description = "Attach to every app instance, and remove any security group that allows all outbound traffic"
  value       = aws_security_group.app_egress.id
}

output "proxy_security_group_id" {
  description = "Attach to the VICT egress proxy instance"
  value       = aws_security_group.proxy.id
}

output "app_route_table_id" {
  value = aws_route_table.app_isolated.id
}
