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

data "aws_vpc" "this" {
  id = var.vpc_id
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
