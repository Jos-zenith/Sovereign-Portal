# Offline checks with a mocked AWS provider: terraform init && terraform test

mock_provider "aws" {
  mock_data "aws_vpc" {
    defaults = {
      cidr_block = "10.20.0.0/16"
    }
  }
}

variables {
  vpc_id                = "vpc-0123456789abcdef0"
  app_subnet_ids        = ["subnet-aaa", "subnet-bbb"]
  internal_egress_cidrs = ["10.20.5.0/24"]
}

run "app_subnets_lose_their_route_out" {
  command = plan

  assert {
    condition     = length(aws_route_table_association.app_isolated) == 2
    error_message = "every app subnet must use the isolated route table"
  }

  assert {
    condition     = alltrue([for a in aws_route_table_association.app_isolated : a.subnet_id != null])
    error_message = "associations must name their subnet"
  }
}

run "nacl_only_allows_traffic_inside_the_vpc" {
  command = plan

  assert {
    condition     = toset(aws_network_acl.app.subnet_ids) == toset(["subnet-aaa", "subnet-bbb"])
    error_message = "the NACL must cover every app subnet"
  }

  assert {
    condition     = alltrue([for rule in aws_network_acl.app.egress : rule.cidr_block == "10.20.0.0/16" && rule.action == "allow"])
    error_message = "the only outbound NACL rule must allow the VPC range"
  }

  assert {
    condition     = length(aws_network_acl.app.egress) == 1 && length(aws_network_acl.app.ingress) == 1
    error_message = "no extra NACL rules may open a path out"
  }
}

run "app_instances_may_only_reach_the_proxy_and_listed_ranges" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.app_to_proxy.from_port == 3128 && aws_vpc_security_group_egress_rule.app_to_proxy.to_port == 3128
    error_message = "app egress to the proxy must be the proxy port only"
  }

  assert {
    condition     = keys(aws_vpc_security_group_egress_rule.app_internal) == ["10.20.5.0/24"]
    error_message = "only listed internal ranges may be reached directly"
  }
}

run "proxy_only_speaks_tls_to_the_internet" {
  command = plan

  assert {
    condition     = aws_vpc_security_group_egress_rule.proxy_https_out.from_port == 443 && aws_vpc_security_group_egress_rule.proxy_https_out.to_port == 443
    error_message = "the proxy may only open TCP 443 to the internet"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.proxy_internal.cidr_ipv4 == "10.20.0.0/16"
    error_message = "the proxy's other egress must stay inside the VPC"
  }
}
