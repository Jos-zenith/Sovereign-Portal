# Offline checks with a mocked AWS provider: terraform init && terraform test

mock_provider "aws" {
  mock_data "aws_vpc" {
    defaults = {
      cidr_block = "10.20.0.0/16"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }

  mock_data "aws_region" {
    defaults = {
      name = "ap-south-1"
    }
  }

  mock_data "aws_ec2_managed_prefix_list" {
    defaults = {
      entries = [
        { cidr = "52.219.62.0/25", description = "" },
        { cidr = "3.5.208.0/22", description = "" },
      ]
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

run "no_aws_endpoints_unless_asked" {
  command = plan

  assert {
    condition     = length(aws_vpc_endpoint.s3) == 0 && length(aws_vpc_endpoint.interface) == 0
    error_message = "the module must not create endpoints by default"
  }
}

run "s3_endpoint_reaches_only_this_account" {
  command = plan

  variables {
    enable_s3_gateway_endpoint = true
  }

  assert {
    condition     = jsondecode(aws_vpc_endpoint.s3[0].policy).Statement[0].Condition.StringEquals["aws:ResourceAccount"] == "111122223333"
    error_message = "S3 writes must be limited to buckets in this account"
  }

  assert {
    condition     = jsondecode(aws_vpc_endpoint.s3[0].policy).Statement[0].Condition.StringEquals["aws:PrincipalAccount"] == "111122223333"
    error_message = "credentials from another account must not work through the endpoint"
  }

  assert {
    condition     = length(jsondecode(aws_vpc_endpoint.s3[0].policy).Statement) == 1
    error_message = "no other S3 access unless listed"
  }

  assert {
    condition     = length(aws_network_acl.app.egress) == 3 && alltrue([for rule in aws_network_acl.app.egress : rule.cidr_block == "10.20.0.0/16" || (rule.protocol == "tcp" && rule.from_port == 443 && rule.to_port == 443)])
    error_message = "the only extra NACL egress is HTTPS to the S3 ranges"
  }

  assert {
    condition     = toset([for rule in aws_network_acl.app.egress : rule.cidr_block]) == toset(["10.20.0.0/16", "52.219.62.0/25", "3.5.208.0/22"])
    error_message = "NACL egress must name exactly the VPC and S3 ranges"
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.app_to_s3[0].from_port == 443
    error_message = "app instances reach S3 over HTTPS only"
  }
}

run "listed_external_objects_are_read_only" {
  command = plan

  variables {
    enable_s3_gateway_endpoint = true
    s3_read_only_external_arns = ["arn:aws:s3:::al2023-repos-ap-south-1-de612dc2/*"]
  }

  assert {
    condition     = jsondecode(aws_vpc_endpoint.s3[0].policy).Statement[1].Action == ["s3:GetObject"]
    error_message = "external buckets may only be read"
  }
}

run "interface_endpoints_are_own_account_and_app_only" {
  command = plan

  variables {
    interface_endpoint_services = ["sqs", "logs"]
  }

  assert {
    condition     = toset(keys(aws_vpc_endpoint.interface)) == toset(["sqs", "logs"])
    error_message = "one endpoint per listed service"
  }

  assert {
    condition     = alltrue([for e in aws_vpc_endpoint.interface : jsondecode(e.policy).Statement[0].Condition.StringEquals["aws:ResourceAccount"] == "111122223333"])
    error_message = "every interface endpoint must be limited to this account"
  }

  assert {
    condition     = aws_vpc_endpoint.interface["sqs"].service_name == "com.amazonaws.ap-south-1.sqs"
    error_message = "endpoints must be in the deployment region"
  }

  assert {
    condition     = aws_vpc_security_group_ingress_rule.endpoints_from_app[0].from_port == 443 && aws_vpc_security_group_ingress_rule.endpoints_from_app[0].to_port == 443
    error_message = "endpoints accept HTTPS only"
  }
}
