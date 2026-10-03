# egress_lockdown

Makes the VICT egress proxy the only way out of an LSP's application subnets, so no application code, SDK or library can bypass it.

```hcl
module "egress_lockdown" {
  source                = "./modules/egress_lockdown"
  vpc_id                = aws_vpc.lsp.id
  app_subnet_ids        = [aws_subnet.app_a.id, aws_subnet.app_b.id]
  internal_egress_cidrs = ["10.0.5.0/24"] # database subnet
}
```

Then:

1. Attach `app_security_group_id` to every app instance, and remove any other security group that allows all outbound traffic. Security group rules add up, so one permissive group defeats layer 3. Layers 1 and 2 still hold.
2. Run the proxy in a public subnet with an Elastic IP, and attach `proxy_security_group_id`. That fixed IP is the address bureaus and AAs put on their allow-lists.
3. Point app instances at the proxy (`HTTPS_PROXY=http://<proxy>:3128`) and run `verify_lockdown.sh <proxy>:3128` on one of them.

## Why not a transparent sidecar or eBPF filter

A transparent interceptor sees only the destination and encrypted bytes. It has no consent token, so it cannot tell one borrower's call from another's. Reading more would mean terminating TLS, which breaks the client certificates and signed payloads bureaus and AAs require. An explicit proxy keeps per-call consent and end-to-end TLS. The network layers above remove the bypass.

## Before you apply

- **Explicit route table associations.** A subnet that already has one must be detached first, or the association fails with `Resource.AlreadyAssociated`.
- **Anything the app reached directly breaks**, including package mirrors and AWS APIs. Add AWS services as VPC endpoints (the S3 gateway endpoint is free), and other hosts to the proxy's allow-list.

## Not covered: DNS

Security groups and network ACLs do not filter queries to the Amazon-provided DNS resolver. Compromised code could leak small amounts of data by looking up names like `<data>.attacker.example`. Closing this needs Route 53 Resolver DNS Firewall, which is a paid AWS service. It is cheap at low volume, but check current pricing before turning it on.

## Cost

Route tables, network ACLs and security groups are free. Public IPv4 addresses, including the proxy's Elastic IP, are billed hourly by AWS. NAT gateways are avoided on purpose, because they are billed hourly plus per GB.
