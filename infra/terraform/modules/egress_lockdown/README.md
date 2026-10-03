# egress_lockdown

Makes the VICT egress proxy the only network path out of an LSP's application subnets, so no application code, SDK or library can bypass it. One gap remains: DNS lookups through the VPC resolver (see [Not covered: DNS](#not-covered-dns)).

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
3. Point app instances at the proxy (`HTTPS_PROXY=http://<proxy>:3128`) and run `verify_lockdown.sh <proxy>:3128` on one of them. See [Prove it on the deployment](#prove-it-on-the-deployment).

## Why not a transparent sidecar or eBPF filter

A transparent interceptor sees only the destination and encrypted bytes. It has no consent token, so it cannot tell one borrower's call from another's. Reading more would mean terminating TLS, which breaks the client certificates and signed payloads bureaus and AAs require. An explicit proxy keeps per-call consent and end-to-end TLS. The network layers above remove the bypass.

## Before you apply

- **Explicit route table associations.** A subnet that already has one must be detached first, or the association fails with `Resource.AlreadyAssociated`.
- **Anything the app reached directly breaks**, including package mirrors and AWS APIs. Reach AWS services through this module's endpoints (below), and other hosts through the proxy's allow-list.
- **Never add a VPC endpoint by hand.** An endpoint without a policy reaches every account's resources, so app code could write borrower data to an attacker's bucket or queue without touching the internet.

## AWS services without an internet path

```hcl
module "egress_lockdown" {
  # ...
  enable_s3_gateway_endpoint  = true                 # free
  s3_read_only_external_arns  = ["arn:aws:s3:::al2023-repos-ap-south-1-*/*"]
  interface_endpoint_services = ["sqs", "logs"]      # billed hourly by AWS, per subnet
}
```

Every endpoint gets a policy that allows a request only when both the caller and the resource belong to this account (`aws:PrincipalAccount` and `aws:ResourceAccount`). The first condition stops credentials smuggled in from another account; the second stops writes to another account's bucket or queue. Buckets outside the account, such as OS package repositories, can be listed for read-only access to objects.

The S3 gateway endpoint sends traffic to S3's public ranges, so the module also opens HTTPS to exactly the addresses in the region's S3 prefix list, in both the network ACL and the app security group. Interface endpoints sit inside the VPC and get their own security group that accepts HTTPS from app instances only. Check that each service you list supports endpoint policies.

## Prove it on the deployment

Configuration review isn't proof. `verify_lockdown.sh` tries to get data out from an app instance and records what actually happened, in a JSON report with a SHA-256 you can hand to the NBFC:

| Probe | Must |
|---|---|
| Direct HTTPS to a hostname and to a raw IPv4, plain HTTP, raw TCP to port 53 | time out. A refusal or reset still counts as a path out. |
| Direct HTTPS over IPv6 | fail, or the instance has no IPv6 address |
| UDP DNS query straight to 1.1.1.1 | get no answer |
| External names through the VPC resolver | reported as a **GAP** until DNS Firewall is on |
| The proxy without a token, with a forged token, with plain HTTP | answer 407, 403 and 405 |
| `FOREIGN_BUCKET`: write to and list a bucket in another account | be denied (`OWN_BUCKET` is the control that shows S3 itself works) |
| `FOREIGN_SQS_URL`: send to a queue in another account | be denied |
| `RELAY_CANDIDATES`: forward through internal hosts | fail |

```bash
OWN_BUCKET=lsp-evidence FOREIGN_BUCKET=probe-target-in-another-account RELAY_CANDIDATES="10.0.5.10:3128" ./verify_lockdown.sh 10.0.2.15:3128
```

For the foreign probes, create the target bucket or queue in a second AWS account with a policy that lets anyone write, so the only thing that can stop the write is this module. Run the probes again after every infrastructure change.

## Not covered: DNS

Security groups and network ACLs do not filter queries to the Amazon-provided DNS resolver. Compromised code could leak small amounts of data by looking up names like `<data>.attacker.example`. Closing this needs Route 53 Resolver DNS Firewall, which is a paid AWS service. It is cheap at low volume, but check current pricing before turning it on.

## Cost

Route tables, network ACLs, security groups and the S3 gateway endpoint are free. Interface endpoints are billed per hour, per subnet, plus per GB. Public IPv4 addresses, including the proxy's Elastic IP, are billed hourly by AWS. NAT gateways are avoided on purpose, because they are billed hourly plus per GB.
