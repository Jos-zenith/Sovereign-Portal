# Infrastructure as Code

This directory contains deployment configurations for VICT on sovereign infrastructure.

## Target Platforms

### 1. AWS Graviton (Recommended)
- Region: `ap-south-1` (Mumbai) or `ap-south-2` (Hyderabad)
- Instance: Graviton2/3 (ARM64)
- Storage: EBS encrypted at rest
- Network: VPC with isolated subnets

### 2. Kubernetes (Optional)
- CNI: Cilium (eBPF-based)
- Runtime: containerd with Wasm support
- Monitoring: SigNoz + Prometheus

## Deployment Components

```
infra/
├── terraform/          # AWS Graviton provisioning
├── kubernetes/         # K8s manifests (optional)
├── ansible/            # Configuration management
└── monitoring/         # SigNoz/Prometheus configs
```

## Getting Started

### Deploy on AWS Graviton

```bash
cd terraform/
terraform init
terraform plan -var="region=ap-south-1"
terraform apply
```

### Deploy on Kubernetes

```bash
cd kubernetes/
kubectl apply -f namespace.yaml
kubectl apply -f deployments/
```

## Infrastructure Requirements

- **Compute**: 4+ vCPUs (ARM64 preferred)
- **Memory**: 8GB+ RAM
- **Storage**: 50GB+ encrypted SSD
- **Network**: Private subnet with NAT gateway
- **Region**: India data centers only

## Security Hardening

- SELinux/AppArmor enabled
- eBPF probes require CAP_BPF capability
- TLS 1.3 for all external communication
- Encrypted EBS volumes
- IMDSv2 required for EC2 metadata
