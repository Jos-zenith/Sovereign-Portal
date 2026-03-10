#!/bin/bash
# VICT Server Bootstrap Script
# Runs on first boot of Graviton EC2 instance

set -euo pipefail

echo "=== VICT Sovereign FaaS - Bootstrap ==="

# Update system
apt-get update -y
apt-get upgrade -y

# Install dependencies
apt-get install -y \
    curl \
    wget \
    git \
    jq \
    build-essential \
    linux-tools-common \
    linux-tools-generic \
    ca-certificates \
    gnupg \
    lsb-release

# Install WasmEdge runtime (primary execution engine)
curl -sSf https://raw.githubusercontent.com/WasmEdge/WasmEdge/master/utils/install.sh | bash -s -- -v 0.13.5

# Source WasmEdge environment
source $HOME/.wasmedge/env

# Install Wasmtime CLI for compatibility testing
WASMTIME_VERSION="18.0.4"
wget -qO /tmp/wasmtime.tar.xz "https://github.com/bytecodealliance/wasmtime/releases/download/v${WASMTIME_VERSION}/wasmtime-v${WASMTIME_VERSION}-aarch64-linux.tar.xz"
tar -xJf /tmp/wasmtime.tar.xz -C /tmp
install -m 0755 /tmp/wasmtime-v${WASMTIME_VERSION}-aarch64-linux/wasmtime /usr/local/bin/wasmtime

# Install eBPF tools
apt-get install -y \
    bpfcc-tools \
    libbpf-dev \
    bpftrace

# Prepare monitoring directories (collector deployment is managed by IaC/ops pipeline)
mkdir -p /opt/vict/monitoring

# Create VICT directories
mkdir -p /opt/vict/{gateway,runtime,monitor,consent-db,logs}

# Set permissions
chown -R ubuntu:ubuntu /opt/vict

# Enable eBPF capabilities
echo "kernel.unprivileged_bpf_disabled=0" >> /etc/sysctl.conf
echo "kernel.kptr_restrict=1" >> /etc/sysctl.conf
sysctl -p

# Minimal sovereign runtime defaults
cat >/etc/vict-runtime.env <<EOF
VICT_REGION=ap-south-1
VICT_ALLOWED_WASI_PREOPENS=/tmp
VICT_DEFAULT_NETWORK_ACCESS=deny
VICT_FOREIGN_CACHE_TTL_HOURS=24
EOF

# Configure firewall (UFW)
ufw --force enable
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow from 10.0.0.0/16 to any

# Install PostgreSQL (Consent DB)
apt-get install -y postgresql postgresql-contrib
systemctl enable postgresql
systemctl start postgresql

# Configure PostgreSQL for encryption at rest
echo "Starting PostgreSQL encryption configuration..."
# Note: Additional encryption setup would go here

# Install nginx (for gateway)
apt-get install -y nginx
systemctl enable nginx

# Create marker file
echo "VICT Bootstrap completed at $(date)" > /opt/vict/bootstrap.complete

echo "=== Bootstrap Complete ==="
echo "Next steps:"
echo "1. Deploy VICT gateway code"
echo "2. Configure consent database"
echo "3. Start monitoring collectors (SigNoz/OTel)"
