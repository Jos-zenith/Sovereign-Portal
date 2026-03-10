# VICT Architecture Documentation

## System Design Philosophy

VICT is built on the principle that **data sovereignty is not optional**. Every layer of the stack enforces compliance with India's Digital Personal Data Protection Act (DPDP) and RBI guidelines.

## Five-Layer Architecture

## Sovereign Ecosystem Flow (Zero-Trust)

```
Citizen App (Passkey/Biometric)
   |
Identity Bridge (AAL-based verification)
   |
Consent Gateway (JIT DPDP purpose/consent check)
   |
Wasm Runtime (capability-based, no ambient authority)
   |
eBPF Monitor (kernel-level syscall and egress visibility)
   |
Immutable Evidence Store + SigNoz (forensic preservation + real-time alerts)
```

Security and compliance controls are enforced at each hop. Any failure in identity,
consent, region, or runtime behavior blocks processing by default.

### 1. Consent Gateway

**Location**: `src/gateway/`

**Purpose**: First line of defense - validates user consent before any function execution.

**Responsibilities**:
- Parse and validate consent tokens
- Verify purpose limitation (DPDP Sec 6)
- Route requests to appropriate runtime instances
- Log consent events for audit

**Technology**:
- Fast HTTP proxy (Nginx/Envoy/custom Go service)
- JWT-based consent tokens
- Redis for consent cache
- Identity bridge adapter for passkey/biometric assertions (`src/gateway/identity_bridge.py`)

### 2. VICT Runtime (Wasm Sandbox)

**Location**: `src/runtime/`

**Purpose**: Isolated execution environment for serverless functions.

**Responsibilities**:
- Execute user functions in WebAssembly sandbox
- Enforce memory and CPU limits
- Prevent unauthorized data exfiltration
- Provide minimal, auditable system calls

**Technology**:
- WasmEdge or Wasmtime runtime
- WASI (WebAssembly System Interface)
- Resource quotas per tenant

### 3. Compliance Monitor (eBPF)

**Location**: `src/monitor/`

**Purpose**: Kernel-level visibility and enforcement of data movement.

**Responsibilities**:
- Track all network egress attempts
- Detect cross-border data leakage
- Monitor syscall patterns for anomalies
- Generate forensic audit trails

**Technology**:
- eBPF probes (bpftrace/libbpf)
- Cilium for network policies
- Prometheus metrics export

### 4. Sovereignty Layer

**Location**: `compliance/`

**Purpose**: Policy engine for DPDP and RBI compliance.

**Responsibilities**:
- Define data residency rules
- Implement consent withdrawal workflows
- Purpose limitation enforcement
- Data localization validation

**Technology**:
- Policy-as-code (OPA/Cedar)
- Compliance rules database
- Audit log aggregation

### 5. Deployment Stack

**Location**: `infra/`

**Purpose**: Infrastructure provisioning for sovereign cloud deployment.

**Responsibilities**:
- Deploy to India-region cloud resources
- Configure network isolation
- Setup monitoring and alerting
- Ensure encrypted storage

## Deployment Architecture

### Recommended Setup: AWS Graviton (Mumbai/Hyderabad)

```
┌─────────────────────────────────────────────┐
│  AWS EC2 Graviton Instance (ap-south-1)     │
│                                             │
│  ┌─────────────────────────────────────┐   │
│  │  VICT Gateway (Port 8080)           │   │
│  │  - Consent validation               │   │
│  │  - Request routing                  │   │
│  └─────────────────────────────────────┘   │
│                   │                         │
│  ┌─────────────────────────────────────┐   │
│  │  Wasm Runtime Pool                  │   │
│  │  - WasmEdge instances               │   │
│  │  - Function isolation               │   │
│  └─────────────────────────────────────┘   │
│                   │                         │
│  ┌─────────────────────────────────────┐   │
│  │  eBPF Compliance Monitor            │   │
│  │  - Network tracking                 │   │
│  │  - Syscall auditing                 │   │
│  └─────────────────────────────────────┘   │
│                   │                         │
│  ┌─────────────────────────────────────┐   │
│  │  PostgreSQL (Consent DB)            │   │
│  │  - Encrypted at rest                │   │
│  │  - India region only                │   │
│  └─────────────────────────────────────┘   │
│                                             │
│  ┌─────────────────────────────────────┐   │
│  │  SigNoz Monitoring                  │   │
│  │  - Traces & metrics                 │   │
│  │  - Compliance dashboards            │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

### Why AWS Graviton?

- **Cost-effective**: 40% better price-performance vs x86
- **Energy-efficient**: Lower carbon footprint
- **ARM64**: Native support for modern Wasm runtimes
- **India regions**: Mumbai (ap-south-1), Hyderabad (ap-south-2)

### Optional: Kubernetes Deployment

For multi-tenant scenarios, deploy on K8s with:
- **Network Policies**: Cilium with eBPF dataplane
- **Pod Security**: Isolated namespaces per tenant
- **Service Mesh**: Istio for mTLS and traffic control
- **Monitoring**: SigNoz + Prometheus + Grafana

## Data Flow Example

```
1. User Request
   ↓
2. Consent Gateway validates JWT
   - Check: Valid consent token?
   - Check: Purpose matches request?
   - Check: Consent not withdrawn?
   ↓
3. Route to Wasm Runtime
   - Instantiate sandboxed function
   - Inject approved data scope only
   ↓
4. eBPF Monitor observes execution
   - Track network calls
   - Detect cross-border attempts
   - Log to audit trail
   ↓
5. Response returned to user
   - No data leaked
   - Full audit trail maintained
```

## Security Guarantees

1. **Isolation**: Wasm sandbox prevents lateral movement
2. **Visibility**: eBPF sees every syscall and network packet
3. **Compliance**: Policy engine enforces DPDP/RBI rules
4. **Auditability**: Immutable logs for forensic analysis
5. **Residency**: Data never leaves India infrastructure

## Monitoring & Observability

### Metrics to Track

- Consent validation rate (success/failure)
- Function execution time per tenant
- Cross-border network attempts (should be 0)
- eBPF probe overhead (< 5% CPU)
- Consent withdrawal latency

### Dashboards

- **Sovereignty Dashboard**: Data residency compliance
- **Security Dashboard**: Anomaly detection
- **Performance Dashboard**: Runtime metrics
- **Audit Dashboard**: Forensic event timeline

## Compliance Evidence

All architectural decisions are documented in `docs/` with references to:
- DPDP Act sections (e.g., Sec 6: Purpose Limitation)
- RBI Master Directions on data localization
- ISO 27001 controls
- NIST privacy framework mappings

## Next Steps

1. Implement Consent Gateway prototype (`src/gateway/`)
2. Integrate WasmEdge runtime (`src/runtime/`)
3. Deploy eBPF probes (`src/monitor/`)
4. Define compliance policies (`compliance/`)
5. Build IaC templates (`infra/`)
6. Ship IDE co-pilot diagnostics based on `vict scan` (`docs/IDE_PLUGIN_SPEC.md`)
7. Use `src/vict_cli.py` for scan/wrap/deploy developer workflow
