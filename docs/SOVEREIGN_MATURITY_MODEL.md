# VICT Sovereign Serverless Maturity Model (L1-L5)

This document maps VICT implementation work to a technical maturity model designed to outperform standard cloud-native FaaS architectures under sovereignty, performance, and compliance constraints.

## Level 1 - Sovereign Baseline

- India-region enforcement in IaC (`ap-south-1`, `ap-south-2` only).
- Graviton-first compute baseline for ARM64 efficiency.
- Encrypted storage and IMDSv2 hardening.

Status: Implemented in `infra/terraform/main.tf`.

## Level 2 - Compliance-as-Code Foundation

- Consent and purpose checks codified as a gateway control point.
- Policy-as-code definitions for residency and invocation controls.
- Consent audit trail persistence.

Status: Implemented scaffolding in:
- `src/gateway/consent_gateway.py`
- `src/gateway/identity_bridge.py`
- `compliance/sovereign_policy.rego`
- `compliance/consent_schema.sql`

## Level 3 - Runtime Sovereignty Controls

- Wasm-first execution model with capability-oriented defaults.
- No ambient network access unless explicitly enabled.
- Minimal WASI preopens for least privilege.

Status: Implemented scaffolding in:
- `src/runtime/wasm_runner.py`
- `infra/terraform/scripts/bootstrap.sh`

## Level 4 - Forensic-grade Observability

- eBPF syscall/network visibility for ephemeral workloads.
- Real-time event stream suitable for SigNoz/OTEL ingestion.
- Compliance telemetry rules for cross-border, consent, and isolation events.

Status: Implemented scaffolding in:
- `src/monitor/ebpf_forensics.py`
- `infra/monitoring/compliance_rules.yml`
- `infra/monitoring/prometheus.yml`

## Level 5 - Autonomous Sovereign Enforcement

- Immutable evidence storage to preserve breach forensics.
- Automatic 24-hour purge of non-sovereign ephemeral cache.
- Continuous policy controls that block non-compliant invocation paths.

Status: Implemented in Terraform:
- Immutable object lock bucket (`vict_evidence`).
- Ephemeral cache bucket with max-24h lifecycle.

Status: Implemented in security automation:
- `compliance/iam_autopilot.py`
- `compliance/service_access_manifest.json`
- `compliance/runtime_guardrails.rego`
- `.github/workflows/supply-chain-security.yml`

## Remaining Work to Productionize

- Replace SQLite adapter with managed Postgres (RDS India region).
- Add policy evaluation middleware using OPA sidecar or embedded engine.
- Implement SigNoz/OTEL collector deployment without Docker dependency on host.
- Integrate generated policies with deployment roles and IAM Access Analyzer verification.
- Replace placeholder identity verifier with WebAuthn/FIDO2 + telecom-backed strong auth.
