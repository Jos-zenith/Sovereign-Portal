# VICT - Sovereign FaaS Platform

**Verifiable, Isolated, Compliant, Traceable** - A sovereignty-first serverless platform built for India's data protection regime (DPDP Act & RBI guidelines).

## Architecture Overview

```
User
   │
   ▼
Consent Gateway
   │
   ▼
VICT Runtime (Wasm Sandbox)
   │
   ▼
Compliance Monitor (eBPF)
   │
   ▼
Secure Data Layer (India region)
```

## Core Modules

1. **Consent Gateway** (`src/gateway/`) - Consent-aware API entry point
2. **VICT Runtime** (`src/runtime/`) - WebAssembly sandbox for function isolation
3. **Compliance Monitor** (`src/monitor/`) - eBPF-based observability & enforcement
4. **Sovereignty Layer** (`compliance/`) - DPDP & RBI compliance logic
5. **Deployment Stack** (`infra/`) - Infrastructure-as-Code for sovereign deployment

## Deployment Architecture

```
AWS Graviton EC2 (India Region)
     │
     ├── VICT Gateway
     ├── Wasm Runtime
     ├── Consent DB
     └── SigNoz Monitoring
```

### Technology Stack

- **Compute**: AWS EC2 Graviton (ARM64)
- **Isolation**: WebAssembly Runtime
- **Observability**: eBPF + SigNoz
- **Orchestration**: Kubernetes (optional)
- **Region**: India (Mumbai/Hyderabad)

## Project Structure

```
vict-sovereign-faas/
├── compliance/               # Sovereignty Layer (DPDP & RBI logic)
├── src/
│   ├── gateway/              # Consent-Aware API Entry Point
│   ├── runtime/              # WebAssembly (Wasm) Sandbox Modules
│   └── monitor/              # eBPF & Observability Logic
├── infra/                    # Infrastructure-as-Code (IaC)
├── demo/                     # Visual "Attack vs. Shield" Proofs
└── docs/                     # Forensic Audit & Research Evidence
```

## Getting Started

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture documentation.
See [docs/SOVEREIGN_MATURITY_MODEL.md](docs/SOVEREIGN_MATURITY_MODEL.md) for the L1-L5 scale roadmap and implementation mapping.
See [docs/COMPETITION_POSITIONING.md](docs/COMPETITION_POSITIONING.md) for technical differentiators and service-category framing.

## Quick Start (Local Scaffolding)

```bash
python -m pip install -r src/requirements.txt
set VICT_DEMO_SKIP_WASM=true
uvicorn src.gateway.consent_gateway:app --host 0.0.0.0 --port 8080
```

The consent database is auto-initialized on startup (default path: `vict-consent.db`).

## Unified Sovereign Portal (Demo)

Open `demo/portal/index.html` in a browser to view the three-role interface:
- Developer Co-pilot
- Auditor Command Dashboard
- Citizen Consent Vault

## Developer Workflow (Challenge Demo)

```bash
python src/vict_cli.py scan demo/sample_function.py
python src/vict_cli.py wrap demo/sample_function.py --out dist
python src/vict_cli.py deploy --region ap-south-1 --workspace .
```

## Live Consent + Audit Demo

1. Start gateway:

```bash
set VICT_DEMO_SKIP_WASM=true
uvicorn src.gateway.consent_gateway:app --host 0.0.0.0 --port 8080
```

2. Open `demo/portal/index.html` and use Citizen "Agree" / "Deny".
3. In Developer panel, click `Run Function Demo` to see ALLOWED/BLOCKED runtime result.
4. Switch to Auditor panel to see live `/audit/recent` updates and heartbeat counters.

PowerShell one-shot demo:

```powershell
powershell -ExecutionPolicy Bypass -File demo/run_demo.ps1
```

## IDE Plugin Direction

See `docs/IDE_PLUGIN_SPEC.md` for diagnostics and quick-fix behavior of the VICT security co-pilot extension.

## License

Built for digital sovereignty.
