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
3. **Compliance Monitor** (`src/monitor/`) - Falco/Tetragon rule-first eBPF observability & enforcement
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

## Deploy Backend on Render (for Vercel frontend)

1. Create a new Render Web Service from this repo.
2. Render can auto-detect `render.yaml`, or configure manually:
   - Build command: `pip install -r src/requirements.txt`
   - Start command: `uvicorn src.gateway.consent_gateway:app --host 0.0.0.0 --port $PORT`
3. Ensure env vars are set:
   - `VICT_DEMO_SKIP_WASM=true`
   - `VICT_REGION=ap-south-1`
   - `VICT_CONSENT_DB=/tmp/vict-consent.db`
4. Copy your Render URL, for example:
   - `https://vict-sovereign-faas-api.onrender.com`

Note:
- The repo pins Python via `runtime.txt` (`python-3.11.10`) to avoid `pydantic-core` build failures on unsupported preview runtimes.
- If Render still builds with `python3.14`, set `PYTHON_VERSION=3.11.10` in Render Environment, then redeploy with "Clear build cache".

Then update frontend API config in `demo/portal/index.html`:

```html
<meta name="vict-api-base" content="https://YOUR-RENDER_API_URL.onrender.com" />
```

Without this, the frontend defaults to localhost only during local development.

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
5. In Developer panel, click `Simulate US Egress Breach` to trigger a visible red RBI localization denial banner.

## Hackathon MVP Scope (Hardened PoC)

1. **Level 1 - Identity**: API gateway checks consent table before processing personal/payment data.
2. **Level 2 - Vault/Runtime**: Wasm-based function execution path with minimal capabilities.
3. **Level 3 - Guardrail**: One localization rule blocks non-India egress and emits judge-visible denial.

PowerShell one-shot demo:

```powershell
powershell -ExecutionPolicy Bypass -File demo/run_demo.ps1
```

## IDE Plugin Direction

See `docs/IDE_PLUGIN_SPEC.md` for diagnostics and quick-fix behavior of the VICT security co-pilot extension.

## License

Built for digital sovereignty.
