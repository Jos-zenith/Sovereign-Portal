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

## Portal (Demo)

`demo/portal/` is the public site, aimed at digital-lending LSPs and their NBFC partners. It is static HTML, CSS and JS with no build step:

| Page | What it's for |
|---|---|
| `index.html` | Home: animated flow, DPDP countdown, live loan-file simulator, rejection slips |
| `demo.html` | Seven "try to break it" missions, including withdrawing consent mid-stream and rewriting the log as a dishonest LSP; consent vault, NBFC evidence and the audit ledger |
| `how-it-works.html` | Consent tokens, the proxy, network lockdown, the witnessed ledger, code samples |
| `nbfc.html` | For NBFC risk teams: what the witness checks, proves and doesn't prove |
| `regulation.html` | RBI Digital Lending Directions and DPDP obligations mapped to what VICT enforces |
| `self-host.html` | Running it in AWS Mumbai, costs, what's left to build, limits, FAQ |

Shared code lives in `demo/portal/assets/`. Every live number comes from the running gateway's `/egress/*` API; the vendors are local stand-ins, so no data leaves the server.

Run it locally:

```bash
python -m pip install -r src/requirements.txt
uvicorn src.gateway.consent_gateway:app --host 127.0.0.1 --port 8080
python -m http.server 5500 --directory demo/portal
```

Open http://127.0.0.1:5500. Elsewhere the page uses the `vict-api-base` meta tag, or `?api=<url>` to point at any gateway. The previous portal is kept in `demo/portal-legacy/` and is not deployed.

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
- The portal's demo state (consents, audit log) lives in temporary files, so it starts fresh whenever the free instance sleeps and wakes.

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

## Live Demo Walkthrough

1. Start the gateway and portal as above.
2. LSP developer: run "Eligibility check to the bureau" (allowed), then "Same check for borrower-002" (blocked before any network call).
3. Run "Analytics SDK sends data to analytics.example.com": the egress proxy blocks it because the host is not allow-listed.
4. Borrower: withdraw borrower-001's loan-eligibility consent and run the eligibility check again (blocked: consent-withdrawn).
5. NBFC partner: send a checkpoint, then press "Act as a dishonest LSP". The rebuilt chain still verifies, but the NBFC's checkpoint no longer matches.

## Hackathon MVP Scope (Hardened PoC)

1. **Level 1 - Identity**: API gateway checks consent table before processing personal/payment data.
2. **Level 2 - Vault/Runtime**: Wasm-based function execution path with minimal capabilities.
3. **Level 3 - Guardrail**: One localization rule blocks non-India egress and emits judge-visible denial.

PowerShell one-shot demo:

```powershell
powershell -ExecutionPolicy Bypass -File demo/run_demo.ps1
```

## Egress Gate Spike

A consent-gated CONNECT proxy plus a thin SDK, so LSPs can enforce consent on outbound calls without rewriting code into Wasm:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python demo/egress_spike_demo.py
```

Design, pass criteria and open gaps are in [docs/EGRESS_SPIKE.md](docs/EGRESS_SPIKE.md). Infrastructure lockdown, log throughput and NBFC checkpointing are in [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md).

## IDE Plugin Direction

See `docs/IDE_PLUGIN_SPEC.md` for diagnostics and quick-fix behavior of the VICT security co-pilot extension.

## License

Built for digital sovereignty.
