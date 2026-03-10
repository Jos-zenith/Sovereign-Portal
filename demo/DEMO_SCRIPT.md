# VICT Live Demo Script (5 Minutes)

## Setup (30-60 seconds)

Open terminal in project root and run:

```powershell
python -m pip install -r src/requirements.txt
$env:VICT_DEMO_SKIP_WASM = "true"
python -m uvicorn src.gateway.consent_gateway:app --host 0.0.0.0 --port 8080
```

Open `demo/portal/index.html` in browser.

## Minute 1: Problem Framing

Say:

"A single non-India API call with personal data can create an immediate DPDP and RBI exposure. VICT blocks this before execution, not after audit."

## Minute 2: Developer Build-Time Check

Run in another terminal:

```powershell
python src/vict_cli.py scan demo/sample_function.py
```

Expected: Warning about PII context with non-India endpoint.

## Minute 3: Runtime Block (No Consent)

In portal:

1. Go to `Developer Co-pilot`.
2. Click `Run Function Demo` before granting consent.

Expected:
- `BLOCKED` result (red) in invoke output.
- Auditor feed logs `deny` with `consent-record-not-found`.

## Minute 4: Visual RBI Localization Breach (Judge-visible)

In portal:

1. Stay in `Developer Co-pilot`.
2. Click `Simulate US Egress Breach`.

Expected:
- Red flashing banner: `[ACCESS DENIED: RBI LOCALIZATION BREACH]`.
- Invoke output shows `BLOCKED` with localization breach detail.
- This demonstrates guardrail behavior judges can see instantly.

## Minute 5: Runtime Allow (After Consent)

In portal:

1. Go to `Citizen Consent Vault`.
2. Click `Agree`.
3. Return to `Developer Co-pilot` and click `Run Function Demo` again.

Expected:
- `ALLOWED` result (green).
- Auditor feed logs `allow` with `consent-valid`.
- Compliance Heartbeat counters update.

## Minute 6: Auditor Control + Close

In `Auditor Command`:

1. Show live heartbeat counters (Allow, Deny, Total Events).
2. Show real audit event rows (color-coded).
3. Click `Revoke RBI Compliance (Kill-Switch Demo)`.

Close with:

"This is sovereignty as runtime behavior: identity, consent, and localization enforced on each invocation, with immutable forensic evidence."

## Guardrail Engine Note (Hackathon Scope)

Use Falco or Tetragon rule packs as the eBPF base, not raw kernel programs.
The project includes rule-first scaffolding in `src/monitor/ebpf_forensics.py`.

## Backup Commands

If needed, generate deterministic token and call invoke directly:

```powershell
$token = (Invoke-RestMethod -Uri "http://127.0.0.1:8080/identity/token/citizen-001" -Method GET).assertion_token
Invoke-RestMethod -Uri "http://127.0.0.1:8080/invoke" -Method POST -ContentType "application/json" -Body (@{
  principal_id = "citizen-001"
  purpose = "gst-location"
  data_classification = "personal"
  auth_method = "passkey"
  assertion_token = $token
  payload = @{ amount = 5000 }
} | ConvertTo-Json -Depth 5)
```
