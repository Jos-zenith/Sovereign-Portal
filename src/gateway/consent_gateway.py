"""VICT Just-in-Time Consent Gateway.

Validates consent before every personal-data function invocation.
"""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.gateway.identity_bridge import verify_identity_assertion
from src.runtime.wasm_runner import WasmRunner


DB_PATH = os.getenv("VICT_CONSENT_DB", "/opt/vict/consent-db/consent.db")
RUNTIME_WASM = os.getenv("VICT_RUNTIME_WASM", "/opt/vict/runtime/handler.wasm")

app = FastAPI(title="VICT Consent Gateway", version="0.1.0")
runner = WasmRunner()


class InvocationRequest(BaseModel):
    principal_id: str = Field(..., min_length=3)
    purpose: str = Field(..., min_length=3)
    data_classification: str = Field(..., description="e.g. personal, payment, non-personal")
    auth_method: str = Field(..., description="passkey, mobile-otp, biometric")
    assertion_token: str = Field(..., min_length=12)
    biometric_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    payload: dict[str, Any] = Field(default_factory=dict)


@dataclass
class ConsentDecision:
    allowed: bool
    reason: str


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def evaluate_consent(principal_id: str, purpose: str) -> ConsentDecision:
    with _db() as conn:
        row = conn.execute(
            """
            SELECT granted, withdrawn_at, expires_at
            FROM consent_master
            WHERE principal_id = ? AND purpose = ?
            """,
            (principal_id, purpose),
        ).fetchone()

    if not row:
        return ConsentDecision(False, "consent-record-not-found")
    if int(row["granted"]) != 1:
        return ConsentDecision(False, "consent-not-granted")
    if row["withdrawn_at"]:
        return ConsentDecision(False, "consent-withdrawn")

    if row["expires_at"]:
        expires = datetime.fromisoformat(row["expires_at"])
        if expires < datetime.now(timezone.utc):
            return ConsentDecision(False, "consent-expired")

    return ConsentDecision(True, "consent-valid")


def log_audit(principal_id: str, purpose: str, decision: ConsentDecision) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO consent_audit(principal_id, purpose, decision, reason, recorded_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (principal_id, purpose, "allow" if decision.allowed else "deny", decision.reason, now),
        )
        conn.commit()


@app.post("/invoke")
def invoke(req: InvocationRequest) -> dict[str, Any]:
    identity = verify_identity_assertion(
        principal_id=req.principal_id,
        method=req.auth_method,
        assertion_token=req.assertion_token,
        biometric_confidence=req.biometric_confidence,
    )
    if not identity.verified:
        raise HTTPException(status_code=401, detail="Identity assertion failed")

    # DPDP JIT control: always check consent before handling personal/payment data.
    requires_consent = req.data_classification in {"personal", "payment"}
    if requires_consent:
        decision = evaluate_consent(req.principal_id, req.purpose)
        log_audit(req.principal_id, req.purpose, decision)
        if not decision.allowed:
            raise HTTPException(status_code=403, detail=f"Invocation blocked: {decision.reason}")

    result = runner.execute(
        wasm_path=RUNTIME_WASM,
        payload=req.payload,
        allow_network=False,
        wasi_preopens=["/tmp"],
    )
    return {"status": "ok", "result": result}


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "healthy", "component": "consent-gateway"}
