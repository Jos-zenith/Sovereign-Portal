"""VICT Just-in-Time Consent Gateway.

Validates consent before every personal-data function invocation.
"""

from __future__ import annotations

import os
import json
import sqlite3
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from src.gateway.identity_bridge import build_assertion_token, verify_identity_assertion
from src.runtime.wasm_runner import WasmRunner


DB_PATH = os.getenv("VICT_CONSENT_DB", "vict-consent.db")
RUNTIME_WASM = os.getenv("VICT_RUNTIME_WASM", "/opt/vict/runtime/handler.wasm")
VICT_REGION = os.getenv("VICT_REGION", "ap-south-1")
OPA_POLICY_PATH = os.getenv("VICT_SOVEREIGN_POLICY_PATH", "compliance/sovereign_policy.rego")
DEMO_SKIP_WASM = os.getenv("VICT_DEMO_SKIP_WASM", "false").lower() == "true"
REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "compliance" / "consent_schema.sql"

app = FastAPI(title="VICT Consent Gateway", version="0.1.0")
runner = WasmRunner()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class InvocationRequest(BaseModel):
    principal_id: str = Field(..., min_length=3)
    purpose: str = Field(..., min_length=3)
    data_classification: str = Field(..., description="e.g. personal, payment, non-personal")
    auth_method: str = Field(..., description="passkey, mobile-otp, biometric")
    assertion_token: str = Field(..., min_length=12)
    biometric_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    egress_region: str | None = Field(
        default=None,
        description="Optional destination region for outbound call simulation, e.g. ap-south-1 or us-east-1",
    )
    payload: dict[str, Any] = Field(default_factory=dict)


class ConsentRequest(BaseModel):
    principal_id: str = Field(..., min_length=3)
    purpose: str = Field(..., min_length=3)


@dataclass
class ConsentDecision:
    allowed: bool
    reason: str


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_db() -> None:
    db_file = Path(DB_PATH)
    if db_file.parent != Path("."):
        db_file.parent.mkdir(parents=True, exist_ok=True)
    if not SCHEMA_PATH.exists():
        raise RuntimeError(f"Consent schema not found: {SCHEMA_PATH}")

    with _db() as conn:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


@app.on_event("startup")
def startup() -> None:
    _ensure_db()


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


def evaluate_sovereignty_policy(region: str, data_classification: str, consent_allowed: bool, purpose: str) -> bool:
    # Fall back to region allow-list check if OPA is unavailable in the runtime.
    if not os.path.exists(OPA_POLICY_PATH):
        return region in {"ap-south-1", "ap-south-2"}

    input_doc = {
        "region": region,
        "data_classification": data_classification,
        "requested_purpose": purpose,
        "consent": {
            "granted": consent_allowed,
            "withdrawn": False,
            "purpose": purpose,
        },
    }

    cmd = [
        "opa",
        "eval",
        "-f",
        "json",
        "-d",
        OPA_POLICY_PATH,
        "-I",
        json.dumps(input_doc),
        "data.vict.sovereignty.allow_region",
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return region in {"ap-south-1", "ap-south-2"}

    if result.returncode != 0:
        return False

    payload = json.loads(result.stdout)
    records = payload.get("result", [])
    if not records:
        return False
    expressions = records[0].get("expressions", [])
    if not expressions:
        return False
    return bool(expressions[0].get("value", False))


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

    effective_region = req.egress_region or VICT_REGION

    if not evaluate_sovereignty_policy(
        region=effective_region,
        data_classification=req.data_classification,
        consent_allowed=True,
        purpose=req.purpose,
    ):
        raise HTTPException(
            status_code=403,
            detail=f"[ACCESS DENIED: RBI LOCALIZATION BREACH] Destination region '{effective_region}' is outside India-approved zones",
        )

    if DEMO_SKIP_WASM:
        result = {
            "mode": "demo-skip-wasm",
            "message": "Invocation allowed after identity + consent + sovereignty checks",
            "payload": req.payload,
        }
    else:
        result = runner.execute(
            wasm_path=RUNTIME_WASM,
            payload=req.payload,
            allow_network=False,
            wasi_preopens=["/tmp"],
        )
    return {"status": "ok", "result": result}


@app.get("/")
def root() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "vict-consent-gateway",
        "health": "/healthz",
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "healthy", "component": "consent-gateway"}


@app.post("/consent/grant")
def grant_consent(req: ConsentRequest) -> dict[str, str]:
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO consent_master
            (principal_id, purpose, granted, withdrawn_at, expires_at, updated_at)
            VALUES (?, ?, 1, NULL, NULL, ?)
            """,
            (req.principal_id, req.purpose, now),
        )
        conn.commit()
    return {"status": "granted"}


@app.post("/consent/revoke")
def revoke_consent(req: ConsentRequest) -> dict[str, str]:
    now = datetime.now(timezone.utc).isoformat()
    with _db() as conn:
        conn.execute(
            """
            UPDATE consent_master
            SET granted = 0, withdrawn_at = ?, updated_at = ?
            WHERE principal_id = ? AND purpose = ?
            """,
            (now, now, req.principal_id, req.purpose),
        )
        conn.commit()
    return {"status": "revoked"}


@app.get("/audit/recent")
def audit_recent(limit: int = 10) -> dict[str, Any]:
    bounded = max(1, min(50, limit))
    with _db() as conn:
        rows = conn.execute(
            """
            SELECT id, principal_id, purpose, decision, reason, recorded_at
            FROM consent_audit
            ORDER BY id DESC
            LIMIT ?
            """,
            (bounded,),
        ).fetchall()
    events = [dict(row) for row in rows]
    return {"events": events}


@app.get("/identity/token/{principal_id}")
def identity_token(principal_id: str) -> dict[str, str]:
    # Dev/demo helper to obtain deterministic assertion token.
    return {"principal_id": principal_id, "assertion_token": build_assertion_token(principal_id)}
