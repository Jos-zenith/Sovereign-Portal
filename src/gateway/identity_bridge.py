"""Identity bridge for low-friction authentication.

Supports passkey/mobile assertions and optional biometric confidence checks.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass
class IdentityAssertion:
    principal_id: str
    method: str
    verified: bool
    assurance_level: str


ALLOWED_METHODS = {"passkey", "mobile-otp", "biometric"}
IDENTITY_SECRET = os.getenv("VICT_IDENTITY_SECRET", "dev-secret-change-in-prod")


def build_assertion_token(principal_id: str) -> str:
    return hmac.new(
        IDENTITY_SECRET.encode("utf-8"),
        principal_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_identity_assertion(
    principal_id: str,
    method: str,
    assertion_token: str,
    biometric_confidence: float | None = None,
) -> IdentityAssertion:
    if method not in ALLOWED_METHODS:
        return IdentityAssertion(principal_id, method, False, "none")

    expected_token = build_assertion_token(principal_id)
    token_ok = hmac.compare_digest(assertion_token, expected_token)

    if method == "biometric":
        confidence = biometric_confidence or 0.0
        # NIST-style high-assurance threshold for biometric factors.
        verified = token_ok and confidence >= 0.90
        return IdentityAssertion(principal_id, method, verified, "aal2" if verified else "none")

    verified = token_ok
    assurance = "aal2" if method == "passkey" and verified else "aal1" if verified else "none"
    return IdentityAssertion(principal_id, method, verified, assurance)
