"""Short-lived consent tokens for the VICT egress proxy.

The consent authority mints them and the proxy verifies them. The application
only carries them: the signing key is shared by the authority and the proxy,
never handed to application code, so an app cannot mint its own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Iterable


class TokenError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ConsentToken:
    lsp_id: str
    principal_id: str
    purpose: str
    hosts: tuple[str, ...]
    expires_at: float
    token_id: str


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(key: bytes, body: str) -> str:
    return _b64encode(hmac.new(key, body.encode("ascii"), hashlib.sha256).digest())


def mint(
    key: bytes,
    *,
    lsp_id: str,
    principal_id: str,
    purpose: str,
    hosts: Iterable[str],
    ttl_seconds: float = 60,
    now: float | None = None,
) -> str:
    issued_at = time.time() if now is None else now
    claims = {
        "lsp": lsp_id,
        "sub": principal_id,
        "pur": purpose,
        "hosts": sorted({h.lower() for h in hosts}),
        "exp": issued_at + ttl_seconds,
        "jti": secrets.token_urlsafe(16),
    }
    body = _b64encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    return f"{body}.{_sign(key, body)}"


def verify(key: bytes, token: str, *, now: float | None = None) -> ConsentToken:
    parts = token.split(".")
    if len(parts) != 2:
        raise TokenError("token-malformed")
    body, signature = parts
    if not hmac.compare_digest(signature, _sign(key, body)):
        raise TokenError("token-bad-signature")

    try:
        claims = json.loads(_b64decode(body))
        parsed = ConsentToken(
            lsp_id=str(claims["lsp"]),
            principal_id=str(claims["sub"]),
            purpose=str(claims["pur"]),
            hosts=tuple(claims["hosts"]),
            expires_at=float(claims["exp"]),
            token_id=str(claims["jti"]),
        )
    except (ValueError, KeyError, TypeError):
        raise TokenError("token-malformed") from None

    current = time.time() if now is None else now
    if parsed.expires_at <= current:
        raise TokenError("token-expired")
    return parsed
