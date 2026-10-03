"""Signed audit checkpoints.

The LSP signs each checkpoint with an Ed25519 key whose public half the NBFC
pins. A signed head binds the LSP to one history: it cannot later present a
log that does not pass through that head, or deny having published it.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNED_FIELDS = ("lsp_id", "seq", "head", "ts")


class CheckpointError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _message(checkpoint: dict[str, Any]) -> bytes:
    body = {field: checkpoint[field] for field in SIGNED_FIELDS}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CheckpointSigner:
    def __init__(self, lsp_id: str, private_key: Ed25519PrivateKey) -> None:
        self.lsp_id = lsp_id
        self._key = private_key

    @classmethod
    def generate(cls, lsp_id: str) -> "CheckpointSigner":
        return cls(lsp_id, Ed25519PrivateKey.generate())

    @classmethod
    def from_pem_file(cls, lsp_id: str, path: str | Path) -> "CheckpointSigner":
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("checkpoint signing key must be Ed25519")
        return cls(lsp_id, key)

    def public_key_pem(self) -> str:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("ascii")

    def sign(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        signed = {**checkpoint, "lsp_id": self.lsp_id}
        signed["sig"] = base64.b64encode(self._key.sign(_message(signed))).decode("ascii")
        return signed


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("checkpoint public key must be Ed25519")
    return key


def verify_signed(public_key: Ed25519PublicKey, signed: dict[str, Any], lsp_id: str) -> dict[str, Any]:
    try:
        if signed["lsp_id"] != lsp_id:
            raise CheckpointError("wrong-lsp")
        public_key.verify(base64.b64decode(signed["sig"]), _message(signed))
    except (KeyError, TypeError, ValueError):
        raise CheckpointError("checkpoint-malformed") from None
    except InvalidSignature:
        raise CheckpointError("bad-signature") from None
    return {field: signed[field] for field in (*SIGNED_FIELDS, "sig")}
