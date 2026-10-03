"""Sign and verify lockdown probe reports with the LSP's checkpoint key.

The NBFC already pins this Ed25519 key to verify ledger checkpoints, so a signed
report is tied to the same LSP. A signature proves who published the report and
that it hasn't changed since. It doesn't prove the probes ran as described: the
LSP runs them on its own infrastructure. The report says so in its attestation
field, and so should anyone presenting it.

    python -m src.egress.attest sign report.json --key lsp-checkpoint.pem --lsp-id lsp-acme
    python -m src.egress.attest verify report.json --public-key lsp-checkpoint.pub.pem --lsp-id lsp-acme
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.egress.checkpoint import load_public_key


def _message(statement: dict[str, str]) -> bytes:
    return json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(report: Path, key: Ed25519PrivateKey, lsp_id: str) -> dict[str, str]:
    statement = {
        "lsp_id": lsp_id,
        "report": report.name,
        "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return {**statement, "alg": "Ed25519", "sig": base64.b64encode(key.sign(_message(statement))).decode("ascii")}


def verify(report: Path, signature: dict[str, str], public_key_pem: str, lsp_id: str) -> tuple[bool, str]:
    if signature.get("lsp_id") != lsp_id:
        return False, "wrong-lsp"
    if hashlib.sha256(report.read_bytes()).hexdigest() != signature.get("report_sha256"):
        return False, "report-changed"
    statement = {field: signature[field] for field in ("lsp_id", "report", "report_sha256", "signed_at")}
    try:
        load_public_key(public_key_pem).verify(base64.b64decode(signature["sig"]), _message(statement))
    except (InvalidSignature, ValueError, KeyError):
        return False, "bad-signature"
    return True, "verified"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sign or verify a verify_lockdown.sh report")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("sign")
    s.add_argument("report", type=Path)
    s.add_argument("--key", type=Path, required=True, help="the LSP's Ed25519 checkpoint private key (PEM)")
    s.add_argument("--lsp-id", required=True)
    v = sub.add_parser("verify")
    v.add_argument("report", type=Path)
    v.add_argument("--public-key", type=Path, required=True, help="the LSP's pinned public key (PEM)")
    v.add_argument("--lsp-id", required=True)
    args = parser.parse_args(argv)
    sig_path = args.report.with_name(args.report.name + ".sig")

    if args.command == "sign":
        key = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            parser.error("the checkpoint key must be Ed25519")
        sig_path.write_text(json.dumps(sign(args.report, key, args.lsp_id), indent=2) + "\n", encoding="utf-8")
        print(f"signed: {sig_path}")
        return 0

    ok, reason = verify(args.report, json.loads(sig_path.read_text(encoding="utf-8")), args.public_key.read_text(), args.lsp_id)
    report = json.loads(args.report.read_text(encoding="utf-8"))
    print(f"{reason}: {report.get('summary')} from {report.get('position', {}).get('subnet_id') or 'unknown position'}")
    print(report.get("attestation", ""))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
