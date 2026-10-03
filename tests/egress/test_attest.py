"""Signed lockdown probe reports."""

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.egress import attest

LSP = "lsp-acme"


def _pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _report(tmp_path):
    path = tmp_path / "lockdown-report.json"
    path.write_text(json.dumps({"summary": {"total": 12, "fail": 0, "gap": 1}, "position": {"subnet_id": "subnet-app-a"}}))
    return path


def test_signed_report_verifies_against_the_pinned_key(tmp_path):
    key = Ed25519PrivateKey.generate()
    report = _report(tmp_path)
    assert attest.verify(report, attest.sign(report, key, LSP), _pem(key), LSP) == (True, "verified")


def test_edited_report_wrong_key_or_wrong_lsp_fail(tmp_path):
    key = Ed25519PrivateKey.generate()
    report = _report(tmp_path)
    signature = attest.sign(report, key, LSP)

    assert attest.verify(report, signature, _pem(Ed25519PrivateKey.generate()), LSP) == (False, "bad-signature")
    assert attest.verify(report, signature, _pem(key), "lsp-other") == (False, "wrong-lsp")
    report.write_text(report.read_text().replace('"fail": 0', '"fail": 3'))
    assert attest.verify(report, signature, _pem(key), LSP) == (False, "report-changed")


def test_cli_round_trip(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    key_path = tmp_path / "lsp.pem"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub_path = tmp_path / "lsp.pub.pem"
    pub_path.write_text(_pem(key))
    report = _report(tmp_path)

    assert attest.main(["sign", str(report), "--key", str(key_path), "--lsp-id", LSP]) == 0
    assert attest.main(["verify", str(report), "--public-key", str(pub_path), "--lsp-id", LSP]) == 0
    assert "verified" in capsys.readouterr().out
