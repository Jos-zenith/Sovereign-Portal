import json
import time

import pytest

from src.egress import tokens
from src.egress.audit import AuditLog, _digest, read_records, verify_chain, verify_checkpoint
from src.egress.consent import ConsentDenied
from src.egress.policy import LocalPolicy

from .conftest import KEY, LSP, PURPOSE


def test_token_round_trip():
    raw = tokens.mint(KEY, lsp_id=LSP, principal_id="b-1", purpose=PURPOSE, hosts=["Bureau.Test"])
    parsed = tokens.verify(KEY, raw)
    assert parsed.hosts == ("bureau.test",)
    assert parsed.principal_id == "b-1"


@pytest.mark.parametrize(
    "mutate, reason",
    [
        (lambda t: t + "x", "token-bad-signature"),
        (lambda t: "garbage", "token-malformed"),
        (lambda t: tokens.mint(b"another-key", lsp_id=LSP, principal_id="b", purpose=PURPOSE, hosts=[]), "token-bad-signature"),
    ],
)
def test_token_rejections(mutate, reason):
    raw = tokens.mint(KEY, lsp_id=LSP, principal_id="b-1", purpose=PURPOSE, hosts=["bureau.test"])
    with pytest.raises(tokens.TokenError) as err:
        tokens.verify(KEY, mutate(raw))
    assert err.value.reason == reason


def test_expired_token():
    raw = tokens.mint(KEY, lsp_id=LSP, principal_id="b-1", purpose=PURPOSE, hosts=["bureau.test"], ttl_seconds=1, now=time.time() - 5)
    with pytest.raises(tokens.TokenError) as err:
        tokens.verify(KEY, raw)
    assert err.value.reason == "token-expired"


def test_authority_refuses_without_consent(authority, audit):
    with pytest.raises(ConsentDenied) as err:
        authority.issue(LSP, "borrower-unknown", PURPOSE, ["bureau.test"])
    assert err.value.reason == "consent-record-not-found"
    assert read_records(audit.path)[-1]["event"] == "token-denied"


def test_consent_is_scoped_to_the_lsp(authority):
    with pytest.raises(ConsentDenied):
        authority.issue("another-lsp", "borrower-001", PURPOSE, ["bureau.test"])


def test_local_policy_reports_first_failing_rule():
    policy = LocalPolicy({"bureau.test"})
    request = {
        "host": "evil.test",
        "port": 443,
        "token": {"lsp": LSP, "purpose": PURPOSE, "hosts": ["bureau.test"]},
        "consent": {"valid": True, "reason": "consent-valid"},
    }
    assert policy.decide(request).reason == "host-not-allow-listed"


def _fill(log: AuditLog, n: int = 5) -> None:
    for i in range(n):
        log.append("egress-allowed", target=f"bureau.test:{i}")


def test_chain_verifies_and_survives_reopen(tmp_path):
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 3)
    _fill(AuditLog(path), 2)
    check = verify_chain(path)
    assert check.ok and check.records == 5


def test_edit_breaks_chain(tmp_path):
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path))
    records = read_records(path)
    records[2]["target"] = "us-analytics.example:443"
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    assert verify_chain(path).first_bad_seq == 3


def test_rebuilt_history_passes_chain_but_fails_witness(tmp_path):
    """The audited party can rehash its own log; only a witnessed checkpoint catches it."""
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    _fill(log)
    witnessed = log.checkpoint()

    records = read_records(path)
    records[1]["target"] = "us-analytics.example:443"
    prev = records[0]["hash"]
    for record in records[1:]:
        record["prev"] = prev
        record["hash"] = _digest(record)
        prev = record["hash"]
    path.write_text("".join(json.dumps(r) + "\n" for r in records))

    assert verify_chain(path).ok
    check = verify_checkpoint(path, witnessed)
    assert not check.ok and check.reason == "history-rewritten"


def test_truncated_log_fails_witness(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    _fill(log)
    witnessed = log.checkpoint()
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:3]))
    assert verify_checkpoint(path, witnessed).reason == "log-truncated"
