import json
import time

import pytest

from src.egress import tokens
from src.egress.audit import (
    AuditLog,
    _last_line,
    content_digest,
    digest_range,
    read_records,
    rechain,
    verify_chain,
    verify_checkpoint,
)
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
    rechain(records)
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


def _scanned_digests(path, after, upto):
    return [content_digest(r) for r in read_records(path) if after < r["seq"] <= upto]


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_seeking_digest_range_matches_a_full_scan(tmp_path, newline):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    for i in range(40):
        log.append("egress-allowed", target=f"bureau.test:{i}", note="x" * (i * 7 % 50))
    records = read_records(path)
    path.write_bytes("".join(json.dumps(r) + newline for r in records).encode())

    for after, upto in [(0, 0), (0, 1), (0, 40), (13, 14), (13, 29), (39, 40), (40, 40), (35, 99), (99, 120)]:
        assert digest_range(path, after, upto) == _scanned_digests(path, after, upto), (after, upto)


def test_digest_range_follows_a_rewritten_log(tmp_path):
    """No index to go stale: the witness gets the digests of whatever is on disk."""
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 10)
    records = read_records(path)
    del records[4]
    rechain(records)
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    assert digest_range(path, 2, 9) == _scanned_digests(path, 2, 9)
    assert digest_range(path, 9, 10) == []


def test_reopen_reads_the_tail_without_scanning(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    log.append("egress-allowed", target="bureau.test:443", note="y" * 10_000)
    head = log.checkpoint()["head"]
    path.write_bytes(path.read_bytes() + b"\r\n\n")

    assert json.loads(_last_line(path, block=64))["hash"] == head
    reopened = AuditLog(path)
    assert (reopened.checkpoint()["seq"], reopened.checkpoint()["head"]) == (1, head)


def test_empty_log_has_no_tail(tmp_path):
    path = tmp_path / "a.jsonl"
    path.write_text("\n\n")
    assert _last_line(path) is None
    assert AuditLog(path).checkpoint()["seq"] == 0
    assert digest_range(tmp_path / "missing.jsonl", 0, 5) == []


def test_failed_write_is_rolled_back(tmp_path, monkeypatch):
    """Disk full mid-write: no half record stays behind for the next one to be glued onto."""
    from src.egress import audit as audit_module

    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    _fill(log, 3)
    size, head = path.stat().st_size, log.checkpoint()["head"]

    def half_then_fail(fh, data):
        fh.write(data[: len(data) // 2])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(audit_module, "_write_all", half_then_fail)
    with pytest.raises(OSError):
        log.append("egress-allowed", target="bureau.test:443")
    monkeypatch.undo()

    assert path.stat().st_size == size
    assert log.checkpoint()["head"] == head
    log.append("egress-allowed", target="bureau.test:443")
    check = verify_chain(path)
    assert check.ok and check.records == 4


def test_crash_fragment_is_quarantined_and_logged(tmp_path):
    path = tmp_path / "a.jsonl"
    _fill(AuditLog(path), 3)
    fragment = b'{"event":"egress-allowed","seq":4,"tar'
    path.write_bytes(path.read_bytes() + fragment)

    log = AuditLog(path)
    records = read_records(path)
    recovered = records[-1]
    assert recovered["event"] == "audit-recovered"
    assert recovered["seq"] == 4 and recovered["fragment_bytes"] == len(fragment)
    assert (tmp_path / "a.jsonl.quarantine").read_bytes() == fragment + b"\n"
    log.append("egress-allowed", target="bureau.test:443")
    assert verify_chain(path).ok and verify_chain(path).records == 5


def test_half_written_line_does_not_break_a_witness_poll(tmp_path):
    """The witness can poll while the proxy is mid-append; the unfinished line is not a record yet."""
    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    _fill(log, 5)
    expected = digest_range(path, 2, 5)
    with path.open("ab") as fh:
        fh.write(b'{"event":"egress-blocked","seq":6,"rea')
    assert digest_range(path, 2, 5) == expected
    assert digest_range(path, 4, 6) == expected[2:]
    assert len(read_records(path)) == 5


def test_concurrent_appends_stay_strictly_sequential(tmp_path):
    import threading

    path = tmp_path / "a.jsonl"
    log = AuditLog(path)
    threads = [threading.Thread(target=_fill, args=(log, 50)) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    check = verify_chain(path)
    assert check.ok and check.records == 400
