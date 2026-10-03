"""The NBFC witness against an honest and a dishonest LSP."""

import json

import pytest

from src.egress import witness as witness_module
from src.egress.audit import AuditLog, digest_range, fold, read_records, rechain, GENESIS
from src.egress.checkpoint import CheckpointSigner, load_public_key
from src.egress.witness import Witness

LSP = "lsp-demo"


class FakeLsp:
    """An LSP's audit log plus the two endpoints the witness pulls."""

    def __init__(self, tmp_path, signer=None):
        self.log = AuditLog(tmp_path / "audit.jsonl")
        self.signer = signer or CheckpointSigner.generate(LSP)
        self.override = None
        self.down = False

    def add(self, n=3):
        for i in range(n):
            self.log.append("egress-allowed", target=f"bureau.example.in:{i}", principal_id="borrower-001")

    def checkpoint(self):
        if self.down:
            raise ConnectionError("lsp down")
        return self.override or self.signer.sign(self.log.checkpoint())

    def digests(self, after, upto):
        return digest_range(self.log.path, after, upto)

    def rewrite_entry(self, seq, **changes):
        records = read_records(self.log.path)
        records[seq - 1].update(changes)
        rechain(records)
        self.log.path.write_text("".join(json.dumps(r) + "\n" for r in records))
        self.log.reload()

    def drop_last(self):
        records = read_records(self.log.path)[:-1]
        self.log.path.write_text("".join(json.dumps(r) + "\n" for r in records))
        self.log.reload()


def make_witness(lsp, tmp_path, signer=None, lsp_id=LSP):
    return Witness(
        lsp_id=lsp_id,
        public_key=load_public_key((signer or lsp.signer).public_key_pem()),
        fetch_checkpoint=lsp.checkpoint,
        fetch_digests=lsp.digests,
        state_path=tmp_path / "witness.json",
    )


def test_digests_fold_to_the_head(tmp_path):
    lsp = FakeLsp(tmp_path)
    lsp.add(5)
    assert fold(GENESIS, lsp.digests(0, 5)) == lsp.log.checkpoint()["head"]
    assert all(len(d) == 64 for d in lsp.digests(0, 5))


def test_honest_log_is_verified_as_it_grows(tmp_path):
    lsp = FakeLsp(tmp_path)
    w = make_witness(lsp, tmp_path)
    lsp.add(3)
    assert w.poll().reason == "verified"
    lsp.add(4)
    status = w.poll()
    assert (status.ok, status.reason, status.seq) == (True, "verified", 7)
    assert w.poll().reason == "no-new-entries"
    history = (tmp_path / "witness.history.jsonl").read_text().splitlines()
    assert [json.loads(line)["seq"] for line in history] == [3, 7]


def test_rewritten_history_is_caught_on_the_next_poll(tmp_path):
    lsp = FakeLsp(tmp_path)
    w = make_witness(lsp, tmp_path)
    lsp.add(4)
    w.poll()
    lsp.rewrite_entry(2, target="analytics.example.com:443")
    lsp.add(1)
    status = w.poll()
    assert (status.ok, status.reason) == (False, "does-not-extend-witnessed-head")


def test_deleted_entries_are_a_rollback(tmp_path):
    lsp = FakeLsp(tmp_path)
    w = make_witness(lsp, tmp_path)
    lsp.add(4)
    w.poll()
    lsp.drop_last()
    assert w.poll().reason == "rollback"


def test_a_second_head_for_the_same_seq_is_a_fork(tmp_path):
    lsp = FakeLsp(tmp_path)
    w = make_witness(lsp, tmp_path)
    lsp.add(2)
    w.poll()
    forged = lsp.log.checkpoint()
    forged["head"] = "ab" * 32
    lsp.override = lsp.signer.sign(forged)
    assert w.poll().reason == "fork"


def test_checkpoint_signed_by_another_key_is_rejected(tmp_path):
    lsp = FakeLsp(tmp_path, signer=CheckpointSigner.generate(LSP))
    w = make_witness(lsp, tmp_path, signer=CheckpointSigner.generate(LSP))
    lsp.add(1)
    assert w.poll().reason == "bad-signature"


def test_checkpoint_for_another_lsp_is_rejected(tmp_path):
    lsp = FakeLsp(tmp_path)
    w = make_witness(lsp, tmp_path, lsp_id="some-other-lsp")
    lsp.add(1)
    assert w.poll().reason == "wrong-lsp"


def test_alarm_is_sticky_and_survives_restart(tmp_path):
    lsp = FakeLsp(tmp_path)
    w = make_witness(lsp, tmp_path)
    lsp.add(3)
    w.poll()
    lsp.drop_last()
    w.poll()
    lsp.add(5)
    assert w.poll().reason == "rollback"
    restarted = make_witness(lsp, tmp_path)
    assert restarted.poll().reason == "rollback"


def test_unreachable_lsp_is_reported_but_not_an_alarm(tmp_path):
    lsp = FakeLsp(tmp_path)
    w = make_witness(lsp, tmp_path)
    lsp.add(2)
    w.poll()
    lsp.down = True
    status = w.poll()
    assert (status.ok, status.reason, status.alarm) == (False, "lsp-unreachable", None)
    lsp.down = False
    lsp.add(1)
    assert w.poll().reason == "verified"


def test_large_gaps_are_fetched_in_pages(tmp_path, monkeypatch):
    monkeypatch.setattr(witness_module, "MAX_DIGESTS_PER_FETCH", 4)
    lsp = FakeLsp(tmp_path)
    calls = []
    original = lsp.digests
    lsp.digests = lambda a, u: calls.append((a, u)) or original(a, u)
    w = make_witness(lsp, tmp_path)
    lsp.add(10)
    assert w.poll().reason == "verified"
    assert calls == [(0, 4), (4, 8), (8, 10)]
