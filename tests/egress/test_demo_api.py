"""The portal's API, exercised through the real gateway app."""

import pytest
from fastapi.testclient import TestClient

from src.gateway.consent_gateway import app

BUREAU = {"principal_id": "borrower-001", "purpose": "loan-eligibility", "token_host": "bureau.example.in", "target_host": "bureau.example.in"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def fresh(client):
    assert client.post("/egress/reset").status_code == 200


def test_consented_call_is_allowed_and_counted(client):
    result = client.post("/egress/call", json=BUREAU).json()
    assert result == {"allowed": True, "stage": "egress-proxy", "status": 200, "reason": "allowed", "network_call": True}
    counts = client.get("/egress/state").json()["counts"]
    assert counts["tunnels_allowed"] == 1 and counts["tokens_issued"] == 1


def test_no_consent_is_blocked_before_any_network_call(client):
    result = client.post("/egress/call", json={**BUREAU, "principal_id": "borrower-002"}).json()
    assert result["stage"] == "consent-authority"
    assert result["reason"] == "consent-record-not-found"
    assert result["network_call"] is False


def test_leaky_sdk_to_foreign_host_is_blocked_at_the_proxy(client):
    result = client.post("/egress/call", json={**BUREAU, "target_host": "analytics.example.com"}).json()
    assert (result["stage"], result["reason"]) == ("egress-proxy", "host-not-allow-listed")
    assert client.get("/egress/state").json()["counts"]["blocked_by_reason"] == {"host-not-allow-listed": 1}


def test_revoke_then_grant(client):
    assert client.post("/egress/consent/revoke", json={"principal_id": "borrower-001", "purpose": "loan-eligibility"}).status_code == 200
    assert client.post("/egress/call", json=BUREAU).json()["reason"] == "consent-withdrawn"
    client.post("/egress/consent/grant", json={"principal_id": "borrower-001", "purpose": "loan-eligibility"})
    assert client.post("/egress/call", json=BUREAU).json()["allowed"] is True


def test_witness_catches_rewritten_history(client):
    from src.egress import demo_api

    client.post("/egress/call", json={**BUREAU, "target_host": "analytics.example.com"})
    assert demo_api._env.witness.poll().reason == "verified"

    rewrite = client.post("/egress/simulate/rewrite-history").json()
    assert rewrite["removed"]["reason"] == "host-not-allow-listed"
    assert rewrite["chain_still_verifies"] is True
    assert demo_api._env.witness.poll().reason == "rollback"

    state = client.get("/egress/state").json()
    assert state["chain"]["ok"] is True
    assert state["witness"]["ok"] is False and state["witness"]["alarm"]["reason"] == "rollback"


def test_witness_endpoints_serve_signed_heads_and_digests_only(client):
    client.post("/egress/call", json=BUREAU)
    checkpoint = client.get("/egress/witness/checkpoint").json()
    assert set(checkpoint) == {"lsp_id", "seq", "head", "ts", "sig"}
    digests = client.get(f"/egress/witness/digests?after=0&upto={checkpoint['seq']}").json()["digests"]
    assert len(digests) == checkpoint["seq"] and all(len(d) == 64 for d in digests)
    assert client.get("/egress/witness/digests?after=5&upto=1").status_code == 400


def test_rewrite_needs_a_blocked_call(client):
    assert client.post("/egress/simulate/rewrite-history").status_code == 409


def test_audit_is_newest_first(client):
    client.post("/egress/call", json=BUREAU)
    records = client.get("/egress/audit?limit=5").json()["records"]
    seqs = [r["seq"] for r in records]
    assert seqs == sorted(seqs, reverse=True)


def _wait_for(client, stream_id, done, timeout=5.0):
    import time

    deadline = time.time() + timeout
    while time.time() < deadline:
        stream = client.get(f"/egress/stream/{stream_id}").json()
        if done(stream):
            return stream
        time.sleep(0.05)
    raise AssertionError(f"stream never reached the expected state: {stream}")


def test_withdrawal_cuts_a_live_stream(client):
    started = client.post("/egress/stream", json={"principal_id": "borrower-001"}).json()
    assert started["state"] == "opening"
    _wait_for(client, started["id"], lambda s: s["pages"] >= 2)

    revoked = client.post("/egress/consent/revoke", json={"principal_id": "borrower-001", "purpose": "loan-eligibility"}).json()
    stream = _wait_for(client, started["id"], lambda s: s["state"] != "open")
    assert (stream["state"], stream["reason"]) == ("cut", "consent-withdrawn")
    assert stream["ended_at"] - revoked["revoked_at"] < 1.0


def test_stream_without_consent_never_opens(client):
    started = client.post("/egress/stream", json={"principal_id": "borrower-002"}).json()
    assert (started["id"], started["stage"], started["reason"]) == (None, "consent-authority", "consent-record-not-found")
    assert client.get("/egress/stream/nope").status_code == 404
