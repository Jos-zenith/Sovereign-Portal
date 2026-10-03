"""Pass criteria for the egress spike, exercised with raw CONNECT requests."""

import base64
import time

import pytest

from src.egress import tokens
from src.egress.audit import verify_chain

from .conftest import KEY, LSP, PURPOSE, events, open_tunnel, wait_for_event


def bearer(token: str) -> str:
    return f"Bearer {token}"


def test_valid_token_opens_tunnel(proxy, authority, audit):
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    status, _, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(token))
    assert status == 200
    sock.sendall(b"ping")
    assert sock.recv(4) == b"ping"
    sock.close()
    allowed = events(audit, "egress-allowed")[-1]
    assert allowed["principal_id"] == "borrower-001"
    assert allowed["resolved_ip"] == "127.0.0.1"


def test_basic_auth_carries_token_like_a_proxy_url(proxy, authority):
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    basic = base64.b64encode(f"vict:{token}".encode()).decode()
    status, _, sock = open_tunnel(proxy.port, "bureau.test:443", f"Basic {basic}")
    sock.close()
    assert status == 200


def test_no_token_is_407(proxy):
    status, reason, sock = open_tunnel(proxy.port, "bureau.test:443")
    sock.close()
    assert (status, reason) == (407, "token-missing")


def test_expired_token_is_blocked(proxy):
    token = tokens.mint(
        KEY, lsp_id=LSP, principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"], ttl_seconds=1, now=time.time() - 5
    )
    status, reason, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(token))
    sock.close()
    assert (status, reason) == (403, "token-expired")


def test_consent_revoked_after_issue_is_blocked(proxy, authority, store):
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    store.revoke(LSP, "borrower-001", PURPOSE)
    status, reason, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(token))
    sock.close()
    assert (status, reason) == (403, "consent-withdrawn")


@pytest.mark.parametrize(
    "target, reason",
    [
        ("aa.test:443", "host-not-in-token"),
        ("us-analytics.example:443", "host-not-allow-listed"),
        ("bureau.test:8443", "port-not-allowed"),
        ("127.0.0.1:443", "raw-ip-target"),
    ],
)
def test_wrong_destination_is_blocked(proxy, authority, target, reason):
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    status, got, sock = open_tunnel(proxy.port, target, bearer(token))
    sock.close()
    assert (status, got) == (403, reason)


def test_forged_token_is_blocked(proxy):
    forged = tokens.mint(b"app-made-this-up", lsp_id=LSP, principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"])
    status, reason, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(forged))
    sock.close()
    assert (status, reason) == (403, "token-bad-signature")


def test_plain_http_is_refused(proxy, authority):
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    status, reason, sock = open_tunnel(proxy.port, "http://bureau.test/", bearer(token), method="GET")
    sock.close()
    assert (status, reason) == (405, "method-not-allowed")


def test_token_opens_a_bounded_number_of_tunnels(proxy, authority):
    """Criterion 6, part one: a leaked token cannot fan out into unlimited tunnels."""
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    results = [open_tunnel(proxy.port, "bureau.test:443", bearer(token)) for _ in range(5)]
    for _, _, sock in results:
        sock.close()
    assert [status for status, _, _ in results] == [200, 200, 200, 200, 403]
    assert results[-1][1] == "token-tunnel-limit"


def test_tunnel_is_closed_when_token_expires(proxy, audit):
    """Criterion 6, part two: a pooled tunnel cannot outlive the consent it was opened under."""
    token = tokens.mint(KEY, lsp_id=LSP, principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"], ttl_seconds=1)
    status, _, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(token))
    assert status == 200
    sock.sendall(b"before")
    assert sock.recv(6) == b"before"

    time.sleep(1.5)
    try:
        closed = sock.recv(16) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        closed = True
    sock.close()
    assert closed
    assert wait_for_event(audit, "tunnel-closed")["reason"] == "token-expired"


def test_every_outcome_is_logged_in_one_valid_chain(proxy, authority, audit):
    good = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    for target, auth in [("bureau.test:443", bearer(good)), ("bureau.test:443", None), ("evil.test:443", bearer(good))]:
        _, _, sock = open_tunnel(proxy.port, target, auth)
        sock.close()

    wait_for_event(audit, "tunnel-closed")
    assert len(events(audit, "egress-allowed")) == 1
    assert {r["reason"] for r in events(audit, "egress-blocked")} == {"token-missing", "host-not-allow-listed"}
    assert verify_chain(audit.path).ok
