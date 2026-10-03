"""Pass criteria for the egress spike, exercised with raw CONNECT requests."""

import base64
import socket
import socketserver
import threading
import time

import pytest

from src.egress import tokens
from src.egress.audit import AuditLog, verify_chain
from src.egress.consent import ConsentStore

from .conftest import KEY, LSP, PURPOSE, ProxyThread, events, make_proxy, open_tunnel, wait_for_event


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
def test_wrong_destination_is_blocked(proxy, authority, audit, target, reason):
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    status, got, sock = open_tunnel(proxy.port, target, bearer(token))
    sock.close()
    assert (status, got) == (403, reason)
    if reason != "raw-ip-target":
        assert events(audit, "egress-blocked")[-1]["principal_id"] == "borrower-001"


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


def test_tunnel_is_closed_when_token_expires(proxy, audit, store):
    """Criterion 6, part two: a pooled tunnel cannot outlive the consent it was opened under."""
    grant_id = store.check(LSP, "borrower-001", PURPOSE).grant_id
    token = tokens.mint(KEY, lsp_id=LSP, principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"], ttl_seconds=1, grant_id=grant_id)
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
    assert wait_for_event(audit, "tunnel-cut")["reason"] == "token-expired"


def test_every_outcome_is_logged_in_one_valid_chain(proxy, authority, audit):
    good = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    for target, auth in [("bureau.test:443", bearer(good)), ("bureau.test:443", None), ("evil.test:443", bearer(good))]:
        _, _, sock = open_tunnel(proxy.port, target, auth)
        sock.close()

    wait_for_event(audit, "tunnel-closed")
    assert len(events(audit, "egress-allowed")) == 1
    assert {r["reason"] for r in events(audit, "egress-blocked")} == {"token-missing", "host-not-allow-listed"}
    assert verify_chain(audit.path).ok


def _is_closed(sock: socket.socket, timeout: float = 2.0) -> bool:
    sock.settimeout(timeout)
    try:
        return sock.recv(16) == b""
    except (ConnectionResetError, ConnectionAbortedError):
        return True
    except socket.timeout:
        return False


def test_revoking_consent_closes_open_tunnels_at_once(proxy, authority, store, audit):
    """A withdrawal takes effect on tunnels already open, not when their token expires."""
    tunnels = {}
    for borrower in ("borrower-001", "borrower-002"):
        token = authority.issue(LSP, borrower, PURPOSE, ["bureau.test"])
        status, _, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(token))
        assert status == 200
        tunnels[borrower] = sock

    store.revoke(LSP, "borrower-001", PURPOSE)

    assert _is_closed(tunnels["borrower-001"])
    tunnels["borrower-002"].sendall(b"still-open")
    assert tunnels["borrower-002"].recv(10) == b"still-open"
    closed = wait_for_event(audit, "tunnel-cut")
    for sock in tunnels.values():
        sock.close()
    assert (closed["principal_id"], closed["reason"]) == ("borrower-001", "consent-withdrawn")


class _RevokedDuringCheck(ConsentStore):
    """Consent is withdrawn just after the proxy's check has read it as valid."""

    def check(self, lsp_id, principal_id, purpose):
        result = super().check(lsp_id, principal_id, purpose)
        self.revoke(lsp_id, principal_id, purpose)
        return result


def test_revocation_racing_the_consent_check_still_blocks(tmp_path, audit, echo_server):
    store = _RevokedDuringCheck(tmp_path / "racy.db")
    grant_id = store.grant(LSP, "borrower-001", PURPOSE)
    token = tokens.mint(KEY, lsp_id=LSP, principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"], grant_id=grant_id)
    with ProxyThread(make_proxy(store, audit, echo_server)) as running:
        status, reason, sock = open_tunnel(running.port, "bureau.test:443", bearer(token))
        sock.close()
    assert (status, reason) == (403, "consent-withdrawn")


class _BrokenAudit(AuditLog):
    broken = False

    def append(self, event, **fields):
        if self.broken:
            raise OSError("disk full")
        return super().append(event, **fields)


def test_audit_failure_blocks_and_closes_both_sockets(tmp_path, store, authority):
    """With no audit record there is no tunnel, and neither side is left holding a socket."""
    upstream_closed = threading.Event()

    class Upstream(socketserver.BaseRequestHandler):
        def handle(self):
            while self.request.recv(4096):
                pass
            upstream_closed.set()

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Upstream)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    audit = _BrokenAudit(tmp_path / "broken.jsonl")
    try:
        token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
        audit.broken = True
        with ProxyThread(make_proxy(store, audit, server.server_address[1])) as running:
            status, reason, sock = open_tunnel(running.port, "bureau.test:443", bearer(token))
            assert (status, reason) == (500, "proxy-error")
            assert _is_closed(sock)
            sock.close()
            assert upstream_closed.wait(2)
    finally:
        server.shutdown()
        server.server_close()


class _StoreDown(ConsentStore):
    def check(self, lsp_id, principal_id, purpose):
        import sqlite3

        raise sqlite3.OperationalError("database is locked")


def test_authority_refuses_on_the_record_when_the_store_is_down(tmp_path, audit):
    from src.egress.consent import ConsentAuthority, ConsentDenied

    authority = ConsentAuthority(_StoreDown(tmp_path / "down.db"), KEY, audit)
    with pytest.raises(ConsentDenied) as denied:
        authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    assert denied.value.reason == "consent-unavailable"
    assert (events(audit, "token-denied")[-1]["reason"]) == "consent-unavailable"


def test_proxy_fails_closed_when_the_store_is_down(tmp_path, audit, echo_server):
    token = tokens.mint(KEY, lsp_id=LSP, principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"])
    with ProxyThread(make_proxy(_StoreDown(tmp_path / "down.db"), audit, echo_server)) as running:
        status, reason, sock = open_tunnel(running.port, "bureau.test:443", bearer(token))
        sock.close()
    assert (status, reason) == (503, "consent-unavailable")
    assert events(audit, "egress-blocked")[-1]["reason"] == "consent-unavailable"


def test_regrant_does_not_revive_a_token_from_the_withdrawn_grant(proxy, store, audit):
    """Withdrawal is one-way: a new grant gets a new grant_id, and older tokens stay dead."""
    from src.egress.consent import ConsentAuthority

    authority = ConsentAuthority(store, KEY, audit)
    old_token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    withdrawn = authority.withdraw(LSP, "borrower-001", PURPOSE)
    new_grant = authority.grant(LSP, "borrower-001", PURPOSE)
    assert new_grant != withdrawn["grant_id"]

    status, reason, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(old_token))
    sock.close()
    assert (status, reason) == (403, "consent-superseded")

    new_token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    status, _, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(new_token))
    sock.close()
    assert status == 200


def test_tunnel_closes_when_the_consent_expires_not_the_token(tmp_path, audit, echo_server):
    import datetime as dt

    from src.egress.consent import ConsentAuthority, ConsentStore

    store = ConsentStore(tmp_path / "expiring.db")
    authority = ConsentAuthority(store, KEY, audit, ttl_seconds=60)
    authority.grant(LSP, "borrower-001", PURPOSE, expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1.2))
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    with ProxyThread(make_proxy(store, audit, echo_server)) as running:
        status, _, sock = open_tunnel(running.port, "bureau.test:443", bearer(token))
        assert status == 200
        started = time.time()
        assert _is_closed(sock, timeout=5)
        elapsed = time.time() - started
        sock.close()
        cut = wait_for_event(audit, "tunnel-cut")
    assert cut["reason"] == "consent-expired"
    assert elapsed < 3, "the tunnel must close at consent expiry, not at the 60 s token expiry"


def test_ledger_ties_every_call_to_its_grant(proxy, store, audit):
    from src.egress.consent import ConsentAuthority

    authority = ConsentAuthority(store, KEY, audit)
    grant_id = authority.grant(LSP, "borrower-001", PURPOSE)
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    status, _, sock = open_tunnel(proxy.port, "bureau.test:443", bearer(token))
    assert status == 200
    authority.withdraw(LSP, "borrower-001", PURPOSE)
    assert _is_closed(sock)
    sock.close()

    cut = wait_for_event(audit, "tunnel-cut")
    granted = events(audit, "consent-granted")[-1]
    withdrawn = events(audit, "consent-withdrawn")[-1]
    issued = events(audit, "token-issued")[-1]
    allowed = events(audit, "egress-allowed")[-1]
    assert granted["grant_id"] == withdrawn["grant_id"] == issued["grant_id"] == allowed["grant_id"] == cut["grant_id"] == grant_id
    assert cut["reason"] == "consent-withdrawn" and withdrawn["revoked_at"]
    assert verify_chain(audit.path).ok


def test_old_consent_databases_get_grant_ids(tmp_path):
    import sqlite3

    from src.egress.consent import ConsentStore

    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE egress_consent (lsp_id TEXT NOT NULL, principal_id TEXT NOT NULL, purpose TEXT NOT NULL,"
            " granted_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, PRIMARY KEY (lsp_id, principal_id, purpose))"
        )
        conn.execute("INSERT INTO egress_consent VALUES ('lsp-demo', 'borrower-001', 'loan-eligibility', '2026-01-01T00:00:00+00:00', NULL, NULL)")
    check = ConsentStore(path).check("lsp-demo", "borrower-001", "loan-eligibility")
    assert check.valid and len(check.grant_id) == 16
