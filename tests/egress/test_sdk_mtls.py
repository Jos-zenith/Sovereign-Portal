"""End to end: requests through the SDK, the proxy and a bureau that demands a client certificate.

Tests using `mtls_bureau` run twice: against a bureau that closes the
connection after each response and against one that keeps it alive.
"""

import time

import pytest

from src.egress.consent import ConsentAuthority, ConsentDenied
from src.egress.sdk import EgressBlocked, VictEgress

from .conftest import KEY, LSP, PURPOSE, ProxyThread, events, make_proxy


@pytest.fixture
def bureau_proxy(store, audit, mtls_bureau):
    with ProxyThread(make_proxy(store, audit, mtls_bureau)) as running:
        yield running


@pytest.fixture
def keepalive_proxy(store, audit, keepalive_bureau):
    with ProxyThread(make_proxy(store, audit, keepalive_bureau)) as running:
        yield running


def client(authority, proxy) -> VictEgress:
    return VictEgress(issuer=authority, proxy_url=proxy.url, lsp_id=LSP)


def call(session, pki, path="/score"):
    return session.get(
        f"https://bureau.test{path}",
        verify=str(pki["ca"]),
        cert=(str(pki["client_crt"]), str(pki["client_key"])),
        timeout=5,
    )


def test_client_certificate_passes_through_the_tunnel(bureau_proxy, authority, pki):
    with client(authority, bureau_proxy).session(principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"]) as s:
        response = call(s, pki)
    assert response.status_code == 200
    assert response.json()["client_cn"] == LSP


def test_several_calls_in_one_session_stay_with_one_borrower(bureau_proxy, authority, audit, pki):
    with client(authority, bureau_proxy).session(principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"]) as s:
        assert [call(s, pki, p).status_code for p in ("/score", "/report", "/limits")] == [200, 200, 200]
    tunnels = events(audit, "egress-allowed")
    assert 1 <= len(tunnels) <= 3
    assert {t["principal_id"] for t in tunnels} == {"borrower-001"}


def test_keep_alive_session_reuses_one_tunnel(keepalive_proxy, authority, audit, pki):
    with client(authority, keepalive_proxy).session(principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"]) as s:
        assert call(s, pki, "/score").status_code == 200
        assert call(s, pki, "/report").status_code == 200
    assert len(events(audit, "egress-allowed")) == 1


def test_each_borrower_gets_their_own_tunnel(bureau_proxy, authority, audit, pki):
    vict = client(authority, bureau_proxy)
    for borrower in ("borrower-001", "borrower-002"):
        with vict.session(principal_id=borrower, purpose=PURPOSE, hosts=["bureau.test"]) as s:
            assert call(s, pki).status_code == 200
    assert [r["principal_id"] for r in events(audit, "egress-allowed")] == ["borrower-001", "borrower-002"]


def test_no_consent_means_no_network_call(bureau_proxy, authority, audit):
    with pytest.raises(ConsentDenied):
        with client(authority, bureau_proxy).session(principal_id="borrower-999", purpose=PURPOSE, hosts=["bureau.test"]):
            pass
    assert events(audit, "egress-allowed") == [] and events(audit, "egress-blocked") == []


def test_pooled_connection_dies_with_its_token(keepalive_proxy, store, audit, pki):
    short_lived = ConsentAuthority(store, KEY, audit, ttl_seconds=1)
    with client(short_lived, keepalive_proxy).session(principal_id="borrower-001", purpose=PURPOSE, hosts=["bureau.test"]) as s:
        assert call(s, pki).status_code == 200
        time.sleep(1.5)
        with pytest.raises(EgressBlocked) as err:
            call(s, pki)
    assert err.value.reason == "token-expired"
