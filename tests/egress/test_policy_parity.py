"""LocalPolicy and compliance/egress_policy.rego must agree.

Runs only against a live OPA server, e.g.:
  opa run --server compliance/egress_policy.rego compliance/egress_allowlist.json
  set VICT_OPA_URL=http://127.0.0.1:8181/v1/data/vict/egress/decision
"""

import itertools
import os

import pytest

from src.egress.policy import LocalPolicy, OpaPolicy

OPA_URL = os.getenv("VICT_OPA_URL")


@pytest.mark.skipif(not OPA_URL, reason="VICT_OPA_URL not set")
def test_local_policy_matches_opa():
    local = LocalPolicy({"bureau.test", "aa.test"}, allowed_ports=(443,))
    opa = OpaPolicy(OPA_URL)
    hosts = ["bureau.test", "aa.test", "evil.test"]
    consents = [{"valid": True, "reason": "consent-valid"}, {"valid": False, "reason": "consent-withdrawn"}]
    for host, port, token_hosts, consent in itertools.product(hosts, [443, 8443], [["bureau.test"], []], consents):
        request = {
            "host": host,
            "port": port,
            "token": {"lsp": "lsp-demo", "purpose": "loan-eligibility", "hosts": token_hosts},
            "consent": consent,
        }
        assert local.decide(request) == opa.decide(request), request
