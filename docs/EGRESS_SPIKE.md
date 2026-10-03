# Egress Gate Spike

**Question:** can VICT enforce consent on outbound calls without making LSPs rewrite their code into Wasm?

**Answer so far:** yes, for code that uses the SDK and goes through the proxy. A CONNECT proxy that checks a short-lived consent token, plus a thin SDK, enforces consent, destination and expiry per tunnel. Client certificates pass through untouched. The one part still untested is the network lockdown that blocks code which ignores the proxy.

## Run it

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q             # 54 tests, about 20 seconds
python demo/egress_spike_demo.py
```

To check the Rego policy against the Python one, run a free [OPA](https://www.openpolicyagent.org/docs/latest/#running-opa) binary:

```bash
opa run --server compliance/egress_policy.rego compliance/egress_allowlist.json
set VICT_OPA_URL=http://127.0.0.1:8181/v1/data/vict/egress/decision
python -m pytest -q tests/egress/test_policy_parity.py
```

## How it works

```
App code ── SDK: session(borrower, purpose, hosts)
              │  1. asks the consent authority for a token (refused → no network call)
              ▼
         Egress proxy ── CONNECT bureau.test:443 + token
              │  2. checks signature, expiry, tunnel cap, consent still valid,
              │     host allow-list, host named in token, port 443
              │  3. logs allow/block to the hash-chained audit log
              ▼
         Bureau / AA  (TLS end to end; the proxy cannot read the traffic)
```

| File | Role |
|---|---|
| [src/egress/tokens.py](../src/egress/tokens.py) | Signed consent tokens: LSP, borrower, purpose, hosts, expiry |
| [src/egress/consent.py](../src/egress/consent.py) | Consent store keyed on (LSP, borrower, purpose); the authority that issues tokens |
| [src/egress/proxy.py](../src/egress/proxy.py) | CONNECT-only proxy |
| [src/egress/policy.py](../src/egress/policy.py), [compliance/egress_policy.rego](../compliance/egress_policy.rego) | Same rules in Python (default) and OPA |
| [src/egress/audit.py](../src/egress/audit.py) | Hash-chained log; each link is sha256(previous head ‖ record digest) |
| [src/egress/checkpoint.py](../src/egress/checkpoint.py), [src/egress/witness.py](../src/egress/witness.py) | Ed25519-signed checkpoints and the NBFC-side witness that pulls them |
| [src/egress/sdk.py](../src/egress/sdk.py) | `VictEgress.session(...)` over `requests` |

## Pass criteria

| Criterion | Result | Test |
|---|---|---|
| Valid token opens a tunnel | Pass | `test_valid_token_opens_tunnel` |
| No token is refused | Pass (407) | `test_no_token_is_407` |
| Expired token is refused | Pass | `test_expired_token_is_blocked` |
| Consent revoked after the token was issued is refused | Pass | `test_consent_revoked_after_issue_is_blocked` |
| Wrong host, US host, wrong port or raw IP is refused | Pass | `test_wrong_destination_is_blocked` |
| A second borrower cannot ride an existing tunnel | Pass | `test_each_borrower_gets_their_own_tunnel`, `test_pooled_connection_dies_with_its_token`, `test_token_opens_a_bounded_number_of_tunnels` |
| Every outcome is logged in one valid chain | Pass | `test_every_outcome_is_logged_in_one_valid_chain` |
| Client certificate (mTLS) works through the tunnel | Pass | `test_client_certificate_passes_through_the_tunnel` |
| A rewritten log is caught by a witnessed checkpoint | Pass | `test_rebuilt_history_passes_chain_but_fails_witness` |
| Python and OPA policies agree | Pass (24 input combinations, OPA 1.21.1) | `test_local_policy_matches_opa` |

## What the spike found

1. **Single-use tokens break real upstreams.** A server that closes the connection after each response needs a new tunnel per request, and a single-use token refuses the second one. The fix is a cap of 4 tunnels per token. Each new tunnel re-checks consent and is logged, and every tunnel closes when its token expires, 60 seconds by default.
2. **Consent is checked when a tunnel opens, not on every request inside it.** A revocation takes effect at the next tunnel, at most one token lifetime later. This trade-off should be stated plainly to buyers.
3. **Cost of a new tunnel:** about 8 ms on a laptop, against 0.5 ms for a reused one. That covers the consent lookup and the audit write. In production, add one TCP and TLS handshake to the bureau.
4. **Two bugs were found in the existing gateway's OPA path and fixed.** The older `.rego` files used syntax that OPA 1.x rejects, and `consent_gateway.py` passed the input as a query argument instead of on stdin. Either bug would have made the gateway deny every request as soon as OPA was installed.

## Not tested yet

- **Calls that skip the proxy on real infrastructure.** The [egress_lockdown](../infra/terraform/modules/egress_lockdown) Terraform module passes offline tests but has not been applied to AWS yet. See [PRODUCTION_READINESS.md](PRODUCTION_READINESS.md).
- **Real AA and bureau sandboxes.** The likely snag is their IP allow-lists: the proxy must leave through the LSP's already-whitelisted address.
- **Envoy or Squid as the production proxy.** The asyncio proxy is good enough to test the design, but it is not hardened.
- **Authority as a separate service.** In the spike the authority runs inside the app's process. In production it must be its own service, so app code never holds the signing key.
- **Node and Java SDKs.** Node's built-in `fetch` honours `HTTPS_PROXY` only from v22.21 / v24.5 with `NODE_USE_ENV_PROXY=1`.
