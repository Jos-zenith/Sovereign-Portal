# Revocation semantics

What VICT does when consent is withdrawn, expires or can't be checked. Each guarantee names the test that shows it, and each timing figure was measured, not estimated.

Consent is keyed on (LSP, borrower, purpose). Withdrawing one purpose doesn't touch the borrower's other purposes. Every grant gets its own `grant_id`, carried in the tokens minted under it and in every ledger entry for calls made with them.

## Guarantees

| Situation | What happens | Shown by |
|---|---|---|
| Withdrawal, then a new call | The consent authority refuses a token (`consent-withdrawn`). No network call is made. | `test_revoke_then_grant` |
| Withdrawal while holding an unexpired token | Each new tunnel re-checks consent at the proxy and is refused (`consent-withdrawn`). | `test_consent_revoked_after_issue_is_blocked` |
| Withdrawal while a fetch is streaming | Every open tunnel under that consent is cut mid-transfer. The ledger gets a `consent-withdrawn` entry with the commit time, then a `tunnel-cut` entry per tunnel with the bytes moved before the cut. | `test_revoking_consent_closes_open_tunnels_at_once`, `test_ledger_ties_every_call_to_its_grant` |
| Withdrawal while the consent check is running | The tunnel is registered before the check, so a withdrawal landing in between still cuts it. | `test_revocation_racing_the_consent_check_still_blocks` |
| Withdrawal, then a new grant within the token's lifetime | Old tokens stay dead (`consent-superseded`). Withdrawal is one-way; the new grant gets a new `grant_id`. | `test_regrant_does_not_revive_a_token_from_the_withdrawn_grant` |
| Consent reaches its expiry while a tunnel is open | The tunnel's deadline is the earlier of the token's and the consent's expiry, so it is cut at the consent's expiry (`tunnel-cut`, `consent-expired`). | `test_tunnel_closes_when_the_consent_expires_not_the_token` |
| Consent store unavailable | New tokens are refused (`token-denied`, `consent-unavailable`) and new tunnels are refused (`503 consent-unavailable`), both on the record. | `test_authority_refuses_on_the_record_when_the_store_is_down`, `test_proxy_fails_closed_when_the_store_is_down` |
| Ledger unavailable | No tunnel opens without its `egress-allowed` record on disk. The client gets `500 proxy-error`; both sockets close. | `test_audit_failure_blocks_and_closes_both_sockets` |
| Withdrawal fails to save | The withdrawal returns an error and nothing is cut until it is committed. The borrower's app must show the failure rather than claim success. | `ConsentStore.revoke` runs listeners only after commit |

## Measured revocation latency

Run `python -m demo.revocation_latency` to reproduce. Measured 4 October 2026 on a Windows 11 laptop, Python 3.12, everything in one process. Latency runs from the withdrawal's timestamp, taken before the database commit, to the moment the client sees its connection die.

| Scenario | Result |
|---|---|
| Withdrawal reaches the proxy (50 trials) | Open tunnel cut at p50 38 ms, p95 45 ms, max 48 ms |
| Proxy never hears of it, as across services without a push channel (token lifetime 3 s for the test) | New tunnels refused immediately, because the proxy re-checks the shared store. The open tunnel was cut by token expiry at 2.8 s, inside its lifetime. |
| Consent store down (token lifetime 3 s) | New tunnels `503 consent-unavailable`, new tokens refused. The withdrawal itself could not be recorded. The open tunnel ran to token expiry at 3.0 s. |

**What can be promised.** Today the push path runs inside one process, and only that configuration has been measured. In any deployment the upper bound for an open tunnel is the token lifetime: 60 seconds by default. Publish a tighter number for a production setup only after measuring it there, including with the push channel broken.

**What design partners should hear.** Failing closed means that if the consent store goes down, the loan flow stops: no new tokens, no new tunnels. Open tunnels finish within the token lifetime. A borrower can't record a withdrawal until the store is back, so the borrower's app must say so.

## Decisions taken

1. **In-flight fetches are cut on withdrawal, not allowed to finish.** A withdrawal that doesn't stop processing is hard to defend. The cost is that a loan function can be aborted midway, so **functions calling vendors through VICT must be safe to abort**: treat a dropped connection as "no data", never as partial data, and retry only with a fresh token. The cut is its own ledger entry (`tunnel-cut`). Confirm the legal standard with counsel.
2. **Consent expiry is enforced at the expiry time**, not when the token runs out. Expiry is known in advance, so it needs no propagation.
3. **A token is bound to one grant.** A re-grant creates a new `grant_id`, so no call can run under a consent that was withdrawn at that moment, even if consent was granted again for the same purpose.

## Still open

- **The push channel between services.** Once the consent authority runs as its own service, withdrawals must reach every proxy instance, for example over Postgres `LISTEN/NOTIFY`. Until it's built and measured, the 60-second token lifetime is the bound.
- **Proxy restart.** Open tunnels drop. The per-token tunnel count is held in memory, so after a restart an unexpired token can open up to four more tunnels. Each one still re-checks consent and grant.

## AA flows

For Account Aggregator fetches, the AA's consent artefact already governs purpose, duration and revocation. VICT doesn't replace it. It adds the egress check and an NBFC-verifiable record of the fetch.
