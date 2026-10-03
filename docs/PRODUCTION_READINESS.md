# Production Readiness: Egress Gate

Three proposals for moving VICT from demo to production, what was built for each, and the evidence behind any departure from the proposal.

| Proposal | What was built | Evidence |
|---|---|---|
| Enforce at the infrastructure level so no app code can bypass the proxy | Terraform module [`infra/terraform/modules/egress_lockdown`](../infra/terraform/modules/egress_lockdown): isolated route table, VPC-only network ACL, proxy-only security groups. Kept the explicit proxy rather than a transparent sidecar or eBPF filter. | `terraform validate` passes; 4 offline `terraform test` runs against a mocked AWS provider pass. Not yet applied to a real AWS account. |
| Batched Merkle trees for high-throughput hash-chaining | Not built: measured first. Changed each chain link to `sha256(prev_head ‖ record_digest)` so witnesses can verify from digests alone. | The current log appends about 3,000 records/s on a laptop; 100,000 calls/day needs about 5 records/s. |
| Automated NBFC checkpointing | Ed25519-signed checkpoints ([`checkpoint.py`](../src/egress/checkpoint.py)), digest endpoint, and an NBFC-side witness ([`witness.py`](../src/egress/witness.py)) that pulls on a schedule. | 10 witness tests. A live run over HTTP raised a rollback alarm on the first poll after a rewrite, while the LSP's own chain still self-verified. |

## 1. Infrastructure enforcement

Calls from app code can only leave through the proxy, apart from DNS lookups (see the known gap below), because the network gives them no other path:

1. **Route table.** App subnets get one with only the local VPC route: no internet gateway, no NAT.
2. **Network ACL.** App subnets may only exchange traffic with the VPC's own range.
3. **Security groups.** App instances may only connect to the proxy's port plus listed internal ranges. The proxy may only open TCP 443 outbound.

Each layer holds on its own, so attaching a permissive security group later doesn't reopen a path.

**Why not a transparent sidecar or eBPF filter.** A transparent interceptor sees the destination and encrypted bytes, nothing else. It has no consent token, so it cannot tell one borrower's call from another's. Seeing more would mean terminating TLS, which breaks the client certificates and signed payloads that bureaus and AAs require. Pairing an explicit proxy with network lockdown keeps per-call consent and end-to-end TLS, and still removes the bypass.

**Known gap: DNS.** Queries to the Amazon-provided resolver aren't filtered by security groups or network ACLs, so compromised code could leak small amounts of data through DNS lookups. Route 53 Resolver DNS Firewall closes this. It is a paid AWS service.

**To verify on real infrastructure:** run [`verify_lockdown.sh`](../infra/terraform/modules/egress_lockdown/verify_lockdown.sh) on an app instance. Direct HTTPS, direct raw-IP and plain HTTP must fail, and the proxy must answer 407 without a token.

## 2. Hash-chain throughput

Measured on the development laptop (Windows, Python 3.12):

| Measure | Result |
|---|---|
| `AuditLog.append`, including the file write and rollback on a failed write | about 3,000 records/s (about 330 µs each) |
| SHA-256 of one record alone | about 1.1 million/s |
| Needed for 100,000 calls/day (about 4 records per call) | 4.6 records/s on average |

Hashing is under 1% of the append cost; opening the file dominates. At 10 times the expected peak the log still has about 65 times headroom. A Merkle tree would not raise throughput.

Merkle trees are mainly useful for **proof size**: proving one record is in a log of millions without sending the whole log. The witness only needs to check that each new head extends the last one. Each chain link is therefore `sha256(previous head ‖ record digest)`. The witness folds the digests since its last checkpoint, about 100 × 32 bytes per minute at expected volume, and never sees record contents.

**Reads scale with the request, not the log.** A witness poll binary-searches the file by byte offset for its starting `seq` and reads only the records it needs. Reopening the log reads only its last line. There is no separate index that could go stale after a rewrite. On a 500,000-record (185 MB) log, a poll for the last 100 digests takes 3 ms instead of 3.3 s for a full scan. The proxy writes audit records on a worker thread, so a slow disk does not stall other tunnels.

**When to revisit:** if an NBFC needs per-record inclusion proofs, or volume grows by orders of magnitude, move to an RFC 9162-style Merkle log (Certificate Transparency's design). A cheaper first step is keeping the log file open between appends.

## 3. Automated NBFC checkpointing

- **Signed checkpoints.** The LSP signs `{lsp_id, seq, head, ts}` with an Ed25519 key, and the NBFC pins the public key. A signed head binds the LSP to one history, and the LSP cannot deny publishing it.
- **Pull, not push.** The NBFC's witness polls `GET /egress/witness/checkpoint` and `GET /egress/witness/digests?after=&upto=` on its own schedule. Pulling means the LSP can't choose when to report. An LSP that stops answering is reported as `lsp-unreachable`, which is a signal but not an alarm.
- **Checks on every poll:** valid signature from the pinned key, the right LSP, no rollback, no fork (two heads for one sequence number), no time going backwards, and that the new head extends the held head.
- **Sticky alarms.** Once raised, an alarm persists across restarts until someone investigates.
- **No borrower data reaches the NBFC.** Only signed heads and 32-byte record digests are sent.

Run the witness at the NBFC:

```bash
python -m src.egress.witness --lsp-url https://vict.lsp.example.in --lsp-id lsp-demo \
    --public-key lsp-checkpoint.pub.pem --state witness-state.json --interval 10
```

**Interval trade-off:** the LSP can only rewrite entries newer than the last accepted checkpoint. A 10-second interval caps that window at 10 seconds of history, at negligible cost.

## 4. Revocation and failure handling

- **Withdrawal closes open tunnels.** The proxy tracks open tunnels by LSP, borrower and purpose. A revocation closes the matching tunnels at once, and each closure is logged as `tunnel-closed` with reason `consent-withdrawn`. Before this change, an open tunnel lasted until its token expired, up to 60 seconds. A tunnel is registered before its consent check, so a revocation that arrives between the check and the relay still closes it.
- **No audit record, no tunnel.** The `egress-allowed` record is written before the client gets its `200`. If the write fails, the client gets `500 proxy-error`, and both the client and upstream sockets are closed.
- **Limit: the proxy hears about revocations in-process.** That is enough while the consent store runs inside the proxy. Once the consent authority becomes its own service, it must push revocations to the proxy, for example over Postgres `LISTEN/NOTIFY`. Until then, an out-of-process revocation reaches open tunnels only when their token expires.

## 5. Adversarial lockdown probes and AWS endpoints

`verify_lockdown.sh` now tries every exit it knows of and records the outcome in a JSON report: direct HTTPS, raw IPv4 and IPv6, plain HTTP, raw TCP, UDP DNS to an outside resolver, external names through the VPC resolver, the proxy with no token or a forged one, another account's S3 bucket and SQS queue, and internal relays. A refusal or reset counts as a path out, because the packet got there. On a machine without the lockdown it correctly reports every direct path as FAIL.

The module can now create the S3 gateway endpoint and interface endpoints itself, each with an own-account policy. The old advice to add endpoints by hand would have let app code write to another account's bucket once someone loosened the network ACL to make S3 work.

What happens on withdrawal, expiry and outages is specified in [REVOCATION_SEMANTICS.md](REVOCATION_SEMANTICS.md), with the open product decisions listed.

## Still needed before production

- **Apply the lockdown module** in a real AWS Mumbai account and run `verify_lockdown.sh`.
- **Run the consent authority as its own service.** Today it runs in-process, and app code must never hold the token-signing key.
- **Persist the audit log to durable storage.** The S3 Object Lock bucket in `infra/terraform/main.tf` is a natural target. The demo writes to temporary files.
- **Manage the signing key.** Generate it at install time, store it in AWS KMS or Secrets Manager, and give the NBFC a key-rotation procedure.
- **Have the NBFC acknowledge each accepted checkpoint** with a counter-signature, so the LSP also holds proof of what was witnessed.
