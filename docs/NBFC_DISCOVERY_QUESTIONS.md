# Questions for an NBFC compliance team

For the first design-partner call. The goal is to learn what record the NBFC needs for each outbound call to a non-AA vendor, so that VICT's technical decisions map onto their legal and audit requirements instead of only producing valid tokens. Listen more than pitch; the answers set the first build.

## The consent record per vendor

1. For each non-AA vendor category you work with (credit bureaus, CKYC and KYC, PAN or bank-account verification, fraud and device checks, collections), what legal basis do you rely on? Explicit consent, or something else, such as a legal obligation for KYC?
2. For consent-based calls, what must a consent record contain for you to accept it as evidence? For example: the notice version and language shown, the timestamp and channel, the purpose wording, and whether the vendor is named.
3. Does a borrower's consent name specific vendors, or categories such as "credit bureaus"? Can you share your purpose list, so ours matches it instead of inventing one?
4. Who must hold the record of each call, the LSP or you, and for how long?

## Withdrawal and failure

5. When a borrower withdraws, what do you expect to happen, and by when? Stop new calls only, cut calls in flight, or also tell vendors to delete what they hold?
6. If the consent check can't run because the store is down, VICT refuses all calls and the loan flow stops. Is that acceptable, or would you accept a degraded mode with after-the-fact review?

## Oversight and evidence

7. How do you oversee an LSP's vendor calls today: questionnaires, audits, logs on request? What's the hardest part of that?
8. What would you want to see for one loan file: each vendor called, with purpose, time and outcome? In what form: a report, CSV, or an API?
9. Could you run a small witness process that pulls signed checkpoints from the LSP over outbound HTTPS? Who on your side would own its alarms?
10. Which findings would make you act, and what would you do? For example, pause disbursal through that LSP.

## Adoption

11. Would you recommend this to your LSPs, require it, or neither? What would it take to require it?
12. Who has to agree internally: compliance, risk, the CISO, IT?

## After the call

Write down, for each vendor category, the legal basis, the record fields, the retention period and the withdrawal expectation. That table becomes the specification for what a consent token must reference and what the ledger must keep.
