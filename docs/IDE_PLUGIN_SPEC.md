# VICT IDE Plugin Spec (Security Co-pilot)

## Goal

Surface sovereignty and compliance issues during coding, before deployment.

## Core Diagnostics

- `VICT001`: Non-India data localization route detected.
- `VICT002`: Wildcard IAM permission detected.
- `VICT003`: Missing consent check on personal/payment path.
- `VICT004`: Runtime guardrail violation (unauthorized process/egress).

## Suggested Quick Fixes

- Replace non-India endpoint with India endpoint (`ap-south-1`/`ap-south-2`).
- Narrow IAM actions to resource-scoped permissions.
- Insert consent middleware call before invocation.
- Inject runtime guardrail policy checks.

## Minimal Extension Flow

1. Run `vict scan` on save.
2. Parse findings into VS Code diagnostics.
3. Offer quick-fix snippets based on error code.
4. Expose `VICT: Wrap and Deploy` command in command palette.
