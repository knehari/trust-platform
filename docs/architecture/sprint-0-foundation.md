# Sprint 0 — engineering foundation

**Status:** implementation proposed in draft PR #1. Validation and review required.

## Delivered in branch

- Rust workspace: trust-pki-core, trust-pki-policy, trust-pki-crypto.
- DenyAll and explicit StaticPolicy with negative test cases.
- Separation between trusted authenticated actor and untrusted requested names.
- Immutable policy authorization with algorithm and validity constraints.
- RFC 5280 serial validation and lab-only issuer-scoped uniqueness store.
- Pure issuance-state transition map (NOT a persistent enforcement mechanism).
- PostgreSQL schema proposal in migrations/0001_foundation.sql.
- Secure-by-default absent signing provider, with negative tests.
- CI: format, generate lockfile, tests, Clippy.

## Not delivered

No CSR parser, cryptographic operation, real CA or certificate, HSM, signing authorization gateway, durable database adapter, or production-grade identity service.

## Acceptance conditions

1. GitHub Actions format, test and Clippy jobs pass.
2. No secrets or copyrighted employer material.
3. All security caveats and remaining risks documented.
4. Explicit owner review, G0 legal/IP status and PR approval before merge.
5. Source and Jira issue links recorded.

## Traceability

TRUST-11 to TRUST-15, TRUST-23, TRUST-27 (engineering groundwork). No ticket should be marked Done solely because a draft PR exists.
