# Signing intent & Rust/PostgreSQL adapter — v0.5

**Status:** draft PR #5. The module is a lab integration adapter, not an operational CA service.

## Added interfaces
- `crates/pki-core/src/postgres_store.rs` (feature flag `postgres-store`) uses the synchronous Rust `postgres` driver.
- `create_request`: transactionally idempotent per issuer, request key, CSR SHA-256, actor and policy version.
- `transition`: calls a state-checked DB transition with same-transaction audit.
- `reserve_serial`: obtains the database-issued 126-bit random unique serial, reusing the reservation on legitimate replay.
- `record_signing_intent`: persists an operation reference, key reference, policy version and TBS digest **before an external signature operation**. If the same intent already exists, the Rust adapter returns `ReplayedSigningIntent`, not approval to call the signer again.
- `mark_uncertain`: records that the external sign operation may or may not have succeeded, and prohibits blind re-signing.

## Why this is important
External HSM signing and PostgreSQL transactions are not atomic together. Network timeout after an HSM call may mean a signature happened. The persistent intent is the reconciliation anchor; the state RECONCILIATION_REQUIRED is a **stop condition**, not a retry queue.

## Planned signing protocol (NOT yet implemented)
1. Authenticate and authorize issuance, validate CSR and profile, allocate serial durably.
2. Construct final TBS and its hash; record one immutable signing intent tied to signing key and approved policy.
3. Invoke the signing provider using the recorded operation reference **once**.
4. If the signature succeeds, verify output externally and persist signed DER/fingerprint atomically; then publish.
5. On uncertainty, mark reconciliation required. Reconcile against external signing provider audit/certificate journal. Avoid blindly repeating signing calls.

## Current limitations / security blockers
- No production-grade authenticated and authorized CA API, TLS-verifying connection or runtime least-privilege database role.
- `connect_lab` uses PostgreSQL NoTls intentionally for a CI loopback DB only. Never deploy it over a real network.
- The runtime adapter does not yet cryptographically verify signed certificate results or call `store_signed_certificate`; SQL `store_signed_certificate` enforces structural record linkage and SHA-256 digest only, **not a valid X.509 signature**.
- Any caller claiming an authenticated actor or approved TBS must be treated as untrusted unless a reviewed boundary validates it.
- The audit store lacks external integrity anchoring/WORM. Backup/restore and cross-process crash recovery are not yet tested end-to-end.
- The laboratory CA still uses ephemeral signing key and its own in-memory serials; **it is not wired to the PostgreSQL adapter for issuance**.
- PostgreSQL schema owners and superusers can bypass most in-database triggers and restrictions.

## Test
GitHub CI creates a disposable PostgreSQL 16 service, migrates schema 0001–0003, runs SQL security cases and Rust integration tests for create/replay, serial reserve/replay, durable signing intent and uncertain outcome.

## Before production
G0 employer IP separation, rigorous PKI signing API, TLS/mTLS and RBAC, PKCS#11, immutable policy revisions, validated result reconciliation, crash injection, threat modeling, backup/restore and external security assessment.
