# Revocation port checkpoint — 2026-11-07

This branch ports the experimental Claude PR #94 onto the profile-lifecycle integration branch. It is an **incomplete laboratory integration** and must not be merged into `main` or deployed yet.

## Applied work and evidence

- The profile stack keeps migrations `0014`–`0025`. All 52 migrations from #94 were moved in their original order to `0026`–`0077`; their exact migration references inside SQL were changed with their filenames. A disposable PostgreSQL 16 database accepted the full `0001`–`0077` sequence.
- On that database, the SQL suites `revocation_lifecycle`, `crl_pipeline`, `crl_robustness`, `ca_admin_dual_control`, `signed_status_changes`, `audit_chain`, and `crl_delta` passed. These transaction-rolled-back suites do not establish upgrade or restore compatibility.
- The new CA administration and revocation APIs require the same explicit OIDC client binding as the profile API. Their test-token helpers now include the client and issue time claims. `cargo check --workspace --all-targets --all-features --locked` passed in the pinned Rust 1.99.0 container after dependency alignment.
- The original profile management API `main.rs` was retained. Automatic text merging produced an incoherent hybrid of profile and #94 handlers, so #94's management API rate-limit, TLS, database and response-header additions are **not integrated** into that binary. The separately added revocation and CA administration binaries compile.

## Required before `main`

1. Rework `scripts/lab/migrate.sh` and the management migration runner for a verified upgrade from an existing `0025` profile database. The imported runner assumes its schema-change ledger starts at `0026` and its file-digest ledger at `0064`; after renumbering they start at `0038` and `0076`. It currently cannot safely upgrade the profile database.
2. Reconcile the Compose stack, initialization scripts, API contracts, CI workflows and operational documentation for both families of services. The textual merge has not been accepted as semantic integration.
3. Run database-backed API and core tests, full Rust and frontend suites, populated upgrade, logical restore, CRL/revocation fault paths and final-head CI. The full Rust test run here stopped at link time because the local disk filled; it did not establish a code failure or a passing suite.
4. Link the G0 legal/IP and independent security-review artifacts. The user confirmed both decisions are complete, but their evidence is not yet in this repository checkpoint.

No production keys, authorities or data were used. The disposable migration test database should be removed after the remaining SQL checks.
