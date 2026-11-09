# Development status — main after PR #190

**Checked 2026-11-08 against `main` at `8ea2446`.** The laboratory CA lifecycle, authenticated certificate applications, issuance through a separate software signer, revocation and signed CRL publication are now in `main` through [PR #190](https://github.com/knehari/trust-platform/pull/190). The earlier statement that these routes were absent from `main` is obsolete. The MVP score remains **5/12 (42%)** because the full criteria still require protected key custody, recovery, reconciliation and release evidence; partial laboratory flows do not close them.

## Current integration

- Migrations 0026–0032 belong to the CA/application/revocation/CRL stack merged through #190. The console and management API expose its laboratory flows, and the signer uses a software key mounted separately from the API.
- [Draft PR #94](https://github.com/knehari/trust-platform/pull/94) and its [port PR #193](https://github.com/knehari/trust-platform/pull/193) contain a different signed-administration and revocation model. Their migrations also start at 0026 and continue to 0078. PR #193 cannot be merged into the current schema; it is retained as a comparison and recovery source.
- The current main-based follow-up excludes `.lab-keys` from Docker build contexts and fixes Unicode audit-filter length validation. It does not change the database schema or revocation state machine.

## Verification and remaining work

- The main-based management API suite passes (61 tests, Rust 1.99.0 in an isolated container); database-backed tests requiring `TRUST_API_TEST_DATABASE_URL` were skipped by their existing guards. A Docker build with a synthetic marker under `.lab-keys` confirms that the marker is absent after `COPY . .`. These are code and build-context checks, not a fresh end-to-end verification of #190.
- The #94 port branch separately passed its 59 management API tests, 79 control API tests, PostgreSQL suites, seven-service laboratory Compose health checks, and a Keycloak code/PKCE smoke. These results do not validate the new #190 schema or a combined branch.
- Reconcile the two models by mapping operations, permissions, durable evidence and migration paths before porting the unique features of #94. In particular, existing databases upgraded through #190 must never receive the competing 0026–0032 scripts.
- Then validate the reconciled schema with a populated database upgrade, signed status-change and CRL recovery paths, scoped API authorization and a full isolated Compose run. Link the already confirmed G0 legal/IP and independent security review artifacts to the release record; production custody and operational pilot evidence remain open.
