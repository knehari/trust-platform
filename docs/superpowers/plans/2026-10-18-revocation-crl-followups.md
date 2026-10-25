# Revocation/CRL lab slice — follow-ups

Collected from the per-task and whole-branch reviews of
`2026-10-18-revocation-crl.md` (branch head cdfef84); statuses refreshed on
22 October 2026 for migrations up to 0055. None blocks the lab slice;
items marked **before non-lab use** must be done before any non-ephemeral issuer
or exposed service. The plan's Task 2 text still shows the original 4-argument
`record_crl_intent`; spec §4 step 3 (8 arguments, content-bound) supersedes it.
Its `CrlPlan` still carries `tbs_der`; `crl_once` now builds the TBS from the
reservation and `CrlPlan::issuer` (spec §4 step 2).

## Before non-lab use
- Least-privilege write model and dual-controlled CA administration:
  implemented in the lab by 0023-0024 (ADR-0006). Open: its acceptance
  conditions (independent review of the SECURITY DEFINER functions, runtime
  without superuser, schema-change control, external audit anchoring,
  authenticated time), real service logins and their credentials, and the
  owner role holding UPDATE on `ca`/`certificate` (row locks).
- Maker-checker is textual by default; `AGENTS.md` requires cryptographically
  distinct signer keys. Since 0028-0029 (status changes) and 0037-0042 (CA
  administration) a CA can opt in, one way, to WebAuthn-signed claims with
  distinct keys and persons (ADR-0007, still Proposed); CAs that do not opt
  in keep the known deviation.
- Authentication of revocation officers stays with the identity adapter.
- CA issuer binding (0022) has one immutable issuer certificate per CA; key
  rollover (several issuer certificates over time, CRLs signed by the new key
  for the old certificates) is not modelled.

## Test gaps
- Integration test asserts no thisUpdate/nextUpdate values (OpenSSL now
  checks the PostgreSQL-stored CRLs, and `ExpiredCertsOnCRL` is tested per
  conformance target through PostgreSQL).
- Migration-retry and ledger scripts stop at 0013 (the populated 0014/0015
  upgrade and its fail-closed aborts are covered by
  `tests/revocation_populated_upgrade.sh`). From 0026 on,
  `scripts/lab/migrate.sh` applies only the missing migrations to an
  existing database and refuses gaps, newer databases and pre-0026 ones
  (`tests/revocation_migration_runner.sh`); it keeps no checksums.
- Rerunning on a reused database: `revocation_lifecycle.sql` and
  `lab_policy_gate` (a fresh CA per run since 22 October 2026) pass again,
  as do `audit_chain_postgres` and `signed_status_change_postgres`. The
  historical issuance suites `postgres_store`, `lab_verified_issuance`,
  `lab_rsa_pss_postgres` and `policy_decisions` still fail on a second run:
  they use the CI-seeded CA and fixed idempotency keys or ids by design and
  are left unchanged; run them on a fresh database (as CI does).

## Robustness and hygiene
- `crl_housekeeping` (management-api binary, verified TLS,
  `docs/operations/lab-crl-housekeeping.md`) runs the sweeps and alerts
  through its exit status; deploying it, `signed_evidence_audit` and the
  audit chain anchoring on a schedule with their dedicated logins remains
  open.
- `crl_due` / `overdue_status_changes` still call `crl_change_covered` per
  approved change (the supersession probe is indexed since 0025); read-only
  queries do not check isolation.
- Closed in 0025: `propose_` locked the grant before the certificate while
  `approve_`/`reject_`/`withdraw_` locked the certificate first, so a bulk grant
  deletion could deadlock (`tests/revocation_lock_order.sh`).
- Migrations copy whole function bodies to change one line (0016-0020), and the
  entries digest expression is repeated in `reserve_crl` and
  `store_verified_crl`; shared helpers would reduce drift.
- The lifecycle audit decision format is built in four function bodies
  (0018/0019); a shared SQL helper would keep it in one place.
- Reject path and approve's generic message still fold maker=checker wording;
  (0021 reports the certain "reserve again" refusals as SQLSTATE 55000 /
  `CrlError::ReserveAgain`.)
- `reconcile_crl` (0021) stores a quarantined CRL only when the caller still
  holds its DER (`CrlError::VerifiedButNotStored`); a CRL lost with its
  process stays `RECONCILIATION_REQUIRED` (no signer read-back exists).
- Expired-entry pruning (`keep_expired_on_crl = false`): implemented in 0031
  from `certificate.not_after` recorded at issuance; certificates stored
  before 0031 are backfilled by housekeeping from their stored DER (0055);
  an unreadable DER is reported and never pruned. Entry
  order is raw serial bytes, not OpenSSL's (length, bytes).
