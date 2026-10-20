# Revocation/CRL lab slice — follow-ups

Collected from the per-task and whole-branch reviews of
`2026-10-18-revocation-crl.md` (branch head cdfef84). None blocks the lab slice;
items marked **before non-lab use** must be done before any non-ephemeral issuer
or exposed service. The plan's Task 2 text still shows the original 4-argument
`record_crl_intent`; spec §4 step 3 (8 arguments, content-bound) supersedes it.
Its `CrlPlan` still carries `tbs_der`; `crl_once` now builds the TBS from the
reservation and `CrlPlan::issuer` (spec §4 step 2).

## Before non-lab use
- Least-privilege write model: SQL functions are SECURITY INVOKER, so any caller
  role needs DML on `revocation` / `certificate_status_change` and could bypass
  maker-checker (spec §6). Proposed design: ADR-0006 (SECURITY DEFINER
  functions, EXECUTE-only service roles), pending human review.
- Maker-checker is textual only; `AGENTS.md` requires cryptographically distinct
  signer keys (known deviation). ADR-0006 part B proposes signed claims.
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
  `tests/revocation_populated_upgrade.sh`).
- `lab_policy_gate` and the policy block of `revocation_lifecycle.sql` are not
  idempotent on a reused database (pre-existing).

## Robustness and hygiene
- `crl_housekeeping` (lab example, `docs/operations/lab-crl-housekeeping.md`)
  runs the sweeps and alerts through its exit status; deploying it on a
  schedule, and under the ADR-0006 operator role, remains open.
- `crl_due` / `overdue_status_changes` are O(history) per call (a
  `crl_change_covered` call and supersession probe per approved change, no
  supporting index); read-only queries do not check isolation.
- Lock order: `propose_` locks the grant before the certificate, `approve_`,
  `reject_` and `withdraw_` the certificate first; with concurrent bulk grant
  deletion this can deadlock (PostgreSQL aborts one transaction, fail closed).
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
- Expired-entry pruning (`keep_expired_on_crl = false`) needs a stored
  `not_after`; entry order is raw serial bytes, not OpenSSL's (length, bytes).
