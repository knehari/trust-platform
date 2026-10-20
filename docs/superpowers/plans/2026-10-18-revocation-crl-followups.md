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
- Nothing schedules `abandon_stale_crl_reservations` /
  `quarantine_stale_crl_intents`; since 0017 a stale reservation can no longer
  be signed, but it stays `RESERVED` until the sweep runs; ADR-0006 part C
  proposes a scheduled operator job.
- `crl_due` is O(history) per call; read-only queries do not check isolation.
- Audit rows carry no `change_id`/reason; reject path and approve's generic
  message still fold maker=checker wording; `suspension_cps_ref` accepts
  whitespace-only text; intent mismatch is reported as
  `ReplayedOrAmbiguousIntent` (no distinct variant).
- Expired-entry pruning (`keep_expired_on_crl = false`) needs a stored
  `not_after`; entry order is raw serial bytes, not OpenSSL's (length, bytes).
