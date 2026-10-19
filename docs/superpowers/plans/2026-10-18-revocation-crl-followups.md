# Revocation/CRL lab slice — follow-ups

Collected from the per-task and whole-branch reviews of
`2026-10-18-revocation-crl.md` (branch head cdfef84). None blocks the lab slice;
items marked **before non-lab use** must be done before any non-ephemeral issuer
or exposed service. The plan's Task 2 text still shows the original 4-argument
`record_crl_intent`; spec §4 step 3 (8 arguments, content-bound) supersedes it.

## Before non-lab use
- Least-privilege write model: SQL functions are SECURITY INVOKER, so any caller
  role needs DML on `revocation` / `certificate_status_change` and could bypass
  maker-checker (spec §6). Design SECURITY DEFINER wrappers or a service role
  with EXECUTE only, plus INSERT guards on history and `crl_publication`.
- AKI is derived from the SPKI hash, not read from the issuer's SKI extension;
  verifier does not check issuer keyUsage cRLSign or curve (`crl.rs`).
- `crl_once` accepts `tbs_der` independently of the reservation; only the
  verifier binds them, after signing. Build or re-check the TBS from the
  reservation before `record_intent`.
- Authentication of revocation officers stays with the identity adapter.

## Test gaps
- Integration test asserts no thisUpdate/nextUpdate values (OpenSSL now
  checks the PostgreSQL-stored CRLs, and `ExpiredCertsOnCRL` is tested per
  conformance target through PostgreSQL).
- Migration-retry and ledger scripts stop at 0013 (the populated 0014/0015
  upgrade and its fail-closed aborts are covered by
  `tests/revocation_populated_upgrade.sh`).
- No golden DER vector; no high-bit serial test; `crl_once` doubles ignore
  `operation_ref`; best-effort `mark_uncertain` failure path untested.
- Fuzz seeds are signed by another key, so `crl_verify` never reaches signature
  success; `seed-corpus.sh` hides OpenSSL errors.
- `lab_policy_gate` and the policy block of `revocation_lifecycle.sql` are not
  idempotent on a reused database (pre-existing).

## Robustness and hygiene
- Orphan `RESERVED` CRL rows (failure between reserve and snapshot read, or
  abandoned reservations) are never swept; stale-intent age is measured from
  `this_update` (add `intent_recorded_at`).
- `this_update` is not forced monotonic across numbers (clock step back).
- `revocation.revoked_at` has no range CHECK (only direct/legacy rows at risk).
- CA row `FOR UPDATE` in `reserve_crl` could be `FOR NO KEY UPDATE`.
- `crl_due` is O(history) per call; read-only queries do not check isolation.
- `Row::get` can panic in `revocation_store.rs` (use `try_get`).
- Audit rows carry no `change_id`/reason; reject path and approve's generic
  message still fold maker=checker wording; `suspension_cps_ref` accepts
  whitespace-only text; intent mismatch is reported as
  `ReplayedOrAmbiguousIntent` (no distinct variant).
- Expired-entry pruning (`keep_expired_on_crl = false`) needs a stored
  `not_after`; entry order is raw serial bytes, not OpenSSL's (length, bytes).
