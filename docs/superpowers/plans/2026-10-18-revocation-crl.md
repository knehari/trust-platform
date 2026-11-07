# Revocation, Suspension and CRL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Maker-checker suspend/release/revoke of issued certificates and a durable, independently verified full CRL v2 pipeline for the P-256 lab CA, with per-CA RFC 5280 / ETSI conformance targets.

**Architecture:** Two migrations hold the rules (0014 status lifecycle, 0015 CRL numbering and intents) and re-check everything the Rust layer decides. Rust adds a pure decision layer (`revocation_policy`), CRL encoding/verification (`crl`), a `crl_once` orchestrator mirroring `issue_once`, and a PostgreSQL adapter. A lab example feeds OpenSSL interoperability checks.

**Tech Stack:** Rust 1.99.0 workspace, `x509-cert =0.2.5` (`crl`, `ext::pkix::crl`), `p256` via `trust-pki-crypto`, `postgres =0.19.12`, PostgreSQL 16, OpenSSL CLI, cargo-fuzz.

**Spec:** `docs/superpowers/specs/2026-10-18-revocation-crl-design.md`

## Global Constraints

- Lab only: new code sits behind `lab-software` / `postgres-store` exactly like existing lab issuance; no production claim in docs or messages.
- No home-grown cryptography: signatures via `EphemeralLabCa` (`ExternalSigner`) and `trust_pki_crypto::verify_p256_ecdsa_sha256` only.
- Accepted reason codes: 0, 1, 2, 3, 4, 5, 6 (SUSPEND only, only if `suspension_allowed`), 9, 10. Code 7 does not exist; code 8 (`removeFromCRL`) is always rejected.
- A definitive revocation (reason ≠ 6) is irreversible for every caller and every conformance target.
- Maker ≠ checker means a different `(issuer, subject)` pair; both need a `revocation_officer_grant` for the CA when they act.
- `conformance_target` ∈ `RFC5280` (default), `ETSI_EN_319_411_1`, `ETSI_EN_319_411_2`. ETSI targets: `crl_issue_interval <= '24 hours'`, `status_publication_deadline <= '24 hours'`, suspension requires `suspension_cps_ref`. `ETSI_EN_319_411_2`: CRL carries `ExpiredCertsOnCRL` (OID 2.5.29.60).
- Generic bounds: `crl_validity` 1 hour–90 days and ≥ `crl_issue_interval`; `crl_issue_interval` and `status_publication_deadline` 1 hour–7 days; defaults 7 days / 24 hours / 24 hours.
- `keep_expired_on_crl` is fixed to `true` in this slice (CHECK); pruning needs a stored `not_after` and is a follow-up (see Task 2, spec update).
- CRL profile: v2, issuer = CA subject DER, `ecdsa-with-SHA256`, AKI = CA SKI, CRL Number, `reasonCode` omitted for unspecified, `invalidityDate` when set, no IDP, `revokedCertificates` omitted when empty, entries sorted by serial bytes, times UTCTime through 2049 and GeneralizedTime from 2050.
- CRL numbers: per CA, strictly increasing, never reused, `< 2^63`; any failure after the intent marks `RECONCILIATION_REQUIRED`; never re-sign automatically.
- Every new SQL function: `REVOKE ALL ... FROM PUBLIC`; every state change writes `audit_event`. New tables get no grant to `trust_api_reader` (the management API refuses to start if its login can read public tables).
- Errors from SQL use: `22023` invalid input, `42501` missing grant, `23514` rule violation.
- Database tests honour `TRUST_REQUIRE_DATABASE=1` (fail if the URL is missing).
- Every commit ends with the session's `Co-Authored-By` and `Claude-Session` trailers.

## Review Focus

- **Approval racing a second proposal or a CRL reservation.** Both functions lock the certificate (status) or CA row (CRL); a CRL reserved during an approval must contain either the old or the new state, never a half-applied one. Test in Task 2 (`crl_concurrency.sh` runs approvals alongside reservations).
- **Policy changed between proposal and approval** (suspension disabled, grant removed, target switched to ETSI). Approval re-checks grants and state; RELEASE stays allowed when suspension is later disabled so a hold can still be lifted. Tests in Task 1.
- **Time encodings around 2050 and second precision.** `x509-cert`'s `TryFrom<SystemTime> for Time` always yields GeneralizedTime, which breaks RFC 5280 before 2050 and makes OpenSSL comparisons inconsistent; use `rfc5280_time`. SQL truncates `this_update` to whole seconds so DB and DER agree. Tests in Task 3.
- **Empty CRL and first CRL of a CA.** No revoked entries must give a valid CRL without `revokedCertificates`; numbering starts at 1. Tests in Tasks 2 and 3.
- **Management API startup after 0014/0015.** The restricted reader login must still have no table privilege in `public`; compose and the API readiness check would otherwise fail. Test in Task 1 (SQL assertion) and the existing compose smoke job.

---

### Task 1: Migration 0014 — status lifecycle, policies and grants

**Files:**
- Create: `migrations/0014_revocation_lifecycle.sql`
- Create: `tests/revocation_lifecycle.sql`
- Modify: `.github/workflows/rust-ci.yml` (schema job: apply 0014 after 0013, run the test)

**Interfaces:**
- Produces tables `ca_revocation_policy`, `revocation_officer_grant`, `certificate_status_change`; column `revocation.change_id`.
- Produces SQL functions:
  - `certificate_status(p_ca UUID, p_serial BYTEA) RETURNS TEXT` → `'VALID' | 'SUSPENDED' | 'REVOKED'` (raises `22023` if no such certificate)
  - `propose_certificate_status_change(p_ca UUID, p_serial BYTEA, p_action TEXT, p_reason SMALLINT, p_invalidity TIMESTAMPTZ, p_maker_issuer TEXT, p_maker_subject TEXT) RETURNS UUID`
  - `approve_certificate_status_change(p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT, p_expected_action TEXT, p_expected_reason SMALLINT) RETURNS TEXT` → `'APPROVED'`
  - `reject_certificate_status_change(p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT) RETURNS TEXT` → `'REJECTED'`
  - `withdraw_certificate_status_change(p_change UUID, p_maker_issuer TEXT, p_maker_subject TEXT) RETURNS TEXT` → `'WITHDRAWN'`
- Audit `event_type` values: `certificate.status.proposed|approved|rejected|withdrawn`; `request_id` = the certificate's request; `actor_id` = `issuer || '|' || subject`.

- [ ] **Step 1: Write the failing SQL test `tests/revocation_lifecycle.sql`**

One transaction, `\set ON_ERROR_STOP 1`, fixtures inserted directly as table owner: CA `c0c0c0c0-0000-4000-8000-000000000001`, three requests/serials/certificates (`\x01`, `\x02`, `\x03`; DER may be a placeholder byte string), officer grants for `('https://idp.lab.invalid','maker')` and `('https://idp.lab.invalid','checker')`, and policy row with `suspension_allowed = true`. Each rejection is asserted with a `DO` block that catches the expected `SQLSTATE` and raises if no error occurred. Assertions:
- serial 1: propose REVOKE reason 1 → approve → `certificate_status = 'REVOKED'`; `revocation.reason_code = 1`.
- serial 2: SUSPEND (6) → approve → `'SUSPENDED'`; RELEASE → approve → `'VALID'`, no `revocation` row; SUSPEND again → approve; REVOKE reason 1 → approve → `'REVOKED'` and `revoked_at` equals the second suspension's `revoked_at`.
- serial 3: withdraw by maker → `'WITHDRAWN'`; reject by checker → `'REJECTED'`; status still `'VALID'`.
- `23514`: approve by the maker identity; any proposal on serial 1 (REVOKED); a second `PROPOSED` on serial 3; REVOKE with reason 6; SUSPEND with reason ≠ 6; RELEASE on a VALID certificate.
- `22023`: reason 7, reason 8, reason 11, NULL maker, unknown action `'UNREVOKE'`.
- `42501`: proposal by `('https://idp.lab.invalid','stranger')`; approval by a checker whose grant was deleted after the proposal.
- `23514`: SUSPEND when `suspension_allowed = false`; RELEASE of an existing hold still succeeds after `suspension_allowed` is set to false.
- ETSI targets: `UPDATE ca_revocation_policy SET conformance_target='ETSI_EN_319_411_1', crl_issue_interval='25 hours'` fails `23514`; ETSI with `suspension_allowed = true` and NULL `suspension_cps_ref` fails `23514`; `keep_expired_on_crl = false` fails `23514`.
- Irreversibility: `DELETE FROM revocation` for serial 1 and `UPDATE revocation SET reason_code = 6` for serial 1 both fail; `UPDATE`/`DELETE` on an `APPROVED` `certificate_status_change` row fails.
- `has_function_privilege('public', 'propose_certificate_status_change(uuid,bytea,text,smallint,timestamptz,text,text)', 'EXECUTE')` is false, likewise for the other four functions.
- `trust_api_reader` has no `SELECT` on the three new tables (`has_table_privilege` false).
- Ends with `ROLLBACK`.

- [ ] **Step 2: Run it to verify it fails**

Run: `psql "$DB" -X -v ON_ERROR_STOP=1 -f migrations/0001_foundation.sql ... -f migrations/0013_management_reader_grants.sql && psql "$DB" -X -v ON_ERROR_STOP=1 -f tests/revocation_lifecycle.sql`
Expected: FAIL, `relation "ca_revocation_policy" does not exist`.

- [ ] **Step 3: Write `migrations/0014_revocation_lifecycle.sql`**

`BEGIN; ... COMMIT;` like earlier migrations. Tables and CHECKs as in the Interfaces block and Global Constraints (one `PROPOSED` per certificate via partial unique index; status/decision field coherence; maker ≠ checker; `reason_code IS NULL` iff `action = 'RELEASE'`). Guard triggers: `certificate_status_change` allows only `PROPOSED → APPROVED|REJECTED|WITHDRAWN` and no `DELETE`; `revocation` allows `DELETE` only when `reason_code = 6` and `UPDATE` only from 6 to a reason in (0–5, 9, 10) with unchanged `revoked_at`. Functions lock `certificate` `FOR UPDATE`, read the policy row with defaults when absent (`RFC5280`, no suspension), use `clock_timestamp()` for `revoked_at`/`decided_at`, and write `audit_event`. End with `REVOKE ALL ON FUNCTION ... FROM PUBLIC` for all five.

- [ ] **Step 4: Run the test to verify it passes**

Run: same as Step 2.
Expected: exits 0, ends with `ROLLBACK`.

- [ ] **Step 5: Wire CI and commit**

Add `docker exec -i "$CONTAINER" psql ... < migrations/0014_revocation_lifecycle.sql` after the 0013 line and `... < tests/revocation_lifecycle.sql` after `tests/management_api_readonly.sql` in the schema job. Validate YAML (`python3 -c "import yaml; yaml.safe_load(open('.github/workflows/rust-ci.yml'))"`).

```bash
git add migrations/0014_revocation_lifecycle.sql tests/revocation_lifecycle.sql .github/workflows/rust-ci.yml
git commit -m "feat(db): maker-checker certificate status lifecycle (0014)"
```

---

### Task 2: Migration 0015 — CRL numbering, intents and deadlines

**Files:**
- Create: `migrations/0015_crl_pipeline.sql`
- Create: `tests/crl_pipeline.sql`, `tests/crl_concurrency.sh`
- Modify: `.github/workflows/rust-ci.yml` (schema job), `docs/superpowers/specs/2026-10-18-revocation-crl-design.md` (state `keep_expired_on_crl` fixed to true this slice)

**Interfaces:**
- Consumes: Task 1 tables and `revocation` rows.
- Produces columns on `crl_publication`: `status` (`RESERVED|INTENT_RECORDED|STORED|RECONCILIATION_REQUIRED`), `operation_ref TEXT`, `actor_id TEXT`, `entries_sha256 BYTEA`, `tbs_sha256 BYTEA NULL`, `crl_der BYTEA NULL`, `expired_certs_on_crl_since TIMESTAMPTZ NULL`; `crl_sha256` becomes nullable; CHECK `STORED ⇒ crl_der, crl_sha256, tbs_sha256 NOT NULL`; CHECK `crl_number BETWEEN 1 AND 9223372036854775806`; UNIQUE `(ca_id, operation_ref)`.
- Produces table `crl_entry_snapshot (ca_id, crl_number, serial_der_content, revoked_at, reason_code, invalidity_at, PK (ca_id, crl_number, serial_der_content))`.
- Produces SQL functions:
  - `reserve_crl(p_ca UUID, p_actor TEXT, p_operation_ref TEXT) RETURNS TABLE(crl_number BIGINT, this_update TIMESTAMPTZ, next_update TIMESTAMPTZ, expired_certs_on_crl_since TIMESTAMPTZ)`
  - `crl_snapshot_entries(p_ca UUID, p_crl_number BIGINT) RETURNS TABLE(serial_der_content BYTEA, revoked_at TIMESTAMPTZ, reason_code SMALLINT, invalidity_at TIMESTAMPTZ)` ordered by `serial_der_content`
  - `record_crl_intent(p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA) RETURNS TEXT` → `'INTENT_RECORDED'`
  - `mark_crl_uncertain(p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT) RETURNS TEXT`
  - `store_verified_crl(p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA, p_crl_sha256 BYTEA, p_crl_der BYTEA) RETURNS TEXT` → `'STORED'`
  - `quarantine_stale_crl_intents(p_ca UUID, p_older_than INTERVAL) RETURNS INTEGER`
  - `crl_due(p_ca UUID) RETURNS BOOLEAN`
  - `overdue_status_changes(p_ca UUID) RETURNS TABLE(change_id UUID, status TEXT, proposed_at TIMESTAMPTZ)`

`reserve_crl` locks the `ca` row `FOR UPDATE`; number = `COALESCE(max(crl_number), 0) + 1` over all statuses; `this_update = date_trunc('second', clock_timestamp())`; `next_update = this_update + crl_validity`; snapshot = all current `revocation` rows; `entries_sha256` = SHA-256 of the ordered concatenation of `int4send(octet_length(serial)) || serial || int8send(epoch(revoked_at)) || int2send(reason_code) || int8send(COALESCE(epoch(invalidity_at), -1))`; `expired_certs_on_crl_since = ca.created_at` only for target `ETSI_EN_319_411_2`. `store_verified_crl` recomputes `entries_sha256` from the snapshot and fails `23514` on mismatch, wrong status, wrong operation or wrong TBS hash. `crl_due` is true when no `STORED` row exists, the latest `STORED.this_update` is older than `crl_issue_interval`, or an `APPROVED` change has `decided_at` later than the latest `STORED.this_update`. `overdue_status_changes` returns `PROPOSED` rows whose `proposed_at + status_publication_deadline < clock_timestamp()` and `APPROVED` rows meeting the same condition with no `STORED` CRL whose `this_update >= decided_at`.

- [ ] **Step 1: Write the failing SQL test `tests/crl_pipeline.sql`**

Fixture CA and two certificates as in Task 1 (separate CA id `c0c0c0c0-0000-4000-8000-000000000002`). Assertions:
- First `reserve_crl` returns `crl_number = 1` and an empty snapshot; `next_update - this_update = '7 days'`; `this_update = date_trunc('second', this_update)`.
- After revoking serial `\x01` through Task 1 functions, the next reservation returns 2 with one snapshot row (reason 1).
- `record_crl_intent` twice with the same arguments → second fails `23514`; with a non-existent number fails `23514`.
- `store_verified_crl` before an intent fails `23514`; after an intent with a mismatched TBS hash fails `23514`; with matching values returns `'STORED'`.
- Number 3 reserved, intent recorded, `mark_crl_uncertain` → status `RECONCILIATION_REQUIRED`; `store_verified_crl` on it fails; next reservation returns 4.
- `quarantine_stale_crl_intents(ca, '0 seconds')` moves an `INTENT_RECORDED` row to `RECONCILIATION_REQUIRED` and returns 1.
- `crl_due` true before any `STORED`, false right after storing, true again after a new approval. `overdue_status_changes` is empty with the default 24 h deadline; after `UPDATE ca_revocation_policy SET status_publication_deadline='1 hour'` it lists a `PROPOSED` fixture row inserted directly with `proposed_at = clock_timestamp() - interval '2 hours'` (insert, not update: the guard trigger forbids changing `proposed_at`).
- Target `ETSI_EN_319_411_2` → `expired_certs_on_crl_since = ca.created_at`; other targets → NULL.
- `UPDATE`/`DELETE` on a `STORED` `crl_publication` row and on `crl_entry_snapshot` fail.
- `EXECUTE` not granted to `PUBLIC` for all eight functions; `trust_api_reader` cannot `SELECT` `crl_entry_snapshot`.

- [ ] **Step 2: Run it to verify it fails**

Run: apply 0001–0014, then `psql "$DB" -X -v ON_ERROR_STOP=1 -f tests/crl_pipeline.sql`
Expected: FAIL, `function reserve_crl(uuid, text, text) does not exist`.

- [ ] **Step 3: Write `migrations/0015_crl_pipeline.sql`** as described in Interfaces, with a guard trigger making `STORED` rows and snapshots immutable and allowing only `RESERVED → INTENT_RECORDED → STORED | RECONCILIATION_REQUIRED` (plus `RESERVED → RECONCILIATION_REQUIRED`). Audit events `crl.reserved|intent|stored|uncertain|quarantined` with `request_id` NULL.

- [ ] **Step 4: Run the test to verify it passes**

Run: same as Step 2. Expected: exits 0.

- [ ] **Step 5: Write `tests/crl_concurrency.sh <container>`**

Mirror `tests/recovery_concurrency.sh`: create a CA, 12 background `psql` clients each call `reserve_crl` once while 4 others approve prepared proposals; assert `SELECT count(*), count(DISTINCT crl_number), min(crl_number), max(crl_number)` returns `12|12|1|12`, and that every snapshot contains, for each approved change, either no row or the post-approval row (no row with a reason other than the approved one). Print `PASS: twelve concurrent CRL reservations got distinct consecutive numbers`.

- [ ] **Step 6: Run it locally and in CI wiring**

Run: `bash tests/crl_concurrency.sh "$CONTAINER"` against a database with 0001–0015.
Expected: the PASS line. Add 0015, `tests/crl_pipeline.sql` and the script to the schema job after Task 1's lines.

- [ ] **Step 7: Update the spec and commit**

In the spec, replace the `keep_expired_on_crl` description with "fixed to true in this slice; pruning needs the certificate's notAfter persisted and is a follow-up".

```bash
git add migrations/0015_crl_pipeline.sql tests/crl_pipeline.sql tests/crl_concurrency.sh .github/workflows/rust-ci.yml docs/superpowers/specs/2026-10-18-revocation-crl-design.md
git commit -m "feat(db): durable CRL numbering, intents and deadline queries (0015)"
```

---

### Task 3: Rust status types and pure decision layer

**Files:**
- Create: `crates/pki-core/src/revocation.rs`
- Modify (rewrite): `crates/pki-core/src/revocation_policy.rs`
- Modify: `crates/pki-core/src/lib.rs` (add `pub mod revocation;`)

**Interfaces:**
- Produces in `revocation`:
  - `pub enum RevocationReason { Unspecified, KeyCompromise, CaCompromise, AffiliationChanged, Superseded, CessationOfOperation, CertificateHold, PrivilegeWithdrawn, AaCompromise }` with `pub fn code(self) -> i16` and `pub fn from_code(code: i16) -> Result<Self, StatusChangeError>` (7, 8, negative and >10 → `UnknownReason`).
  - `pub enum StatusAction { Suspend, Release, Revoke }` with `pub fn as_sql(self) -> &'static str` (`"SUSPEND"|"RELEASE"|"REVOKE"`).
  - `pub enum CertificateStatus { Valid, Suspended, Revoked }` with `pub fn from_sql(&str) -> Option<Self>`.
  - `pub enum ConformanceTarget { Rfc5280, EtsiEn319411_1, EtsiEn319411_2 }` with `as_sql` (`"RFC5280"`, `"ETSI_EN_319_411_1"`, `"ETSI_EN_319_411_2"`).
  - `pub struct OfficerIdentity<'a> { pub issuer: &'a str, pub subject: &'a str }`.
- Produces in `revocation_policy`:
  - `pub enum StatusChangeError { UnknownReason, ReasonNotAllowedForAction, SuspensionDisabled, InvalidTransition, TerminalState }`
  - `pub enum Transition { Suspend, Release, RevokeFromValid, RevokeFromSuspended }`
  - `pub fn decide_status_change(current: CertificateStatus, action: StatusAction, reason: Option<RevocationReason>, suspension_allowed: bool) -> Result<Transition, StatusChangeError>`

Rules: `Revoked` → `TerminalState` for every action. `Suspend` needs `Valid`, `Some(CertificateHold)`, `suspension_allowed`. `Release` needs `Suspended` and `None`; allowed even when `suspension_allowed` is false. `Revoke` needs `Valid` or `Suspended` and `Some(r)` with `r != CertificateHold`. A wrong reason shape → `ReasonNotAllowedForAction`; a wrong state → `InvalidTransition`.

- [ ] **Step 1: Write failing unit tests** in both files:
  - `reason_codes_round_trip_and_reject_7_8_and_out_of_range`: every variant's `code()` round-trips; `from_code` of 7, 8, -1, 11 is `Err(UnknownReason)`.
  - `exhaustive_transition_table`: iterate all `CertificateStatus × StatusAction × {None, each reason} × {true,false}` and compare with an expected table written as a `match` in the test (assert the four `Ok` cases above and the error kind for every other combination).
  - `release_allowed_after_suspension_disabled`: `decide_status_change(Suspended, Release, None, false) == Ok(Transition::Release)`.
  - `revoke_from_suspended_with_hold_reason_rejected`.
- [ ] **Step 2: Run** `cargo test -p trust-pki-core --lib revocation --locked`. Expected: FAIL (module/functions missing).
- [ ] **Step 3: Implement** the types and `decide_status_change`; delete the old `authorize_revocation`/`RevocationError` and its test (their rules contradict the spec; serial validation lives in `serial::SerialNumber`).
- [ ] **Step 4: Run** the same command plus `cargo clippy -p trust-pki-core --all-targets --all-features --locked -- -D warnings`. Expected: PASS, no warnings.
- [ ] **Step 5: Commit**

```bash
git add crates/pki-core/src/revocation.rs crates/pki-core/src/revocation_policy.rs crates/pki-core/src/lib.rs
git commit -m "feat(core): typed revocation reasons and pure status transition rules"
```

---

### Task 4: CRL encoding and independent verification

**Files:**
- Create: `crates/pki-core/src/crl.rs` (`#[cfg(feature = "lab-software")]` for `LabCrlVerifier`/`LabCrlAssembler`; types and builder always compiled)
- Modify: `crates/pki-core/src/lib.rs`

**Interfaces:**
- Consumes: `revocation::RevocationReason`, `serial::SerialNumber`, `x509_extensions::key_identifier`, `trust_pki_crypto::verify_p256_ecdsa_sha256`.
- Produces:
  - `pub enum CrlError { Encoding, JournalFailure, ReplayedOrAmbiguousIntent, SigningFailure, AssemblyFailure, VerificationFailure, PersistenceFailure }`
  - `pub struct CrlEntry { pub serial: SerialNumber, pub revoked_at_unix: i64, pub reason: RevocationReason, pub invalidity_at_unix: Option<i64> }`
  - `pub struct CrlReservation { pub ca_id: String, pub crl_number: u64, pub this_update_unix: i64, pub next_update_unix: i64, pub entries: Vec<CrlEntry>, pub expired_certs_on_crl_since_unix: Option<i64> }`
  - `pub fn rfc5280_time(unix_seconds: i64) -> Result<x509_cert::time::Time, CrlError>` (UTCTime for years 1950–2049, GeneralizedTime otherwise)
  - `pub fn build_tbs_cert_list(issuer: &x509_cert::Certificate, reservation: &CrlReservation) -> Result<Vec<u8>, CrlError>` (DER; issuer name and SKI taken from `issuer`; entries sorted by serial bytes; profile from Global Constraints; `invalidityDate` OID 2.5.29.24 and `ExpiredCertsOnCRL` OID 2.5.29.60 encoded as `GeneralizedTime` extension values)
  - `pub struct LabCrlAssembler;` implementing `CrlAssembler` (Task 5 trait): wraps TBS + `ecdsa-with-SHA256` + signature into `CertificateList` DER.
  - `pub struct LabCrlVerifier { issuer: Certificate }` with `pub fn new(issuer: Certificate) -> Self`, implementing `CrlVerifier` (Task 5 trait) with every check of spec §4 step 5.

Task 5 defines the `CrlAssembler`/`CrlVerifier` traits; to keep this task independently testable, define both traits in `crl.rs` now and have Task 5 import them.

  - `pub trait CrlAssembler { fn assemble(&self, tbs_der: &[u8], signature: &[u8]) -> Result<Vec<u8>, CrlError>; }`
  - `pub trait CrlVerifier { fn verify(&self, reservation: &CrlReservation, crl_der: &[u8]) -> Result<(), CrlError>; }`

- [ ] **Step 1: Write failing tests** (in `crl.rs` test module, `lab-software` feature, using `EphemeralLabCa::new("Sovereign Trust Lab Root")` and signing the TBS with its `ExternalSigner` impl):
  - `rfc5280_time_switches_at_2050`: 2049-12-31T23:59:59Z → `Time::UtcTime`; 2050-01-01T00:00:00Z → `Time::GeneralTime`; 9999-12-31T23:59:59Z → `GeneralTime`.
  - `empty_crl_has_no_revoked_list_and_verifies`: reservation number 1, no entries → `tbs_cert_list.revoked_certificates` is `None`, version V2, verifier accepts.
  - `entries_are_sorted_and_reason_rules_hold`: entries given as serials `[\x03, \x01]` with reasons Unspecified and KeyCompromise and one invalidity date → DER order `\x01, \x03`; the Unspecified entry has no `reasonCode` extension; the KeyCompromise entry has `reasonCode = 1` and `invalidityDate`.
  - `crl_extensions_are_aki_and_number`: AKI key id equals the root's SKI; CRL Number decodes to 1; no other CRL extension unless `expired_certs_on_crl_since_unix` is set, in which case OID 2.5.29.60 is present.
  - Verifier rejections, each `Err(CrlError::VerificationFailure)`: signature by a second `EphemeralLabCa`; issuer name altered; AKI altered; `crl_number` differs from reservation; `this_update`/`next_update` differ; an entry added, removed, or with another reason; version V1; trailing bytes after the DER.
- [ ] **Step 2: Run** `cargo test -p trust-pki-core --features lab-software --lib crl --locked`. Expected: FAIL.
- [ ] **Step 3: Implement** the items above. The verifier decodes with `CertificateList::from_der`, re-encodes and compares to the input (rejects non-canonical DER), extracts the SEC1 key from the issuer SPKI and calls `verify_p256_ecdsa_sha256` over the re-encoded TBS.
- [ ] **Step 4: Run** the tests and clippy (all features). Expected: PASS.
- [ ] **Step 5: Commit** `feat(core): CRL v2 encoding and independent lab verification`.

---

### Task 5: `crl_once` orchestrator

**Files:**
- Create: `crates/pki-core/src/crl_orchestrator.rs`
- Modify: `crates/pki-core/src/lib.rs`

**Interfaces:**
- Consumes: `crl::{CrlError, CrlReservation, CrlAssembler, CrlVerifier}`, `orchestrator::ExternalSigner`.
- Produces:
  - `pub struct CrlPlan<'a> { pub reservation: &'a CrlReservation, pub signer_key_ref: &'a str, pub operation_ref: &'a str, pub tbs_der: &'a [u8] }`
  - `pub trait CrlJournal { fn record_intent(&mut self, plan: &CrlPlan<'_>, tbs_sha256: &[u8; 32]) -> Result<(), CrlError>; fn mark_uncertain(&mut self, plan: &CrlPlan<'_>) -> Result<(), CrlError>; fn persist_verified(&mut self, plan: &CrlPlan<'_>, tbs_sha256: &[u8; 32], crl_sha256: &[u8; 32], crl_der: &[u8]) -> Result<(), CrlError>; }`
  - `pub fn crl_once<J: CrlJournal, S: ExternalSigner, A: CrlAssembler, V: CrlVerifier>(journal: &mut J, signer: &mut S, assembler: &A, verifier: &V, plan: &CrlPlan<'_>) -> Result<Vec<u8>, CrlError>`

Same control flow as `issue_once`: reject empty TBS/operation; record intent (no signer call on error); sign once (`IssueError` → `SigningFailure`); assemble; verify; persist; every failure after the intent calls `mark_uncertain` best-effort and returns the specific error.

- [ ] **Step 1: Write failing tests** with in-file doubles (a `Vec`-backed journal recording calls, a counting signer, assemblers/verifiers that fail on demand):
  - `never_signs_without_intent`: journal refuses intent → `Err(JournalFailure)`, signer call count 0.
  - `each_failure_after_intent_marks_uncertain`: signer, assembler, verifier and persistence failures each return their error and leave exactly one `mark_uncertain` call.
  - `success_signs_once_and_persists_verified_bytes`: signer count 1, persisted DER equals returned DER, `crl_sha256 = SHA-256(DER)`.
  - `empty_tbs_or_operation_is_rejected_before_journal`.
- [ ] **Step 2: Run** `cargo test -p trust-pki-core --lib crl_orchestrator --locked`. Expected: FAIL.
- [ ] **Step 3: Implement** `crl_once`.
- [ ] **Step 4: Run** tests + clippy. Expected: PASS.
- [ ] **Step 5: Commit** `feat(core): crl_once orchestrator with intent-before-sign`.

---

### Task 6: PostgreSQL adapter for status changes and CRL journal

**Files:**
- Create: `crates/pki-core/src/revocation_store.rs` (`#[cfg(feature = "postgres-store")]`)
- Create: `crates/pki-core/tests/revocation_crl_postgres.rs` (`#![cfg(all(feature = "postgres-store", feature = "lab-software"))]`)
- Modify: `crates/pki-core/src/lib.rs`, `.github/workflows/rust-ci.yml` (schema job: run the new test with `TRUST_REQUIRE_DATABASE=1` and `TRUST_CI_DATABASE_URL`)

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces:
  - `pub enum RevocationStoreError { Database(postgres::Error), Denied(StatusChangeError), InconsistentResult }`
  - `pub struct PgRevocationStore` with `pub fn connect_lab(conn_str: &str) -> Result<Self, RevocationStoreError>` (NoTls, same caveat comment as `PgIssuanceStore::connect_lab`)
  - `pub fn status(&mut self, ca_id: &str, serial: &SerialNumber) -> Result<CertificateStatus, RevocationStoreError>`
  - `pub fn propose(&mut self, ca_id: &str, serial: &SerialNumber, action: StatusAction, reason: Option<RevocationReason>, invalidity_at_unix: Option<i64>, maker: &OfficerIdentity<'_>) -> Result<String, RevocationStoreError>` — reads status and `suspension_allowed`, calls `decide_status_change`, then the SQL function; returns the change id.
  - `pub fn approve(&mut self, change_id: &str, checker: &OfficerIdentity<'_>, expected_action: StatusAction, expected_reason: Option<RevocationReason>) -> Result<(), RevocationStoreError>`; `pub fn reject(...)`, `pub fn withdraw(...)` with the SQL signatures of Task 1.
  - `pub fn reserve_crl(&mut self, ca_id: &str, actor: &str, operation_ref: &str) -> Result<CrlReservation, RevocationStoreError>` (calls `reserve_crl` then `crl_snapshot_entries`)
  - `pub fn quarantine_stale_crl_intents(&mut self, ca_id: &str, older_than_seconds: i64) -> Result<i32, RevocationStoreError>`
  - `impl CrlJournal for PgRevocationStore` (maps any database error to `CrlError::JournalFailure` / `PersistenceFailure`, a replayed intent to `ReplayedOrAmbiguousIntent`).

- [ ] **Step 1: Write the failing integration test** `revocation_crl_postgres.rs`, guarded like `lab_verified_issuance.rs` (`TRUST_REQUIRE_DATABASE=1` makes a missing URL fail). Fresh CA id per run (`uuid` from `pg gen_random_uuid()` inserted as owner) with `suspension_allowed = true` and grants for `maker`/`checker`. Issue three certificates through the existing `issue_once` flow (reuse the `context()` setup pattern of `lab_verified_issuance.rs`, idempotency keys `crl-<n>`), keeping one `EphemeralLabCa` for the whole test. Then:
  - revoke #1 (`KeyCompromise`), suspend #2, leave #3; `status` returns `Revoked`, `Suspended`, `Valid`.
  - `reserve_crl` → `build_tbs_cert_list` → `crl_once` with `LabCrlVerifier::new(root)`: CRL 1 has number 1 and entries #1 (reason 1) and #2 (reason 6); a separate `postgres::Client` reads back the same DER with status `STORED`.
  - release #2; CRL 2 has number 2 and only #1.
  - `crl_once` replay with CRL 2's plan → `Err(ReplayedOrAmbiguousIntent)`, signer not called (wrap the CA in a counting `ExternalSigner`).
  - a plan whose verifier rejects (`LabCrlVerifier` built from a different CA) → `Err(VerificationFailure)` and the row is `RECONCILIATION_REQUIRED`; the next reservation gets number 4.
  - `propose` of `Revoke` on #1 → `Err(Denied(TerminalState))` without any SQL call reaching the database (assert the `certificate_status_change` row count is unchanged).
  - `approve` by the maker → `Err(Database(_))` with SQLSTATE `23514`.
- [ ] **Step 2: Run** `TRUST_REQUIRE_DATABASE=1 TRUST_CI_DATABASE_URL=... cargo test -p trust-pki-core --test revocation_crl_postgres --features postgres-store,lab-software --locked`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement** `revocation_store.rs`.
- [ ] **Step 4: Run** the same command against PostgreSQL 16 with 0001–0015. Expected: PASS. Also run `TRUST_REQUIRE_DATABASE=1` without the URL and confirm it fails.
- [ ] **Step 5: Wire CI and commit** `feat(core): PostgreSQL revocation store and CRL journal`.

---

### Task 7: Lab example and OpenSSL interoperability

**Files:**
- Create: `crates/pki-core/examples/issue_crl_lab.rs` (`required-features = ["lab-software"]` in `crates/pki-core/Cargo.toml`)
- Create: `tests/crl_openssl_lab.sh`
- Modify: `crates/pki-core/Cargo.toml`, `.github/workflows/rust-ci.yml` (rust job)

**Interfaces:**
- Consumes: `EphemeralLabCa`, `crl::*`, `crl_orchestrator::crl_once`.
- Produces: `cargo run -p trust-pki-core --features lab-software --example issue_crl_lab -- <out-dir>` writing `root.der`, `leaf1.der`, `leaf2.der`, `leaf3.der`, `crl1.der`, `crl2.der`. Uses an in-memory `CrlJournal` and in-memory reservations (this example proves CRL format interop only; maker-checker and durability are proven by Tasks 1, 2 and 6). Scenario mirrors Task 6: CRL 1 = {#1 keyCompromise, #2 certificateHold}, CRL 2 = {#1}.

- [ ] **Step 1: Write the failing script** `tests/crl_openssl_lab.sh` (`set -euo pipefail`): run the example into `$RUNNER_TEMP`/`mktemp -d`; convert DER to PEM; assert:
  - `openssl crl -inform DER -in crl1.der -CAfile root.pem -noout` prints `verify OK` (also for `crl2.der`);
  - `openssl crl -text` of `crl1.der` shows `X509v3 CRL Number:` `1`, `Key Compromise` and `Certificate Hold`;
  - `openssl verify -crl_check -CAfile root.pem -CRLfile crl1.pem leaf1.pem` fails with `certificate revoked`; same for `leaf2.pem`; `leaf3.pem` → `OK`;
  - with `crl2.pem`: `leaf1.pem` revoked, `leaf2.pem` → `OK`.
  - Print `PASS: OpenSSL accepts lab CRLs and enforces revocation and released holds`.
- [ ] **Step 2: Run** `bash tests/crl_openssl_lab.sh`. Expected: FAIL (example missing).
- [ ] **Step 3: Implement** the example (leaves via `issue_leaf` with the existing P-256 fixture CSR from `crates/pki-core/tests/fixtures/ecdsa-p256-request.pem`, serials `\x01..\x03`).
- [ ] **Step 4: Run** the script. Expected: the PASS line.
- [ ] **Step 5: Add a rust-job step** "CRL issuance verified by OpenSSL (lab only)" running the script; commit `test(interop): lab CRLs verified and enforced by OpenSSL`.

---

### Task 8: Fuzz target, documentation and mutation evidence

**Files:**
- Create: `fuzz/fuzz_targets/crl_verify.rs`
- Modify: `fuzz/Cargo.toml`, `fuzz/seed-corpus.sh`, `fuzz/README.md`, `.github/workflows/fuzz.yml` (matrix), `docs/architecture/unintegrated-contracts.md`, `README.md`, `docs/architecture/issuance-state-machine.md` (link the revocation lifecycle), `ROADMAP.md` (status line for this slice, lab only)

- [ ] **Step 1: Fuzz target** `crl_verify`: build one `EphemeralLabCa` once (`std::sync::OnceLock`), then for each input call `LabCrlVerifier::verify` with a fixed reservation (number 1, empty entries); must not panic. Seed corpus: an OpenSSL-generated CRL (`openssl ca -gencrl` with a throwaway config) added to `seed-corpus.sh`.
- [ ] **Step 2: Run** `cargo +nightly-2026-10-17 fuzz run crl_verify corpus/crl_verify -- -max_total_time=60`. Expected: `Done N runs`, no crash.
- [ ] **Step 3: Mutation evidence.** For each guard, temporarily break it, run the named test, record the failing output, restore:
  - maker ≠ checker check in `approve_certificate_status_change` → `tests/revocation_lifecycle.sql` fails;
  - irreversibility trigger on `revocation` → `tests/revocation_lifecycle.sql` fails;
  - reason 8 acceptance in `RevocationReason::from_code` → `reason_codes_round_trip_and_reject_7_8_and_out_of_range` fails;
  - verifier entry comparison removed → `LabCrlVerifier` entry-alteration test fails;
  - `record_intent` call skipped in `crl_once` → `never_signs_without_intent` fails.
- [ ] **Step 4: Documentation.** Mark `revocation_policy` integrated in `unintegrated-contracts.md` (15 remaining); README and ROADMAP: revocation/CRL lab slice with its limits (no publication, no OCSP, ephemeral key); state machine doc: link the spec.
- [ ] **Step 5: Full verification and commit.** Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-targets --all-features --locked`, the strict DB tests, the SQL tests, `bash tests/crl_openssl_lab.sh`, `cargo deny check`, `python3 scripts/ci/lockfile_sbom.py --check`. Record results (commit SHA, toolchain, features) in the commit message. Commit `test(fuzz): CRL verifier fuzzing; docs for revocation slice`.
