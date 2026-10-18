# Revocation, suspension and CRL — design (laboratory slice)

Status: design approved in conversation on 2026-10-18; pending written-spec
review. Laboratory only: no production, qualification or G0 claim.

## 1. Goal and success criteria

Close the most blocking gap for calling the lab CA a CA: a certificate that the
CA issued can be suspended, released or revoked under maker-checker control,
and the CA produces a signed, monotonically numbered, independently verified
and durably stored **full CRL** that OpenSSL accepts.

Success means, in CI and locally:

1. A certificate revoked with `keyCompromise` fails `openssl verify -crl_check`
   with "certificate revoked" against the CA's latest CRL.
2. A suspended certificate fails the same check; after its suspension is
   released, the next CRL no longer lists it and verification succeeds.
3. CRL numbers are strictly increasing per CA and never reused, including after
   an ambiguous signing attempt or a crash.
4. Every state change needed two distinct authorized actors and left an audit
   trail; a definitive revocation cannot be undone by any function or direct
   `UPDATE`/`DELETE` on the current-state table.

Out of scope for this slice: OCSP, delta CRLs, HTTP distribution and the CRL
Distribution Points extension, CRL reads through the management API, non-P-256
issuers, pruning expired entries, durable CA keys (HSM slice).

## 2. Standards decisions

| Topic | Decision | Basis |
| --- | --- | --- |
| Suspension | Supported as revocation with reason `certificateHold` (6), the only reversible reason. Disabled per CA by default (`suspension_allowed = false`). Must be declared in the CA's CP/CPS before enabling. Must stay disabled for any CA issuing publicly trusted TLS. | RFC 5280 §5.3.1; CA/Browser Forum Baseline Requirements §4.9.13 forbid suspension for public TLS; ETSI EN 319 411-1 permits it when documented. |
| Release of a hold | The entry is simply absent from the next full CRL. `removeFromCRL` (8) is rejected because there are no delta CRLs. | RFC 5280 §5.3.1. |
| Hold → definitive revocation | Allowed. The reason changes (e.g. to `keyCompromise`); the original revocation date is kept. | RFC 5280 §5.3.1; OpenSSL `ca` behaviour. |
| Undoing a definitive revocation | Not supported and blocked in the database. Errors are corrected before approval (reject or withdraw), by suspending first when in doubt, or by reissuing a new certificate. | RFC 5280 defines no reversal for reasons other than hold; ETSI EN 319 411-1 forbids reinstating a definitively revoked certificate (clause number to confirm during review). |
| Accepted reasons | 0 unspecified, 1 keyCompromise, 2 cACompromise, 3 affiliationChanged, 4 superseded, 5 cessationOfOperation, 6 certificateHold (only for SUSPEND, only if allowed), 9 privilegeWithdrawn, 10 aACompromise. 7 does not exist; 8 is rejected. | RFC 5280 §5.3.1. |
| CRL profile | v2; issuer = CA subject (exact DER); signature algorithm = CA's; `thisUpdate`/`nextUpdate` (UTCTime before 2050); CRL extensions Authority Key Identifier (= CA SKI) and CRL Number; per entry `reasonCode` (omitted for unspecified) and `invalidityDate` when set; no Issuing Distribution Point (full CRL for all certificates); `revokedCertificates` omitted when empty. | RFC 5280 §5.1–5.3. |

## 3. Certificate status lifecycle (maker-checker)

States: `VALID → SUSPENDED → VALID` (release), `VALID → REVOKED`,
`SUSPENDED → REVOKED`. `REVOKED` is terminal.

Every transition is a **proposal** by one actor and an **approval** by a second
actor. A proposal can be rejected by a checker or withdrawn by its maker while
it is still `PROPOSED`. Only one open proposal per certificate.

Actors are issuer-qualified identities `(issuer, subject)` supplied by the
trusted identity adapter, as in the management API. The core does not
authenticate them; it enforces that maker and checker are different
`(issuer, subject)` pairs and that both hold a revocation-officer grant for the
CA at the time they act. Two accounts held by one person are an IdP concern.

### Data model — migration `0014_revocation_lifecycle.sql`

- `ca_revocation_policy (ca_id PK → ca, suspension_allowed BOOLEAN NOT NULL
  DEFAULT false, crl_validity INTERVAL NOT NULL DEFAULT '7 days'
  CHECK (crl_validity BETWEEN '1 hour' AND '90 days'))`. A CA without a row
  uses the defaults.
- `revocation_officer_grant (issuer, subject, ca_id → ca, PK all three)`;
  server-managed like `management_reader_grant`, no API write path.
- `certificate_status_change` (append-only history):
  `change_id UUID PK`, `ca_id`, `serial_der_content` (FK → certificate),
  `action` in `SUSPEND | RELEASE | REVOKE`, `reason_code SMALLINT` (NULL only
  for RELEASE), `invalidity_at TIMESTAMPTZ NULL`, `maker_issuer`,
  `maker_subject`, `checker_issuer NULL`, `checker_subject NULL`,
  `status` in `PROPOSED | APPROVED | REJECTED | WITHDRAWN`, `proposed_at`,
  `decided_at NULL`. Partial unique index: one `PROPOSED` row per
  `(ca_id, serial_der_content)`. CHECKs tie `status` to the presence of
  checker/decided fields and require checker ≠ maker. A trigger allows only
  the `PROPOSED → APPROVED | REJECTED | WITHDRAWN` update and no `DELETE`.
- Existing `revocation` table (0001) is the **current state**: one row per
  revoked or suspended certificate. Add `change_id UUID REFERENCES
  certificate_status_change`. A guard trigger enforces irreversibility for any
  caller: `DELETE` only when `reason_code = 6`; `UPDATE` only from
  `reason_code = 6` to a definitive reason, with `revoked_at` unchanged.

### Functions (`EXECUTE` revoked from `PUBLIC`; each writes `audit_event`)

- `propose_certificate_status_change(ca, serial, action, reason, invalidity,
  maker_issuer, maker_subject) → change_id` — locks the certificate row;
  requires the certificate to exist, the maker's grant, an action valid for the
  current state (`SUSPEND`/`REVOKE` from VALID, `RELEASE`/`REVOKE` from
  SUSPENDED), reason rules from §2 and `suspension_allowed` for `SUSPEND`.
- `approve_certificate_status_change(change_id, checker_issuer,
  checker_subject, expected_action, expected_reason)` — re-locks, re-checks the
  state and grants, requires checker ≠ maker and the re-confirmed action and
  reason, then applies: insert `revocation` (SUSPEND/REVOKE from VALID),
  delete the hold row (RELEASE), or update reason keeping `revoked_at`
  (REVOKE from SUSPENDED). `revoked_at` = approval time (database clock).
- `reject_certificate_status_change(change_id, checker_issuer,
  checker_subject)` and `withdraw_certificate_status_change(change_id,
  maker_issuer, maker_subject)`.

### Rust

Module `pki-core::revocation`: `RevocationReason` enum (no free integers;
`certificateHold` only constructible for a suspension), `StatusAction`,
`OfficerIdentity { issuer, subject }`, and a PostgreSQL adapter behind the
`postgres-store` feature calling the functions above. The unused
`revocation_policy` contract module is superseded and removed, and
`docs/architecture/unintegrated-contracts.md` updated.

## 4. CRL pipeline (`crl_once`)

The lab CA key is ephemeral and in memory, so a CRL must be signed in the same
process that issued the certificates (tests and lab examples). Durable CA keys
belong to the HSM slice.

`crl_once` mirrors `issue_once`: it reuses `ExternalSigner` (at most one
signature, only after a durable intent) and adds `CrlJournal`, `CrlAssembler`
and `CrlVerifier` traits.

1. **Reserve** — `reserve_crl(ca, actor, operation_ref)` locks the CA row
   (serialising CRLs per CA), assigns `crl_number = last reserved + 1`, sets
   `this_update = clock_timestamp()` truncated to seconds and
   `next_update = this_update + crl_validity`, copies the current `revocation`
   rows into `crl_entry_snapshot` and returns number, times, entries and the
   SHA-256 of the canonical entry list.
2. **Build** — Rust builds the `TBSCertList` deterministically from the
   reservation (entries sorted by serial).
3. **Intent** — `record_crl_intent(ca, crl_number, operation_ref, tbs_sha256)`;
   a replay or a mismatched number fails and the signer is not called.
4. **Sign** once.
5. **Verify independently before persistence** — signature with the CA
   certificate's public key; issuer equals the CA subject byte for byte; AKI
   equals the CA SKI; version 2; number and times equal the reservation;
   entries exactly equal the snapshot (serial, date, reason, invalidity date).
6. **Store** — `store_verified_crl(ca, crl_number, operation_ref, tbs_sha256,
   crl_sha256, crl_der)` checks the intent and moves the row to `STORED`.

`crl_publication` (0001) gains `status` in `RESERVED | INTENT_RECORDED |
STORED | RECONCILIATION_REQUIRED`, `operation_ref`, `entries_sha256`,
`tbs_sha256`, `crl_der`, `actor_id`; `crl_sha256` becomes nullable with a CHECK
that `STORED` rows have DER and hash. `crl_number` is limited to `< 2^63` so
Rust can use `u64` (well inside RFC 5280's 20-octet limit).

Any failure after the intent marks the row `RECONCILIATION_REQUIRED`; its
number is burnt and the next CRL takes the following number. A
`quarantine_stale_crl_intents(ca, older_than)` function, modelled on 0004,
handles intents left by a crash. No automatic re-sign.

## 5. Testing and evidence

- **SQL** (`tests/revocation_lifecycle.sql`, CI `schema` job): every allowed
  transition; rejections for same maker/checker, missing grant, suspension
  disabled, reasons 6 (outside SUSPEND) and 8, any transition from REVOKED,
  a second open proposal, direct `UPDATE`/`DELETE` on history and on a
  definitive `revocation` row; CRL numbers strictly increasing and never
  reused after `RECONCILIATION_REQUIRED`; `EXECUTE` not granted to `PUBLIC`.
- **Concurrency** (`tests/crl_concurrency.sh`): 12 concurrent `reserve_crl`
  callers on one CA get 12 distinct consecutive numbers.
- **Rust unit tests**: reason enum rejects 6/8 outside their contexts and
  unknown values; `crl_once` never signs without an intent; every failure
  after the intent records uncertainty (injected signer/assembler/verifier
  failures); the verifier rejects another key's signature, a different issuer
  or AKI, a different number or time, an added/removed/altered entry, and v1.
- **Rust + PostgreSQL integration** (strict `TRUST_REQUIRE_DATABASE=1`): issue
  three certificates from a P-256 lab CA; revoke #1 (`keyCompromise`), suspend
  #2, leave #3; CRL 1 lists #1 and #2; release #2; CRL 2 lists only #1 with a
  higher number.
- **OpenSSL interoperability** (`tests/crl_openssl_lab.sh`, CI `rust` job):
  `openssl crl -verify` accepts both CRLs; `openssl verify -crl_check`
  rejects #1 with "certificate revoked", rejects #2 with CRL 1 and accepts it
  with CRL 2, and accepts #3.
- **Mutation evidence** for each security guard (distinct checker, forbidden
  reasons, irreversibility, verify-before-store): removing the guard makes a
  test fail.
- **Fuzzing**: a `crl_verify` target on the CRL verifier.

## 6. Risks and limits

- Actor identities are asserted by the caller; the core enforces distinctness
  and grants, not authentication.
- Lab CA keys are ephemeral; CRLs cannot be produced after the issuing process
  ends. This is a lab limit, not a design choice for production.
- No publication: a stored CRL is not proof that relying parties can fetch it.
- Database owners can bypass triggers; external append-only audit remains an
  open item (D-04).
