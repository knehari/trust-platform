# Revocation, suspension and CRL — design (laboratory slice)

Status: design approved in conversation on 2026-10-18; revised the same day
after an ETSI EN 319 411-1 review (section 2.1); pending written-spec review.
Laboratory only: no production, qualification or G0 claim.

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
4. Every state change made through the provided functions needed two
   distinct authorized actors and left an audit trail; a definitive revocation
   cannot be undone by any function or direct `UPDATE`/`DELETE` on the
   current-state table (see section 6 for direct writes).

Out of scope for this slice: OCSP, delta CRLs, HTTP distribution and the CRL
Distribution Points extension, CRL reads through the management API, non-P-256
issuers, durable CA keys (HSM slice), and a scheduler that produces CRLs
automatically (section 2.1 provides the due/overdue queries it would use).

## 2. Standards decisions

| Topic | Decision | Basis |
| --- | --- | --- |
| Suspension | Supported as revocation with reason `certificateHold` (6), the only reversible reason. Disabled per CA by default (`suspension_allowed = false`). Must be declared in the CA's CP/CPS before enabling. Must stay disabled for any CA issuing publicly trusted TLS. | RFC 5280 §5.3.1; CA/Browser Forum Baseline Requirements §4.9.13 forbid suspension for public TLS; ETSI EN 319 411-1 permits it when documented. |
| Release of a hold | The entry is simply absent from the next full CRL. `removeFromCRL` (8) is rejected because there are no delta CRLs. | RFC 5280 §5.3.1. |
| Hold → definitive revocation | Allowed. The reason changes (e.g. to `keyCompromise`); the original revocation date is kept. | RFC 5280 §5.3.1; OpenSSL `ca` behaviour. |
| Undoing a definitive revocation | Not supported and blocked in the database, whatever the conformance target. Errors are corrected before approval (reject or withdraw), by suspending first when in doubt, or by reissuing a new certificate. | RFC 5280 defines no reversal for reasons other than hold; ETSI EN 319 411-1 REV-6.3.9-04: "Once a certificate is definitively revoked (i.e. not suspended) it shall not be reinstated." |
| Accepted reasons | 0 unspecified, 1 keyCompromise, 2 cACompromise, 3 affiliationChanged, 4 superseded, 5 cessationOfOperation, 6 certificateHold (only for SUSPEND, only if allowed), 9 privilegeWithdrawn, 10 aACompromise. 7 does not exist; 8 is rejected. | RFC 5280 §5.3.1. |
| CRL profile | v2; issuer = CA subject (exact DER); signature algorithm = CA's; `thisUpdate`/`nextUpdate` (UTCTime through 2049, GeneralizedTime from 2050, as RFC 5280 §5.1.2.4 requires); CRL extensions Authority Key Identifier (= CA SKI) and CRL Number; per entry `reasonCode` (omitted for unspecified) and `invalidityDate` when set; no Issuing Distribution Point (full CRL for all certificates); `revokedCertificates` omitted when empty. | RFC 5280 §5.1–5.3. |

### 2.1 Conformance targets (flexible ETSI alignment)

Organisations choose per CA whether to align with ETSI. The core always
enforces RFC 5280 and the irreversibility of definitive revocation; an ETSI
target adds database-enforced limits on top. Requirement IDs below come from
EN 319 411-1 V1.1.1–V1.5.1 (2025-04) and EN 319 411-2 V2.6.1 as reported by
public copies; they were not re-read from the official PDF in this
environment (etsi.org unreachable) and must be checked against the edition an
assessment uses, since numbering changes between editions.

`ca_revocation_policy.conformance_target` takes one of:

| Target | Meaning | Enforced settings |
| --- | --- | --- |
| `RFC5280` (default) | Private PKI with no ETSI claim. | Any values within the generic bounds below. |
| `ETSI_EN_319_411_1` | Intends EN 319 411-1 alignment (not a certification). | `crl_issue_interval <= 24 hours` (CSS-6.3.9-05, CRLs covering end-user certificates published at least every 24 h); `status_publication_deadline <= 24 hours` (REV-6.2.4-03A, at most 24 h from receipt of a revocation or suspension request to the status change being available to relying parties). Suspension may be enabled only together with a CP/CPS reference recorded in `suspension_cps_ref`. |
| `ETSI_EN_319_411_2` | As above, for qualified certificates. | As 411-1, plus status kept beyond expiry: `keep_expired_on_crl = true` and the CRL carries the X.509 `ExpiredCertsOnCRL` extension (EN 319 411-2 CSS-6.3.10-06). |

Settings (`ca_revocation_policy`, one row per CA, defaults when absent):

| Column | Default | Generic bounds | Meaning |
| --- | --- | --- | --- |
| `suspension_allowed` | false | — | Enables SUSPEND/RELEASE. |
| `suspension_cps_ref` | NULL | 1–256 chars | CP/CPS section declaring suspension; required when an ETSI target enables suspension. |
| `crl_validity` | 7 days | 1 hour – 90 days | `nextUpdate − thisUpdate`. Must be ≥ `crl_issue_interval`. |
| `crl_issue_interval` | 24 hours | 1 hour – 7 days | Maximum time between two stored CRLs. |
| `status_publication_deadline` | 24 hours | 1 hour – 7 days | Maximum time from proposal (request receipt) to a stored CRL reflecting the approved change. |
| `keep_expired_on_crl` | true | — | Fixed to true in this slice; pruning needs the certificate's notAfter persisted and is a follow-up. |

Requirements already met by the design for every target: status covers
certificates at least until expiry (CSS-6.3.10-04, entries are kept); status
information is signed (integrity and authenticity, CSS-6.3.10-03); every CRL
states `nextUpdate`; revocation requests are authenticated and authorised
(REV-6.2.4) through officer grants and maker-checker.

Deadline evidence without a scheduler (lab): `crl_due(ca)` returns whether a
CRL must be produced now (no stored CRL, last stored CRL older than
`crl_issue_interval`, or an approved change not yet covered by a stored CRL),
and `overdue_status_changes(ca)` lists proposals and approved changes whose
request time plus `status_publication_deadline` has passed without a covering
stored CRL. Maker-checker adds latency, so organisations with an ETSI target
must staff checkers to meet 24 h and describe the exception procedure for
requests that cannot be confirmed in time in their CPS (REV-6.2.4).

Not covered here and still required for an ETSI claim: publication to relying
parties (a stored CRL is not a published one), 24/7 availability of revocation
and status services, the subscriber's own revocation channel, the final CRL
with `nextUpdate = 99991231235959Z` on CA termination, OCSP, and for qualified
certificates the eIDAS rules on registering revocation within 24 hours and on
indicating suspension periods (Regulation (EU) No 910/2014 as amended,
Articles 24 and 28).

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

- `ca_revocation_policy (ca_id PK → ca, conformance_target, suspension_allowed,
  suspension_cps_ref, crl_validity, crl_issue_interval,
  status_publication_deadline, keep_expired_on_crl)` with the defaults and
  bounds of section 2.1; table CHECKs enforce the generic bounds and the
  stricter limits of the chosen `conformance_target`. A CA without a row uses
  the defaults with target `RFC5280`.
- `revocation_officer_grant (issuer, subject, ca_id → ca, PK all three)`;
  server-managed like `management_reader_grant`, no API write path.
- `certificate_status_change` (append-only history):
  `change_id UUID PK`, `ca_id`, `serial_der_content` (FK → certificate),
  `action` in `SUSPEND | RELEASE | REVOKE`, `reason_code SMALLINT` (NULL only
  for RELEASE), `invalidity_at TIMESTAMPTZ NULL` (1970-01-01 .. 9999-12-31,
  not after `proposed_at` / `decided_at`; the functions refuse other dates
  with 22023, so every CRL can encode it), `maker_issuer`,
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
`certificateHold` can be constructed like any other reason, but
`decide_status_change` accepts it only for a suspension and rejects it for a
revocation, and the database re-checks the same rule), `StatusAction`,
`OfficerIdentity { issuer, subject }`, and a PostgreSQL adapter behind the
`postgres-store` feature calling the functions above.

The existing `revocation_policy` module is **reused, not deleted**: it becomes
the pure decision layer, `decide_status_change(current_state, action, reason,
ca_policy) -> Result<Transition, StatusChangeError>`, which the adapter calls
before any SQL (defence in depth; SQL re-checks everything). Its historical
contents (`authorize_revocation`, `RevocationError` and their test) stay in the
file verbatim, marked `#[deprecated]` and called by nothing, because the
recovery inventory (`docs/recovery/RECOVERY_PLAN.md`, CI job `preservation`)
preserves every historical public name and test. New code must not use them,
because they conflict with this design: `authorize_revocation` accepts
`removeFromCRL` (8) and `certificateHold` (6) without a suspension context,
treats a caller-supplied `authorized: bool` as authorisation, and checks
serial format more weakly than the database (it accepts non-minimal and
all-zero encodings); serial validation moves to the existing
`serial::ReservedSerial` type. `docs/architecture/unintegrated-contracts.md` is
updated to mark the module integrated.

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
   rows into `crl_entry_snapshot` (no pruning in this slice: `keep_expired_on_crl`
   is fixed to true) and returns number and times. `entries_sha256` is the
   SHA-256 of the entries in serial order, each encoded by
   `crl_entry_encoding` (`int4send(len) || serial || int8send(floor(epoch
   revoked_at)) || int2send(reason) || int8send(floor(epoch invalidity_at)
   or -1)`).
2. **Build** — `crl_once` itself builds the `TBSCertList` deterministically
   from the reservation and the trusted issuer certificate in `CrlPlan`
   (entries sorted by serial). Callers cannot supply TBS bytes, so the
   journaled and signed bytes always match the reservation. Before the
   intent, `crl_once` also refuses an empty signer key reference and a
   verifier whose issuer certificate differs from the plan's
   (`CrlError::IssuerMismatch`). The issuer must
   carry exactly one keyUsage with cRLSign (an absent keyUsage is refused),
   exactly one non-empty subjectKeyIdentifier (copied into the AKI, never
   recomputed) and an id-ecPublicKey key on the named curve P-256; otherwise
   the build fails before any intent or signature.
3. **Intent** — `record_crl_intent(ca, crl_number, operation_ref, tbs_sha256,
   entries_sha256, this_update, next_update, expired_certs_on_crl_since)`; the
   CA core computes `entries_sha256` in Rust from the reservation it signs
   (`crl::entries_sha256`, same layout as `crl_entry_encoding`) and the
   database refuses (23514) a replay, a mismatched number, or any difference
   between these values and the reservation, so the signer is not called.
   `CrlReservation` is sealed (private fields, validated constructor), so a
   reservation cannot be edited between reserve and sign.
4. **Sign** once.
5. **Verify independently before persistence** — signature with the CA
   certificate's public key; issuer equals the CA subject byte for byte; AKI
   equals the CA SKI; version 2; number and times equal the reservation;
   entries exactly equal the snapshot (serial, date, reason, invalidity date);
   `ExpiredCertsOnCRL` present exactly when the target is
   `ETSI_EN_319_411_2`.
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
- **Conformance targets** (SQL): an ETSI target rejects `crl_issue_interval`
  or `status_publication_deadline` above 24 h and suspension without
  `suspension_cps_ref`; `RFC5280` accepts them within generic bounds;
  `crl_due` and `overdue_status_changes` report the right rows before and
  after a covering CRL is stored.
- **Concurrency** (`tests/crl_concurrency.sh`): 12 concurrent `reserve_crl`
  callers on one CA get 12 distinct consecutive numbers.
- **Rust unit tests**: reason enum rejects 6/8 outside their contexts and
  unknown values; `revocation_policy::decide_status_change` covers every
  state × action × reason × suspension setting combination; `crl_once` never signs without an intent; every failure
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
- The SQL functions are `SECURITY INVOKER`, so any role able to call them needs
  DML on `revocation` and `certificate_status_change` and could bypass
  maker-checker with direct writes (the guard triggers and CHECKs still hold,
  the two-actor rule does not); the least-privilege write model is deferred to
  the API slice and proposed in ADR-0006.
- Maker-checker compares textual `(issuer, subject)` identities only. `AGENTS.md`
  requires cryptographically distinct signer keys as well; this slice does not
  meet that requirement (known deviation). ADR-0006 proposes signed claims
  verified by the Rust core with `verify_dual_approval`.
- An ETSI conformance target is a configuration guard, not evidence of
  conformity; only an assessment by a conformity assessment body can establish
  that.
