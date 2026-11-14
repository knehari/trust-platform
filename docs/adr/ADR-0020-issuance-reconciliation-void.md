# ADR-0020 — Reconciling an ambiguous application issuance by voiding its serial

**Status:** Proposed · 2026-11-09. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0034;
- two API routes;
- the console's requests view;
- the laboratory end-to-end suite.

**Roadmap:** closes the "reconciliation tooling for applications" gap left
open by ADR-0017. It does not complete MVP criterion 7. Recovering a
certificate that was signed but not stored remains open.

**Laboratory only.** The signer is the software-key laboratory signer of
ADR-0017. Nothing here is a production disposition procedure.

## Context

ADR-0017 marks an issuance `RECONCILIATION_REQUIRED` when the signer
refused, failed, timed out or returned a certificate that does not verify.
The core never re-signs such a request (migration 0003), and its request
state has no way out. The application stays blocked: the requester cannot
obtain a certificate, and the reserved serial may or may not exist in a
signed certificate somewhere. The owner observed this state in the
laboratory.

The signer claims an intent in the database, once, **before** it signs
(`lab_signer_claim`, migration 0030):
- no claim means the signer never started signing that intent;
- a claim means a certificate with the reserved serial may exist.

The owner chose (decision of 2026-11-09) reconciliation as the next slice.

## Decision

1. **Void under dual control.** Two registration officers of the CA close
   an ambiguous issuance. Neither may be the application's requester.
   - **Proposal**
     (`POST /v1/cas/{ca_id}/certificate-applications/{id}/void-proposal`,
     body `{ "reason": … }`). The application's issuance must be
     `RECONCILIATION_REQUIRED`. The proposal records:
     - the reserved serial;
     - whether the signer had claimed the intent (`signer_claimed`);
     - the reason and the proposer.

     There is one proposal per application.
   - **Confirmation**
     (`POST …/void-confirmation`, body `{ "reason": … }`). A different
     officer confirms, once. Confirmation takes the CA's CRL lock and
     records the instant with `clock_timestamp()`, as an approved
     revocation does (ADR-0018). A CRL intent fixed earlier never lists the
     serial; one fixed later always does.
   - Both steps are idempotent (`Idempotency-Key`). Each writes an
     application event and an audit event:
     `certificate.application.void_proposed`, then
     `certificate.application.voided`.
2. **The voided serial is listed on every later CRL**, without a reason
   code (unspecified). This holds whether or not the signer had claimed
   the intent. Listing a serial that was never signed is harmless; leaving
   a signed one unlisted is not. The core certificate and revocation
   tables are not touched: no certificate row exists for that serial. The
   CRL entry functions read voided serials beside revocations
   (`crl_intent_entries`, `lab_signer_crl_entry`). The API, the signer and
   the audit tool therefore build and check the same list.
3. **The serial is never reused.** It stays reserved for the voided
   request, whose core state stays `RECONCILIATION_REQUIRED`: the history
   is not rewritten.
4. **The application becomes `VOIDED`**, which is final. The requester
   submits a new application to obtain a certificate. A new issuance uses
   a new request and a new serial.
5. **Readers** see:
   - the status;
   - whether a proposal exists and whether they made it;
   - whether the signer had claimed the intent;
   - the voided serial and its instant.

   They never see the other officer's identity.

## Alternatives considered

- **Recover the certificate.** An officer would submit the DER the signer
  produced, which the API verifies against the journaled TBS digest and the
  CA key before storing it. The laboratory signer keeps no output, so there
  is nothing to recover yet. This also needs a new core transition out of
  `RECONCILIATION_REQUIRED`. It is deferred.
- **Re-sign with the same serial.** Refused: it breaks the sign-once rule,
  and two different certificates could carry one serial.
- **Void without CRL listing when the signer never claimed.** This relies
  on the signer having followed the protocol. Listing costs one CRL entry.

## Consequences and open risks

- A voided serial appears on CRLs even if no certificate was ever signed.
- There is no withdrawal or rejection of a proposal. A wrong proposal
  simply stays unconfirmed.
- Decisions are authenticated sessions, not signed claims (as in ADR-0018).
- CRL intents left `RECONCILIATION_REQUIRED` are still only superseded by
  the next number (ADR-0018). They are not reconciled here.
- No HSM, no production custody (ADR-0017).

## Tests

- `tests/management_application_void.sql`:
  - refusals: wrong role, the requester, a state other than
    `RECONCILIATION_REQUIRED`, the proposer confirming, a second proposal
    or confirmation;
  - idempotent replay, and a key reused for another request;
  - `signer_claimed` with and without a claim;
  - the VOIDED status;
  - the serial listed only by CRL intents fixed after confirmation;
  - reader isolation.
- Certificate-application e2e: a wrong-key signer makes the issuance
  ambiguous. Two officers then void it, and the next CRL lists the serial.
  OpenSSL verifies that CRL.
