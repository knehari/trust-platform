# ADR-0028 — The signer verifies a signed authorization before signing a certificate

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It
answers the main finding of the architecture review of 2026-11-10 and
follows the owner's request of 2026-11-11: the signer must verify
authorization proofs, and the RA must still be able to add an extension or
correct the subject sent in the CSR.

**Scope:**
- migration 0041;
- `trust-pki-core` (`authorization`, `ra_request`, `csr`, `application_leaf`);
- the laboratory signer;
- the API's decision, issuance and RA issuance routes;
- the audit tool `lab_verify_issued_certificates`;
- the console's Requests view;
- the laboratory keys and the end-to-end suites.

**Boundary:** ADR-0024. The CA signs requests that an RA or a registration
officer authorized; identity and domain checks stay with the RA or the CLM.

## Context

Until now the signer (ADR-0017) re-checked the CSR, the TBS and the
profile, then trusted the `APPROVED` state the API wrote. A compromised API
or writer login could therefore:
- approve its own application;
- or insert an approval row;

and the signer would sign. The RA's request (ADR-0025) was signed, but
only the API verified that signature.

## Decision

1. **Every issuance needs a signed authorization** that the signer itself
   verifies, with a key only the database owner registers. There are two
   kinds:
   - **An RA request**, version 1 (ADR-0025) or version 2 (below). It is
     signed by an enabled RA system's key (`ra_system`).
   - **A registration officer's signed approval.** The officer signs the
     claim `trust-platform/issuance-authorization/v1;decision=…;ca=…;
     application=…;profile=…;revision=…;csr_sha256=…;subject_cn=…;
     dns_names=…;validity_days=…;extensions=…;key=…;issued_at=…`, which
     the database builds and `trust_pki_core::authorization` rebuilds. The
     key comes from `registration_officer_key`, one active key per officer,
     owner-registered. A key cannot also be a profile approver, CA approver
     or RA key.
2. **The signer rebuilds the signed bytes** from the intent's facts and the
   application. The facts are: CA, profile and revision, the SHA-256 of the
   stored CSR, the subject, the names, the validity and the optional
   extensions. It reads them from the `lab_signer_authorization` view. It
   then verifies the signature with the registered key. It refuses before
   any claim when:
   - there is no proof, or there are two;
   - the RA is disabled or the officer's key revoked;
   - the decision is a rejection;
   - an extension is outside the catalogue;
   - the signature does not verify (`Unauthorized` or
     `AuthorizationSignature`).
3. **Signed officer decisions.** `POST …/decision-claims` returns the claim
   and records nothing. `POST …/decision` now requires the signature, and the
   API verifies it in the recording transaction (422 and nothing kept). This
   is the profile-decision pattern of ADR-0011. Unsigned decisions are
   refused: an incompatible change of the laboratory API.
4. **The RA may correct the subject and add an extension** (version 2,
   `trust-platform:ra-issuance-request:v2`). The request adds two signed
   fields to version 1:
   - **the subject CN.** It must be one of the names the RA validated,
     whatever the CSR says. The CSR is then checked for proof of possession
     only.
   - **optional extensions**, from a closed catalogue. It holds one entry,
     `client-auth`, which adds the TLS client EKU. The owner must allow it
     per CA and profile in `profile_optional_extension`; otherwise TP422.

   A version 1 request is valid only when the subject is the first name and
   there is no extension.
5. **The subject comes from the authorization, not the CSR.** The signer,
   the API and the audit tool check CSRs for proof of possession and the
   key digest. The requester route still requires the CSR to name the
   common name, so a correction is the RA's to make.
6. **No ambiguous refusal.** Before it reserves a serial, the API checks
   that a proof exists (`application_authorization_present_lab`). Without
   one it answers 409, and nothing is journaled or left to reconcile.
7. **Independent audit.** For every officer decision, the audit tool checks:
   - that the stored claim is the application's;
   - that the recorded key is the registered one, and that it signed;
   - that the decision matches;
   - that the key's officer holds the grant and made the event.

   It also verifies version 2 RA requests. It reports a certificate whose
   intent was journaled after 0041 was applied without a proof.

## Alternatives considered

- **Have the database verify the signatures.** Rejected: PostgreSQL has no
  reviewed ECDSA verifier, and a compromised owner defeats it anyway.
- **Have the signer trust a separate "approved" table it can read.**
  Rejected: a writer that can insert approvals can insert into that table.
- **Allow any CSR subject.** Rejected: the subject must come from someone who
  validated the names. A version 2 request binds it to the RA's key, and an
  officer's approval binds it to the officer's.
- **Arbitrary extensions requested by the RA.** Rejected: copying requested
  extensions is forbidden (AGENTS.md §4). The catalogue is closed, and each
  entry is implemented in `application_leaf`, allowed by the owner and
  tested.

## Consequences and open risks

- **What a compromised API can no longer do:** forge an approval the
  signer accepts. It can still:
  - refuse service;
  - record unsigned approvals. These are never signed, and the e2e suite
    shows such an application stays `APPROVED` with no intent.
- **Revoking an officer's or RA's key** stops further signatures based on
  that key's earlier approvals.
- **A compromised owner login** can still register keys. Separating that
  role is not addressed here.
- **Legacy data.** Applications approved before 0041 without a proof cannot
  be issued afterwards. The audit tool does not report certificates whose
  intent predates 0041, according to the migration ledger.
- **Writer function.** `decide_certificate_application_lab` stays callable
  by the writer, for the earlier SQL suites. The signer is the control.
- **The catalogue holds one extension.** Adding one means changing the
  catalogue, the check constraints, `application_leaf` and the tests.

## Tests

- `crates/pki-core`:
  - the claim builder rejects separators;
  - its output equals the SQL builder's vector;
  - the v2 message vector;
  - `client-auth` leaves.
- `crates/lab-signer`, 17 tests, each refused before any claim:
  - no proof, or two proofs;
  - a wrong key, a revoked key, a rejection;
  - another revision, another instant;
  - a disabled RA, an unknown extension;
  - an extension missing from the TBS;
  - v1 and v2 RA requests;
  - a corrected subject with `client-auth` (accepted in v2, refused in v1).
- `tests/management_authorization_proofs.sql`: officer keys, signed
  decisions, the claim, v2 requests, the extension allow-list, the signer
  view, and isolation.
- The API HTTP tests (63) with the real signer:
  - signed decisions: the claim's contents, another key, another decision,
    a stale claim, the requester;
  - an RA v2 request correcting the subject, with `client-auth` once the
    owner allows it. The certificate's EKU is checked.
- The certificate-application e2e suite:
  - signed decisions through the API;
  - an officer signing in the console;
  - an unsigned approval that is never issued;
  - an RA v2 request whose certificate OpenSSL verifies for both
    `sslserver` and `sslclient`.
