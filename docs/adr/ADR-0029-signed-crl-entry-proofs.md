# ADR-0029 — The signer verifies a signed proof for every CRL entry

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It
completes ADR-0028 for revocation, the other half of the architecture
review's main finding.

**Scope:**
- migration 0042;
- `trust-pki-core::authorization`;
- the laboratory signer's CRL path;
- the API's revocation decision and void confirmation routes;
- the audit tool `lab_verify_issued_certificates`;
- the console's Requests view;
- the end-to-end suite.

## Context

ADR-0028 made the signer verify a signed authorization before it signs a
certificate. A CRL, however, listed every revocation and void the database
held. An officer's approval of a revocation request (migration 0031), and
the second officer's confirmation of a void (migration 0034), were recorded
on the API's word: the acting identity is a parameter. A compromised API or
writer login could therefore revoke any certificate in an officer's name.
That is a denial of service against subscribers, signed by the CA.

RA revocations (ADR-0026) were signed, but only the API checked them.

## Decision

1. **Every CRL entry recorded from now on carries a proof** signed by a key
   only the database owner registers. There are three kinds:
   - an RA's signed revocation (`ra_revocation_message`, ADR-0026), checked
     with the RA's key;
   - a registration officer's signed approval of the revocation request,
     over `trust-platform/revocation-authorization/v1;decision=…;ca=…;
     application=…;revocation=…;serial=<hex>;reason_code=…;key=…;
     issued_at=…`;
   - for a voided serial, the confirming officer's signed claim
     `trust-platform/void-authorization/v1;ca=…;application=…;serial=…;
     signer_claimed=…;key=…;issued_at=…`.

   The free-text reason is not signed. The reason code is, and it is what
   the CRL carries.
2. **The signer checks every entry before it claims the CRL intent.** It
   reads `lab_signer_crl_entry_proof`. It requires exactly one proof per
   listed entry, with the same serial, instant and reason code. It rebuilds
   the claim or RA message from the entry's facts and verifies the
   signature. Otherwise it refuses: `Unauthorized` or
   `AuthorizationSignature`. The API then marks the CRL intent
   `RECONCILIATION_REQUIRED`, as for any refusal.
3. **What is listed is never unlisted.**
   - A key counts if it was active when its claim was issued: revoking an
     officer key later, or disabling an RA, does not remove what it
     authorized.
   - Entries recorded before the requirement (`crl_entry_proof_policy`,
     owner-held and immutable, set when 0042 is applied) were never signed.
     They stay listed and are marked legacy.
4. **Signed routes.**
   - `…/revocation-requests/{id}/decision-claims` and
     `…/void-confirmation-claims` return the claim and record nothing.
   - The decision and confirmation routes require the signature. The API
     verifies it in the recording transaction (422 and nothing kept).
   - Unsigned bodies are refused (400): an incompatible change of the
     laboratory API.
   - The rules of migrations 0031 and 0034 are unchanged: the requester of
     a revocation never decides it, and the proposer of a void never
     confirms it.
5. **Independent audit.** For each officer proof, the audit tool checks:
   - that the stored claim is the request's or the void's;
   - that the registered key signed it;
   - that the decision matches;
   - that the key's officer holds the grant and made the event.

   It reports any revocation or void recorded since the requirement
   without a proof.

## Alternatives considered

- **Let the signer drop unproven entries.** Rejected: a CRL must never
  silently omit a revocation. A refusal is visible: the intent is
  reconciled and the console alerts.
- **Sign the void proposal as well.** Not now. The confirmation is the act
  that lists the serial, and an officer other than the proposer must sign
  it. A forged proposal still needs a real officer's signed confirmation.
  This is noted as a residual risk below.
- **Have the database verify signatures.** Rejected as in ADR-0028.

## Consequences and open risks

- **A compromised API can no longer have the CA sign** a revocation no
  officer or RA signed. It can still record one through the unsigned
  functions. Every later CRL of that CA is then refused, which is visible:
  - the CRL is `RECONCILIATION_REQUIRED`, and the console shows it;
  - the audit tool reports the entry.

  Recovery needs the owner. This trades availability for integrity, on
  purpose.
- **Void proposals are not signed.** Dual control rests on the API's word
  for the proposer, and on a signature for the confirmer.
- **The owner login can still register keys**, as in ADR-0028.
- **The CI audit step.** The HTTP test ends with a forged revocation, so CI
  requires the audit tool to report exactly that one problem.

## Tests

- `crates/pki-core`: the revocation and void claim vectors, which are the
  SQL builder's; separator injection is refused.
- `crates/lab-signer` (19 tests). The signer refuses each of the following
  before any claim:
  - an entry without a proof, or a proof for nothing listed;
  - another key, another instant, a flipped `signer_claimed`;
  - a rejection, a key not active when it signed, no proof;
  - a void listed as a revocation.

  It signs CRLs with legacy entries, and checks RA revocations with the
  RA's key.
- `tests/management_revocation_proofs.sql`:
  - claims, grants and keys;
  - the requester cannot decide, even when signed;
  - stale claims, replays, double decisions;
  - the proposer cannot confirm;
  - the signer view's rows and their legacy marking;
  - a key revoked after its claim;
  - immutability, and isolation from readers and writers.
- The API HTTP test (63 tests) with the real signer:
  - signed revocation decisions and void confirmations, with wrong keys,
    unsigned bodies and the requester refused;
  - the CRLs signed afterwards;
  - finally, a forged unsigned revocation makes the next CRL
    `RECONCILIATION_REQUIRED`.
- The certificate-application e2e suite:
  - signed revocation and void confirmation through the API;
  - an officer signing a revocation in the console;
  - the CRLs verified with OpenSSL.
