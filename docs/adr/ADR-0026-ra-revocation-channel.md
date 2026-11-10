# ADR-0026 — Revocation through the RA channel

**Status:** Proposed · 2026-11-10. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0039;
- the route `POST /v1/ra/cas/{ca_id}/revocations`;
- `lab_verify_issued_certificates`;
- the laboratory end-to-end suite.

**Roadmap:** completes the RA channel of ADR-0025 for MVP criteria 7 and 8.
Revocation by the subscriber stays the RA's or the CLM's business
(ADR-0024). The CA records it and publishes it in its CRLs.

## Context

ADR-0025 lets a registered RA system obtain certificates with signed
requests. Revoking them still required the console flow: a requester asks,
and a different registration officer approves. An RA that learns of a key
compromise had no way to revoke what it obtained.

## Decision

1. **Scope:** an RA revokes only a certificate it obtained through the
   channel, meaning one whose application is recorded in its
   `ra_issuance_request`. It cannot revoke anything else, including
   certificates issued through the officer flow or to another RA.
2. **Signed request.** The RA signs, with ECDSA P-256 and SHA-256 (DER),
   `trust_pki_core::ra_request::ra_revocation_message`, version 1. That is
   a domain prefix, then:
   - the RA identifier and the CA;
   - its request identifier (idempotency);
   - the serial, as length-prefixed bytes;
   - the reason code (16-bit);
   - the reason text;
   - `signed_at`.

   The SQL function `ra_revocation_message` builds the same bytes; shared
   vectors are asserted on both sides.
3. **Authentication is the same as for issuance** (ADR-0025): freshness of
   300 seconds, then an enabled registered RA, then the signature. Each
   failure is a 401, checked before the request reaches the database
   functions.
4. **The signed request is both the request and its approval.** In one
   transaction, `submit_ra_revocation_lab`:
   - checks the RA and the replay or conflict;
   - checks freshness again;
   - finds the RA's certificate by serial;
   - files the request through `request_certificate_revocation_lab` (the
     rules of migration 0031: a closed list of reason codes, issued and
     not yet revoked, no open request, a publishing CA);
   - records the approval with the RA as decider;
   - writes the core revocation under the CA's CRL lock;
   - stores the signed bytes and the signature (`ra_revocation_request`,
     append-only).

   The audit trail names the RA for the request, the approval and the
   revocation.
5. **Publication is unchanged.** The revocation appears on the next CRL,
   whether an officer publishes it or the renewer does when the CRL is due
   (ADR-0018, ADR-0021). A short CRL lifetime, or a later on-revocation
   publication, bounds the delay.
6. **Independent verification.** `lab_verify_issued_certificates`
   accepts a revocation approved by its own requester only when it is an
   RA-signed revocation, and then verifies that:
   - the stored bytes are the revocation's (serial, reason code, reason,
     identifiers);
   - the RA's registered key signed them;
   - the RA obtained the certificate.

   Every other revocation still needs a different registration officer.

## Alternatives considered

- **An officer approves RA requests.** Rejected: the RA is the
  subscriber-facing authority (ADR-0024). A second human step would make
  machine revocation, for example after a key compromise, depend on staff
  availability.
- **Revocation by serial for any certificate of the CA.** Rejected: an RA
  could then revoke certificates it never issued, including other RAs'.

## Consequences and open risks

- **A stolen RA key can also revoke** that RA's certificates. That is a
  denial of service within its own scope, which is detectable in the audit
  trail. The owner disables the RA.
- **The CRL is not republished on revocation.** Relying parties learn of
  the revocation at the next CRL. OCSP, or an on-revocation publication,
  remains a separate decision.
- The other limits of ADR-0025 remain: there is no transport security in
  the laboratory and no RA key rotation, and the API, not PostgreSQL,
  verifies signatures at request time.

## Tests

- `tests/management_ra_revocation.sql`:
  - the SQL/Rust vector, and that readers are refused;
  - unknown and disabled RAs;
  - another RA's certificate and an unknown serial;
  - reason codes outside the list, and stale requests;
  - revocation by the RA and its attribution, replay and conflict;
  - a second request for a revoked certificate;
  - stored bytes, and append-only storage.
- The HTTP test with the real signer:
  - another key gives 401;
  - a certificate the RA did not obtain gives 404;
  - revoked gives 201, the replay 200 with the same instant, a new request
    409;
  - the next CRL, verified, lists the serial.
- The audit tool verifies the RA-signed revocation and accepts it only on
  that basis.
- Certificate-application e2e: the suite, acting as an RA, revokes the
  certificate it obtained, with Node's crypto. After the officer publishes
  the next CRL, `openssl verify -crl_check` reports the certificate
  revoked.
