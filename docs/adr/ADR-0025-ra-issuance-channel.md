# ADR-0025 — Issuance channel for registration authorities

**Status:** Proposed · 2026-11-09. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0038;
- the route `POST /v1/ra/cas/{ca_id}/certificates`;
- `lab_verify_issued_certificates`;
- the laboratory end-to-end suite.

**Roadmap:** first slice of the RA/CLM channel that ADR-0024 calls for
(MVP criterion 7). Out of this slice:
- revocation through the channel;
- RA key rotation;
- transport security.

## Context

ADR-0024 assigns subscriber identity and domain validation to a light RA or
to the CLM. The CA signs the requests they authorize. Until now the only
way in was the console flow, in which people sign in through OIDC as
requester and officer. The API refuses workload tokens (ADR-0009). An RA
system therefore had no way to obtain a certificate.

## Decision

1. **RA systems are registered by the database owner.** The table
   `ra_system` holds:
   - an identifier (`[a-z0-9-]`, at most 63 characters);
   - a display name;
   - its P-256 public key, an uncompressed SEC1 point, unique across RAs;
   - an `enabled` flag.

   The owner also grants:
   - the profiles the RA may request, per CA (`ra_profile_grant`);
   - the CA's `certificate-requester` role to the RA's principal,
     `(urn:trust-platform:ra, ra_id)`. That makes the RA the requester of
     record of its applications.

   The API cannot register or grant anything.
2. **Each request is signed by the RA, not authenticated by a token.** The
   RA signs, with ECDSA P-256 and SHA-256 (DER), the bytes of
   `trust_pki_core::ra_request::ra_issuance_message`, version 1. That is a
   domain prefix, then:
   - the RA identifier, the CA and the profile;
   - the RA's request identifier (its idempotency key);
   - the SHA-256 of the CSR DER;
   - the DNS names in order;
   - the validity;
   - `signed_at`, in Unix seconds.

   The SQL function `ra_issuance_message` builds the same bytes; shared
   vectors are asserted on both sides.
3. **The API checks, before anything is recorded:**
   - `signed_at` is within 300 seconds of its clock;
   - the RA is registered and enabled;
   - the signature verifies with the registered key over the bytes it
     rebuilds from the body.

   Each failure is a 401, and a bad signature is logged without the
   request. Then the CSR must prove possession of its key and name exactly
   the first DNS name. Its extensions are never used.
4. **The RA's signed request is its registration decision.** In one
   transaction, `submit_ra_issuance_lab`:
   - checks the RA and its profile grant again;
   - rebuilds the bytes;
   - checks freshness again;
   - submits the application under the profile's rules (migration 0029:
     ACTIVE CA, active revision, zones, number of names, validity, not the
     CA's key);
   - records the approval with the RA as decider;
   - stores the exact signed bytes and the signature
     (`ra_issuance_request`, append-only).

   The separation of duties between requester and officer is a rule for
   people. Here the RA system is accountable through its stored signature.
   The audit trail names the RA for both steps.
5. **Issuance is unchanged.** The API issues as the RA's principal, through
   the journaled intent, the separate signer and independent verification
   (ADR-0017), once. An ambiguous outcome is `RECONCILIATION_REQUIRED`
   (502) and goes through the void flow (ADR-0020).
6. **Idempotency:**
   - the same signed bytes under the same request identifier return the
     same certificate (200);
   - other bytes under that identifier are refused (409);
   - the issuance operation identifier is derived from the RA and its
     request, so a replay after an interruption continues the same
     issuance and never re-signs.
7. **Independent verification.** `lab_verify_issued_certificates`, for
   every RA request:
   - rebuilds the bytes from the stored application and the request's
     identifiers, and checks they are the stored bytes;
   - verifies the signature with the RA's registered key;
   - checks that the RA submitted and approved the application.

## Alternatives considered

- **OAuth client credentials with a shared secret** (the existing
  laboratory workload client). Rejected: ADR-0009 already refuses it, and a
  secret proves nothing after the fact.
- **`private_key_jwt` at the identity provider.** It would authenticate the
  RA to Keycloak, but the CA would hold only a bearer token, not a signature
  over the request. Kept for a production identity provider.
- **mTLS.** It authenticates the connection, not the request, and it needs
  TLS termination the laboratory API does not have. It is complementary
  for production transport.
- **The RA as an OIDC user going through the officer flow.** Rejected: it
  would require a second officer. The RA, not the CA, is the decision maker
  (ADR-0024).

## Consequences and open risks

- **The API is trusted to verify signatures.** PostgreSQL does not verify
  ECDSA. A compromised API or writer login could record a request no RA
  signed; the audit tool detects it, as for signed decisions (ADR-0011).
- **A compromised RA key yields certificates within that RA's profiles and
  zones,** and nothing beyond them. The owner disables the RA by clearing
  `enabled`. There is no automated rotation or revocation of RA keys yet.
- **No transport security** in the laboratory (plain HTTP on localhost or
  Compose). The signature protects integrity and authenticity, not
  confidentiality. The freshness window and unique request identifiers
  limit replay.
- **No revocation through the channel yet.** RA-originated certificates are
  revoked through the existing officer flow.
- **One response size:** the certificate PEM is returned inline.

## Tests

- `tests/management_ra_channel.sql`:
  - the SQL/Rust message vector;
  - RA identifier and key constraints;
  - reader and writer privileges;
  - unknown, disabled or ungranted RAs, and ungranted profiles;
  - stale and future requests;
  - names outside the zones and excessive validity;
  - acceptance as submitted and approved by the RA;
  - replay and conflict;
  - stored bytes and attribution;
  - append-only storage.
- Rust:
  - message vectors and field sensitivity;
  - RA identifier and operation derivation;
  - an HTTP test with the real signer:
    - another key, a stale request or a tampered body gives 401;
    - names outside the zones give 422;
    - issuance under the CA key to the CSR's key gives 201;
    - the replay returns the same certificate;
    - other bytes under the same request identifier give 409;
  - the audit tool verifies the stored request.
- Certificate-application e2e on the laboratory stack:
  - the suite acts as an RA with an ephemeral key registered by the owner;
  - it signs with Node's crypto, independently of the Rust code;
  - OpenSSL verifies the issued certificate for its second name;
  - replay, conflict, another key and a stale request are checked.
