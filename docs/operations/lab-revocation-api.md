# Laboratory revocation write API

Lab only. `crates/management-api/src/bin/revocation_api.rs` exposes the
signed maker-checker flow of ADR-0007 over HTTP (contract:
`openapi/revocation-v1.yaml`). The Rust core takes every decision; the
binary authenticates and routes. ADR-0005 and ADR-0007 are still Proposed.

Flow for one change:
1. The maker asks for a challenge:
   `POST /v1/cas/{ca}/status-change-challenges` with serial, action and
   reason.
2. The maker's authenticator signs `webauthn_challenge` (the SHA-256 of the
   canonical claim).
3. The maker posts the assertion to
   `/v1/status-change-challenges/{id}/assertion`.
4. The checker asks for a challenge on the change:
   `POST /v1/status-changes/{change}/approval-challenges`.
5. The checker signs it and posts the assertion. The status change is
   applied in the same transaction as the approval.

Who may act:
- The acting officer is the access token's `(iss, sub)`; requests carry no
  identity, and unknown body fields are refused (422). The token needs the
  `trust-revocation-officer` role and the CA in `ca_ids`.
- The database still requires the officer grant and an active enrolled
  credential.
- A challenge can only be answered by the officer it was issued to (403
  otherwise).

What is verified, and when:
- `submit_signed` verifies the assertion before writing.
- The database re-checks everything but the ECDSA signature, consumes the
  challenge once, and keeps the evidence (`reverify_signed_change`).

Database access and logging:
- The database login must hold only `trust_revocation_officer_api`;
  `connect_lab_service` refuses privileged logins. The connection is the
  lab `NoTls` adapter.
- Logs carry event names, challenge and change identifiers, never tokens or
  assertions.

```
TRUST_OIDC_ISSUER=... TRUST_OIDC_AUDIENCE=trust-api \
TRUST_REVOCATION_DATABASE_URL=postgresql://officer-api@127.0.0.1/trust \
TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
  cargo run -p trust-management-api --bin revocation_api
```

Other endpoints:
- `GET /v1/cas/{ca}/pending-status-changes` lists the CA's proposed changes,
  oldest first, with whether the maker signed (migration 0034).
- `POST /v1/status-changes/{change}/rejection` (a checker other than the
  maker) and `.../withdrawal` (the maker only) close a change. They change no
  certificate status and are not signed yet, like the database functions.
  The actor is still the token's.
- For any change identifier, the change's CA is checked against the token's
  scope before anything is written (unknown 404, out of scope 403). This
  includes approval challenges.

Not covered:
- signed rejection and withdrawal;
- CA-admin endpoints (credential enrolment, grants);
- listing pending changes;
- rate limiting beyond 8 concurrent requests;
- TLS termination;
- a browser client.

Tested by the binary's tests:
- missing or invalid token;
- wrong role;
- CA out of scope;
- malformed input and unknown fields;
- a full HTTP revocation with real ES256 assertions against PostgreSQL;
- a challenge answered by another officer;
- a forged signature;
- the maker approving;
- a replayed assertion.
