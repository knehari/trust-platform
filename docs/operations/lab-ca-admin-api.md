# Laboratory CA-administration API

Lab only. ADR-0005 and ADR-0007 are Proposed. Contract: `openapi/ca-admin-v1.yaml`.

`crates/management-api/src/bin/ca_admin_api.rs` is the CA-admin counterpart of the revocation API. It runs in its own process with its own database login, so separation of duties holds at the login and not only at the token.

Every change is signed:
- A CA admin proposes it with `POST /v1/cas/{ca}/admin-change-challenges`. The changes are issuer registration, officer grant or removal, and officer or admin credential enrolment or removal.
- Another admin approves or rejects it with `POST /v1/admin-changes/{family}/{change}/approval-challenges` or `.../rejection-challenges`. `family` is `ca-admin`, `credential` or `admin-credential`.
- Each step signs the `trust-platform/ca-admin/v1` claim with an enrolled WebAuthn key. The assertion goes to `POST /v1/admin-change-challenges/{challenge}/assertion`. For a proposal, the body repeats the change, which must be exactly the signed one.

Rules:
- The acting admin is the verified token's `(iss, sub)`. The token must carry the `trust-ca-admin` role and the CA in `ca_ids`.
- The database requires the CA admin grant, an enrolled admin key (migration 0037), and distinct keys and persons for the maker and the checker.
- A CA without `signed_admin_required` still accepts the unsigned SQL paths. Turn the setting on (it is one-way) before relying on this API.
- The database login must hold only `trust_ca_admin`; a privileged login is refused at start.
- The connection uses verified TLS 1.3 (`TRUST_DATABASE_CA_FILE`) unless `TRUST_DATABASE_TLS=disable-lab` is set, which is logged.
- Logs carry event names, challenge and change identifiers, and never tokens or assertions.

```
TRUST_OIDC_ISSUER=... TRUST_OIDC_AUDIENCE=trust-api \
TRUST_CA_ADMIN_DATABASE_URL=postgresql://ca-admin-api@db.lab.invalid/trust \
TRUST_DATABASE_CA_FILE=/etc/trust/db-ca.pem \
TRUST_WEBAUTHN_RP_ID=admin.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://admin.lab.invalid \
  cargo run -p trust-management-api --bin ca_admin_api
```

- `GET /v1/cas/{ca}/pending-admin-changes` lists pending changes with their content and the digest a checker signs (migration 0044). The Rust core recomputes each digest from the content and refuses the whole list if one does not match.

- `GET /v1/cas/{ca}/breakglass-uses` lists the CA's break-glass uses with their review state, and `POST /v1/breakglass-uses/{use}/review-challenges` issues a challenge for a signed review by an admin other than the enrolled one (migration 0045). The assertion route answers it and returns `reviewed: true` at the second review.

Challenge issuance answers 409 once the acting identity already holds 16 open (unexpired, unconsumed) challenges on the CA (migration 0049); they free up as they are used or expire.

Not covered:
- the break-glass enrolment itself (0045): deliberately not over HTTP; see `lab-break-glass.md`;
- the DBA bootstrap of the first admin keys (`enroll_ca_admin_credential`, closed once signed administration is required);
- rate limiting beyond 8 concurrent requests;
- TLS termination for the HTTP side.

The token scope of an approval or rejection is checked on the issued challenge, after the database has already checked the admin grant on the change's CA. Issuing a challenge changes nothing.

Tested by the binary's tests:
- missing token, wrong role and CA out of scope;
- unknown kinds, and fields that do not belong to the kind;
- an officer grant proposed and approved over HTTP with real ES256 assertions against PostgreSQL;
- another admin answering the maker's challenge (refused);
- a proposal without its content, and substituted content (refused);
- the maker approving (refused);
- a signed rejection;
- offline re-verification of both changes.

`tests/management_db_tls.sh` checks the TLS policy.
