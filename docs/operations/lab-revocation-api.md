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
  `PgRevocationStore::from_service_client` refuses privileged logins.
- The connection uses the management API's TLS policy: verified TLS 1.3
  against `TRUST_DATABASE_CA_FILE` by default, plaintext only with
  `TRUST_DATABASE_TLS=disable-lab` (logged). This is covered by
  `tests/management_db_tls.sh`.
- Logs carry event names, challenge and change identifiers, never tokens or
  assertions.

```
TRUST_OIDC_ISSUER=... TRUST_OIDC_AUDIENCE=trust-api \
TRUST_REVOCATION_DATABASE_URL=postgresql://officer-api@db.lab.invalid/trust \
TRUST_DATABASE_CA_FILE=/etc/trust/db-ca.pem \
TRUST_WEBAUTHN_RP_ID=officer.lab.invalid TRUST_WEBAUTHN_ORIGIN=https://officer.lab.invalid \
  cargo run -p trust-management-api --bin revocation_api
```

Other endpoints:
- `GET /v1/cas/{ca}/pending-status-changes` lists the CA's proposed changes,
  oldest first, with whether the maker signed (migration 0034).
- `POST /v1/status-changes/{change}/rejection` (a checker other than the
  maker) and `.../withdrawal` (the maker only) close a change unsigned, on CAs
  that do not require signatures. On a CA with `signed_approvals_required`
  they are refused (403); use `.../rejection-challenges` or
  `.../withdrawal-challenges` instead (migration 0039). These return a
  challenge for the closing claim, and the assertion goes to the usual
  assertion endpoint. The actor is always the token's.
- `POST /v1/cas/{ca}/precautionary-hold-challenges` with `{"serial_hex"}`:
  one officer asks for a challenge to put a valid certificate on hold as a
  precaution (ADR-0007 section 6, migration 0036). The CA must allow
  suspension under a CPS reference and set `precautionary_hold_hours`
  (1-72), otherwise 409. One officer may have at most
  `precautionary_hold_limit` (default 3, migration 0038) holds awaiting
  confirmation on a CA, and all officers together at most
  `precautionary_hold_ca_limit` (default 10, migration 0047); past either
  the assertion is refused (409). The claim's action is
  `PRECAUTIONARY_SUSPEND`, so
  the signature cannot serve as an ordinary maker signature. The assertion
  goes to the usual assertion endpoint, which applies the hold at once and
  logs `precautionary_hold_applied`.
- `GET /v1/cas/{ca}/precautionary-holds` lists holds not yet followed by a
  dual-controlled revocation or release, with `confirm_by_unix` and
  `overdue`. Confirmation is the ordinary signed maker-checker path (hold to
  revoked, or release). Past the deadline the hold stays in place (fail
  closed), and `crl_housekeeping` exits 2.
- For any change identifier, the change's CA is checked against the token's
  scope before anything is written (unknown 404, out of scope 403). This
  includes approval challenges.

Challenge issuance answers 409 once the acting identity already holds 16 open (unexpired, unconsumed) challenges on the CA (migration 0049); they free up as they are used or expire.

Each verified identity (token issuer and subject) may make 60 requests per minute; beyond that the API answers 429 before any database access (`rate_limit.rs`). Since migration 0062 the same budget is also kept in the database (`consume_api_budget`, a SHA-256 of the identity, fixed one-minute windows on the database clock), counted once per request that reaches the database: it holds across replicas and restarts. A database error there fails closed (503). Housekeeping deletes budgets idle for 7 days (0063). The 8-request concurrency bound still applies. Request bodies larger than 64 KiB are refused (413) before they are parsed or authenticated. Before the token is read, each client address (an IPv4 address, or an IPv6 /64) may make 600 requests per minute, per process (`rate_limit::limit_peers`, 429): a flood of invalid tokens is bounded before any verification or key refresh. X-Forwarded-For is read only when the TCP peer is listed in `TRUST_HTTP_TRUSTED_PROXIES` (comma-separated addresses or CIDR prefixes; unset by default, an invalid entry refuses to start): the entries are read from the right, skipping trusted proxies, and the first other address is counted. Entries left of it, supplied by the client, are ignored, and a malformed entry counts the request against the proxy's own address. When 10,000 addresses are already in their window (a flood from many addresses, such as the /64s of one IPv6 /48), a new address is counted under its /48 (IPv4: /24) instead, so a flood spends its own prefix's budget; only if 10,000 prefixes are live as well is the request refused. Connections are bounded too (`http_serve`): at most 1,024 at once per process (a new one beyond that is closed at once), and each request header must arrive within 10 seconds or the connection is closed, and a request, its body included, must be answered within 30 seconds or it gets 408 and the connection is closed, so slow or idle clients cannot hold sockets. HTTP/1.1 only, as the TLS listener advertises.

The pending list shows `maker_evidence_verified`: whether the maker's stored signature re-verifies in the Rust core. An approval challenge for a proposal whose maker signature does not re-verify is refused (409) before anyone signs, and an approval is never written for one.

An assertion is refused with 503 while the database clock and the Rust core's disagree beyond 2 seconds (`ClockSkew`): challenge expiry and deadlines use the database clock.

Every response carries `Cache-Control: no-store` and `X-Content-Type-Options: nosniff` (`response_headers.rs`): challenges and evidence are not kept by browsers or proxies.

- HTTP transport: with `TRUST_HTTP_TLS_CERT_FILE` and
  `TRUST_HTTP_TLS_KEY_FILE` (PEM chain and key) the API serves TLS 1.3 only
  (rustls). Without them it serves plain HTTP only on a loopback bind address,
  for example behind a TLS proxy on the same host. Any other address needs
  `TRUST_HTTP_TLS=disable-lab`, which is logged; otherwise startup is refused
  before any OIDC or database work. There is no client certificate (mTLS) and
  no certificate reload. Tested by `tests/http_tls.sh`.

Not covered:
- CA-admin endpoints: they are in the separate `ca_admin_api` (`lab-ca-admin-api.md`);
- break-glass (ADR-0007 section 6; the 0045 lab version only re-enrols CA-admin keys, see `lab-break-glass.md`);
- mutual TLS, certificate reload or HTTP/2 on the HTTP side;
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
