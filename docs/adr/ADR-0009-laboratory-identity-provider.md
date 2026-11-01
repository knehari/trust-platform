# ADR-0009 — Laboratory identity provider for human and workload sign-in

**Status:** Proposed · 2026-11-01. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).
**Scope:** The disposable Compose stack, the management API's access-token
checks and the console sign-in. It adds no write route and changes no
issuance, signing or revocation path.
**Roadmap:** first slice of MVP criterion 5, *Human IAM and authorization*.
The criterion stays unchecked (see "What remains open").

## Context

Until now the Compose stack used `frontend/dev/oidc-fixture.mjs`, an OIDC
fixture that approves one fixed `lab-operator` without any login. It has one
role and one identity, so it cannot show:

- that a person authenticates;
- that two people are distinct;
- that a role grants only its own permissions;
- that a machine credential is not a human session.

The CA and profile lifecycle contract
([ca-profile-lifecycle-boundary.md](../architecture/ca-profile-lifecycle-boundary.md))
and ADR-0005 forbid write routes until a real identity provider and
separately authenticated actors exist. The owner chose to build this first
(decision of 2026-11-01).

## Decision

1. **Keycloak 26.8.1** (open source, Apache-2.0) replaces the fixture in
   Compose.
   - **Image:** pinned by digest.
   - **Mode:** development mode, with an in-container H2 store.
   - **Realm:** imported at each fresh start from `scripts/lab/keycloak/`. The
     files hold no secret: each password and the workload secret is a
     `${…}` placeholder filled from the private `.env.lab`, which
     `scripts/lab/init-env.sh` generates (48 hex characters per value).
   - **Address:** the issuer is `http://127.0.0.1:8080/realms/trust-lab`,
     published on loopback only.
2. **Realm `trust-lab`.**
   - **Fixed user IDs**, so that the database grants (keyed by issuer and
     `sub`) are reproducible.
   - **Login:** no self-registration, password reset, remember-me or e-mail
     login.
   - **Brute-force protection:** locks an account after 5 failures, for a
     wait that starts at 60 s.
   - **Sessions:** 5-minute access tokens, 15-minute idle and 1-hour maximum
     sessions.
   - **Default role:** grants nothing, not even the account console.
3. **Roles (least privilege).** Four realm roles exist:
   - `trust-ca-reader` is the only one the API accepts today;
   - `trust-profile-editor`, `trust-policy-approver` and `trust-ca-operator`
     are reserved for the lifecycle routes and authorize no read on their
     own.

   The console client only maps these four roles into its tokens
   (`fullScopeAllowed=false`). The CA scope is the `ca_ids` user attribute;
   it is not editable by the user.
4. **Clients.**
   - **`trust-console`** is a public client: authorization code with PKCE
     `S256` only, an exact redirect URI and web origin, no password grant, no
     implicit flow, and RFC 9068 access tokens (`typ: at+jwt`).
   - **`trust-lab-workload`** is a confidential client for client credentials
     only. Its service account deliberately holds the reader role, CA scope
     and a database grant, to prove that a workload token is still refused
     on human routes.
5. **API token profile** (`crates/management-api/src/auth.rs`).
   - **Kept:** RS256 with `typ: at+jwt`, pinned issuer and audience, `exp`,
     `sub`, bounded `roles` and `ca_ids`, JWKS rotation.
   - **New:** `azp` must equal `TRUST_OIDC_CLIENT_ID`, the console client. A
     token issued to any other client of the issuer is refused (401).
   - **New:** `iat` is required and refused when in the future.
   - **Changed: `nbf` is no longer required.** RFC 9068 does not require it,
     and Keycloak does not emit it. It is still refused when in the future or
     malformed.
   - **Changed:** a token without `roles` or `ca_ids` now verifies with none,
     so the route answers 403 instead of 401. Both deny access.
6. **The fixture stays** for development without Docker only. It now emits
   `azp`, and its own comments still say it performs no human authentication.

## Negative evidence

`frontend/dev/iam-negative.mjs` runs in the Compose CI job after the smoke and
browser tests. Each case uses the real login form, a client-credentials
grant or a forged token.

| Case | Expected |
| --- | --- |
| wrong password, disabled user | no authorization code |
| password grant on the console client | refused by Keycloak |
| signed-in user without a role | 403 |
| profile editor without the reader role, CA granted | 403 |
| reader whose token names an ungranted CA | empty list, 403 on that CA |
| workload token with the reader role, CA scope and grant | 401 |
| workload with a wrong secret | no token |
| ID token used as a bearer token | 401 |
| token of another realm on the same server, with a grant under that issuer | 401 |
| widened `ca_ids` or altered signature | 401 |
| two approvers | distinct `sub` and session; one's password does not open the other's account |
| `POST` with an operator token | 404 or 405: no write route exists |
| account console roles and user-profile policy (admin API, read only) | readers and approvers hold no account-console role; `ca_ids` is not a user-editable attribute |
| 5 wrong passwords | the right password is then refused (lockout) |

**Regression.** The unit test `signed_access_token_checks_audience_expiry_type_and_signature`
gains cases for a foreign or missing `azp`, a missing or future `iat`, and an
optional or future `nbf`. The workload case failed on the previous head
`fad16fe` ("workload token accepted as a human session") and passes on this
change.

## What this does not establish

- **Not production IAM.**
  - Keycloak runs in development mode: plain HTTP on loopback, H2 inside the
    container, no clustering, backup or upgrade path.
  - The admin console is published on loopback, protected by a generated
    bootstrap password.
- **No multi-factor authentication.**
  - Passwords alone authenticate.
  - WebAuthn or OTP for approvers is a prerequisite of the approval routes,
    not provided here.
- **Maker/checker is not enforced yet.** This change gives distinct,
  separately authenticated identities and roles. Refusing the same person,
  or the same key, in two approvals belongs to the lifecycle routes
  (criterion 6). Their contract also requires cryptographically distinct
  approval keys.
- **Workload identity is a shared secret.** Client credentials with a secret
  in `.env.lab`. No mTLS, no `private_key_jwt`, and no workload route yet.
- **Personal data in tokens.** The default `profile` scope puts names in the
  access token; the API ignores them.
- **Trust in the identity provider.** Whoever administers the realm can
  create users, roles and CA scopes. Database grants remain a second,
  owner-held layer.

## Alternatives considered

- **Keep the fixture.** It cannot authenticate anyone. Rejected.
- **Write a login service.** Home-grown authentication; AGENTS.md rules out
  home-grown security primitives. Rejected.
- **Dex, Authentik, ZITADEL or Ory Hydra.**
  - Dex has no user store of its own for this purpose.
  - The others are viable.
  - Keycloak was chosen because it is widely deployed and reviewed, emits
    RFC 9068 tokens, has brute-force protection and service accounts, and
    imports declaratively.
  - A production choice is a separate decision.

## Consequences

- Keycloak's embedded schema tool is started with its analytics disabled
  (`-Dliquibase.analytics.enabled=false`); a run without it attempted a
  connection to `config.liquibase.com`.
- Compose starts Keycloak (about 15–30 s) before the API. Its health check
  reads the management port with bash `/dev/tcp`, because the image has no
  curl.
- People sign in with the user names listed in
  [lab-compose.md](../development/lab-compose.md) and the passwords in their
  own `.env.lab`. An `.env.lab` created before this change is completed in
  place by `init-env.sh`; existing database passwords are kept.
- Deployments of the API must set `TRUST_OIDC_CLIENT_ID`; startup fails
  without it.

## What remains open for criterion 5

- Multi-factor authentication for privileged roles.
- A production identity provider deployment with TLS and an external database.
- Workload authentication without a shared secret, and the routes that would
  accept it.
- Enforcing separate actors in the write routes (criterion 6).
- Independent review. G0 and the security review remain human gates.
