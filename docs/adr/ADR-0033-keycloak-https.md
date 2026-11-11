# ADR-0033 — HTTPS for the laboratory identity provider

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It is the
third slice of "TLS everywhere", after ADR-0031 (database) and ADR-0032
(API).

**Scope:**
- the Keycloak service in the laboratory compose stack;
- the OIDC issuer URL;
- the API's discovery and JWKS client;
- the grants and fixtures keyed by issuer;
- the browser and Node test clients;
- CI.

**Supersedes in part:** ADR-0009, which ran Keycloak on plain HTTP on
loopback. The realms, clients, users and roles are unchanged.

## Context

Passwords, authorization codes, tokens and the JWKS travelled in plain
HTTP between the browser, the Node clients, the API and Keycloak. Anyone on
the path could:
- capture a password or an authorization code;
- serve the API a forged signing key through an altered JWKS response.

The second is the more serious: forged tokens would then pass the API's
signature check.

## Decision

1. **Keycloak serves HTTPS only.**
   - The service listens on `https://127.0.0.1:8443`, with
     `--http-enabled=false`.
   - Its certificate comes from the laboratory service CA (ADR-0031) and
     covers `localhost`, `127.0.0.1` and `issuer`.
   - The hostname, and therefore the token `iss`, is
     `https://127.0.0.1:8443`.
   - The management interface (health) stays plain HTTP inside the
     container, on a port that is not published, so the healthcheck needs
     no client certificate store.
2. **The issuer changes everywhere it is a key:**
   - the database grants and approver/officer keys of `init-db.sh`;
   - the issuing-CA provisioning;
   - the end-to-end suites;
   - the API and console configuration.

   The API's issuer pinning is unchanged; only the URL changes.
3. **The API trusts only the lab CA for OIDC.** With `TRUST_OIDC_CA_FILE`,
   discovery and JWKS fetches use only that CA. The built-in roots are
   disabled, so a public CA cannot impersonate the identity provider.
4. **Test browsers pin the identity provider's key.** Chromium is launched
   with `--ignore-certificate-errors-spki-list`, set to the SPKI SHA-256 of
   the lab Keycloak certificate. That certificate's chain error is accepted;
   any other certificate error still fails. Node clients use
   `NODE_EXTRA_CA_CERTS`.
5. **The console** is still served by the Vite development server on plain
   HTTP loopback. Its pages carry no secret, and its OIDC and API traffic
   now goes to HTTPS origins. Serving the console over HTTPS is left for a
   production build (below).

## Alternatives considered

- **Ignore TLS errors in the test browser** (`ignoreHTTPSErrors`). Rejected:
  it would accept any certificate. Pinning accepts exactly the lab key.
- **Import the lab CA into a browser trust store.** That needs NSS tools in
  the CI image. The pin is narrower and needs no extra package.
- **Keep the old issuer URL behind a redirect.** Rejected: issuers must match
  exactly, and the grants are keyed by issuer.

## Consequences and open risks

- **Existing lab databases** hold grants under the old issuer. A stack must
  be recreated (`down -v`) after this change. Lab stacks are disposable.
- **The Keycloak key is world-readable** (mode 0644) because Keycloak runs
  as uid 1000 and reads a bind mount. It is protected by the 0700 host
  directory, as for the API key (ADR-0032).
- **Development mode remains:** no clustering, H2 storage, no MFA.
- **The console origin is still plain HTTP on loopback.**
- **No rotation tooling.**

## Tests

- Locally, against Keycloak on HTTPS with the lab certificate:
  - API compatibility and the compose smoke;
  - the browser suite (Keycloak login form, PKCE, sign-out);
  - the profile, CA proposal and certificate-application suites, including
    the console steps;
  - the IAM negative suite: foreign realm, workload token, admin API,
    lockout.
- CI's compose job runs the same suites against the compose stack.
