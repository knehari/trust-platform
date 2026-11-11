# ADR-0032 — HTTPS for the management API

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It is the
second slice of "TLS everywhere", after ADR-0031 (database).

**Scope:**
- the management API's listener;
- the laboratory service PKI;
- compose: the API and the console's development proxy;
- the end-to-end clients;
- CI.

**Out of scope, for the next slice:**
- HTTPS for Keycloak, which changes the OIDC issuer URL in every grant and
  fixture;
- mTLS;
- the static CRL server, which stays plain HTTP (below).

## Context

The API carries OIDC bearer tokens, CSRs, signed decisions, RA-signed
requests and issued certificates. It served them in plain HTTP. Anyone on
the path could read or replay a bearer token within its lifetime, or alter
responses.

## Decision

1. **HTTPS when configured.** When `TRUST_API_TLS_CERT_FILE` and
   `TRUST_API_TLS_KEY_FILE` are both set, the API serves only TLS 1.2+. It
   uses rustls with the ring provider, the versions already locked through
   `reqwest` and ADR-0031. It has no plain listener.
   - Setting only one of the two variables is a startup error, never a
     silent fallback.
   - The API logs `"https": true|false` at startup.
2. **Bounded handshakes.** Handshakes run concurrently, each bounded to 5
   seconds, with at most 64 in flight. A slow client cannot hold the accept
   loop.
3. **Laboratory certificate.** `init-env.sh` issues an API certificate from
   the service CA of ADR-0031, for `localhost`, `127.0.0.1` and `issuer` (the
   compose service whose network namespace the API shares).
4. **Clients verify the lab CA.**
   - The console's development proxy targets `https://issuer:8081` with
     `secure: true`.
   - The proxy and the Node test clients trust the CA through
     `NODE_EXTRA_CA_CERTS`.
   - The compose healthcheck uses `curl --cacert`.
   - Nothing disables verification.
5. **CRL distribution stays HTTP**, as is usual for CRLs: they are signed,
   and fetching them over TLS would make revocation checking depend on
   another certificate chain. ADR-0030 is unchanged.

## Alternatives considered

- **A TLS-terminating proxy in front of the API.** That adds a service, and
  the API–proxy hop would still be plaintext. In-process TLS reuses the
  locked rustls.
- **`axum-server`.** That adds a dependency. axum 0.8's `Listener` trait is
  enough.

## Consequences and open risks

- **Plain HTTP by default.** Without the variables, the API serves plain
  HTTP: CI's in-process tests and local development. A deployment must set
  them, and the startup log shows whether it did.
- **The lab API key is world-readable** (mode 0644) because the API runs as
  `nobody` and reads a bind mount. It is protected on the host by the 0700
  `.lab-keys/tls/` directory. A deployment should use a secret store or a
  key owned by the service user.
- **Keycloak is still plain HTTP.** The browser's sign-in and the API's
  JWKS fetch are not yet protected; that is the next slice.
- **No certificate rotation.** A new certificate takes effect only when the
  API restarts.

## Tests

- Unit tests: incomplete or invalid TLS material is refused.
- Locally, against an API serving HTTPS with the lab certificate:
  - verified HTTPS with the lab CA;
  - plain HTTP and an unknown CA refused;
  - `check-api-compat`;
  - all e2e suites through the HTTPS API: the console proxy, the Node
    clients and the RA channel.
- CI (compose job): verified HTTPS answers; plain HTTP and verification
  without the lab CA fail. The suites then run over HTTPS.
