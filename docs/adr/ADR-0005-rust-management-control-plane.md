# ADR-0005 — Rust management control plane for the first integrated application

**Status:** Accepted for laboratory implementation · 2026-10-17  
**Scope:** First authenticated, read-only management slice; production approval remains gated by G0 and independent security review.  
**Supersedes:** The tentative Go API direction in ADR-0001 and ADR-0003. It does not change ADR-0003's separation of authenticated identity from CSR content.

## Context

The CA core, policy contracts and PostgreSQL adapter are Rust. There is no deployed management API, trusted OIDC boundary or UI. A Go API would add a second service and an IPC/FFI contract before the policy engine can be called; mistakes in that contract could let API endpoints bypass CA policy. Rust gives the first vertical slice a direct, typed integration with the existing core, while still requiring explicit authentication, authorization and database permissions.

## Decision

Build a **single Rust management service** alongside the existing crates. Keep the CA engine and policy engine as separate modules/crates, not as an HTTP handler. The initial service exposes only versioned read-only endpoints (`/v1/health`, CA and certificate inventory, audit navigation). Mutating issuance, revocation and governance endpoints are out of scope until the identity boundary, role/scope authorization and policy adapters have integration evidence.

The service validates OIDC access tokens from a configured test issuer using its discovered JWKS. It pins allowed issuer, audience and signing algorithms; checks signature, expiry, not-before and token type; rejects missing/stale keys and malformed claims. A token's CA scope and role are intersected with a server-side role mapping before a query is made. The browser holds no client secret or CA key. Every response is scoped server-side; request parameters never provide authorization. Authenticated actor identity comes from verified token claims, never CSR fields or caller-provided headers.

Give the service a PostgreSQL login with SELECT only on the exact views needed by the first slice. Do not give it migration ownership, signing functions, writable tables or software signer credentials. Keep the health/liveness endpoint free of sensitive data; readiness may check connectivity but must not disclose database details. Use correlation IDs and structured security events with bounded fields and no tokens, CSRs, private keys or SQL parameters in logs. OpenAPI is the versioned API contract, with contract and integration tests against a disposable database and OIDC test issuer.

Deployment remains a modular monolith: Rust API + CA/policy crates, PostgreSQL, React frontend and a test IAM container under Compose. HSM/PKCS#11 is a future provider boundary, never a key exposed to the API or browser. Any future Go control-plane service requires a new ADR and an authenticated, versioned internal protocol that cannot bypass the Rust policy engine.

## Alternatives considered

- **Go API + Rust CA process:** useful isolation and Go's service ecosystem, but adds a second deployable, protocol translation and another authorization boundary before the existing core is callable. Revisit if operational evidence justifies it.
- **Go via FFI into Rust:** in-process overhead is low, but ABI, memory ownership and panic/error translation add risk at the trust boundary.
- **HTTP API inside CA signing code:** smaller initially, but would conflate untrusted network parsing with high-trust issuance and custody responsibilities.

## Consequences and verification gates

Rust's web/OIDC ecosystem and compile times add implementation cost. The decision does **not** make existing policy contracts a trusted runtime boundary by itself. Before any issuance endpoint, tests must show: invalid/missing/stale/wrong-audience tokens fail closed; role and CA-scope checks cannot be bypassed; PostgreSQL login cannot mutate protected objects; Core verifies CSR PoP and authorization before durable intent; ambiguous signing never triggers automatic re-sign; audit/correlation remains bounded. Production use additionally requires G0, independent security review, operational key custody and release approval.
