# System architecture — baseline v0.1

Status: proposed, not implemented. Private PKI only, no public WebPKI/QTSP MVP.

## Boundaries
1. Rust CA Core: CSR parsing, policy evaluation, issuance state, X.509 encoding, revocation and CRL generation.
2. Signing Provider: software lab implementation; PKCS#11/HSM adapter in a later milestone. Signing requires explicit authorization context.
3. PostgreSQL: durable certificate/serial/revocation/audit records.
4. Go control plane: future authenticated management API, RBAC, CLM, ACME.
5. React UI: future static console.

The authorization/control plane must not bypass the CA signing policy. Offline root CA is operated separately.

## Non-functional constraints
Air-gapped capable; no mandatory SaaS; backup and restore tested; least privilege; secure defaults; no private CA keys in DB/logs/source; observability without leaking secrets.

## Key decisions
See ADR-0001 and ADR-0002. Full design review required before implementation.