# System architecture — baseline v0.1

Status: partially implemented laboratory architecture; no deployed application. Rust CSR/issuance/policy and PostgreSQL intent/recovery paths exist; revocation/CRL, authenticated API and console remain planned. Private PKI only, no public WebPKI/QTSP MVP.

## Boundaries
1. Rust CA Core: CSR parsing, policy evaluation, issuance state, X.509 encoding, revocation and CRL generation.
2. Signing Provider: software lab implementation; PKCS#11/HSM adapter in a later milestone. Signing requires explicit authorization context.
3. PostgreSQL: durable certificate/serial/revocation/audit records.
4. Control plane: future authenticated management API, RBAC, CLM, ACME; Go versus Rust requires an ADR before implementation.
5. React UI: future static console.

The authorization/control plane must not bypass the CA signing policy. Offline root CA is operated separately.

## Non-functional constraints
Air-gapped capable; no mandatory SaaS; backup and restore tested; least privilege; secure defaults; no private CA keys in DB/logs/source; observability without leaking secrets.

## Key decisions
See ADR-0001 and ADR-0002. Full design review required before operational exposure. See ../recovery/EXECUTION_STATUS.md for execution evidence.