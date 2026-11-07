# Sprint 0 — assurance and limitations

## Implemented

- Default-deny policy engine, with explicit lab-only allowlists.
- Separate authenticated principal from CSR-requested identity.
- Strict lower-case ASCII FQDN validation, disallowing wildcards and malformed names.
- Policy binding of actor, profile, subject, SAN, validity and signature algorithm.
- Failure-closed unconfigured signing provider.
- RFC 5280 positive DER integer serial constraints and per-issuer duplicate rejection in a test store.
- State transition guard and proposed relational schema.
- Automated unit and negative tests and Rust CI.

## Not implemented

- PKCS#10/CSR DER parsing or proof-of-possession verification.
- X.509 TBS construction or certificate signing.
- Real HSM, PKCS#11, private key generation or storage.
- Persistent state machine, issuer-scoped transaction guarantees or runtime PostgreSQL access.
- Authenticated API, publication, CRLs, OCSP, backup/restore or multi-tenancy.
- Formal threat analysis, fuzzing, audit integrity guarantees, penetration testing or external audit.

## Security gate

This is a **foundation prototype** only. No real certificates can be issued. Before G1, implement CSR validation, policy-governed issuance and independent X.509 interop tests. Before customer use, complete G0-G4 and independent review.

## Founder IP guardrail

Only original code and public standards may enter this repository. Do not transfer employer code, private documentation, client information, secrets or network identifiers.
