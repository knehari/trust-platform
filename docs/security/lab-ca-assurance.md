# Lab X.509 CA — security assurance register

**Status:** *functional laboratory prototype*, not an operational CA, qualified service or security certification.

## What the code proves

- Strict DER PKCS#10 CSR parsing and SHA-256/ECDSA P-256 proof-of-possession verification.
- The authenticated requester is a **trusted input contract**, not proved by the CSR.
- Profile-based issuance uses authorized CN/SAN and validity rather than copying untrusted CSR extensions.
- Root and leaf certificates are constructed as native X.509 v3 DER structures in Rust.
- A feature-gated ephemeral RustCrypto signer signs test-only root and leaf certificates.
- Per-issuer positive serial format and duplicate rejection in memory.
- Unit/negative tests, Rustfmt, Clippy, PostgreSQL invariants and independent OpenSSL path validation.

## Important RFC 5280 and operational gaps

- **No SKI / AKI extensions yet**; issuer binding, strict-profile interoperability and path processing remain to be expanded and tested.
- No CRL Distribution Points, AIA/OCSP, Certificate Policies OID, CP/CPS document URI linkage or revocation.
- Serial value used by the lab is fixed/low and not suitable for production's unpredictability requirements.
- The serial reservation store and issuer key are **process-local** and lost on restart. Never run as a networked CA or for client certificates.
- No durable issuance state, HSM, signing-intent authorization gateway, idempotent recovery, API authentication, audit sink or trusted time.
- No meaningful claim about operator controls, physical security, identity proofing, legal liability or qualification assessment.
- No audited supply chain, release provenance, independent pen-test, high assurance key ceremony or successful certification.

## Development next

1. SKI/AKI generation and profile negative/interoperability tests.
2. Strong requester authentication boundary and CSR subject/SAN authorization driven exclusively by policy.
3. Production-grade random issuer-unique serial reservation and durable issuance state machine.
4. RFC 5280 profile extensions and policy OID mapping (CP/CPS traceability).
5. Real software-provider lab lifecycle, later HSM/PKCS#11, CRL publication and independent review.

## Audit and standards posture

Implementation can later *facilitate* ETSI/ISO/eIDAS audits, but regulatory qualification is not implied. CP/CPS draft generation and controls catalog are documented requirements, **not yet implemented code**.
