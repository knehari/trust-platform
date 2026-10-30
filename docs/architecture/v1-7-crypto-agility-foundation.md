# V1.7 — Crypto-agility foundation

**Status:** laboratory-only incremental design, stacked on PR #16. This is not production PQC support.

## Core invariant
An algorithm must satisfy three independently checked conditions before selection: (1) explicitly permitted by the operation's policy, (2) implemented and reviewed for the intended environment, and (3) supported by the actual signing provider. Unsupported, unknown or unapproved requests fail closed, without downgrade.

## Current catalogue
- ECDSA P-256 / SHA-256: laboratory software signing and signature verification.
- RSA-PSS / SHA-256: named in the Rust API but not implemented.
- ML-DSA-65: named in the Rust API but not implemented.
- Other classical or post-quantum algorithms: future catalogue/versioning changes, not presently supported.

## Required follow-up
1. Distinguish **algorithm identifier**, key generation, signing, verification, CSR parse/verify, X.509 SPKI/signature encoding, HSM/KMS mechanism, and relying-party interoperability as separate capabilities.
2. Introduce a versioned policy with effective dates, issuer profile and a deny-by-default algorithm list; include explicit transitions and exception audit trail.
3. Implement an independently tested signing-provider adapter with PKCS#11/HSM boundaries and robust error mapping. Never expose signing private keys through the API.
4. Add RSA-PSS and ECDSA P-384 support with standards-compliant parameter handling, negative tests and external interoperability test fixtures.
5. Implement ML-DSA signing/verification and certificate profile support only after choosing reviewed libraries, well-defined X.509 algorithms/OIDs and interoperable provider capability tests.
6. Treat hybrid signatures as explicit versioned profiles, not an automatic fallback or ad-hoc concatenation.
7. Keep ML-KEM out of the certificate-signature algorithm namespace: it is a key-encapsulation mechanism, not a signature scheme.

## Security note
The initial `select_lab_algorithm` only checks the declared laboratory capability. Production readiness requires a separate trusted capability attestation and complete end-to-end test, including verified key type, sign/verify and certificate encoding. Do not present laboratory selection as production issuance.
