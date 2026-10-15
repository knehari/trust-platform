# Crypto-agility by design — classical algorithms foundation

Status: **laboratory policy contract, not production support**. Branch is stacked on V4.0 and must not be merged while G0 employment/IP clearance and independent security review remain unresolved.

## Core design principles
- Separate **signature scheme**, **key type/size/curve**, **digest**, **issuer key**, **subject key**, **provider capability**, **certificate profile**, and **policy decision**. An RSA CA must be able to issue an EC-subject certificate (and vice versa) if the certificate profile and interoperability permit it.
- An algorithm being enumerated is NOT evidence of an executable signer. Provider advertising support is not evidence of verified custody or correct implementations.
- Fail closed: no silent fallback, downgrade, mutable default, or algorithm selection based only on CSR-provided metadata.
- Version and pin approved algorithm suites per CA/profile/tenant/policy and per signing operation. Publish a deprecation/migration timeline and generate actionable inventory impact reports.
- Signature encoding, DER AlgorithmIdentifier and SPKI rules, digest/prehash semantics, ECDSA deterministic or randomized nonce sourcing, and RSA-PSS MGF1/salt settings must be validated per suite; EdDSA uses intrinsic hashing.
- Separate cryptographic library implementation, PKCS#11/HSM adapters and remote KMS adapters. Keys stay within controlled custody. Require independent conformance, provenance and negative tests.
- Do not conflate TLS key agreement (X25519, ECDH, ML-KEM) with certificate signing algorithms (RSA-PSS, ECDSA, EdDSA, ML-DSA).
- RSA-2048 is an optional legacy compatibility profile, never an implicit recommendation. High-assurance policies may require >=3072, and RSA-8192 is subject to provider performance and platform interoperability.

## Planned support matrix (not implemented merely by this PR)
| Scheme | Parameters | Status |
| --- | --- | --- |
| RSA-PSS | RSA 2048/3072/4096/8192; SHA-256/384/512 | P0 provider + X.509 completion |
| RSA PKCS#1 v1.5 signature | RSA 2048/3072/4096/8192; SHA-256/384/512 | P0 compatibility, policy gated |
| ECDSA | P-256/SHA-256; P-384/SHA-384; P-521/SHA-512 | P0/P1 CA signing and interop |
| EdDSA | Ed25519; Ed448 | P1, restrict to compatible private profiles |
| PQC | ML-DSA 44/65/87 | Later, disabled until proven |

## Required end-to-end acceptance criteria
1. Create keys and issuer CA, import verified SPKI, validate cross-provider signatures and chain.
2. Verify PKCS#10 signature and actual key parameters independently from applicant metadata.
3. Bind issuer signature algorithm separately from subject public-key algorithm, persist authorized suite and version before calling signer.
4. Emit RFC 5280-compliant cert with exact signatureAlgorithm/AlgorithmIdentifier, key identifiers, authorized extensions and serial; validate through independent chain builder.
5. Cover revoke -> signed CRL publication and online status if supported by the released profile.
6. Test RSA key sizes and RSA-PSS parameter combinations, ECDSA curves, EdDSA semantics, algorithm mismatch, cross-family issues, revoked algorithms, and HSM unsupported operations.
7. Measure throughput, latency, HSM capability matrix and rollback/migration. Security review + SLO acceptance before production.
8. Provide actual conformance evidence for every provider/suite/profile; never infer implementation from this Rust policy module.

## Delivery sequence
A. Implement algorithm-neutral selection and validation contract (this PR).
B. Refactor existing fixed SignatureAlgorithm and legacy algorithm catalogue to use it; migrate callers without breaking published interfaces.
C. Implement/test classical crypto signers, verifiers and X.509 serializers using reviewed libraries and supported HSM adapters.
D. Demonstrate issuance and revocation integration, negative tests and OpenSSL interoperability per suite.
E. Add policy/version lifecycle, inventory and algorithm migration workflows; PQC follows as separately gated adapters.

This increment adds only a compile-time policy module and negative tests. It does not claim B–E are complete.
