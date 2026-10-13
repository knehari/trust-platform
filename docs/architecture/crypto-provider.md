# Cryptographic provider contract

Normative decision: **ADR-0004**. Algorithm strategy: **ADR-0003**. Reference types: crate `crates/crypto-provider`.

API: `capabilities()`, `public_key(key_ref)`, `sign(key_ref, algorithm, SignInput, SigningAuthorization) -> Result<Signature, SignError>`.

## Requirements
- Closed, typed algorithm identifiers; explicit parameter negotiation; no silent fallback or downgrade.
- Explicit signing input: `Message`, `Prehashed` or `MlDsaExternalMu`; incompatible algorithm/input combinations are rejected before reaching a provider.
- Signing authorization is bound to the intent ID, key, algorithm and digest of the exact TBS bytes; adapters re-check the digest.
- Outcome classification `Rejected` / `Failed` / `Indeterminate`; any `Indeterminate` result enters reconciliation (ADR-0002).
- Mandatory sign-then-verify with an independent verifier before persistence or publication.
- Key handle never reveals private material; key generation, backup and rotation are a separate `KeyManagement` interface, not reachable from the online issuance service.
- PKCS#11 semantics isolated behind an adapter crate.

ML-DSA is a signature algorithm; ML-KEM is a KEM and must never sign a CSR, certificate or CRL. X.509 uses **pure ML-DSA with an empty context string** (RFC 9881); RSA/ECDSA digest conventions do not apply to ML-DSA.

All cryptographic primitives come from reviewed libraries/providers. Validate provider capabilities before accepting a policy.
