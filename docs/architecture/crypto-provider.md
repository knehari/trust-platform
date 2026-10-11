# Cryptographic provider contract

Candidate API: `capabilities()`, `public_key(key_ref)`, `sign(key_ref, algorithm, message_or_digest, context)`.

## Requirements
Explicit algorithm and parameter negotiation; key handle never reveals private material; no silent fallback or downgrade; PKCS#11 semantics isolated behind adapter; key generation, backup and rotation operations separated from signing.

ML-DSA is a signature algorithm, ML-KEM is a KEM and must not be used to sign a CSR or certificate. Define byte-level signature input and prehash semantics per supported algorithm; do not assume RSA/ECDSA digest conventions apply to ML-DSA.

All cryptographic primitives come from reviewed libraries/providers. Validate provider capabilities before accepting policy.