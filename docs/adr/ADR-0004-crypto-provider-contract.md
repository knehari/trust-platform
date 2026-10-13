# ADR-0004 — Cryptographic signing provider contract

Status: Proposed · 2026-10-13
Related: ADR-0002, ADR-0003, `docs/architecture/crypto-provider.md`, crate `crates/crypto-provider`

## Context
The initial candidate API `sign(key_ref, algorithm, message_or_digest, context)`
is ambiguous:
- "message or digest" allows double hashing, prehash/pure confusion (ML-DSA vs
  HashML-DSA, Ed25519 vs Ed25519ph) and algorithm-confusion bugs;
- `context` collides with the FIPS 204 ML-DSA context string `ctx`, while it is
  meant to carry the *authorization* context;
- it gives no way to distinguish a definitive signing failure from an
  **indeterminate** outcome (timeout, HSM session loss), which ADR-0002 needs;
- it does not require verification of the produced signature.

## Decision
### 1. Closed, typed algorithm identifiers
Algorithms are a closed Rust `enum` (`SignatureAlgorithm`), never strings or raw
OIDs. Each variant fully determines its parameters (hash, padding, salt length,
curve, ML-DSA parameter set, composite pairing). Mapping to/from
`AlgorithmIdentifier` is done in one audited place.

### 2. Explicit signing input
```rust
pub enum SignInput<'a> {
    /// Full message (e.g. DER TBSCertificate). Required for pure ML-DSA,
    /// SLH-DSA, Ed25519 and composite suites.
    Message(&'a [u8]),
    /// Digest computed by the caller. Only for algorithms that define a
    /// prehash mode (ECDSA, RSA-PSS, RSA PKCS#1 v1.5); the hash algorithm is
    /// implied by the SignatureAlgorithm and the digest length is checked.
    Prehashed(&'a [u8]),
    /// FIPS 204 external mu (PKCS#11 v3.2 style) for HSMs that support it.
    MlDsaExternalMu(&'a [u8; 64]),
}
```
`SignatureAlgorithm::accepts(&SignInput)` defines the compatibility table; any
other combination is rejected before reaching the provider.

Normative rules:
- **X.509 ML-DSA = pure ML-DSA with empty context string** (RFC 9881). HashML-DSA
  is not used for certificates or CRLs.
- RSA-PSS: MGF1 with the same hash, salt length = hash length.
- Ed25519: pure only (no Ed25519ph).
- ECDSA: deterministic (RFC 6979) or hedged nonces; never a caller-provided nonce.

### 3. Authorization is a separate, bound parameter
`sign` takes a `SigningAuthorization` (renamed from "context") that binds the
issuance intent ID, CA key reference, algorithm and **SHA-256 digest of the exact
bytes to be signed** (TBSCertificate / TBSCertList). The provider adapter
recomputes the digest and refuses on mismatch, so a compromised caller cannot
reuse an authorization to sign other content.

### 4. Outcome classification
```rust
pub enum SignError {
    Rejected(..),       // definitive: nothing was signed (bad input, policy, capability)
    Failed(..),         // definitive: provider reports failure, no signature exists
    Indeterminate(..),  // outcome unknown: MUST go to RECONCILIATION_REQUIRED (ADR-0002)
}
```
Adapters must classify conservatively: any error after the request may have
reached the HSM is `Indeterminate`.

### 5. Mandatory sign-then-verify
The CA core never persists or publishes a signature that it has not verified
with the CA public key, using a **verifier independent from the signing path**
(software verifier for HSM output). This detects fault-induced signatures
(e.g. RSA-CRT faults) and adapter bugs. A verification failure is treated as a
security event and the signature is discarded (never retried blindly).

### 6. Separation of duties
- `SigningProvider`: `capabilities()`, `public_key()`, `sign()` only.
- `KeyManagement` (generation, backup, rotation, destruction): a separate trait,
  never available to the online issuance service; used by key-ceremony tooling.
- `KeyRef` is an opaque handle; no API returns private key material.

### 7. Implementation candidates (to confirm by review)
- PKCS#11: `cryptoki` crate, adapter isolated in its own crate.
- Software lab provider: `aws-lc-rs` (FIPS-validated module, ML-DSA available)
  or RustCrypto crates. Sovereignty note: `aws-lc-rs` is vendor-maintained
  (Amazon) open source; dependency provenance and the acceptability of this
  choice for sovereign customers must be recorded in a dedicated decision.
- Secrets in memory: `zeroize` / `secrecy`.

## Consequences
- Provider adapters are small and testable against a shared conformance test
  suite (algorithm/input matrix, digest binding, outcome classification).
- The CA core owns hashing for prehash algorithms, which keeps hash selection
  out of adapters.
- Composite signing is implemented in the core over two component signatures,
  each produced through this contract with its own authorization.
