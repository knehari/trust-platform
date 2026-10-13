# X.509 / PKCS#10 requirements

Baseline: RFC 5280, RFC 2986, applicable algorithm profiles and interoperability requirements.

- Strict CSR signature (proof-of-possession) verification and DER parsing: size limit, DER only, no trailing data, canonical re-encoding.
- Exact `AlgorithmIdentifier` parameters: absent for ECDSA, Ed25519 and ML-DSA; NULL for RSA PKCS#1 v1.5; parsed and checked for RSA-PSS.
- Refuse CSRs carrying a CA public key, weak keys (RSA < 3072 outside the legacy profile, ROCA, invalid EC points) and ML-KEM keys used for signing.
- Enforce server-side subject/SAN policies and approved key algorithms; normalize names (IDN/punycode, case, trailing dot); wildcards only where policy allows; restrict DN string types (UTF8String, PrintableString).
- BasicConstraints, KeyUsage, ExtendedKeyUsage, SKI, AKI, AIA, CRLDP only as required by the selected profile; Name Constraints for subordinate CAs where applicable.
- Serial numbers: positive, ≥ 64 bits from a CSPRNG (implementation: 16 octets, top bit cleared = 127 bits), DER content ≤ 20 octets (a 20-octet positive integer has at most 159 significant bits), unique per CA, never reused.
- Validity: UTCTime for dates before 2050, GeneralizedTime from 2050 (RFC 5280 §4.1.2.5); bounded backdating; maximum validity per profile.
- Correct issuer and path length semantics.
- Reject unknown critical extensions unless explicitly supported.
- Validate resulting certificates with independent toolchains and test vectors (see `docs/testing/acceptance-gates.md`).

PQC: ML-DSA X.509 follows RFC 9881 (pure ML-DSA, empty context). Composite and SLH-DSA support follow ADR-0003. ML-KEM is not a signature algorithm.
