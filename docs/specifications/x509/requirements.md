# X.509 / PKCS#10 requirements

Baseline: RFC 5280, RFC 2986, applicable algorithm profiles and interoperability requirements.

- Strict CSR signature verification and DER parsing.
- Enforce server-side subject/SAN policies and approved key algorithms.
- BasicConstraints, KeyUsage, ExtendedKeyUsage, SKI, AKI, AIA, CRLDP only as required by the selected profile.
- Positive unique serial per CA, max 20 octets per RFC 5280.
- Correct validity, issuer and path length semantics.
- Reject unknown critical extensions unless explicitly supported.
- Validate resulting certificates with independent X.509 toolchains and test vectors.

PQC ML-DSA X.509 support is separate and must follow RFC 9881 and relevant evolving standards. ML-KEM is not a signature algorithm.