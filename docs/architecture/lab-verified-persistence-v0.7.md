# PKI v0.7 — Cryptographically verified X.509 persistence (laboratory)

**Status:** code in draft [PR #7](https://github.com/knehari/trust-platform/pull/7), stacked on PR #6. Not merged or production ready.

## Demonstrated test path

1. Parse and independently verify PKCS#10 ECDSA P-256 CSR proof-of-possession.
2. Obtain an explicitly allowed lab profile, actor and CP-policy OID binding.
3. Create issuer-scoped idempotent request in PostgreSQL and reserve random serial durably.
4. Build the final X.509 v3 To-Be-Signed certificate **before** journaled signing.
5. Commit TBS SHA-256, signing key and single operation reference to the signing-intent table.
6. Sign with a process-local RustCrypto P-256 key via `ExternalSigner` interface.
7. Assemble DER certificate without altering the journaled TBS.
8. Independently verify the leaf's ECDSA signature against root SPKI, issuer identity, serial, exact TBS DER, single authorized SAN, BasicConstraints CA=false, digitalSignature KU, serverAuth EKU and explicit certificatePolicies OID.
9. Persist verified DER and SHA-256 with request transition to SIGNED, then independently query the database from a separate connection to confirm the stored certificate equals the signed result.
10. Retry the same operation and confirm the durable journal refuses a new signature.

## Negative cases

- Invalid signature is rejected by cryptographic verification.
- A certificate with another TBS is rejected even when it has a valid signature.
- Wrong DNS SAN is rejected by decoded ASN.1 comparison.
- Missing/unapproved policy OID is rejected.
- PostgreSQL journal replay refuses a second signing call.
- Additional fault-injection tests from PR #6 cover signer timeout, verification rejection and persistence failure.

## Hard security limits

- The issuer is ephemeral, its signing key cannot survive a restart, and the calling identity/policy origin are **not** established by an authenticated server boundary.
- The verifier is a *restricted laboratory verifier*, NOT a complete RFC 5280 path validation engine. It does not verify trusted wall-clock validity, revocation status, CA policy constraints across chains, algorithm retirement, SAN name constraints or qualification status.
- This first integration does **not** prove process termination/restart crash recovery or reconciliation of a real HSM operation. The prior fault-injection suite uses mocks for interruptions.
- The CP/CPS reference hash in this test is illustrative. It is not a real approved/published document, evidence record or registered policy OID.
- SQL result storage can be invoked by privileged database actors without the Rust verifier; isolate database roles, function grants, and a reviewed authentication boundary before deployment.
- No backup/restore, HSM/PKCS#11, CRL/OCSP, signed immutable audit anchoring or ETSI/eIDAS compliance can be claimed.

## Further engineering gates

- Implement stronger typed trusted issuance plans, server-side policy/CP revisions, and immutable authorization envelopes rather than caller-supplied strings.
- Add actual process SIGKILL fault injection, recovery scans of UNCONFIRMED intents, and HSM-signature operation references with authoritative reconciliation.
- Move signing behind an authenticated, mutually TLS-protected service, enforce DB ownership separation and least-privilege grants.
- Replace ephemeral issuer with offline root ceremonies and reviewed HSM lifecycle; add revocation and CRL services.
- Expand X.509 verifier or integrate fully independent RFC 5280 path validation, expiry, revocation and certificate profiles.
- Independent security review, G0 employer/IP, eIDAS and ETSI assessment scope separation.
