# Restricted laboratory X.509 certificate profile

Status: test-only; not a production X.509 profile.

## Root CA
- Native X.509 v3, ECDSA P-256/SHA-256, ephemeral signing key.
- BasicConstraints critical: CA=true, pathLenConstraint=0.
- KeyUsage critical: keyCertSign + cRLSign.
- Seven-day duration. Test cert serial constant 0x01, only to demonstrate encoding.
- **SKI/AKI not implemented.** Root offline ceremony and key durability are not implemented.

## Server end-entity
- CSR proof-of-possession verified ECDSA P-256 SHA-256 in strict DER.
- CN and DNS SAN read exclusively from separately approved policy authorization.
- BasicConstraints critical: CA=false.
- KeyUsage critical: digitalSignature.
- ExtendedKeyUsage noncritical: serverAuth.
- SAN noncritical: DNS names approved from bounded lab zone.
- Issuer signature algorithm must be ECDSA P-256/SHA-256, and duration cannot exceed 3 days.
- Test serial positive and issuer-unique only within the in-memory issuer instance.
- Signature is verified by a separate OpenSSL verifier; pass is **not proof** of full strict RFC5280 profile conformance.

## CP/CPS requirements to implement
- Bind approved `certificatePolicies` OID to issuance profile and immutable effective CP/CPS versions.
- Add approved policy URI and public CP/CPS publication states, not user-supplied CSR values.
- Introduce distinct signer/provider identifiers, auditable approval and backed-up serial transactions.
- Verify full interoperability in strict mode and hardened path processing.
