# Laboratory capability registry — TRUST-26 / TRUST-43

`AlgorithmSuite` remains the typed identity: signature scheme, key parameters and digest. `suite_registry::registered_backend` maps exact valid suites to implemented software routes; `compiled_backend` additionally accounts for feature and platform availability. Neither function claims OpenSSL runtime availability, CSR support, profile conformance, durable issuance or qualification.

`LaboratorySigner::supported_suites` derives availability from its actual key parameters and implementation route. The same route now participates in sign/verify authorization, so an advertised catalogue and dispatch cannot diverge silently. The policy allowlist, key reference and issuer-key binding remain required. OpenSSL-backed keys expose only their exact generated suite. Candidate catalogue records remain Planned and production-disabled: implementation and qualification are different dimensions.

The legacy RSA-PSS SHA256 descriptor now accurately reports LabOnly rather than NotImplemented. A real provider and explicit policy remain necessary; no default key size is inferred and the legacy-to-typed RSA bridge still returns AmbiguousRsaKeySize. Existing public APIs and errors remain available.

## Acceptance for this increment

- Default builds have no compiled software signing routes.
- One RSA2048 key signs/verifies all six PSS/PKCS1 × SHA2 combinations through the dispatcher; tampering, cross-scheme verification, wrong size/key reference and missing policy fail.
- P256 and all four existing OpenSSL routes agree with measured per-key discovery and retain real sign/verify tests.
- Legacy RSA-PSS selection reaches a real RSA3072 provider and verifies a fresh signature from its public SPKI; unsupported provider and denied policy fail.
- Invalid combinations and ML-DSA have no route; all candidates remain production-disabled.

## Remaining phase-3 debt

This is a first executable registry increment, not completion of crypto-agility. Independent provider/profile evidence, CSR PoP for P384/P521/EdDSA/PSS, all RSA sizes/digests (especially positive RSA8192), unified operation types, durable typed issuance and HSM qualification remain open. A source route for RSA8192 is explicitly not a successful test result. Existing separate issuer/subject-key policy and X.509 identifiers are preserved. ML-KEM is not a certificate signature scheme and is not added to this registry.
