# Security requirements

Status: proposed; partially implemented in the lab skeleton (see `traceability.md`). Each requirement has an acceptance criterion and the evidence expected.

| ID | Requirement | Acceptance criterion | Evidence |
|---|---|---|---|
| SEC-01 | Deny by default for CA operations. | Any request not matched by an active policy rule is rejected; no default allow rule exists. | Negative policy tests in CI |
| SEC-02 | Authenticate requester and bind identity to issuance policy. | Every intent records an authenticated requester; unauthenticated requests never reach the policy engine. | Integration tests, audit records |
| SEC-03 | Authorize subject, SAN, EKU, key usage, CA profile, validity and algorithm server-side. | Each field is checked against policy; CSR extensions alone never change the outcome. | Policy test matrix |
| SEC-04 | No CA private keys or secrets in source, application DB or logs. | gitleaks clean in CI; DB schema stores only opaque key references; log fields reviewed. | CI secret scan, schema review |
| SEC-05 | Tamper-evident audit with actor, decision, policy version, operation ID. | Hash-chained events; signed checkpoints stored outside the DB; append-only enforced in DB; verification tool detects any modification. | Tamper test, `migrations/0001_init.sql` |
| SEC-06 | Reject unsupported/weak algorithms; no silent downgrade. | Closed algorithm enum; unknown OIDs rejected; policy referencing an unsupported suite fails at load; lab-only suites refused in production profiles. | `crypto-provider` tests |
| SEC-07 | Strict, bounded, fuzzed parsing of ASN.1/DER and CSRs. | Size limit, DER only, canonical re-encoding check; fuzz smoke on every PR and longer scheduled runs; no crash open. | `ca-core::csr` tests, fuzz CI |
| SEC-08 | Tested backup/restore and reconciliation. | Fault-injection suite (ADR-0002) passes; restore drill restores to a consistent state with no serial reuse. | Test reports, drill record |
| SEC-09 | CRL integrity and publication freshness. | CRLs signed and verified after signing; alert before `nextUpdate`; publication confirmed before reporting success. | Monitoring tests |
| SEC-10 | Dependency and release provenance. | Lockfile committed; cargo-deny (advisories, licences, sources) blocking; actions pinned by SHA; SBOM and signed releases from G2. | CI logs, SBOM |
| SEC-11 | Authorization binding and re-check. | Authorization bound to intent, key, algorithm and TBS SHA-256, with expiry; policy re-checked before SIGNING; idempotency key scoped to (requester, issuer). | `crypto-provider`, `store` tests |
| SEC-12 | CSR proof of possession and key checks. | PoP verified; CA keys refused; RSA < 3072 refused (legacy profile: 2048); invalid EC points, ROCA and known-weak keys refused. | `ca-core::csr` tests, weak-key vectors |
| SEC-13 | Name handling. | IDN/punycode, case and trailing-dot normalization; wildcard only where policy allows; DN string types restricted (UTF8String/PrintableString); Name Constraints on sub-CAs. | Name test vectors |
| SEC-14 | Sign-then-verify. | No certificate or CRL is persisted or published unless its signature verifies with an independent verifier. | `crypto-provider::sign_tbs` tests |
| SEC-15 | Serial numbers and randomness. | Serials from OS CSPRNG, ≥ 64 bits (127 implemented), positive, ≤ 20 octets, unique per issuer, never reused; RNG failure fails closed. | `ca-core::serial`, `store` tests |
| SEC-16 | Trusted time. | Authenticated time sync; skew alarm; backdating ≤ profile limit (default 5 min); UTCTime before 2050, GeneralizedTime from 2050. | Tests, monitoring |
| SEC-17 | Service-to-service authentication. | mTLS with pinned service identities between control plane, CA core and provider service. | Deployment tests |
| SEC-18 | Policy integrity. | Policies are versioned, signed or approved by two persons, and cannot be re-activated at an older version without audit. | Policy lifecycle tests |
| SEC-19 | Abuse resistance. | Rate limits and quotas per requester and per CA; bounded queues; HSM saturation does not lose intents. | Load tests |
| SEC-20 | Key ceremonies and separation of duties. | Root/intermediate key generation in HSM, m-of-n activation, scripted ceremony with witnesses and recorded evidence; KeyManagement not reachable from the online service. | Ceremony records |
