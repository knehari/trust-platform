# Threat model — v0.2

Status: draft for review · 2026-10-13. Scope: private PKI CA core (system-overview v0.1). Method: assets → trust boundaries → STRIDE per component → controls traced to requirements (`traceability.md`).

## Assets
| ID | Asset | Security property |
|---|---|---|
| A1 | CA private keys (root, intermediates) | Confidentiality, integrity of use |
| A2 | Audit checkpoint signing key | Confidentiality |
| A3 | Issuance policy and its versions | Integrity |
| A4 | Authenticated identities, authorizations | Integrity, authenticity |
| A5 | Certificate / serial / intent database | Integrity, availability |
| A6 | CRLs and their publication | Integrity, freshness |
| A7 | Audit log | Integrity (tamper evidence), availability |
| A8 | Trusted time source | Integrity |
| A9 | Backups (DB, configuration, wrapped keys) | Confidentiality, integrity |
| A10 | Credentials: DB, HSM PINs, service identities | Confidentiality |
| A11 | Build pipeline, dependencies, release artifacts | Integrity, provenance |

## Trust boundaries
TB1 User/API → authenticated control plane → TB2 policy engine → TB3 CA signing service → TB4 signing provider/HSM. TB5 persistence (PostgreSQL), TB6 publication (CRL distribution), TB7 time source, TB8 build/release pipeline, TB9 offline root ceremony environment.

## STRIDE analysis
| ID | Component / boundary | STRIDE | Threat | Controls | Req |
|---|---|---|---|---|---|
| T01 | TB1 control plane | S | Requester impersonation | Strong authentication, mTLS between services | SEC-02, SEC-17 |
| T02 | Policy engine | E | Unauthorized issuance (subject/SAN/EKU outside entitlement) | Deny by default; server-side policy; CSR extensions never grant | SEC-01, SEC-03 |
| T03 | Policy engine | T | Policy rollback / downgrade to an older, weaker version | Signed, versioned policies; monotonic activation; audit | SEC-05, SEC-18 |
| T04 | Issuance | T/E | Authorization replay or reuse for different content | Authorization bound to TBS digest, key, algorithm, expiry; idempotency scope | SEC-11 |
| T05 | Issuance | T | Policy changes between authorization and signing (TOCTOU) | Re-check before SIGNING; authorization expiry | SEC-11 |
| T06 | CSR parser | T/D | Malformed DER / BER, oversized input, parser crash | Size limit, strict DER, canonical re-encoding check, fuzzing | SEC-07 |
| T07 | CSR validation | S | No proof of possession; CA key submitted in CSR; weak keys (small RSA, ROCA, invalid EC points) | PoP verification, CA-key check, weak-key checks | SEC-12 |
| T08 | Subject/SAN | S/E | Name confusion: IDN homographs, case, trailing dot, wildcard abuse, DN encoding tricks | Normalization rules, explicit wildcard policy, Name Constraints for sub-CAs | SEC-03, SEC-13 |
| T09 | Signing provider | I | CA key theft or export | HSM, non-exportable keys, separate KeyManagement interface | SEC-04 |
| T10 | Signing provider | T | Faulty signature (RSA-CRT fault, adapter bug) leaks key or yields invalid cert | Sign-then-verify with independent verifier | SEC-14 |
| T11 | Signing provider | T | Algorithm confusion: prehash vs pure, wrong hash, ML-KEM used as signature | Closed algorithm enum, explicit `SignInput`, compatibility table | SEC-06 |
| T12 | Signing ↔ DB | T/R | Ambiguous outcome → duplicate certificate with same serial, or untracked certificate | Durable intent, reconciliation, burn + preventive revocation | SEC-08, SEC-11 |
| T13 | Serial numbers | T | Predictable serials enabling chosen-prefix collision; reuse | ≥ 64 bits CSPRNG (127 used), UNIQUE constraint, never released | SEC-15 |
| T14 | Randomness | T | Weak or failed RNG (serials, nonces, keys) | OS CSPRNG only; fail closed on RNG error | SEC-15 |
| T15 | Time source | T | Clock manipulation → backdated/postdated validity, stale CRL | Authenticated time sync, skew monitoring, bounded backdating | SEC-16 |
| T16 | CRL | T/D | Manipulated, stale or missing CRL | Signed CRLs, freshness monitoring, publication confirmation | SEC-09 |
| T17 | DB | T | DBA or attacker rewrites audit log / intents | Hash chain + signed checkpoints stored outside DB, append-only triggers and grants | SEC-05 |
| T18 | Logging | I/T | Secrets in logs; log injection | Structured logging, no secret fields, encoding of untrusted values | SEC-04, SEC-05 |
| T19 | Service | D | Signing exhaustion (HSM throughput), request floods | Rate limits and quotas per requester, bounded queues | SEC-19 |
| T20 | Credentials | I | DB password / HSM PIN leakage via repo, env, logs | Secret manager, secret scanning in CI, rotation | SEC-04, SEC-10 |
| T21 | Backups | I/T | Backup theft or tampering; untested restore | Encrypted, integrity-protected backups; restore drills | SEC-08 |
| T22 | Software provider | I | Timing side channels in software signing (lab) | Constant-time reviewed libraries; software provider lab-only | SEC-06, SEC-14 |
| T23 | Supply chain | T | Malicious or vulnerable dependency, compromised CI action, unsigned release | Pinned deps and actions (SHA), cargo-deny, SBOM, provenance, signed releases | SEC-10 |
| T24 | Insider | E/R | Privileged abuse (issuing for oneself, policy change, key ceremony) | Role separation, two-person control for policy/key operations, audit | SEC-05, SEC-20 |
| T25 | Root CA | E | Root key misuse or incomplete ceremony | Offline root, scripted ceremony, m-of-n, witnesses, recorded evidence | SEC-20 |
| T26 | PQC transition | T | Silent fallback to classical-only, or draft composite OIDs in production | Suite fixed per CA, lab-only flags, policy load validation | SEC-06 |

## CA key compromise response (to be detailed in a runbook)
1. Detect / declare (who may declare, criteria). 2. Stop issuance for the affected CA. 3. Revoke the CA certificate at the parent; publish CRL. 4. Notify relying parties per policy. 5. Re-key and re-issue subordinate material. 6. Forensics and post-mortem. Exercise at least once before gate G4.

## Residual risks and open items
- Composite signatures rely on an IETF draft until RFC publication (ADR-0003).
- Software provider is lab-only; side-channel guarantees depend on the selected library.
- Risk scoring (likelihood × impact) and an independent review remain required before a non-critical pilot (G4).
