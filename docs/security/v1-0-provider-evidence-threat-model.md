# Security assurance: signing evidence, not signing authority (v1.0)

**Status:** security design + lab tests only; independent review pending. This document does not assert ISO, ETSI, ANSSI or eIDAS conformity.

## Trust topology

```
CA issuance service --(one sign request)-> Cryptographic provider
       |                                    |
       | intention stored                  | provider audit records
       v                                    v
PostgreSQL signing journal       Independent read-only audit collector
       |                                    |
       | TBS, issuer, request, policy       | raw logs + source verification (TODO)
       |                                    | signed canonical evidence statement
       +---------------> Review engine <----+
                               |
                      X.509 independent verifier
                               |
                        evidence proposal
                               |
                     second authorized reviewer
                               |
                    remain quarantined in v1.0
```

## Evidence statement semantics

`EvidenceClaim` is signed using ECDSA P-256/SHA-256 over a byte-for-byte canonical, length-prefixed and domain-separated message:

- outcome `SigningEventObserved`, `RetrievedSignedCertificate`, or `NoMatchingEvent`;
- observation timestamp **claimed by collector** (not trusted time);
- issuer, request, policy revision, signing operation reference, signer key reference;
- independent collector key identifier and unique event identifier;
- immutable signed TBS SHA-256, raw provider-log SHA-256;
- optional signed-certificate SHA-256, which is mandatory only for the retrieved-result outcome.

A protected configuration must pin the collector's public key. A signing key or key ID supplied by the same untrusted provider response is **never** an acceptable trust anchor. Test keys are volatile laboratory keys and must not be reused.

**Collector attestation is NOT HSM attestation.** A valid signature proves that the holder of the collector key signed these bytes. It does not itself validate the raw event's origin, completeness, ordering, configuration, honest interpretation, or that an HSM signed.

## Threats and expected boundaries

| Threat | Lab mitigation | Still required before production |
|---|---|---|
| Claim modified after collection | ECDSA signature verification | Collector key custody/rotation, release evidence |
| Correct claim signed by another collector | Pinned public key / key ID | Independently governed trust store, revocation |
| Claim replayed for another issuer/request | Signed CA ID, request ID and operation ref | Persistent global event uniqueness/replay rejection |
| Claim reused for different CP/CPS edition | Signed policy revision and TBS | Verified effective CP/CPS version repository and approval |
| Result swapped for different certificate | Signed cert SHA-256, independent X.509 signature/profile check | Trusted full RFC 5280 profile/time/revocation checks |
| Provider log altered/mismatched | Claimed raw log hash bound to result | Download and HSM-verify the **raw log**, retention/WORM |
| Provider reports no matching sign event | Classified as inconclusive | Source completeness proof; **no automatic re-sign** |
| Audit collector lies or omits events | None; a collector signature alone cannot detect this | Isolation, source attestation, independent sampling |
| Log is from another key/tenant | Signed CA/key/operation fields | Vendor-specific trusted key/object mapping |
| Cryptographic signing already succeeded but result lost | Durable intent + quarantine (v0.8) | Provider retrieval or never auto re-sign |
| Reviewer impersonation | Different caller strings in SQL | Real IdP integration, role separation, identity non-repudiation |
| Replay of a legitimately signed evidence statement | Not yet prevented by durable uniqueness enforcement | Event-ID uniqueness DB constraints and trusted timestamp checks |
| PostgreSQL privileged insider changes events | Application triggers reject mutation | Remote independently governed WORM/cryptographic anchoring |

## Non-bypassable product policy

1. A missing/ambiguous provider record NEVER implies that no signature was produced.
2. A valid audit event alone NEVER implies signed certificate DER is recoverable.
3. A verified recovered certificate is an **investigation candidate**, not an automatically approved/published certificate.
4. Human review does not create a new sign authorization or bypass the issuer's immutable TBS.
5. Any provider-specific downgrade in capability MUST be explicit and visible to operators; no hidden software signing fallback.
6. Signed collector attestation MUST NOT be marketed as a native HSM signature or as a qualified eIDAS audit trail.

## Acceptance gates beyond v1.0

- Signed audit collector build/release provenance and separately managed key custody.
- HSM audit verification according to **specific** target model/firmware, not generic PKCS#11 assumptions.
- Authoritative log-to-operation correlation, including what an event means: initialization versus completed signature.
- Evidence consistency/replay store, provider log ingestion and normalized record validation.
- Trusted time source, external immutable archive and cryptographic chain-of-custody.
- Authentication/RBAC and dual-control linked to human identities; pen test, backup/restore and DR exercises.
- Independent security evaluation, G0 IP/legal clearance, CP/CPS governance and ETSI/eIDAS controls applicability assessment.

Implementation: `crates/pki-core/src/provider_evidence.rs`; proof tests in
`crates/pki-core/tests/provider_evidence.rs` and `lab_verified_issuance.rs`.
