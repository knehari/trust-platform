# Signing-provider evidence: capabilities and non-capabilities (v1.0 lab)

**Status:** research-backed architecture decision, not an integration test against Thales, AWS KMS or any production HSM. Sources reviewed October 2026. Always verify the target firmware/API version in the proof of concept.

## 1. Important separation of responsibilities

A PKI must not equate the following:

1. **Cryptographic sign API:** signs data using a private key. It does not necessarily retain a result.
2. **Audit event:** indicates an action was logged; its existence can support incident investigation but does not imply the signature bytes are retrievable.
3. **Retrievable signed result:** original signature/certificate DER can be obtained from a durable provider-controlled store and independently cryptographically validated. This is an additional capability and must be demonstrated.

The standard PKCS#11 Cryptoki v3.1 `C_SignInit` and `C_Sign` functions support an active session and return a signature to the caller. The standard does **not define an application-level replay lookup by immutable `operation_ref`**. It cannot serve as a provider-independent guaranteed exactly-once signing ledger.

## 2. Provider capability assessment

| System / documented interface | Signing | Audit event | Lookup by our operation_ref | Recover original signed DER |
|---|---|---|---|---|
| Generic PKCS#11 3.1 | Supported via C_Sign | No generic durable audit guarantee in sign API | **Not standardized** | **Not standardized** |
| Thales Luna Network HSM 7 | Yes | Configurable HSM audit of signing events with protected logs and separate audit role | **Not demonstrated by official reviewed docs** | **Not demonstrated by official reviewed docs** |
| Thales Luna Cloud HSM + DPoD | Yes | DPoD Audit Query API, logs sign actions (client v10.2+ prerequisite) | **Not demonstrated**; fields are source/resource/actor/action/status/meta | **Not demonstrated** |
| AWS KMS Sign + CloudTrail | Yes; response returns signature | CloudTrail records Sign API calls and RequestID, key references | CloudTrail API-call lookup is not a stored signature retrieval API | **Not documented by Sign/CloudTrail API** |

**Interpretation:** a `SIGN` event and a successfully verified provider log entry can establish evidence of a cryptographic operation *within the applicable log configuration and provenance limits*. It does not automatically produce the X.509 signature or exact DER lost during a crash. Never infer that an absent log entry proves signing did not happen.

### Source documents

- [OASIS PKCS #11 v3.1, Signing and MACing](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/csd01/pkcs11-spec-v3.1-csd01.html#_Toc112478971) — C_SignInit, C_Sign, C_SignFinal.
- [Thales Luna Network HSM 7 — Audit Logging](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_hsm/audit/audit.htm) — independent audit user, log rotation and HMAC-based audit integrity.
- [Thales Luna 7 — Signing audit event categories](https://www.thalesdocs.com/gphsm/luna/7/docs/pci/Content/admin_hsm/audit/audit-log_categories_and_hsm_events.htm) — LUNA_SIGN and LUNA_SIGN_SINGLEPART event families (verify target model/firmware).
- [Thales Luna Cloud HSM — Service Audit Logs](https://thalesdocs.com/dpod/services/luna_cloud_hsm/service/audit_logs/index.html) — DPoD Audit Query API, sign-related event types.
- [AWS KMS API Sign](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html) — KeyId, Signature, SigningAlgorithm in response.
- [AWS CloudTrail record example for KMS Sign](https://docs.aws.amazon.com/kms/latest/developerguide/ct-sign.html) — requestID/eventID and API audit fields; responseElements is null in the example.

## 3. Architecture decision (preliminary)

**Vendor-neutral base implementation**: strict issuer-scoped signing intent, operation reference, reserved serial, TBS hash and database quarantine from v0.8–v0.9.

**Evidence collector adapter**: optional separate read-only integration captures and authenticates raw provider logs where available. A separately administered collector may sign a **canonical evidence envelope** using an **independently pinned key**. The signature attests to what the collector claims to have recorded, **not independently to what the HSM actually did**. Require verified source integrity, log continuity, trusted observation time, anti-replay storage, collector rotation, and source-to-operation binding in a real deployment.

**Recovered-result adapter**: may provide original certificate/signature bytes **only when the specific provider has demonstrated durable retrieval**. A recovered X.509 certificate must be independently verified against the authoritative issuer public key, exact persisted TBS, serial, SAN/profile and policy before it is considered a candidate. The process remains in quarantine until separately authenticated two-person review and a dedicated result-disposition operation exist.

**Fail-closed defaults**: do not deploy an adapter claiming retrievable results if the vendor API only returns audit events; never resubmit `C_Sign` after timeout without a reviewed provider idempotency protocol.

## 4. Vendor proof-of-concept acceptance checklist

1. Obtain exact hardware model, client/firmware revisions, deployment mode (network/cloud) and audit configuration.
2. Demonstrate whether a caller-supplied operation reference can be bound to an audit event, key, TBS fingerprint, cryptographic algorithm, actor and timestamp. Do not assume the audit log contains all of these.
3. Verify audit integrity with separate audit-role custody, file rotation, retention and actual HSM/provider validation API. Identify whether a log entry proves completion vs initialization.
4. Simulate network timeout and SIGKILL after `C_Sign`, verify forensic visibility and state classification.
5. Check whether original signature/certificate DER can be retrieved without a new signing operation; if not, mark retrieval **unsupported**.
6. Demonstrate least-privilege read-only access that cannot sign, export keys, or change audit settings.
7. Establish trusted timestamps, external immutable storage and evidence collector signing key lifecycle, including revocation/rotation.
8. Obtain independent PKI/security review and G0 legal/IP approval before target HSM access.

## 5. v1.0 code and limitations

`crates/pki-core/src/provider_evidence.rs` implements a **signed collector evidence statement** with deterministic domain-separated canonical encoding, ECDSA P-256/SHA-256 signature verification under a pinned collector key, expected issuer/operation/key/TBS digest correlation, and certificate/result hash binding. It reuses the independent X.509 verifier from v0.7 for retrieved-result candidates.

All verification is read-only. It does not call `sign`, persist a recovered result, transition to SIGNED, check true HSM provenance, or implement ETSI/eIDAS qualified practices. The lab unit tests sign collector envelopes using an ephemeral software key; those proofs MUST NOT be represented as original HSM attestations.
