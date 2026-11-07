# v0.8 — SIGKILL crash quarantine and signing reconciliation evidence

**Lab-only architecture increment. Not an operational CA, not qualified and not proof of production disaster recovery.**

## Security property

After a durable `SIGNING` intent is committed, an HSM/signing operation may succeed even if the application crashes before storing its certificate. **Never re-sign the request automatically.**

An unresolved intent must become `RECONCILIATION_REQUIRED` with its immutable `operation_ref`, `signer_key_ref`, `request_id`, `intent_id` and `tbs_sha256` preserved for independently authorized investigation.

## Implemented in PR #8

1. Migration `0004_signing_recovery.sql`: `quarantine_stale_signing_intents` scans one issuer and selected age cutoff, locks request rows with `FOR UPDATE OF cr SKIP LOCKED`, and marks unfinished `SIGNING/UNCONFIRMED` intentions uncertain in the **same database transaction** as the audit event. Completed results and other issuers are untouched.
2. `signing_reconciliation_observation`: append-only database entries with actor, observation type, evidence SHA-256 and timestamp. Observations cannot mark the request SIGNED, approve a new signing attempt, or assert compliance. The database owner can override the trigger; external anchoring remains needed.
3. Rust `PgIssuanceStore::quarantine_stale`: checked parameters, issuer scoping and typed recovery candidate metadata. No signer access or re-sign capability.
4. SQL negative tests: age cutoff, scope isolation, completed certificate exclusion, repeated scan idempotence, denied status rollback, immutable observations and audit event uniqueness.
5. **Real process-kill test:** `crash_recovery_lab` validates an actual PKCS#10, builds a policy-scoped X.509 TBS, persists the signing intent, invokes a real process-local RustCrypto ECDSA P-256 sign operation, verifies signed DER in RAM, and prints `SIGNED_VERIFIED_NOT_STORED`. CI sends kernel **SIGKILL** to that process *before* the signed certificate reaches PostgreSQL. An independent second Rust process scans the unresolved intent, quarantines it and refuses any re-sign. A repeat scan changes nothing.

The interrupted signer key is **ephemeral** and lost on SIGKILL. The test proves conservative *discovery and quarantine*, not completion of a previously signed certificate nor recovery of a key.

## Non-goals and unresolved production risks

- **No real HSM**, provider operation journal, independent HSM forensic confirmation, backed-up keys or durable signed-result outbox.
- No automatic recovery from RECONCILIATION_REQUIRED to SIGNED, even when evidence exists. That transition requires independently verified certificate bytes, issuer/key/policy/serial/TBS controls, dual approval and separately designed reconciliation.
- No production authentication, authorization/RBAC, runtime DB role separation, TLS database transport, external WORM evidence or trusted audit time.
- `min_age_seconds=0` is permitted **only** for the disposable CI crash test. In a service, select a grace period longer than normal expected signing durations; in-flight legitimate signatures must not be prematurely quarantined.
- The test's CP OID and CP/CPS hash are placeholders, not owned, approved or published organizational policies.
- Real system **exactly-once cryptographic signing cannot be guaranteed** without a signing-provider idempotency contract and independent operation history. Database transactions alone cannot make an external HSM sign atomic.
- Concurrency and SIGKILL tests are regression evidence, not a formal safety proof.

## Production-grade next gates

- Design a signed-result evidence/outbox protocol that persists the *verified* certificate before external publication, with atomic intent and result correlation.
- HSM provider-specific reconcile-by-operation-reference and independent evidence attestation. No blind retry.
- Authenticate recovery workers and restrict them by issuer; apply database principal separation and deny direct table access.
- Test actual recovery under HSM partial failures, abrupt host power-off, network partition, schema migration, backup/restore and clock shifts.
- G0 employer IP/legal separation, supply-chain reviews and independent PKI security/penetration assessment.
