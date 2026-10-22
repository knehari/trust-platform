# Rust issuance orchestrator: fault containment v0.6

**Prototype only.** PR #6 is stacked on PR #5, not yet merged into main. The orchestrator is a lab protocol skeleton, not a deployment-grade CA issuance service.

## Flow

1. Obtain trusted and independently authenticated/authorized issuer, subject, policy, key, request ID and final immutable TBS.
2. Compute SHA-256 over exact TBS DER bytes.
3. Persist one immutable signing intent, including operation reference; do NOT sign if journal rejects or indicates replay.
4. Invoke external signer *at most once in this process* using the journalled operation reference.
5. Assemble certificate without changing previously journalled TBS.
6. Verify signature, issuer, profile, SAN, serial and policy against the verified issuance plan.
7. Persist verified DER, fingerprint, state and audit transactionally.

On timeout, verifier rejection or persistence ambiguity, mark the attempt `RECONCILIATION_REQUIRED` and never auto-retry signing. A database outage may also prevent that write, so recovered UNCONFIRMED intents **must be treated as ambiguous and reconciled**.

## Implemented interfaces

- `IssuanceJournal`: record intent, mark uncertain, persist verified certificate result.
- `ExternalSigner`: one signing call, operation key and immutable TBS input.
- `CertificateAssembler`: assemble a DER certificate.
- `CertificateVerifier`: independent verification boundary contract.
- `issue_once`: stateful call ordering and fail-closed error paths.

The `postgres-store` feature adapts these interfaces to functions introduced in SQL migration 0003.

## Tested faults

- Database refuses intent: **zero signing calls**.
- Signer returns failure: mark uncertain and refuse a second signing call.
- Assembled result fails verifier: no certificate persistence.
- Storage fails after signing: mark uncertain and refuse blind reissue.
- Disposable PostgreSQL integration: actual intent persistence, failure, replay prevention across separate database calls.

## Important missing implementation

The default `CertificateVerifier` is only a trait. Existing orchestrator unit tests use **test doubles**; they do not cryptographically validate a real certificate. A genuine X.509 verifier, issuer public-key binding, strict extension checks and production authenticated boundary remain mandatory. The Rust lab CA's signing process is **not yet wired as the orchestration signer**.

No HSM, TLS-authenticated service, production signing intent recovery, HSM event reconciliation, crash-kill test, signed audit anchoring, DR or regulatory qualification has been achieved.

## Security acceptance gate

A successful CI confirms tests of these software boundaries, not assurance that production calls are authorized or that crash recovery is complete. Before a pilot, perform independent review, fuzzing, fault injection under process termination, and legal/IP ownership clearance.
