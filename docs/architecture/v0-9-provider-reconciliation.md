# PKI v0.9 — Read-only provider reconciliation and maker/checker review

**Status:** engineering laboratory prototype, stacked draft PR #9. No real HSM integration, no authenticated production service, and no approval to publish or reissue certificates.

## Why this increment exists

A database cannot determine whether a remote HSM signed after an application lost the network response. v0.8 safely quarantined such cases; v0.9 adds a **read-only inspection contract** and a **two-person review ledger**. These must never be confused with cryptographic proof of provider execution or with a qualified QTSP control.

## Rust module: `reconciliation.rs`

- `ReadOnlySigningProvider::lookup(operation_ref, signer_key_ref)` deliberately has no signing method.
- `ProviderResponse::SignedCertificate` provides candidate DER, operation/key reference and provider evidence hash.
- `NoResultFound` is explicitly **not** proof the operation was never performed; `Unknown` remains inconclusive.
- `inspect_provider` rejects missing/changed TBS digest, operation/key reference mismatch, oversized/missing result, zero evidence hash and certificates rejected by the independently supplied `CertificateVerifier`.
- A positive finding returns a certificate SHA-256 plus provider evidence SHA-256, **not** a permission to change database state.
- The Rust lab integration uses an **in-memory mock read-only provider that returns a genuinely signed ECDSA P-256 X.509**; it checks that forged DER and mismatched intent hashes fail. No live provider or authenticated provider statement is yet available.

## PostgreSQL migration `0005_reconciliation_review.sql`

- `signing_reconciliation_review` correlates one quarantined issuer/request/intent to an existing `PROVIDER_RESULT_OBSERVED` observation, TBS hash, operation reference, proposed signed-result digest and maker identity.
- `propose_reconciliation_review` requires matching prior intent, qualifying observation and `RECONCILIATION_REQUIRED`. No missing/changed policy references are tolerated.
- `review_reconciliation_proposal` requires a **different checker actor** and matching proposed cert/evidence digests. A row lock and single state transition guard duplicate approvals.
- All review actions append audit events. A table trigger blocks edits to immutable proposal fields, deletion and further changes after the first review.
- **Even reviewed proposals keep the request quarantined**; the database does not store a certificate or allow signing. A future separate recovery transaction would require a verified original certificate, authenticated authority, HSM provider evidence and additional governance.
- **These SQL functions accept caller-supplied actors and asserted digests. They do not authenticate identities, verify provider signatures, validate CP/CPS approvals or independently validate X.509.** Tables and triggers can be bypassed by database superusers. Treat this as defense-in-depth rather than complete maker/checker enforcement.

## Regression matrix

| Threat/condition | Expected behavior |
|---|---|
| Remote provider timeout / inconclusive response | Unknown; keep quarantined |
| Provider says no matching operation | Record absence evidence only; NEVER conclude no signature |
| Forged or invalid X.509 certificate | Reject in independent Rust verifier |
| Changed operation/key reference | Reject correlation |
| Wrong TBS hash | Reject before reading provider |
| Wrong/missing evidence digest | Reject |
| Not-quarantined request | Database denies review proposal |
| Attempt to reuse a no-result observation | Database denies signed-result proposal |
| Maker approves their own evidence | Database denies |
| Checker compares changed hashes | Database denies |
| Second approval, manual edits, deleting review row | Database denies |
| Successful two-person review | Record review and audit; **do not transition to SIGNED or publish** |

## Critical acceptance gates outstanding

1. Actual authenticated read-only connector for target HSM/provider, including its **documented** ability (or inability) to look up operation IDs or fetch signed results.
2. Verified provider evidence origin, independent timestamp and external append-only archive; the hash alone is insufficient.
3. API authentication, issuer-scoped RBAC and distinct privileged approver identities.
4. Formal dual-approval workflow with named human approvers, enforceable identity and policy authorities.
5. Secure provider-independent artifact repository and a separate audited, idempotent commit of an independently verified recovered result. No automatic re-sign.
6. HSM test environment, key ceremonies, disaster recovery and independent security/PKI assessment.
7. G0 employer intellectual property/license separation, before merging or pilot.

## Evidence

- [PR #9 — v0.9](https://github.com/knehari/trust-platform/pull/9)
- [Jira TRUST-84](https://knehari.atlassian.net/browse/TRUST-84)
- [v0.8 recovery protocol](v0-8-crash-recovery.md)
- [Ambiguous signing runbook](../operations/ambiguous-signing-reconciliation.md)
