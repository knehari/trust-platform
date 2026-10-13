# Issuance state machine

Normative decision: **ADR-0002**. Reference implementation: `crates/ca-core/src/issuance.rs` (transition table, unit-tested).

Nominal path: RECEIVED -> CSR_VALIDATED -> AUTHORIZED -> SERIAL_RESERVED -> SIGNING -> SIGNED -> PUBLISHED.

Failure / terminal states: REJECTED, FAILED_RETRYABLE, FAILED_FINAL, RECONCILIATION_REQUIRED, VOIDED.

## Transitions
| From | To |
|---|---|
| RECEIVED | CSR_VALIDATED, REJECTED |
| CSR_VALIDATED | AUTHORIZED, REJECTED |
| AUTHORIZED | SERIAL_RESERVED, REJECTED (authorization expired / policy changed) |
| SERIAL_RESERVED | SIGNING, REJECTED (policy re-check failed), VOIDED |
| SIGNING | SIGNED, FAILED_RETRYABLE, FAILED_FINAL, RECONCILIATION_REQUIRED |
| SIGNED | PUBLISHED |
| RECONCILIATION_REQUIRED | SIGNED (persisted certificate found and verified), VOIDED (burn + preventive revocation) |
| FAILED_RETRYABLE | VOIDED (a retry is a new intent with a new serial) |

PUBLISHED, REJECTED, FAILED_FINAL and VOIDED are terminal. Revocation is a separate certificate lifecycle (ACTIVE -> REVOKED), not an issuance state.

## Invariants
- CSR extensions never independently grant privileges.
- Authorization binds authenticated requester, CA, policy version, subject/SANs, public key, validity and an expiry; the policy is re-checked immediately before SIGNING.
- Serial numbers: ≥ 64 bits from a CSPRNG (implementation: 16 random octets), positive, DER-encoded in at most 20 octets, unique per issuer, **never reused**, including after failure.
- External HSM signing and PostgreSQL commits are **not** one atomic transaction. A durable intent (TBS + SHA-256 digest) is committed before signing.
- Every signature is verified (sign-then-verify) before the certificate is persisted.
- Ambiguous signing results require reconciliation, never blind re-signing; unresolved intents are VOIDED and their serial is revoked preventively.
- No certificate is considered published until persisted and publication confirmed.

## Tests
Negative policy tests, duplicate/idempotent requests, crashes before/after signing, retries, serial uniqueness, reconciliation (both outcomes), audit continuity.
