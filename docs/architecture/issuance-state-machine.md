# Issuance state machine

RECEIVED -> CSR_VALIDATED -> AUTHORIZED -> SERIAL_RESERVED -> SIGNING -> SIGNED -> PUBLISHED.

Failure states: REJECTED, FAILED_RETRYABLE, FAILED_FINAL, RECONCILIATION_REQUIRED.

## Invariants
- CSR extensions never independently grant privileges.
- Authorization binds authenticated requester, CA, policy version, subject/SANs, public key and validity.
- Positive serial numbers unique per issuer and at most 20 octets in RFC 5280 conforming certificates; never reuse a reserved serial.
- External HSM signing and PostgreSQL commits are **not** one atomic transaction. Use durable intent records, idempotency keys and reconciliation.
- No certificate is considered published until persisted and publication confirmed.
- Ambiguous signing results require reconciliation, not blind re-signing.

## Tests
Negative policy tests, duplicate requests, crashes before/after signing, retries, serial uniqueness, audit continuity.