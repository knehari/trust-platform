# V1.6 — One-time policy approval challenge (design and acceptance contract)

Status: design only. No production anti-replay service is implemented by this document.

## Threat and objective
A valid dual-signed CP/CPS approval must not be accepted for a second workflow, different issuer, policy revision, document hash, or session. The signed 32-byte `decision_nonce` in v1.5 is externally supplied and currently does not prove issuance by a trusted service.

## Trusted challenge lifecycle
1. After independently verified protocol authentication and authorization, a dedicated challenge authority uses a CSPRNG to mint 256 random bits.
2. Persist a SHA-256 digest of the challenge with a unique challenge identifier, issuer/CA ID, draft ID, CP and CPS digest, policy revision, proposer and approver issuer-qualified stable subjects, session identifiers or cryptographic session bindings, issue time, expiry, and state `issued`.
3. Deliver a challenge bound to the immutable exact `ApprovalClaim`; require both participants to sign the same canonical claim.
4. During approval, verify both signatures, identity/role entitlements, current sessions or step-up authentication, claim field equality, and pending challenge binding.
5. In a single serializable database transaction, atomically consume the challenge using a conditional state change from `issued` to `consumed`, persist the verified signed receipt and its audit linkage, and reject zero-row updates/replays.
6. Never transition consumed or expired challenges back to issued. Cancellations and withdrawals create separately audited state transitions; retries are idempotent only when returning the same already-committed result to the same authenticated caller.

## Database invariants and adversarial tests
- Unique, unpredictable challenge identifier and nonce digest; explicit tenant/issuer foreign keys.
- Immutable binding to both reviewer subjects and the exact CP/CPS revision and hashes.
- Conditional update with `state='issued' AND expires_at > trusted_server_time` and returning the consumed row; verified receipt saved in the same transaction.
- Parallel clients must not both consume; run concurrent PostgreSQL tests with separate connections.
- Reject old/future challenges, swapped participants, changed claims, stale sessions, revoked entitlements, wrong issuer, and direct inserts by unprivileged accounts.
- Restrict DB roles: issuance, consumption, receipt writing, and privileged admin operations separated; enforce at the service boundary in addition to DB constraints.
- Only write a successful audit decision after commit. Audit publication via transactionally committed outbox; reconciliation handles failure.

## Assumptions and boundaries
- Trusted clock, cryptographically secure randomness and the protocol-specific identity adapters are prerequisites.
- Anti-replay is not provided by a nonce alone, nor by a Rust in-memory set across workers.
- A production API must not accept arbitrary `AuthenticationContext` or `TrustedReviewer` values directly from clients.
- This design does not imply that the documented CPS describes controls proven to exist or that any qualified trust-service audit has passed.
