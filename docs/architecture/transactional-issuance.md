# Transactional issuance persistence — foundation v0.2

**Status:** SQL prototype / migration and automated database tests, not an integrated or operational CA.

## Goals and proven data boundaries

- `create_issuance_request`: insert-once with unique (issuer, idempotency key). Only exact same CSR digest, actor and policy version replay to the same immutable request ID.
- `transition_issuance_request`: per-request PostgreSQL row lock, expected-state compare and transition graph, with same-transaction append-only audit event.
- `reserve_issuance_serial`: lock the request, verify AUTHORIZED, generate a positive, canonical 16-octet serial using `gen_random_bytes` (126 random bits), enforce issuer/serial uniqueness at database level, insert reservation and transition request to SERIAL_RESERVED in the **same transaction**.
- Signing state requires a reserved serial. SIGNED state requires a durably persisted certificate record; no blind transition from RECONCILIATION_REQUIRED back to SIGNING.
- Replays of serial reservation yield the same issuer-specific value. Random uniqueness is not a replacement for the database unique constraint.

## Deliberate limitation: external signing is not atomic with PostgreSQL

A signing operation sent to a real HSM may succeed while a process crashes before recording its result. A transaction cannot roll back an HSM signature. Therefore:

1. Persist signing intent, request fingerprint, approved policy, key reference and reserved serial.
2. Issue one deliberately keyed HSM request; record outcome and signed certificate.
3. On ambiguous failure, stop at RECONCILIATION_REQUIRED and investigate authoritative provider/certificate records; **never blindly retry**.
4. Persist a signed certificate and its fingerprint before advancing SIGNING -> SIGNED.
5. Operator-mediated reconciliation and a full signing-intent protocol have **not** been implemented in this increment.

## Trust boundaries and authorization

These SQL functions accept an actor ID provided by a caller and **do not authenticate** it. They have no deployed Go API or enforced CA policy binding. PUBLIC EXECUTE is revoked to avoid accidental execution; database roles and least-privilege function security need explicit design. Database ownership or superuser can still write tables or modify triggers. The audit log is not externally anchored or WORM.

Before any runtime use, separate schema ownership from runtime roles, enforce authenticating clients, authorize each action by issuer/profile, deny direct table mutation and test every negative permission path.

## CP/CPS and audit evidence connection

In subsequent migrations, link each request to its approved `certificatePolicies` OID, immutable CP/CPS revision and actual SHA-256 digest. These must be authoritative server-side objects, not caller-supplied attestations. The current lab OID and document digest **are fixtures**.

## Test coverage

`tests/transactional_issuance.sql` checks exact idempotent replay, changed-payload rejection, required authorization, transition validity, positive 16-byte random serial, database persistence, duplicate replay, issuer scoping, SIGNED-without-cert rejection, ambiguous signing fail closed and audit event counts.

`tests/transactional_concurrency.sh` stresses simultaneous request creation and serial allocation against a disposable PostgreSQL service. These tests establish SQL constraints under tested conditions, not a formal concurrency proof. Backup and restore remain to be designed and tested.

## Production acceptance gates (not yet met)

- Authenticating runtime API, source-bound request identity and least-privilege grants.
- Durable signing intent and ambiguous HSM operation reconciliation.
- Crash/restart and backup/restore tests, correct HSM key custody, persistent root.
- Offline-root ceremonies, PKCS#11 providers, CRL lifecycle, OCSP/AIA publication.
- Integrity-anchored audit and authorized qualified-profile CP/CPS control mappings.
- Independent code review, threat modeling and penetration testing.
