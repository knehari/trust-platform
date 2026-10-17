# Conceptual persistence model — v0.1

Entities:
- `ca`: immutable CA identity and active policy reference.
- `certificate_request`: requester, CSR fingerprint, idempotency key, status and policy decision.
- `serial_reservation`: unique (issuer_id, serial_bytes), allocated before signing, never reused.
- `certificate`: issuer, serial, DER fingerprint, lifecycle status and publication state.
- `revocation`: certificate identity, reason, invalidity/revocation timestamps, authorizer.
- `crl_publication`: issuer, CRL number, thisUpdate, nextUpdate, fingerprint and publication confirmation.
- `audit_event`: actor, request correlation, policy version, decision, timestamp and integrity metadata.

No production schema or migrations are implemented. Transactional consistency cannot encompass an external HSM signature. Persist intent and reconcile ambiguous outcomes.
