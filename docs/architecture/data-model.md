# Conceptual persistence model — v0.1

Entities:
- `ca`: immutable CA identity and active policy reference.
- `certificate_request`: requester, CSR fingerprint, idempotency key, status and policy decision.
- `serial_reservation`: unique (issuer_id, serial_bytes), allocated before signing, never reused.
- `certificate`: issuer, serial, DER fingerprint, lifecycle status and publication state.
- `revocation`: certificate identity, reason (0-6, 9, 10; never 7 or 8), invalidity/revocation timestamps (invalidity date limited to 1970-01-01 .. 9999-12-31 and never after the proposal or decision, so every CRL can encode it), `change_id` of the approved status change. Definitive revocations (reason other than 6) are irreversible; a hold (6) may be released or upgraded. Status transitions go through `certificate_status_change` (maker-checker, migration 0014).
- `crl_publication`: issuer, `crl_number` (BIGINT, per CA, strictly increasing, below 2^63; formerly NUMERIC), thisUpdate, nextUpdate, plus (migration 0015) `status` (`RESERVED`, `INTENT_RECORDED`, `STORED`, `RECONCILIATION_REQUIRED`, and from 0016 `ABANDONED`), `operation_ref`, `actor_id`, `entries_sha256`, `tbs_sha256`, `crl_der`, `expired_certs_on_crl_since`, and (0016) `intent_recorded_at`, set once by the intent. A `STORED` row is immutable. `abandon_stale_crl_reservations` retires `RESERVED` rows older than a threshold: they never recorded an intent, so they were never signed, and no intent can be recorded for them afterwards; their numbers stay taken. `reserve_crl` (0016) fails closed when the database clock is behind the CA's latest thisUpdate, so thisUpdate never decreases with the CRL number. `quarantine_stale_crl_intents` measures age from `intent_recorded_at` (from thisUpdate for intents recorded before 0016). `record_crl_intent` refuses an intent whose entries digest (computed by the Rust CA core from the reservation it signs), thisUpdate, nextUpdate or ExpiredCertsOnCRL date differ from the reservation. "Stored" is not "published": no distribution is implemented.
- `crl_entry_snapshot`: the revoked entries frozen when a CRL number is reserved, keyed by (CA, CRL number, serial); immutable.
- `audit_event`: actor, request correlation, policy version, decision, timestamp and integrity metadata.

Lab migrations 0001-0016 exist; no production schema is implemented. Transactional consistency cannot encompass an external HSM signature. Persist intent and reconcile ambiguous outcomes.
