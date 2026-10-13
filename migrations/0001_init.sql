-- trust-platform: initial schema (ADR-0002). PostgreSQL >= 15.
-- Not yet applied by code; reviewed as part of the design. No secrets are stored here.

BEGIN;

CREATE TABLE issuer (
    id              text PRIMARY KEY,
    algorithm_suite text NOT NULL,          -- ADR-0003: fixed at key creation
    key_ref         text NOT NULL,          -- opaque provider handle, never key material
    spki_der        bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE issuance_state AS ENUM (
    'RECEIVED', 'CSR_VALIDATED', 'AUTHORIZED', 'SERIAL_RESERVED', 'SIGNING',
    'SIGNED', 'PUBLISHED', 'REJECTED', 'FAILED_RETRYABLE', 'FAILED_FINAL',
    'RECONCILIATION_REQUIRED', 'VOIDED'
);

-- One row per reserved serial. Rows are never deleted (serials are never reused).
CREATE TABLE issuance_intent (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer_id         text NOT NULL REFERENCES issuer(id),
    serial            bytea NOT NULL CHECK (octet_length(serial) BETWEEN 1 AND 20),
    requester         text NOT NULL,
    idempotency_key   text NOT NULL,
    request_sha256    bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    policy_version    text NOT NULL,
    authorization_id  text NOT NULL,
    authorization_expires_at timestamptz NOT NULL,
    algorithm         text NOT NULL,
    state             issuance_state NOT NULL,
    tbs_der           bytea,
    tbs_sha256        bytea CHECK (tbs_sha256 IS NULL OR octet_length(tbs_sha256) = 32),
    max_not_after     timestamptz,           -- bounds preventive revocation
    certificate_der   bytea,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT serial_unique_per_issuer UNIQUE (issuer_id, serial),
    CONSTRAINT idempotency_unique UNIQUE (requester, issuer_id, idempotency_key),
    CONSTRAINT tbs_before_signing CHECK (
        state IN ('RECEIVED','CSR_VALIDATED','AUTHORIZED','SERIAL_RESERVED','REJECTED')
        OR state = 'VOIDED' OR tbs_der IS NOT NULL),
    CONSTRAINT certificate_when_signed CHECK (
        state NOT IN ('SIGNED','PUBLISHED') OR certificate_der IS NOT NULL)
);

CREATE TYPE revocation_origin AS ENUM ('REQUESTED', 'PREVENTIVE_RECONCILIATION');

CREATE TABLE revocation (
    issuer_id   text NOT NULL REFERENCES issuer(id),
    serial      bytea NOT NULL,
    reason      smallint NOT NULL,           -- RFC 5280 CRLReason
    origin      revocation_origin NOT NULL,
    revoked_at  timestamptz NOT NULL DEFAULT now(),
    keep_until  timestamptz,                 -- remove from CRL after this (max notAfter)
    PRIMARY KEY (issuer_id, serial),
    FOREIGN KEY (issuer_id, serial) REFERENCES issuance_intent(issuer_id, serial)
);

-- Tamper-evident audit log (SEC-05): hash chain, append-only, anchored by
-- signed checkpoints stored outside the database (see threat model, E3).
CREATE TABLE audit_event (
    seq          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at  timestamptz NOT NULL DEFAULT now(),
    actor        text NOT NULL,
    operation_id text NOT NULL,
    action       text NOT NULL,
    decision     text NOT NULL,
    policy_version text,
    payload      jsonb NOT NULL,
    prev_hash    bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    entry_hash   bytea NOT NULL UNIQUE CHECK (octet_length(entry_hash) = 32)
);

CREATE TABLE audit_checkpoint (
    seq          bigint PRIMARY KEY REFERENCES audit_event(seq),
    entry_hash   bytea NOT NULL,
    signature    bytea NOT NULL,             -- signed with the audit key (not a CA key)
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME;
END $$;

CREATE TRIGGER audit_event_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_event
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER audit_checkpoint_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_checkpoint
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER intent_no_delete BEFORE DELETE OR TRUNCATE ON issuance_intent
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- Least privilege: the issuance service role can append audit events but never
-- modify them. Role creation is environment-specific (not in this migration).
-- GRANT SELECT, INSERT ON audit_event TO trust_issuance;
-- GRANT SELECT, INSERT, UPDATE ON issuance_intent, revocation TO trust_issuance;

COMMIT;
