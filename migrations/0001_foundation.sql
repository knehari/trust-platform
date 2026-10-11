-- Sovereign Trust Platform — PostgreSQL conceptual schema v0.1.
-- NOT YET INSTALLED IN A LIVE SYSTEM. No database adapter or migrations runner exists.
-- For production, enforce transaction boundaries, write privileges, backup/restore
-- and HSM reconciliation separately. All identifiers are supplied by the application.

BEGIN;

CREATE TABLE ca (
    ca_id UUID PRIMARY KEY,
    parent_ca_id UUID REFERENCES ca (ca_id),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 255),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE certificate_request (
    request_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    csr_sha256 BYTEA NOT NULL CHECK (octet_length(csr_sha256) = 32),
    requester_id TEXT NOT NULL CHECK (length(requester_id) BETWEEN 1 AND 256),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    state TEXT NOT NULL CHECK (
        state IN (
            'RECEIVED', 'CSR_VALIDATED', 'AUTHORIZED', 'SERIAL_RESERVED',
            'SIGNING', 'SIGNED', 'PUBLISHED', 'REJECTED',
            'RECONCILIATION_REQUIRED', 'FAILED_RETRYABLE', 'FAILED_FINAL'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ca_id, idempotency_key)
);

CREATE TABLE serial_reservation (
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    serial_der_content BYTEA NOT NULL CHECK (
        octet_length(serial_der_content) BETWEEN 1 AND 20
        AND get_byte(serial_der_content, 0) < 128
    ),
    request_id UUID NOT NULL UNIQUE REFERENCES certificate_request (request_id),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ca_id, serial_der_content)
);

CREATE TABLE certificate (
    ca_id UUID NOT NULL,
    serial_der_content BYTEA NOT NULL,
    request_id UUID NOT NULL UNIQUE REFERENCES certificate_request (request_id),
    fingerprint_sha256 BYTEA NOT NULL CHECK (octet_length(fingerprint_sha256) = 32),
    certificate_der BYTEA NOT NULL CHECK (octet_length(certificate_der) > 0),
    signed_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    PRIMARY KEY (ca_id, serial_der_content),
    FOREIGN KEY (ca_id, serial_der_content)
        REFERENCES serial_reservation (ca_id, serial_der_content)
);

CREATE TABLE revocation (
    ca_id UUID NOT NULL,
    serial_der_content BYTEA NOT NULL,
    reason_code SMALLINT NOT NULL CHECK (reason_code BETWEEN 0 AND 10),
    revoked_at TIMESTAMPTZ NOT NULL,
    invalidity_at TIMESTAMPTZ,
    actor_id TEXT NOT NULL,
    PRIMARY KEY (ca_id, serial_der_content),
    FOREIGN KEY (ca_id, serial_der_content)
        REFERENCES certificate (ca_id, serial_der_content)
);

CREATE TABLE crl_publication (
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    crl_number NUMERIC(39, 0) NOT NULL CHECK (crl_number >= 0),
    this_update TIMESTAMPTZ NOT NULL,
    next_update TIMESTAMPTZ NOT NULL,
    crl_sha256 BYTEA NOT NULL CHECK (octet_length(crl_sha256) = 32),
    published_at TIMESTAMPTZ,
    CHECK (this_update < next_update),
    PRIMARY KEY (ca_id, crl_number)
);

CREATE TABLE audit_event (
    event_id UUID PRIMARY KEY,
    ca_id UUID REFERENCES ca (ca_id),
    request_id UUID REFERENCES certificate_request (request_id),
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    decision TEXT NOT NULL,
    policy_version TEXT,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Defense in depth only. The database owner or superuser can bypass this
-- trigger; external append-only storage is needed for stronger audit integrity.
CREATE FUNCTION prevent_audit_modification() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_event records may not be updated or deleted';
END;
$$;

CREATE TRIGGER prevent_audit_update
    BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

COMMIT;
