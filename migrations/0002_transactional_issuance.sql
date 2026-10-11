-- Transactional issuance foundation v0.2, PostgreSQL 16.
-- The database stores requests/serials/transitions, NOT HSM key material.
-- External HSM signing and database commits are fundamentally non-atomic.
-- These routines are NOT a production authentication boundary.
--
-- Installation order: 0001_foundation.sql, then 0002_transactional_issuance.sql.
BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Exactly one request per CA and idempotency key.
-- Competing payloads under the same key are rejected rather than aliased.
CREATE FUNCTION create_issuance_request(
    p_ca_id UUID,
    p_idempotency_key TEXT,
    p_csr_sha256 BYTEA,
    p_requester_id TEXT,
    p_policy_version TEXT
)
RETURNS TABLE (request_id UUID, state TEXT, replay BOOLEAN)
LANGUAGE plpgsql AS $fn$
DECLARE
    v_row certificate_request%ROWTYPE;
    v_new_id UUID := gen_random_uuid();
    v_inserted INTEGER;
BEGIN
    IF p_idempotency_key IS NULL OR length(p_idempotency_key) NOT BETWEEN 1 AND 128
       OR p_csr_sha256 IS NULL OR octet_length(p_csr_sha256) <> 32
       OR p_requester_id IS NULL OR length(p_requester_id) NOT BETWEEN 1 AND 256
       OR p_policy_version IS NULL OR length(p_policy_version) NOT BETWEEN 1 AND 128
    THEN
        RAISE EXCEPTION 'invalid request input' USING ERRCODE = '22023';
    END IF;

    INSERT INTO certificate_request (
        request_id, ca_id, idempotency_key, csr_sha256,
        requester_id, policy_version, state
    ) VALUES (
        v_new_id, p_ca_id, p_idempotency_key, p_csr_sha256,
        p_requester_id, p_policy_version, 'RECEIVED'
    )
    ON CONFLICT (ca_id, idempotency_key) DO NOTHING;

    GET DIAGNOSTICS v_inserted = ROW_COUNT;

    SELECT * INTO STRICT v_row FROM certificate_request AS cr
    WHERE cr.ca_id = p_ca_id AND cr.idempotency_key = p_idempotency_key;

    IF v_row.csr_sha256 <> p_csr_sha256
       OR v_row.requester_id <> p_requester_id
       OR v_row.policy_version <> p_policy_version
    THEN
        RAISE EXCEPTION 'idempotency key reused with different payload'
            USING ERRCODE = '23505';
    END IF;

    IF v_inserted = 1 THEN
        INSERT INTO audit_event (
            event_id, ca_id, request_id, actor_id, event_type, decision, policy_version
        ) VALUES (
            gen_random_uuid(), p_ca_id, v_row.request_id, p_requester_id,
            'request.received', 'accepted', p_policy_version
        );
    END IF;

    RETURN QUERY SELECT v_row.request_id, v_row.state, v_inserted = 0;
END
$fn$;

-- Enforced state-transition graph. Authentication/authorization must be checked upstream
-- before this is callable. Such a boundary is NOT implemented in this milestone.
CREATE FUNCTION allowed_issuance_transition(p_from TEXT, p_to TEXT)
RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE STRICT AS $fn$
    SELECT (p_from, p_to) IN (
        ('RECEIVED', 'CSR_VALIDATED'),
        ('RECEIVED', 'REJECTED'),
        ('CSR_VALIDATED', 'AUTHORIZED'),
        ('CSR_VALIDATED', 'REJECTED'),
        ('AUTHORIZED', 'SERIAL_RESERVED'),
        ('SERIAL_RESERVED', 'SIGNING'),
        ('SIGNING', 'SIGNED'),
        ('SIGNING', 'RECONCILIATION_REQUIRED'),
        ('SIGNED', 'PUBLISHED')
    );
$fn$;

CREATE FUNCTION transition_issuance_request(
    p_ca_id UUID, p_request_id UUID, p_expected_state TEXT, p_next_state TEXT,
    p_actor_id TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_current TEXT;
    v_policy TEXT;
BEGIN
    IF p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR NOT allowed_issuance_transition(p_expected_state, p_next_state)
    THEN
        RAISE EXCEPTION 'invalid actor or issuance transition' USING ERRCODE = '22023';
    END IF;

    -- Locks precisely the addressed issuance; concurrent competing transitions serialize.
    SELECT cr.state, cr.policy_version INTO STRICT v_current, v_policy
    FROM certificate_request AS cr
    WHERE cr.ca_id = p_ca_id AND cr.request_id = p_request_id
    FOR UPDATE;

    IF v_current <> p_expected_state THEN
        RAISE EXCEPTION 'stale or invalid transition: expected %, found %',
            p_expected_state, v_current USING ERRCODE = '40001';
    END IF;

    IF p_next_state = 'SERIAL_RESERVED'
       AND NOT EXISTS (
           SELECT 1 FROM serial_reservation sr
           WHERE sr.ca_id = p_ca_id AND sr.request_id = p_request_id
       )
    THEN
        RAISE EXCEPTION 'serial must be durably reserved first' USING ERRCODE = '23514';
    END IF;

    IF p_next_state = 'SIGNED'
       AND NOT EXISTS (
           SELECT 1 FROM certificate c
           WHERE c.ca_id = p_ca_id AND c.request_id = p_request_id
       )
    THEN
        RAISE EXCEPTION 'signed certificate must be durably persisted first'
            USING ERRCODE = '23514';
    END IF;

    UPDATE certificate_request
    SET state = p_next_state, updated_at = now()
    WHERE ca_id = p_ca_id AND request_id = p_request_id;

    INSERT INTO audit_event (
        event_id, ca_id, request_id, actor_id, event_type, decision, policy_version
    ) VALUES (
        gen_random_uuid(), p_ca_id, p_request_id, p_actor_id,
        'request.transition', p_expected_state || ' -> ' || p_next_state, v_policy
    );

    RETURN p_next_state;
END
$fn$;

-- Generate 16-byte positive DER INTEGER content. The high nibble is bounded:
-- top bit cleared (positive); bit 6 set (non-zero, canonical 16-octet encoding).
-- Remaining 126 bits uniformly random. Unique per issuer through PK.
CREATE FUNCTION reserve_issuance_serial(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT
)
RETURNS BYTEA
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_serial BYTEA;
    v_existing BYTEA;
    v_attempt INTEGER;
BEGIN
    IF p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION 'invalid actor' USING ERRCODE = '22023';
    END IF;

    SELECT cr.state INTO STRICT v_state
    FROM certificate_request cr
    WHERE cr.ca_id = p_ca_id AND cr.request_id = p_request_id
    FOR UPDATE;

    IF v_state NOT IN ('AUTHORIZED', 'SERIAL_RESERVED') THEN
        RAISE EXCEPTION 'serial reservation requires authorized request'
            USING ERRCODE = '23514';
    END IF;

    SELECT sr.serial_der_content INTO v_existing
    FROM serial_reservation sr
    WHERE sr.ca_id = p_ca_id AND sr.request_id = p_request_id;

    IF FOUND THEN
        RETURN v_existing;
    END IF;

    IF v_state <> 'AUTHORIZED' THEN
        RAISE EXCEPTION 'serial reservation state has no reservation'
            USING ERRCODE = '23514';
    END IF;

    FOR v_attempt IN 1..16 LOOP
        v_serial := gen_random_bytes(16);
        v_serial := set_byte(v_serial, 0, (get_byte(v_serial, 0) & 63) | 64);
        BEGIN
            INSERT INTO serial_reservation (ca_id, request_id, serial_der_content)
            VALUES (p_ca_id, p_request_id, v_serial);
            EXIT;
        EXCEPTION WHEN unique_violation THEN
            IF v_attempt = 16 THEN
                RAISE EXCEPTION 'unable to reserve unique random serial'
                    USING ERRCODE = '23505';
            END IF;
        END;
    END LOOP;

    -- No signing action here. Explicit state transition and audit are done in
    -- the SAME transaction, so reservation/state/audit roll back together.
    PERFORM transition_issuance_request(
        p_ca_id, p_request_id, 'AUTHORIZED', 'SERIAL_RESERVED', p_actor_id
    );
    RETURN v_serial;
END
$fn$;

COMMENT ON FUNCTION reserve_issuance_serial(UUID, UUID, TEXT) IS
'Issuer-unique CSPRNG serial with durable reservation; assumes upstream authenticated authorized caller.';

-- PostgreSQL grants EXECUTE to PUBLIC for new functions by default. Revoke it.
-- Runtime roles receive narrowly scoped grants only after authentication and
-- authorization boundaries are implemented, reviewed and deployed.
REVOKE ALL ON FUNCTION create_issuance_request(UUID, TEXT, BYTEA, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION allowed_issuance_transition(TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION transition_issuance_request(UUID, UUID, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION reserve_issuance_serial(UUID, UUID, TEXT) FROM PUBLIC;

-- No direct tables are granted to a runtime role here. Use a distinct database
-- role with EXECUTE grants only AFTER building a trustworthy authenticated API.
-- Even EXECUTE permissions alone do not establish issuance authorization.
COMMIT;
