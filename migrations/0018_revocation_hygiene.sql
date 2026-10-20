-- v0.18 (lab): revocation/CRL hygiene. LAB ONLY.
-- * reserve_crl locks the CA row FOR NO KEY UPDATE instead of FOR UPDATE
--   (0015/0016). Reservations still serialise with each other and with
--   approvals (FOR SHARE), so the snapshot guarantee is unchanged, but rows
--   that merely reference the CA (certificate_request, audit_event, ...) are
--   no longer blocked while a reservation is in progress. The comments in
--   0014 and 0015 that mention FOR UPDATE describe the earlier lock.
-- * ca_revocation_policy.suspension_cps_ref must contain a non-blank
--   character: ETSI targets require a CPS reference before allowing
--   suspension, and whitespace satisfied the 0014 NOT NULL/length check.
--   Existing blank values make this migration abort with nothing applied.
-- Apply after 0017 as the migration owner.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD CONSTRAINT suspension_cps_ref_not_blank
    CHECK (suspension_cps_ref IS NULL OR suspension_cps_ref ~ '[^[:space:]]');

CREATE OR REPLACE FUNCTION reserve_crl(p_ca UUID, p_actor TEXT, p_operation_ref TEXT)
RETURNS TABLE(crl_number BIGINT, this_update TIMESTAMPTZ, next_update TIMESTAMPTZ,
              expired_certs_on_crl_since TIMESTAMPTZ)
LANGUAGE plpgsql AS $fn$
#variable_conflict use_column
DECLARE
    v_created TIMESTAMPTZ;
    v_target TEXT := 'RFC5280';
    v_validity INTERVAL := INTERVAL '7 days';
    v_number BIGINT;
    v_this TIMESTAMPTZ;
    v_expired TIMESTAMPTZ;
    v_latest TIMESTAMPTZ;
BEGIN
    -- Fail closed: under REPEATABLE READ / SERIALIZABLE the transaction
    -- snapshot predates the CA row lock, so an approval that commits while
    -- this call waits would be missing from the snapshot although its
    -- decided_at precedes this_update.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'reserve_crl requires transaction isolation read committed (got %)',
            current_setting('transaction_isolation') USING ERRCODE='23514';
    END IF;
    IF p_ca IS NULL
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 1024
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION 'invalid CRL reservation input' USING ERRCODE='22023';
    END IF;
    -- FOR NO KEY UPDATE still conflicts with approve_certificate_status_change
    -- (CA row FOR SHARE) and with other reservations, but not with the
    -- FOR KEY SHARE taken by foreign-key checks of issuance-side inserts.
    SELECT c.created_at INTO v_created FROM ca c WHERE c.ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT p.conformance_target, p.crl_validity INTO v_target, v_validity
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca FOR SHARE;
    IF NOT FOUND THEN
        v_target := 'RFC5280';
        v_validity := INTERVAL '7 days';
    END IF;

    SELECT COALESCE(max(cp.crl_number), 0) + 1 INTO v_number
    FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_number > 9223372036854775806 THEN
        RAISE EXCEPTION 'CRL number space exhausted' USING ERRCODE='23514';
    END IF;
    v_this := date_trunc('second', clock_timestamp());
    -- Under the CA row lock: no concurrent reservation can add a later row.
    SELECT max(cp.this_update) INTO v_latest
    FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_latest > v_this THEN
        RAISE EXCEPTION 'clock is behind the latest CRL thisUpdate of this CA'
          USING ERRCODE='23514';
    END IF;
    IF v_target = 'ETSI_EN_319_411_2' THEN v_expired := v_created; END IF;

    -- One statement, one snapshot: the digest and the stored entries come
    -- from the same set of revocation rows.
    WITH cur AS MATERIALIZED (
        SELECT r.serial_der_content, r.revoked_at, r.reason_code, r.invalidity_at
        FROM revocation r WHERE r.ca_id = p_ca
    ), pub AS (
        INSERT INTO crl_publication(
            ca_id, crl_number, this_update, next_update, status, operation_ref,
            actor_id, entries_sha256, expired_certs_on_crl_since)
        SELECT p_ca, v_number, v_this, v_this + v_validity, 'RESERVED',
               p_operation_ref, p_actor,
               sha256(COALESCE((SELECT string_agg(
                   crl_entry_encoding(cur.serial_der_content, cur.revoked_at,
                                      cur.reason_code, cur.invalidity_at),
                   '\x'::bytea ORDER BY cur.serial_der_content) FROM cur), '\x'::bytea)),
               v_expired
        RETURNING 1
    )
    INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content,
                                   revoked_at, reason_code, invalidity_at)
    SELECT p_ca, v_number, cur.serial_der_content, cur.revoked_at,
           cur.reason_code, cur.invalidity_at
    FROM cur;

    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_actor, 'crl.reserved',
            'RESERVED:' || v_number);
    RETURN QUERY SELECT v_number, v_this, v_this + v_validity, v_expired;
END $fn$;

COMMIT;
