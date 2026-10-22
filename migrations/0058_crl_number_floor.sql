-- v0.58 (lab): CRL number floor after restoring an older backup
-- (RFC 5280 5.2.3). LAB ONLY.
-- The next CRL number is the CA's highest stored number plus one. After a
-- database is restored from a backup older than the last published CRL,
-- that maximum goes back, and the next CRL would reuse a number relying
-- parties already hold with different content. The external audit
-- checkpoint detects the rollback (tests/revocation_backup_restore.sh);
-- nothing stopped the reuse.
-- * crl_number_floor: append-only, one row per raise (CA, floor, reason,
--   who, when).
-- * raise_crl_number_floor(ca, floor, reason): superuser only (no grant),
--   under the CA row lock that reservations take. The floor must be above
--   both the highest stored number and the current floor (it only rises).
--   Writes a crl.number_floor.raised audit event.
-- * reserve_crl: the next number is above both the stored maximum and the
--   floor. Numbers stay increasing; a gap is allowed by RFC 5280.
-- The floor is the highest number known to be published (the distribution
-- point or a relying party's copy); choosing it is an operator decision.
-- Revocations recorded after the backup are not restored by this.
-- Apply after 0057 as a superuser.
BEGIN;

CREATE TABLE crl_number_floor (
    floor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    floor BIGINT NOT NULL CHECK (floor BETWEEN 1 AND 9223372036854775805),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    raised_by TEXT NOT NULL DEFAULT session_user,
    raised_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX crl_number_floor_ca ON crl_number_floor (ca_id, floor);
ALTER TABLE crl_number_floor OWNER TO trust_revocation_owner;
REVOKE ALL ON crl_number_floor FROM PUBLIC;

CREATE FUNCTION guard_crl_number_floor() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'crl_number_floor is append-only' USING ERRCODE = '23514';
END $fn$;
ALTER FUNCTION guard_crl_number_floor() OWNER TO trust_revocation_owner;
ALTER FUNCTION guard_crl_number_floor() SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION guard_crl_number_floor() FROM PUBLIC;
CREATE TRIGGER crl_number_floor_append_only
    BEFORE UPDATE OR DELETE ON crl_number_floor
    FOR EACH ROW EXECUTE FUNCTION guard_crl_number_floor();
CREATE TRIGGER crl_number_floor_no_truncate
    BEFORE TRUNCATE ON crl_number_floor
    FOR EACH STATEMENT EXECUTE FUNCTION guard_crl_number_floor();

-- Invoker rights, granted to nobody: a superuser raises the floor as part
-- of a restore, like acknowledge_schema_changes.
CREATE FUNCTION raise_crl_number_floor(p_ca UUID, p_floor BIGINT, p_reason TEXT)
RETURNS BIGINT
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
DECLARE
    v_current BIGINT;
BEGIN
    IF p_ca IS NULL OR p_floor IS NULL OR p_reason IS NULL
       OR p_floor NOT BETWEEN 1 AND 9223372036854775805
       OR length(p_reason) NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'invalid CRL number floor' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM public.ca c WHERE c.ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE = '22023';
    END IF;
    SELECT GREATEST(COALESCE((SELECT max(cp.crl_number) FROM public.crl_publication cp
                              WHERE cp.ca_id = p_ca), 0),
                    COALESCE((SELECT max(f.floor) FROM public.crl_number_floor f
                              WHERE f.ca_id = p_ca), 0))
    INTO v_current;
    IF p_floor <= v_current THEN
        RAISE EXCEPTION 'CRL number floor % does not rise above %', p_floor, v_current
          USING ERRCODE = '23514';
    END IF;
    INSERT INTO public.crl_number_floor (ca_id, floor, reason) VALUES (p_ca, p_floor, p_reason);
    INSERT INTO public.audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, session_user, 'crl.number_floor.raised',
            'FLOOR:' || p_floor || ':previous=' || v_current);
    RETURN p_floor;
END $fn$;
REVOKE ALL ON FUNCTION raise_crl_number_floor(uuid, bigint, text) FROM PUBLIC;

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
    v_reserved TIMESTAMPTZ;
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

    -- 0058: never at or below a floor raised after a restore.
    SELECT GREATEST(COALESCE(max(cp.crl_number), 0),
                    COALESCE((SELECT max(f.floor) FROM crl_number_floor f
                              WHERE f.ca_id = p_ca), 0)) + 1 INTO v_number
    FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_number > 9223372036854775806 THEN
        RAISE EXCEPTION 'CRL number space exhausted' USING ERRCODE='23514';
    END IF;
    -- Exact reservation time, taken under the CA row lock like the decided_at
    -- of approvals: coverage compares it with decided_at (thisUpdate is
    -- truncated to the second).
    v_reserved := clock_timestamp();
    v_this := date_trunc('second', v_reserved);
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
          -- 0031: expired entries leave once a stored CRL issued after the
          -- certificate expired has listed them (RFC 5280 3.3).
          AND NOT crl_entry_pruned_from(p_ca, r.serial_der_content, v_number)
    ), pub AS (
        INSERT INTO crl_publication(
            ca_id, crl_number, this_update, next_update, status, operation_ref,
            actor_id, entries_sha256, expired_certs_on_crl_since, reserved_at)
        SELECT p_ca, v_number, v_this, v_this + v_validity, 'RESERVED',
               p_operation_ref, p_actor,
               sha256(COALESCE((SELECT string_agg(
                   crl_entry_encoding(cur.serial_der_content, cur.revoked_at,
                                      cur.reason_code, cur.invalidity_at),
                   '\x'::bytea ORDER BY cur.serial_der_content) FROM cur), '\x'::bytea)),
               v_expired, v_reserved
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
-- CREATE OR REPLACE resets SECURITY DEFINER and the settings: re-apply them.
ALTER FUNCTION reserve_crl(uuid,text,text) OWNER TO trust_revocation_owner;
ALTER FUNCTION reserve_crl(uuid,text,text) SECURITY DEFINER;
ALTER FUNCTION reserve_crl(uuid,text,text) SET search_path = pg_catalog, public, pg_temp;

SELECT acknowledge_schema_changes('0058_crl_number_floor');

COMMIT;
