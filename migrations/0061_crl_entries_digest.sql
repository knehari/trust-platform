-- v0.61 (lab): one definition of the CRL entries digest. LAB ONLY.
-- Hygiene, no behaviour change. The digest that binds a CRL reservation to
-- what is signed (the Rust core's CrlReservation::entries_sha256, checked by
-- record_crl_intent and re-checked at storage) was written out in three
-- function bodies: reserve_crl (0031), reserve_delta_crl and
-- crl_listed_digest (0059). A change to the encoding in one of them would
-- silently make the others refuse every CRL, or worse, agree on a weaker
-- binding.
-- * crl_entries_digest_step / crl_entries_sha256: an ordered aggregate,
--   crl_entries_sha256(serial, revoked_at, reason, invalidity ORDER BY
--   serial) = sha256 of the concatenated crl_entry_encoding (0015) of the
--   entries, sha256 of nothing for no entry, exactly the 0015 expression.
--   Owned by trust_revocation_owner, not executable by PUBLIC (the definer
--   functions call it as their owner).
-- * reserve_crl, reserve_delta_crl and crl_listed_digest use it; their
--   bodies are otherwise those of 0058/0059 (copied once more, so that no
--   further copy is needed for an encoding change).
-- tests/crl_entries_digest.sql checks that no other function body calls
-- crl_entry_encoding and that the aggregate equals the 0015 expression.
-- Apply after 0060 as a superuser.
BEGIN;

CREATE FUNCTION crl_entries_digest_step(p_state BYTEA, p_serial BYTEA, p_at TIMESTAMPTZ,
                                        p_reason SMALLINT, p_invalidity TIMESTAMPTZ)
RETURNS BYTEA
-- Not STRICT: a STRICT step would skip entries without an invalidity date
-- (the encoding writes -1 for them).
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT p_state || crl_entry_encoding(p_serial, p_at, p_reason, p_invalidity)
$fn$;
ALTER FUNCTION crl_entries_digest_step(bytea, bytea, timestamptz, smallint, timestamptz)
    OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_entries_digest_step(bytea, bytea, timestamptz, smallint, timestamptz)
    SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION crl_entries_digest_step(bytea, bytea, timestamptz, smallint, timestamptz)
    FROM PUBLIC;

CREATE AGGREGATE crl_entries_sha256(BYTEA, TIMESTAMPTZ, SMALLINT, TIMESTAMPTZ) (
    SFUNC = crl_entries_digest_step,
    STYPE = BYTEA,
    INITCOND = '',
    FINALFUNC = sha256
);
ALTER AGGREGATE crl_entries_sha256(bytea, timestamptz, smallint, timestamptz)
    OWNER TO trust_revocation_owner;
REVOKE ALL ON FUNCTION crl_entries_sha256(bytea, timestamptz, smallint, timestamptz) FROM PUBLIC;

CREATE OR REPLACE FUNCTION public.reserve_crl(p_ca uuid, p_actor text, p_operation_ref text)
 RETURNS TABLE(crl_number bigint, this_update timestamp with time zone, next_update timestamp with time zone, expired_certs_on_crl_since timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
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
               (SELECT crl_entries_sha256(cur.serial_der_content, cur.revoked_at,
                                          cur.reason_code, cur.invalidity_at
                                          ORDER BY cur.serial_der_content) FROM cur),
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
END $function$;

CREATE OR REPLACE FUNCTION public.reserve_delta_crl(p_ca uuid, p_actor text, p_operation_ref text)
 RETURNS TABLE(crl_number bigint, base_crl_number bigint, this_update timestamp with time zone, next_update timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
#variable_conflict use_column
DECLARE
    v_validity INTERVAL := INTERVAL '7 days';
    v_url TEXT;
    v_base BIGINT;
    v_base_next TIMESTAMPTZ;
    v_base_url TEXT;
    v_number BIGINT;
    v_reserved TIMESTAMPTZ;
    v_this TIMESTAMPTZ;
    v_next TIMESTAMPTZ;
    v_latest TIMESTAMPTZ;
BEGIN
    -- As reserve_crl: the snapshot must not predate the CA row lock.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'reserve_delta_crl requires transaction isolation read committed (got %)',
            current_setting('transaction_isolation') USING ERRCODE='23514';
    END IF;
    IF p_ca IS NULL
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 1024
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION 'invalid CRL reservation input' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM ca c WHERE c.ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT p.crl_validity, p.delta_crl_url INTO v_validity, v_url
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca FOR SHARE;
    IF v_url IS NULL THEN
        RAISE EXCEPTION 'delta CRLs are not enabled for this CA' USING ERRCODE='55000';
    END IF;
    SELECT cp.crl_number, cp.next_update, cp.freshest_crl_url
    INTO v_base, v_base_next, v_base_url
    FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.status = 'STORED' AND cp.base_crl_number IS NULL
    ORDER BY cp.crl_number DESC LIMIT 1;
    IF v_base IS NULL OR v_base_url IS NULL THEN
        RAISE EXCEPTION 'no stored complete CRL advertising delta CRLs; issue one first'
          USING ERRCODE='55000';
    END IF;
    SELECT GREATEST(COALESCE(max(cp.crl_number), 0),
                    COALESCE((SELECT max(f.floor) FROM crl_number_floor f
                              WHERE f.ca_id = p_ca), 0)) + 1 INTO v_number
    FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_number > 9223372036854775806 THEN
        RAISE EXCEPTION 'CRL number space exhausted' USING ERRCODE='23514';
    END IF;
    v_reserved := clock_timestamp();
    v_this := date_trunc('second', v_reserved);
    SELECT max(cp.this_update) INTO v_latest FROM crl_publication cp WHERE cp.ca_id = p_ca;
    IF v_latest > v_this THEN
        RAISE EXCEPTION 'clock is behind the latest CRL thisUpdate of this CA'
          USING ERRCODE='23514';
    END IF;
    -- A delta is only usable with its base: never valid beyond it.
    v_next := LEAST(v_this + v_validity, v_base_next);
    IF v_next <= v_this THEN
        RAISE EXCEPTION 'the base CRL has expired; issue a complete CRL' USING ERRCODE='55000';
    END IF;

    WITH cur AS MATERIALIZED (
        SELECT r.serial_der_content, r.revoked_at, r.reason_code, r.invalidity_at
        FROM revocation r WHERE r.ca_id = p_ca
          AND NOT crl_entry_pruned_from(p_ca, r.serial_der_content, v_number)
    ), base AS MATERIALIZED (
        SELECT e.serial_der_content, e.revoked_at, e.reason_code, e.invalidity_at
        FROM crl_entry_snapshot e WHERE e.ca_id = p_ca AND e.crl_number = v_base
    ), added AS MATERIALIZED (
        SELECT * FROM cur EXCEPT SELECT * FROM base
    ), released AS MATERIALIZED (
        SELECT b.serial_der_content FROM base b
        WHERE NOT EXISTS (SELECT 1 FROM cur c WHERE c.serial_der_content = b.serial_der_content)
    ), listed AS (
        SELECT a.serial_der_content, a.revoked_at AS at, a.reason_code, a.invalidity_at
        FROM added a
        UNION ALL
        SELECT r.serial_der_content, v_this, 8::smallint, NULL::timestamptz
        FROM released r
    ), pub AS (
        INSERT INTO crl_publication(
            ca_id, crl_number, this_update, next_update, status, operation_ref,
            actor_id, entries_sha256, expired_certs_on_crl_since, reserved_at, base_crl_number)
        SELECT p_ca, v_number, v_this, v_next, 'RESERVED', p_operation_ref, p_actor,
               (SELECT crl_entries_sha256(l.serial_der_content, l.at, l.reason_code,
                                          l.invalidity_at ORDER BY l.serial_der_content)
                FROM listed l),
               NULL, v_reserved, v_base
        RETURNING 1
    ), snapshot AS (
        INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content,
                                       revoked_at, reason_code, invalidity_at)
        SELECT p_ca, v_number, a.serial_der_content, a.revoked_at, a.reason_code,
               a.invalidity_at
        FROM added a
        RETURNING 1
    )
    INSERT INTO crl_delta_release(ca_id, crl_number, serial_der_content, released_at)
    SELECT p_ca, v_number, r.serial_der_content, v_this FROM released r;

    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_actor, 'crl.delta_reserved',
            'RESERVED:' || v_number || ':base=' || v_base);
    RETURN QUERY SELECT v_number, v_base, v_this, v_next;
END $function$;

CREATE OR REPLACE FUNCTION public.crl_listed_digest(p_ca uuid, p_crl_number bigint)
 RETURNS bytea
 LANGUAGE sql
 STABLE
 SET search_path TO 'pg_catalog', 'public', 'pg_temp'
AS $function$
    SELECT crl_entries_sha256(x.serial, x.at, x.reason, x.invalidity ORDER BY x.serial)
    FROM (SELECT s.serial_der_content AS serial, s.revoked_at AS at, s.reason_code AS reason,
                 s.invalidity_at AS invalidity
          FROM crl_entry_snapshot s
          WHERE s.ca_id = p_ca AND s.crl_number = p_crl_number
          UNION ALL
          SELECT d.serial_der_content, d.released_at, 8::smallint, NULL::timestamptz
          FROM crl_delta_release d
          WHERE d.ca_id = p_ca AND d.crl_number = p_crl_number) x
$function$;

-- CREATE OR REPLACE keeps owner, SECURITY DEFINER and settings of an
-- existing function; re-assert them anyway (0025).
ALTER FUNCTION reserve_crl(uuid, text, text) OWNER TO trust_revocation_owner;
ALTER FUNCTION reserve_crl(uuid, text, text) SECURITY DEFINER;
ALTER FUNCTION reserve_crl(uuid, text, text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION reserve_delta_crl(uuid, text, text) OWNER TO trust_revocation_owner;
ALTER FUNCTION reserve_delta_crl(uuid, text, text) SECURITY DEFINER;
ALTER FUNCTION reserve_delta_crl(uuid, text, text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION crl_listed_digest(uuid, bigint) OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_listed_digest(uuid, bigint) SET search_path = pg_catalog, public, pg_temp;

SELECT acknowledge_schema_changes('0061_crl_entries_digest');

COMMIT;
