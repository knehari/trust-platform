-- v0.31 (lab): prune expired entries from CRLs (RFC 5280 3.3, 5.1.2.6),
-- except under ETSI EN 319 411-2. LAB ONLY.
-- * certificate.not_after is stored at issuance by the new 8-argument
--   store_signed_certificate, from the certificate the Rust core has just
--   verified independently (postgres_store::persist_verified). It cannot
--   be changed afterwards. Rows from before 0031, or stored through the
--   7-argument function, keep NULL and are never pruned (fail safe).
-- * ca_revocation_policy.keep_expired_on_crl may now be false, except for
--   conformance_target ETSI_EN_319_411_2 (0014 check, kept): qualified CAs
--   keep revocation status of expired certificates (ExpiredCertsOnCRL).
-- * With keep_expired_on_crl false, reserve_crl leaves out an entry whose
--   certificate expired before the thisUpdate of a STORED CRL of the CA that
--   listed it (crl_entry_pruned_from): RFC 5280 3.3 requires an entry to
--   appear on at least one regularly scheduled CRL issued after the
--   certificate's validity period before removal. The revocation row
--   itself stays; only the CRL shrinks.
-- * crl_change_covered treats a legitimately pruned entry as covered, so
--   crl_due and overdue_status_changes do not ask for CRLs forever.
-- reserve_crl and crl_change_covered are the 0020 bodies with only these
-- edits; CREATE OR REPLACE resets definer settings, so they are set again.
-- Apply after 0030 as a superuser.
BEGIN;

ALTER TABLE certificate
    ADD COLUMN not_after TIMESTAMPTZ,
    ADD CONSTRAINT certificate_not_after_after_signing
        CHECK (not_after IS NULL OR not_after > signed_at);

CREATE FUNCTION guard_certificate_not_after() RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp AS $fn$
BEGIN
    IF NEW.not_after IS DISTINCT FROM OLD.not_after THEN
        RAISE EXCEPTION 'certificate not_after is set once, at issuance' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER certificate_not_after_immutable
    BEFORE UPDATE OF not_after ON certificate
    FOR EACH ROW EXECUTE FUNCTION guard_certificate_not_after();
REVOKE ALL ON FUNCTION guard_certificate_not_after() FROM PUBLIC;

ALTER TABLE ca_revocation_policy
    DROP CONSTRAINT ca_revocation_policy_keep_expired_on_crl_check;

-- The certificate behind (p_ca, p_serial) expired before the thisUpdate of
-- a STORED CRL numbered below p_crl_number that listed it, and the CA does
-- not keep expired entries.
CREATE FUNCTION crl_entry_pruned_from(p_ca UUID, p_serial BYTEA, p_crl_number BIGINT)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $fn$
    SELECT EXISTS (
        SELECT 1
        FROM certificate c
        JOIN ca_revocation_policy pol ON pol.ca_id = c.ca_id AND NOT pol.keep_expired_on_crl
        JOIN crl_publication q ON q.ca_id = c.ca_id AND q.status = 'STORED'
             AND q.crl_number < p_crl_number AND q.this_update > c.not_after
        JOIN crl_entry_snapshot e ON e.ca_id = q.ca_id AND e.crl_number = q.crl_number
             AND e.serial_der_content = c.serial_der_content
        WHERE c.ca_id = p_ca AND c.serial_der_content = p_serial
          AND c.not_after IS NOT NULL)
$fn$;
ALTER FUNCTION crl_entry_pruned_from(uuid,bytea,bigint) OWNER TO trust_revocation_owner;
ALTER FUNCTION crl_entry_pruned_from(uuid,bytea,bigint)
    SET search_path = pg_catalog, public, pg_temp;
REVOKE ALL ON FUNCTION crl_entry_pruned_from(uuid,bytea,bigint) FROM PUBLIC;
GRANT SELECT ON certificate TO trust_revocation_owner;

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

    SELECT COALESCE(max(cp.crl_number), 0) + 1 INTO v_number
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

CREATE OR REPLACE FUNCTION crl_change_covered(p_change UUID, p_latest_only BOOLEAN)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $fn$
    SELECT EXISTS (
        SELECT 1
        FROM certificate_status_change s
        JOIN crl_publication cp
          ON cp.ca_id = s.ca_id AND cp.status = 'STORED'
         AND COALESCE(cp.reserved_at, cp.this_update) >= s.decided_at
        WHERE s.change_id = p_change AND s.status = 'APPROVED'
          AND (NOT p_latest_only OR cp.crl_number = (
                SELECT max(x.crl_number) FROM crl_publication x
                WHERE x.ca_id = s.ca_id AND x.status = 'STORED'))
          AND CASE WHEN s.action = 'RELEASE'
                   THEN NOT EXISTS (
                        SELECT 1 FROM crl_entry_snapshot e
                        WHERE e.ca_id = cp.ca_id AND e.crl_number = cp.crl_number
                          AND e.serial_der_content = s.serial_der_content)
                   ELSE EXISTS (
                        SELECT 1 FROM crl_entry_snapshot e
                        WHERE e.ca_id = cp.ca_id AND e.crl_number = cp.crl_number
                          AND e.serial_der_content = s.serial_der_content
                          AND e.reason_code = s.reason_code)
                        -- 0031: legitimately pruned after expiry.
                        OR crl_entry_pruned_from(cp.ca_id, s.serial_der_content, cp.crl_number)
              END
    )
$fn$;

ALTER FUNCTION reserve_crl(uuid,text,text) SECURITY DEFINER;
ALTER FUNCTION reserve_crl(uuid,text,text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION crl_change_covered(uuid,boolean) SET search_path = pg_catalog, public, pg_temp;

-- Issuance with the expiry of the verified certificate.
CREATE FUNCTION store_signed_certificate(
    p_ca_id UUID, p_request_id UUID, p_actor_id TEXT,
    p_serial BYTEA, p_tbs_sha256 BYTEA, p_cert_sha256 BYTEA, p_cert_der BYTEA,
    p_not_after TIMESTAMPTZ
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_state TEXT;
    v_serial BYTEA;
    v_tbs BYTEA;
BEGIN
    IF p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_cert_sha256 IS NULL OR octet_length(p_cert_sha256) <> 32
       OR p_cert_der IS NULL OR octet_length(p_cert_der) NOT BETWEEN 1 AND 65536
       OR digest(p_cert_der,'sha256') <> p_cert_sha256
       OR p_not_after IS NULL OR p_not_after <= now()
       OR p_not_after >= TIMESTAMPTZ '10000-01-01 00:00:00+00'
    THEN RAISE EXCEPTION 'invalid signed certificate input' USING ERRCODE='22023'; END IF;

    SELECT cr.state INTO STRICT v_state FROM certificate_request cr
    WHERE cr.ca_id=p_ca_id AND cr.request_id=p_request_id FOR UPDATE;
    SELECT sr.serial_der_content INTO STRICT v_serial FROM serial_reservation sr
    WHERE sr.ca_id=p_ca_id AND sr.request_id=p_request_id;
    SELECT si.tbs_sha256 INTO STRICT v_tbs FROM signing_intent si
    WHERE si.ca_id=p_ca_id AND si.request_id=p_request_id;

    IF v_state <> 'SIGNING' OR v_serial <> p_serial OR v_tbs <> p_tbs_sha256 THEN
        RAISE EXCEPTION 'signing state, serial or TBS digest mismatch' USING ERRCODE='23514';
    END IF;

    INSERT INTO certificate (
        ca_id,serial_der_content,request_id,fingerprint_sha256,certificate_der,signed_at,
        not_after
    ) VALUES (
        p_ca_id,p_serial,p_request_id,p_cert_sha256,p_cert_der,now(),p_not_after
    );

    UPDATE signing_intent SET outcome='CERTIFICATE_STORED'
    WHERE ca_id=p_ca_id AND request_id=p_request_id;
    PERFORM transition_issuance_request(p_ca_id,p_request_id,'SIGNING','SIGNED',p_actor_id);

    INSERT INTO audit_event(event_id,ca_id,request_id,actor_id,event_type,decision)
    VALUES (gen_random_uuid(),p_ca_id,p_request_id,p_actor_id,'signing.result','persisted');

    RETURN 'SIGNED';
END
$fn$;
REVOKE ALL ON FUNCTION store_signed_certificate(uuid,uuid,text,bytea,bytea,bytea,bytea,timestamp with time zone) FROM PUBLIC;

SELECT acknowledge_schema_changes('0031_crl_expired_entry_pruning');

COMMIT;
