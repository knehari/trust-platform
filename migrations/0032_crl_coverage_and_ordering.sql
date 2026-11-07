-- v0.20 (lab): fixes from the review of 0014-0019. LAB ONLY.
-- * crl_publication.reserved_at records the exact reservation time (taken
--   under the CA row lock, like approvals' decided_at). crl_change_covered and
--   overdue_status_changes compare it, not the second-truncated thisUpdate,
--   with decided_at: a change approved earlier in the same second as the
--   reservation is in the snapshot but was reported as not covered, so
--   crl_due kept asking for another CRL. Rows reserved before 0020 fall back
--   to thisUpdate (previous behaviour). reserved_at is immutable.
-- * record_crl_intent accepts only the CA's highest reserved number: any
--   higher reservation, whatever its status, supersedes this one. This
--   replaces the 0017/0019 status-based checks (which still let n be signed
--   while n+1 was merely reserved, and over-refused for a higher row
--   quarantined before any intent with a misleading message).
-- Function bodies are the latest versions with only these edits.
-- Apply after 0019 as the migration owner.
BEGIN;

ALTER TABLE crl_publication
    ADD COLUMN reserved_at TIMESTAMPTZ,
    ADD CONSTRAINT crl_publication_reserved_at_in_this_update_second CHECK (
        reserved_at IS NULL
        OR (reserved_at >= this_update AND reserved_at < this_update + INTERVAL '1 second')
    );

CREATE OR REPLACE FUNCTION guard_crl_publication() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'crl_publication is append-only' USING ERRCODE='23514';
    END IF;
    IF (OLD.status, NEW.status) NOT IN (
            ('RESERVED','INTENT_RECORDED'),
            ('RESERVED','RECONCILIATION_REQUIRED'),
            ('RESERVED','ABANDONED'),
            ('INTENT_RECORDED','STORED'),
            ('INTENT_RECORDED','RECONCILIATION_REQUIRED'))
       OR (NEW.ca_id, NEW.crl_number, NEW.this_update, NEW.next_update,
           NEW.operation_ref, NEW.actor_id, NEW.entries_sha256,
           NEW.expired_certs_on_crl_since, NEW.published_at, NEW.reserved_at)
          IS DISTINCT FROM
          (OLD.ca_id, OLD.crl_number, OLD.this_update, OLD.next_update,
           OLD.operation_ref, OLD.actor_id, OLD.entries_sha256,
           OLD.expired_certs_on_crl_since, OLD.published_at, OLD.reserved_at)
       OR (OLD.status <> 'RESERVED'
           AND NEW.tbs_sha256 IS DISTINCT FROM OLD.tbs_sha256)
       OR (NEW.intent_recorded_at IS DISTINCT FROM OLD.intent_recorded_at
           AND (OLD.status, NEW.status) <> ('RESERVED','INTENT_RECORDED'))
       OR (OLD.status = 'RESERVED' AND NEW.status = 'INTENT_RECORDED'
           AND NEW.intent_recorded_at IS NULL)
    THEN
        RAISE EXCEPTION 'illegal crl_publication change % -> %', OLD.status, NEW.status
          USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $fn$;

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

CREATE OR REPLACE FUNCTION  crl_change_covered(p_change UUID, p_latest_only BOOLEAN)
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
              END
    )
$fn$;

CREATE OR REPLACE FUNCTION  overdue_status_changes(p_ca UUID)
RETURNS TABLE(change_id UUID, status TEXT, proposed_at TIMESTAMPTZ)
LANGUAGE plpgsql AS $fn$
#variable_conflict use_column
DECLARE
    v_deadline INTERVAL := INTERVAL '24 hours';
BEGIN
    IF p_ca IS NULL OR NOT EXISTS (SELECT 1 FROM ca WHERE ca_id = p_ca) THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    SELECT p.status_publication_deadline INTO v_deadline
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca;
    IF NOT FOUND THEN v_deadline := INTERVAL '24 hours'; END IF;

    RETURN QUERY
        SELECT s.change_id, s.status, s.proposed_at
        FROM certificate_status_change s
        WHERE s.ca_id = p_ca
          AND s.proposed_at + v_deadline < clock_timestamp()
          AND (s.status = 'PROPOSED'
               OR (s.status = 'APPROVED' AND NOT (
                   CASE WHEN EXISTS (
                            SELECT 1 FROM certificate_status_change l
                            WHERE l.ca_id = s.ca_id
                              AND l.serial_der_content = s.serial_der_content
                              AND l.status = 'APPROVED' AND l.decided_at > s.decided_at)
                        -- superseded: covered once any STORED CRL is at least
                        -- as new as its decision (a CRL reflecting the
                        -- superseding change is necessarily newer)
                        THEN EXISTS (
                            SELECT 1 FROM crl_publication cp
                            WHERE cp.ca_id = s.ca_id AND cp.status = 'STORED'
                              AND COALESCE(cp.reserved_at, cp.this_update) >= s.decided_at)
                        -- newest change: the snapshot must reflect it
                        ELSE crl_change_covered(s.change_id, false)
                   END)))
        ORDER BY s.proposed_at, s.change_id;
END $fn$;

CREATE OR REPLACE FUNCTION record_crl_intent(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA,
    p_entries_sha256 BYTEA, p_this_update_unix BIGINT, p_next_update_unix BIGINT,
    p_expired_certs_on_crl_since_unix BIGINT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_pub crl_publication%ROWTYPE;
    v_interval INTERVAL;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_entries_sha256 IS NULL OR octet_length(p_entries_sha256) <> 32
       OR p_this_update_unix IS NULL OR p_next_update_unix IS NULL
    THEN
        RAISE EXCEPTION 'invalid CRL intent input' USING ERRCODE='22023';
    END IF;
    -- Intents and reservations of one CA are serialised on the CA row (taken
    -- before the publication row, as reserve_crl does), so the higher-number
    -- check below cannot race a concurrent reservation.
    PERFORM 1 FROM ca WHERE ca_id = p_ca FOR NO KEY UPDATE;
    SELECT * INTO v_pub FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number FOR UPDATE;
    IF NOT FOUND OR v_pub.status <> 'RESERVED'
       OR v_pub.operation_ref <> p_operation_ref
    THEN
        RAISE EXCEPTION 'CRL intent refused: unknown number, wrong operation or not RESERVED'
          USING ERRCODE='23514';
    END IF;
    IF p_entries_sha256 <> v_pub.entries_sha256
       OR p_this_update_unix <> floor(extract(epoch FROM v_pub.this_update))::bigint
       OR p_next_update_unix <> floor(extract(epoch FROM v_pub.next_update))::bigint
       OR p_expired_certs_on_crl_since_unix IS DISTINCT FROM
          floor(extract(epoch FROM v_pub.expired_certs_on_crl_since))::bigint
    THEN
        RAISE EXCEPTION 'CRL intent refused: entries, number or times differ from the reservation'
          USING ERRCODE='23514';
    END IF;
    -- Only the CA's highest reserved number may be signed: once a newer
    -- reservation exists (in any status), this one is superseded and the
    -- worker must reserve again. Relying parties keep the highest number.
    IF EXISTS (SELECT 1 FROM crl_publication cp
               WHERE cp.ca_id = p_ca AND cp.crl_number > p_crl_number) THEN
        RAISE EXCEPTION 'CRL intent refused: a higher CRL number has been reserved'
          USING ERRCODE='23514';
    END IF;
    -- The reservation's own nextUpdate, independent of later policy changes.
    IF v_pub.next_update <= clock_timestamp() THEN
        RAISE EXCEPTION 'CRL intent refused: the reserved nextUpdate has passed'
          USING ERRCODE='23514';
    END IF;
    -- A reservation older than the issue interval is stale: a newer CRL is
    -- already due. The row stays RESERVED for abandon_stale_crl_reservations.
    SELECT p.crl_issue_interval INTO v_interval
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca FOR SHARE;
    IF v_pub.this_update + COALESCE(v_interval, INTERVAL '24 hours') <= clock_timestamp() THEN
        RAISE EXCEPTION 'CRL intent refused: reservation older than the CRL issue interval'
          USING ERRCODE='23514';
    END IF;
    UPDATE crl_publication
    SET status = 'INTENT_RECORDED', tbs_sha256 = p_tbs_sha256,
        intent_recorded_at = clock_timestamp()
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, v_pub.actor_id, 'crl.intent',
            'INTENT_RECORDED:' || p_crl_number);
    RETURN 'INTENT_RECORDED';
END $fn$;

COMMIT;
