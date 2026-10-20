-- v0.16 (lab): CRL pipeline robustness. LAB ONLY.
-- * Intent age is measured from a recorded intent_recorded_at instead of the
--   reservation's thisUpdate; stale RESERVED rows (no intent, so never handed
--   to a signer) can be retired as ABANDONED, after which no intent can be
--   recorded for them. Numbers are still never reused or deleted.
-- Apply after 0015 as the migration owner.
BEGIN;

-- NULL on rows that recorded their intent before this migration; the stale
-- intent sweep falls back to this_update for them.
ALTER TABLE crl_publication ADD COLUMN intent_recorded_at TIMESTAMPTZ;
ALTER TABLE crl_publication
    DROP CONSTRAINT crl_publication_status_valid,
    ADD CONSTRAINT crl_publication_status_valid CHECK (
        status IN ('RESERVED','INTENT_RECORDED','STORED','RECONCILIATION_REQUIRED',
                   'ABANDONED')
    ),
    ADD CONSTRAINT crl_publication_reserved_has_no_intent_time
        CHECK (status <> 'RESERVED' OR intent_recorded_at IS NULL),
    ADD CONSTRAINT crl_publication_intent_after_reservation
        CHECK (intent_recorded_at IS NULL OR intent_recorded_at >= this_update);

-- Same rules as 0015, plus RESERVED -> ABANDONED (final) and an
-- intent_recorded_at that is set exactly once, by RESERVED -> INTENT_RECORDED
-- (which now requires it).
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
           NEW.expired_certs_on_crl_since, NEW.published_at)
          IS DISTINCT FROM
          (OLD.ca_id, OLD.crl_number, OLD.this_update, OLD.next_update,
           OLD.operation_ref, OLD.actor_id, OLD.entries_sha256,
           OLD.expired_certs_on_crl_since, OLD.published_at)
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

-- As in 0015, and stamps intent_recorded_at. An ABANDONED reservation is not
-- RESERVED, so it is refused like any other closed row.
CREATE OR REPLACE FUNCTION record_crl_intent(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA,
    p_entries_sha256 BYTEA, p_this_update_unix BIGINT, p_next_update_unix BIGINT,
    p_expired_certs_on_crl_since_unix BIGINT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_pub crl_publication%ROWTYPE;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_entries_sha256 IS NULL OR octet_length(p_entries_sha256) <> 32
       OR p_this_update_unix IS NULL OR p_next_update_unix IS NULL
    THEN
        RAISE EXCEPTION 'invalid CRL intent input' USING ERRCODE='22023';
    END IF;
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
    UPDATE crl_publication
    SET status = 'INTENT_RECORDED', tbs_sha256 = p_tbs_sha256,
        intent_recorded_at = clock_timestamp()
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, v_pub.actor_id, 'crl.intent',
            'INTENT_RECORDED:' || p_crl_number);
    RETURN 'INTENT_RECORDED';
END $fn$;

-- Quarantine intents whose signing never completed, by intent age (rows
-- recorded before 0016 have no intent time and fall back to this_update).
CREATE OR REPLACE FUNCTION quarantine_stale_crl_intents(p_ca UUID, p_older_than INTERVAL)
RETURNS INTEGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_count INTEGER := 0;
    v_row RECORD;
BEGIN
    IF p_ca IS NULL OR p_older_than IS NULL OR p_older_than < INTERVAL '0 seconds' THEN
        RAISE EXCEPTION 'invalid CRL quarantine input' USING ERRCODE='22023';
    END IF;
    FOR v_row IN
        SELECT cp.crl_number, cp.actor_id FROM crl_publication cp
        WHERE cp.ca_id = p_ca AND cp.status = 'INTENT_RECORDED'
          AND COALESCE(cp.intent_recorded_at, cp.this_update)
              <= clock_timestamp() - p_older_than
        ORDER BY cp.crl_number FOR UPDATE
    LOOP
        UPDATE crl_publication
        SET status = 'RECONCILIATION_REQUIRED'
        WHERE ca_id = p_ca AND crl_number = v_row.crl_number;
        INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
        VALUES (gen_random_uuid(), p_ca, NULL, v_row.actor_id, 'crl.quarantined',
                'RECONCILIATION_REQUIRED:' || v_row.crl_number);
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END $fn$;

-- Retire reservations that never recorded an intent. crl_once calls the
-- signer only after record_crl_intent, so a RESERVED row was never signed:
-- ABANDONED is a certain outcome, not a reconciliation case. Row locks
-- serialise this with record_crl_intent; a worker that loses the race gets
-- 23514 from record_crl_intent and signs nothing.
CREATE FUNCTION abandon_stale_crl_reservations(p_ca UUID, p_older_than INTERVAL)
RETURNS INTEGER
LANGUAGE plpgsql AS $fn$
DECLARE
    v_count INTEGER := 0;
    v_row RECORD;
BEGIN
    IF p_ca IS NULL OR p_older_than IS NULL OR p_older_than < INTERVAL '0 seconds' THEN
        RAISE EXCEPTION 'invalid CRL abandon input' USING ERRCODE='22023';
    END IF;
    FOR v_row IN
        SELECT cp.crl_number, cp.actor_id FROM crl_publication cp
        WHERE cp.ca_id = p_ca AND cp.status = 'RESERVED'
          AND cp.this_update <= clock_timestamp() - p_older_than
        ORDER BY cp.crl_number FOR UPDATE
    LOOP
        UPDATE crl_publication
        SET status = 'ABANDONED'
        WHERE ca_id = p_ca AND crl_number = v_row.crl_number;
        INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
        VALUES (gen_random_uuid(), p_ca, NULL, v_row.actor_id, 'crl.abandoned',
                'ABANDONED:' || v_row.crl_number);
        v_count := v_count + 1;
    END LOOP;
    RETURN v_count;
END $fn$;

REVOKE ALL ON FUNCTION abandon_stale_crl_reservations(uuid,interval) FROM PUBLIC;

COMMIT;
