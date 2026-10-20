-- v0.21 (lab): operability of the CRL pipeline. LAB ONLY.
-- * record_crl_intent reports the refusals after which nothing was signed and
--   the worker should simply reserve again (abandoned reservation, a higher
--   number reserved, nextUpdate passed, reservation older than the issue
--   interval) with SQLSTATE 55000 (object_not_in_prerequisite_state) instead
--   of 23514. 23514 now only means replay or content mismatch: ambiguous,
--   escalate. Messages are unchanged.
-- * A quarantined CRL that had recorded its intent can be reconciled:
--   store_reconciled_crl stores DER that the Rust core verified again
--   against the reservation, when its TBS hash equals the hash journaled
--   before signing and the snapshot still matches the reserved digest
--   (RECONCILIATION_REQUIRED -> STORED, audited as crl.reconciled with the
--   reconciling actor). Rows quarantined before any intent stay final.
-- Function bodies are the latest versions with only these edits.
-- Apply after 0020 as the migration owner.
BEGIN;

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
    -- An abandoned reservation was never signed: certain, reserve again.
    IF FOUND AND v_pub.status = 'ABANDONED' AND v_pub.operation_ref = p_operation_ref THEN
        RAISE EXCEPTION 'CRL intent refused: the reservation was abandoned'
          USING ERRCODE='55000';
    END IF;
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
          USING ERRCODE='55000';
    END IF;
    -- The reservation's own nextUpdate, independent of later policy changes.
    IF v_pub.next_update <= clock_timestamp() THEN
        RAISE EXCEPTION 'CRL intent refused: the reserved nextUpdate has passed'
          USING ERRCODE='55000';
    END IF;
    -- A reservation older than the issue interval is stale: a newer CRL is
    -- already due. The row stays RESERVED for abandon_stale_crl_reservations.
    SELECT p.crl_issue_interval INTO v_interval
    FROM ca_revocation_policy p WHERE p.ca_id = p_ca FOR SHARE;
    IF v_pub.this_update + COALESCE(v_interval, INTERVAL '24 hours') <= clock_timestamp() THEN
        RAISE EXCEPTION 'CRL intent refused: reservation older than the CRL issue interval'
          USING ERRCODE='55000';
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
            ('INTENT_RECORDED','RECONCILIATION_REQUIRED'),
            ('RECONCILIATION_REQUIRED','STORED'))
       OR (NEW.ca_id, NEW.crl_number, NEW.this_update, NEW.next_update,
           NEW.operation_ref, NEW.actor_id, NEW.entries_sha256,
           NEW.expired_certs_on_crl_since, NEW.published_at, NEW.reserved_at)
          IS DISTINCT FROM
          (OLD.ca_id, OLD.crl_number, OLD.this_update, OLD.next_update,
           OLD.operation_ref, OLD.actor_id, OLD.entries_sha256,
           OLD.expired_certs_on_crl_since, OLD.published_at, OLD.reserved_at)
       OR (OLD.status <> 'RESERVED'
           AND NEW.tbs_sha256 IS DISTINCT FROM OLD.tbs_sha256)
       -- only a quarantined row that recorded an intent can be reconciled
       OR (OLD.status = 'RECONCILIATION_REQUIRED' AND OLD.tbs_sha256 IS NULL)
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

CREATE FUNCTION store_reconciled_crl(
    p_ca UUID, p_crl_number BIGINT, p_operation_ref TEXT, p_tbs_sha256 BYTEA,
    p_crl_sha256 BYTEA, p_crl_der BYTEA, p_actor TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_pub crl_publication%ROWTYPE;
    v_digest BYTEA;
BEGIN
    IF p_ca IS NULL OR p_crl_number IS NULL
       OR p_operation_ref IS NULL OR length(p_operation_ref) NOT BETWEEN 1 AND 256
       OR p_tbs_sha256 IS NULL OR octet_length(p_tbs_sha256) <> 32
       OR p_crl_der IS NULL OR octet_length(p_crl_der) = 0
       OR p_crl_sha256 IS NULL OR p_crl_sha256 <> sha256(p_crl_der)
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 1024
    THEN
        RAISE EXCEPTION 'invalid CRL reconciliation input' USING ERRCODE='22023';
    END IF;
    SELECT * INTO v_pub FROM crl_publication cp
    WHERE cp.ca_id = p_ca AND cp.crl_number = p_crl_number FOR UPDATE;
    -- Quarantined after a recorded intent, and the TBS hash equals the one
    -- journaled before signing: these are the bytes that were meant to be
    -- signed, so storing them once independently verified loses nothing.
    IF NOT FOUND OR v_pub.status <> 'RECONCILIATION_REQUIRED'
       OR v_pub.tbs_sha256 IS NULL
       OR v_pub.operation_ref <> p_operation_ref
       OR v_pub.tbs_sha256 <> p_tbs_sha256
    THEN
        RAISE EXCEPTION 'CRL reconciliation refused: unknown number, not quarantined after an intent, wrong operation or TBS hash'
          USING ERRCODE='23514';
    END IF;
    SELECT sha256(COALESCE(string_agg(
               crl_entry_encoding(s.serial_der_content, s.revoked_at,
                                  s.reason_code, s.invalidity_at),
               '\x'::bytea ORDER BY s.serial_der_content), '\x'::bytea))
    INTO v_digest
    FROM crl_entry_snapshot s
    WHERE s.ca_id = p_ca AND s.crl_number = p_crl_number;
    IF v_digest IS DISTINCT FROM v_pub.entries_sha256 THEN
        RAISE EXCEPTION 'CRL reconciliation refused: snapshot does not match the reserved digest'
          USING ERRCODE='23514';
    END IF;
    UPDATE crl_publication
    SET status = 'STORED', crl_sha256 = p_crl_sha256, crl_der = p_crl_der
    WHERE ca_id = p_ca AND crl_number = p_crl_number;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_actor, 'crl.reconciled',
            'STORED:' || p_crl_number);
    RETURN 'STORED';
END $fn$;

REVOKE ALL ON FUNCTION store_reconciled_crl(uuid,bigint,text,bytea,bytea,bytea,text) FROM PUBLIC;

COMMIT;
