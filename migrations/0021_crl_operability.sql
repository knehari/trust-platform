-- v0.21 (lab): operability of the CRL pipeline. LAB ONLY.
-- * record_crl_intent reports the refusals after which nothing was signed and
--   the worker should simply reserve again (abandoned reservation, a higher
--   number reserved, nextUpdate passed, reservation older than the issue
--   interval) with SQLSTATE 55000 (object_not_in_prerequisite_state) instead
--   of 23514. 23514 now only means replay or content mismatch: ambiguous,
--   escalate. Messages are unchanged.
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

COMMIT;
