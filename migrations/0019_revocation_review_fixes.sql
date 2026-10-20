-- v0.19 (lab): fixes from the review of 0017/0018. LAB ONLY.
-- * record_crl_intent serialises intents per CA on the CA row and refuses
--   CRL n when a higher number recorded an intent (INTENT_RECORDED, STORED
--   or RECONCILIATION_REQUIRED: possibly signed), not only when it is
--   STORED. It also refuses a reservation whose own nextUpdate has passed
--   (0017 inferred that from the current policy, which may have changed),
--   and reads the policy FOR SHARE.
-- * suspension_cps_ref must contain a letter or digit ([[:alnum:]]): the
--   0018 rule ([^[:space:]]) accepted non-ASCII spaces and invisible
--   characters (U+00A0, U+200B, U+3000). Under the C locale only ASCII
--   letters and digits count, which fails closed for a reference written
--   without any. Existing values that fail make this migration abort.
-- * reject_ and withdraw_certificate_status_change take the officer grant
--   FOR SHARE like propose_ and approve_, so a concurrent grant deletion
--   waits for the decision.
-- * approve_certificate_status_change: comment on the reserve_crl lock
--   updated (0018 changed it to FOR NO KEY UPDATE); no code change.
-- Function bodies are the latest versions (0017/0018) with only these edits.
-- Apply after 0018 as the migration owner.
BEGIN;

ALTER TABLE ca_revocation_policy
    DROP CONSTRAINT suspension_cps_ref_not_blank,
    ADD CONSTRAINT suspension_cps_ref_not_blank
        CHECK (suspension_cps_ref IS NULL OR suspension_cps_ref ~ '[[:alnum:]]');

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
    -- Intents of one CA are serialised on the CA row (taken before the
    -- publication row, as reserve_crl does), so the higher-number check
    -- below cannot race a concurrent intent for a higher number.
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
    -- Never sign a CRL older than one that may already be signed: a higher
    -- number that recorded an intent (INTENT_RECORDED, STORED, or quarantined
    -- as RECONCILIATION_REQUIRED). Relying parties keep the highest number.
    IF EXISTS (SELECT 1 FROM crl_publication cp
               WHERE cp.ca_id = p_ca AND cp.crl_number > p_crl_number
                 AND cp.status IN ('INTENT_RECORDED','STORED','RECONCILIATION_REQUIRED')) THEN
        RAISE EXCEPTION 'CRL intent refused: a higher CRL number may already be signed'
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

CREATE OR REPLACE FUNCTION reject_certificate_status_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
    v_serial BYTEA;
    v_chg certificate_status_change%ROWTYPE;
    v_request UUID;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid rejection input' USING ERRCODE='22023';
    END IF;
    SELECT s.ca_id, s.serial_der_content INTO v_ca, v_serial
    FROM certificate_status_change s WHERE s.change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown status change' USING ERRCODE='22023';
    END IF;
    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = v_ca AND c.serial_der_content = v_serial FOR UPDATE;
    SELECT * INTO v_chg FROM certificate_status_change s
    WHERE s.change_id = p_change FOR UPDATE;

    -- FOR SHARE, as in propose/approve: a concurrent grant deletion waits
    -- for this decision instead of committing underneath it.
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
      AND g.ca_id = v_ca FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;
    IF v_chg.status <> 'PROPOSED'
       OR (v_chg.maker_issuer, v_chg.maker_subject)
          = (p_checker_issuer, p_checker_subject)
    THEN
        RAISE EXCEPTION 'rejection refused: closed change or maker-checker separation'
          USING ERRCODE='23514';
    END IF;

    UPDATE certificate_status_change
    SET status = 'REJECTED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, v_request,
            p_checker_issuer || '|' || p_checker_subject,
            'certificate.status.rejected', v_chg.action || ':rejected:change=' || p_change
            || ':reason=' || COALESCE(v_chg.reason_code::text, '-'));
    RETURN 'REJECTED';
END $fn$;

CREATE OR REPLACE FUNCTION withdraw_certificate_status_change(
    p_change UUID, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
    v_serial BYTEA;
    v_chg certificate_status_change%ROWTYPE;
    v_request UUID;
BEGIN
    IF p_change IS NULL
       OR p_maker_issuer IS NULL OR length(p_maker_issuer) NOT BETWEEN 1 AND 1024
       OR p_maker_subject IS NULL OR length(p_maker_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid withdrawal input' USING ERRCODE='22023';
    END IF;
    SELECT s.ca_id, s.serial_der_content INTO v_ca, v_serial
    FROM certificate_status_change s WHERE s.change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown status change' USING ERRCODE='22023';
    END IF;
    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = v_ca AND c.serial_der_content = v_serial FOR UPDATE;
    SELECT * INTO v_chg FROM certificate_status_change s
    WHERE s.change_id = p_change FOR UPDATE;

    -- FOR SHARE, as in propose/approve: a concurrent grant deletion waits
    -- for this decision instead of committing underneath it.
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject
      AND g.ca_id = v_ca FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;
    IF v_chg.status <> 'PROPOSED'
       OR (v_chg.maker_issuer, v_chg.maker_subject)
          <> (p_maker_issuer, p_maker_subject)
    THEN
        RAISE EXCEPTION 'withdrawal refused: closed change or not the maker'
          USING ERRCODE='23514';
    END IF;

    UPDATE certificate_status_change
    SET status = 'WITHDRAWN', decided_at = clock_timestamp()
    WHERE change_id = p_change;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, v_request,
            p_maker_issuer || '|' || p_maker_subject,
            'certificate.status.withdrawn', v_chg.action || ':withdrawn:change=' || p_change
            || ':reason=' || COALESCE(v_chg.reason_code::text, '-'));
    RETURN 'WITHDRAWN';
END $fn$;

CREATE OR REPLACE FUNCTION approve_certificate_status_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT,
    p_expected_action TEXT, p_expected_reason SMALLINT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
    v_serial BYTEA;
    v_chg certificate_status_change%ROWTYPE;
    v_request UUID;
    v_status TEXT;
    v_suspension BOOLEAN;
    v_now TIMESTAMPTZ;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
       OR p_expected_action IS NULL
    THEN
        RAISE EXCEPTION 'invalid approval input' USING ERRCODE='22023';
    END IF;
    SELECT s.ca_id, s.serial_der_content INTO v_ca, v_serial
    FROM certificate_status_change s WHERE s.change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown status change' USING ERRCODE='22023';
    END IF;
    -- Lock order: certificate, then change (same as propose), then the CA row
    -- FOR SHARE. reserve_crl takes the CA row FOR NO KEY UPDATE (0018; FOR
    -- UPDATE before), which conflicts with FOR SHARE, so a CRL
    -- snapshot never interleaves with this decision: an approval either
    -- committed before the snapshot or is stamped after this_update.
    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = v_ca AND c.serial_der_content = v_serial FOR UPDATE;
    SELECT * INTO v_chg FROM certificate_status_change s
    WHERE s.change_id = p_change FOR UPDATE;
    PERFORM 1 FROM ca WHERE ca_id = v_ca FOR SHARE;
    v_now := clock_timestamp();

    -- FOR SHARE: a concurrent grant deletion or policy change waits for this
    -- decision (and this decision waits for one already in flight).
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
      AND g.ca_id = v_ca FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;
    IF (v_chg.maker_issuer, v_chg.maker_subject)
       = (p_checker_issuer, p_checker_subject)
    THEN
        RAISE EXCEPTION 'checker must differ from maker' USING ERRCODE='23514';
    END IF;
    IF v_chg.status <> 'PROPOSED'
       OR v_chg.action <> p_expected_action
       OR v_chg.reason_code IS DISTINCT FROM p_expected_reason
    THEN
        RAISE EXCEPTION 'approval refused: closed change, maker-checker separation or mismatch'
          USING ERRCODE='23514';
    END IF;
    IF v_chg.invalidity_at IS NOT NULL
       AND (v_chg.invalidity_at < TIMESTAMPTZ '1970-01-01 00:00:00+00'
            OR v_chg.invalidity_at >= TIMESTAMPTZ '10000-01-01 00:00:00+00'
            OR v_chg.invalidity_at > v_now)
    THEN
        RAISE EXCEPTION 'invalidity date must be between 1970-01-01 and 9999-12-31 and not in the future'
          USING ERRCODE='22023';
    END IF;

    v_status := certificate_status(v_ca, v_serial);
    IF (v_chg.action = 'SUSPEND' AND v_status <> 'VALID')
       OR (v_chg.action = 'RELEASE' AND v_status <> 'SUSPENDED')
       OR (v_chg.action = 'REVOKE' AND v_status = 'REVOKED')
    THEN
        RAISE EXCEPTION 'status change % not valid for % certificate',
            v_chg.action, v_status USING ERRCODE='23514';
    END IF;
    IF v_chg.action = 'SUSPEND' THEN
        SELECT suspension_allowed INTO v_suspension FROM ca_revocation_policy
        WHERE ca_id = v_ca FOR SHARE;
        IF NOT COALESCE(v_suspension, false) THEN
            RAISE EXCEPTION 'suspension is not enabled for this CA'
              USING ERRCODE='23514';
        END IF;
    END IF;

    UPDATE certificate_status_change
    SET status = 'APPROVED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = v_now
    WHERE change_id = p_change;

    IF v_chg.action = 'RELEASE' THEN
        DELETE FROM revocation
        WHERE ca_id = v_ca AND serial_der_content = v_serial;
    ELSIF v_status = 'SUSPENDED' THEN
        -- hold -> definitive: reason changes, original revoked_at is kept
        UPDATE revocation
        SET reason_code = v_chg.reason_code, invalidity_at = v_chg.invalidity_at,
            actor_id = p_checker_issuer || '|' || p_checker_subject,
            change_id = p_change
        WHERE ca_id = v_ca AND serial_der_content = v_serial;
    ELSE
        INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at,
                               invalidity_at, actor_id, change_id)
        VALUES (v_ca, v_serial, v_chg.reason_code, v_now, v_chg.invalidity_at,
                p_checker_issuer || '|' || p_checker_subject, p_change);
    END IF;

    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, v_request,
            p_checker_issuer || '|' || p_checker_subject,
            'certificate.status.approved', v_chg.action || ':applied:change=' || p_change
            || ':reason=' || COALESCE(v_chg.reason_code::text, '-'));
    RETURN 'APPROVED';
END $fn$;

COMMIT;
