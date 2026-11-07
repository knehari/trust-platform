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
-- * Lifecycle audit decisions name the change and the reason:
--   '<ACTION>:<outcome>:change=<uuid>:reason=<code or ->'. The four
--   functions are the 0014 bodies with only the audit decision changed.
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


CREATE OR REPLACE FUNCTION propose_certificate_status_change(
    p_ca UUID, p_serial BYTEA, p_action TEXT, p_reason SMALLINT,
    p_invalidity TIMESTAMPTZ, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_request UUID;
    v_status TEXT;
    v_suspension BOOLEAN;
    v_change UUID := gen_random_uuid();
BEGIN
    IF p_ca IS NULL OR p_serial IS NULL
       OR p_maker_issuer IS NULL OR length(p_maker_issuer) NOT BETWEEN 1 AND 1024
       OR p_maker_subject IS NULL OR length(p_maker_subject) NOT BETWEEN 1 AND 512
       OR p_action IS NULL OR p_action NOT IN ('SUSPEND','RELEASE','REVOKE')
       OR (p_action = 'RELEASE' AND (p_reason IS NOT NULL OR p_invalidity IS NOT NULL))
       OR (p_action <> 'RELEASE' AND (p_reason IS NULL
            OR p_reason NOT IN (0,1,2,3,4,5,6,9,10)))
    THEN
        RAISE EXCEPTION 'invalid status change proposal input' USING ERRCODE='22023';
    END IF;
    IF p_invalidity IS NOT NULL
       AND (p_invalidity < TIMESTAMPTZ '1970-01-01 00:00:00+00'
            OR p_invalidity >= TIMESTAMPTZ '10000-01-01 00:00:00+00'
            OR p_invalidity > clock_timestamp())
    THEN
        RAISE EXCEPTION 'invalidity date must be between 1970-01-01 and 9999-12-31 and not in the future'
          USING ERRCODE='22023';
    END IF;
    -- FOR SHARE: a concurrent grant deletion waits for this decision.
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject
      AND g.ca_id = p_ca FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
    END IF;

    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = p_ca AND c.serial_der_content = p_serial FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown certificate' USING ERRCODE='22023';
    END IF;
    v_status := certificate_status(p_ca, p_serial);

    IF (p_action = 'SUSPEND' AND (v_status <> 'VALID' OR p_reason <> 6))
       OR (p_action = 'RELEASE' AND v_status <> 'SUSPENDED')
       OR (p_action = 'REVOKE' AND (v_status = 'REVOKED' OR p_reason = 6))
    THEN
        RAISE EXCEPTION 'status change % not valid for % certificate',
            p_action, v_status USING ERRCODE='23514';
    END IF;
    IF p_action = 'SUSPEND' THEN
        SELECT suspension_allowed INTO v_suspension FROM ca_revocation_policy
        WHERE ca_id = p_ca FOR SHARE;
        IF NOT COALESCE(v_suspension, false) THEN
            RAISE EXCEPTION 'suspension is not enabled for this CA'
              USING ERRCODE='23514';
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_status_change s
               WHERE s.ca_id = p_ca AND s.serial_der_content = p_serial
                 AND s.status = 'PROPOSED') THEN
        RAISE EXCEPTION 'an open status change already exists' USING ERRCODE='23514';
    END IF;

    INSERT INTO certificate_status_change(
        change_id, ca_id, serial_der_content, action, reason_code,
        invalidity_at, maker_issuer, maker_subject
    ) VALUES (
        v_change, p_ca, p_serial, p_action, p_reason, p_invalidity,
        p_maker_issuer, p_maker_subject
    );
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, v_request,
            p_maker_issuer || '|' || p_maker_subject,
            'certificate.status.proposed', p_action || ':pending_approval:change=' || v_change
            || ':reason=' || COALESCE(p_reason::text, '-'));
    RETURN v_change;
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
    -- FOR SHARE. reserve_crl (0015) takes the CA row FOR UPDATE, so a CRL
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

    IF NOT EXISTS (SELECT 1 FROM revocation_officer_grant g
                   WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
                     AND g.ca_id = v_ca) THEN
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

    IF NOT EXISTS (SELECT 1 FROM revocation_officer_grant g
                   WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject
                     AND g.ca_id = v_ca) THEN
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

COMMIT;
