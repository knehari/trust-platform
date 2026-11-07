-- v0.25 (lab): status-change lock order and reporting index. LAB ONLY.
-- * propose_certificate_status_change locks the certificate row before the
--   officer grant, like approve_/reject_/withdraw_. With the opposite order,
--   a proposal, an approval on the same certificate and a bulk deletion of
--   the CA's grants formed a lock cycle (40P01, tests/revocation_lock_order.sh).
--   Behaviour and error codes are unchanged, except that an unknown
--   certificate is now reported before a missing grant.
--   CREATE OR REPLACE keeps the owner and grants, but resets SECURITY
--   DEFINER and the pinned search_path to their defaults, so they are set
--   again below (tests/revocation_privileges.sql now checks every service
--   function in the catalog).
-- * certificate_status_change gets an index on (ca_id, serial_der_content,
--   status, decided_at), which the supersession probes of crl_due and
--   overdue_status_changes use for each approved change.
-- Apply after 0024 as a superuser.
BEGIN;

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
    -- Lock order shared by every status-change function: certificate row
    -- first, then the officer grant (0025). Grant-then-certificate here could
    -- deadlock with an approval and a bulk grant deletion.
    SELECT c.request_id INTO v_request FROM certificate c
    WHERE c.ca_id = p_ca AND c.serial_der_content = p_serial FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown certificate' USING ERRCODE='22023';
    END IF;
    -- FOR SHARE: a concurrent grant deletion waits for this decision.
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject
      AND g.ca_id = p_ca FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE='42501';
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

ALTER FUNCTION propose_certificate_status_change(uuid,bytea,text,smallint,timestamp with time zone,text,text)
    SECURITY DEFINER;
ALTER FUNCTION propose_certificate_status_change(uuid,bytea,text,smallint,timestamp with time zone,text,text)
    SET search_path = pg_catalog, public, pg_temp;

CREATE INDEX certificate_status_change_supersession
    ON certificate_status_change (ca_id, serial_der_content, status, decided_at);

COMMIT;
