-- v0.36 (lab): precautionary hold by one signed officer (ADR-0007 §6,
-- status Proposed; implemented in lab at the owner's request). LAB ONLY.
-- * ca_revocation_policy.precautionary_hold_hours (1..72, NULL = off, the
--   default) allows one officer to put a VALID certificate on hold
--   (certificateHold, reason 6) without a checker. It requires suspension
--   to be allowed under a CPS reference (suspension_cps_ref).
-- * The officer signs a claim whose action is PRECAUTIONARY_SUSPEND
--   (StatusChangeClaim; never accepted as the maker half of an ordinary
--   SUSPEND), through a PRECAUTION challenge: single use, bound to the
--   officer, the certificate and the CA, as in 0029. The Rust core
--   verifies the WebAuthn assertion, then apply_precautionary_hold
--   re-checks everything but the ECDSA signature, applies the hold and
--   stores the evidence (one MAKER signature).
-- * The change is recorded APPROVED with no checker and a fixed deadline
--   (confirm_by = decision + precautionary_hold_hours). Only this path can
--   write such a row: a CHECK ties a missing checker to confirm_by, and the
--   guard keeps confirm_by immutable.
-- * The hold is confirmed only by the ordinary dual-controlled path:
--   a definitive revocation (hold -> revoked) or a release. Until then
--   precautionary_holds(ca) lists it, overdue past confirm_by; housekeeping
--   alerts on overdue holds. The deadline does not lift the hold by itself
--   (fail closed: the certificate stays on hold and is reported).
-- * Every hold writes a 'certificate.status.precautionary_hold' audit event.
-- Break-glass (the other half of ADR-0007 §6) is not implemented.
-- Apply after 0035 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD COLUMN precautionary_hold_hours SMALLINT
        CHECK (precautionary_hold_hours BETWEEN 1 AND 72),
    ADD CONSTRAINT precautionary_hold_needs_cps_suspension
        CHECK (precautionary_hold_hours IS NULL
               OR (suspension_allowed AND suspension_cps_ref IS NOT NULL));

ALTER TABLE certificate_status_change
    ADD COLUMN confirm_by TIMESTAMPTZ,
    DROP CONSTRAINT status_change_decision_fields,
    ADD CONSTRAINT status_change_decision_fields CHECK (
        (confirm_by IS NULL AND (
            (status = 'PROPOSED' AND checker_issuer IS NULL AND checker_subject IS NULL
             AND decided_at IS NULL)
            OR (status IN ('APPROVED', 'REJECTED') AND checker_issuer IS NOT NULL
                AND checker_subject IS NOT NULL AND decided_at IS NOT NULL
                AND (checker_issuer <> maker_issuer OR checker_subject <> maker_subject))
            OR (status = 'WITHDRAWN' AND checker_issuer IS NULL AND checker_subject IS NULL
                AND decided_at IS NOT NULL)))
        -- A precautionary hold: applied, single officer, deadline after it.
        OR (confirm_by IS NOT NULL AND status = 'APPROVED' AND action = 'SUSPEND'
            AND reason_code = 6 AND invalidity_at IS NULL
            AND checker_issuer IS NULL AND checker_subject IS NULL
            AND decided_at IS NOT NULL AND confirm_by > decided_at));

-- The 0014 guard, with confirm_by among the fields a decision cannot set.
CREATE OR REPLACE FUNCTION guard_certificate_status_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE') THEN
        RAISE EXCEPTION 'certificate_status_change is append-only'
          USING ERRCODE='23514';
    END IF;
    IF OLD.status <> 'PROPOSED'
       OR NEW.status NOT IN ('APPROVED','REJECTED','WITHDRAWN')
       OR (NEW.change_id, NEW.ca_id, NEW.serial_der_content, NEW.action,
           NEW.reason_code, NEW.invalidity_at, NEW.maker_issuer,
           NEW.maker_subject, NEW.proposed_at, NEW.confirm_by)
          IS DISTINCT FROM
          (OLD.change_id, OLD.ca_id, OLD.serial_der_content, OLD.action,
           OLD.reason_code, OLD.invalidity_at, OLD.maker_issuer,
           OLD.maker_subject, OLD.proposed_at, OLD.confirm_by)
    THEN
        RAISE EXCEPTION 'only PROPOSED may become APPROVED, REJECTED or WITHDRAWN'
          USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $fn$;
-- CREATE OR REPLACE resets the pinned search_path (see 0025).
ALTER FUNCTION guard_certificate_status_change() SET search_path = pg_catalog, public, pg_temp;

ALTER TABLE status_change_challenge
    DROP CONSTRAINT status_change_challenge_purpose_check,
    ADD CONSTRAINT status_change_challenge_purpose_check
        CHECK (purpose IN ('PROPOSE', 'APPROVE', 'PRECAUTION')),
    DROP CONSTRAINT status_change_challenge_action_check,
    ADD CONSTRAINT status_change_challenge_action_check
        CHECK (action IN ('SUSPEND', 'RELEASE', 'REVOKE', 'PRECAUTIONARY_SUSPEND')),
    ADD CONSTRAINT status_change_challenge_precaution_fields
        CHECK ((purpose = 'PRECAUTION') = (action = 'PRECAUTIONARY_SUSPEND')
               AND (purpose <> 'PRECAUTION'
                    OR (reason_code = 6 AND invalidity_at IS NULL)));
CREATE UNIQUE INDEX status_change_challenge_precaution
    ON status_change_challenge (change_id) WHERE purpose = 'PRECAUTION';

CREATE FUNCTION issue_precautionary_hold_challenge(
    p_ca UUID, p_serial BYTEA, p_actor_issuer TEXT, p_actor_subject TEXT,
    p_ttl_seconds INTEGER
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_challenge UUID := gen_random_uuid();
    v_hours SMALLINT;
    v_issuer BYTEA;
    v_edition TEXT;
BEGIN
    IF p_ca IS NULL OR p_serial IS NULL OR octet_length(p_serial) NOT BETWEEN 1 AND 20
       OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 600
       OR p_actor_issuer IS NULL OR length(p_actor_issuer) NOT BETWEEN 1 AND 1024
       OR p_actor_subject IS NULL OR length(p_actor_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid challenge request' USING ERRCODE = '22023';
    END IF;
    SELECT precautionary_hold_hours INTO v_hours FROM ca_revocation_policy
    WHERE ca_id = p_ca;
    IF v_hours IS NULL THEN
        RAISE EXCEPTION 'precautionary holds are not enabled for this CA'
          USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM certificate
                   WHERE ca_id = p_ca AND serial_der_content = p_serial) THEN
        RAISE EXCEPTION 'unknown certificate' USING ERRCODE = '22023';
    END IF;
    IF certificate_status(p_ca, p_serial) <> 'VALID' THEN
        RAISE EXCEPTION 'only a valid certificate can be put on precautionary hold'
          USING ERRCODE = '23514';
    END IF;
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.ca_id = p_ca AND (g.issuer, g.subject) = (p_actor_issuer, p_actor_subject);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE = '42501';
    END IF;
    SELECT certificate_sha256 INTO v_issuer FROM ca_issuer_certificate WHERE ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no issuer certificate registered for this CA' USING ERRCODE = '42704';
    END IF;
    SELECT policy_version INTO v_edition FROM ca WHERE ca_id = p_ca;
    INSERT INTO status_change_challenge(challenge_id, ca_id, purpose, change_id,
        serial_der_content, action, reason_code, invalidity_at, actor_issuer, actor_subject,
        issuer_certificate_sha256, policy_edition, challenge_sha256, expires_at)
    VALUES (v_challenge, p_ca, 'PRECAUTION', gen_random_uuid(), p_serial,
        'PRECAUTIONARY_SUSPEND', 6, NULL, p_actor_issuer, p_actor_subject, v_issuer,
        v_edition, sha256(gen_random_bytes(32)),
        clock_timestamp() + make_interval(secs => p_ttl_seconds));
    RETURN v_challenge;
END $fn$;

CREATE FUNCTION apply_precautionary_hold(
    p_challenge UUID, p_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch status_change_challenge%ROWTYPE;
    v_cred officer_credential%ROWTYPE;
    v_policy ca_revocation_policy%ROWTYPE;
    v_request UUID;
    v_claim BYTEA;
    v_actor TEXT;
    v_now TIMESTAMPTZ;
    v_confirm_by TIMESTAMPTZ;
BEGIN
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    -- Lock order (0025): certificate, then challenge and credential, then
    -- the CA row FOR SHARE (orders the hold against CRL snapshots, as an
    -- approval does), then grant and policy.
    SELECT request_id INTO v_request FROM certificate
    WHERE ca_id = v_ch.ca_id AND serial_der_content = v_ch.serial_der_content FOR UPDATE;
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    SELECT * INTO v_cred FROM officer_credential WHERE credential_id = p_credential_id FOR UPDATE;
    v_claim := consume_signed_challenge(v_ch, 'PRECAUTION', v_cred, p_authenticator_data,
                                        p_client_data_json, p_signature_der);
    PERFORM 1 FROM ca WHERE ca_id = v_ch.ca_id FOR SHARE;
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.ca_id = v_ch.ca_id AND (g.issuer, g.subject) = (v_ch.actor_issuer, v_ch.actor_subject)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_policy FROM ca_revocation_policy WHERE ca_id = v_ch.ca_id FOR SHARE;
    IF v_policy.precautionary_hold_hours IS NULL OR NOT v_policy.suspension_allowed THEN
        RAISE EXCEPTION 'precautionary holds are not enabled for this CA'
          USING ERRCODE = '23514';
    END IF;
    IF certificate_status(v_ch.ca_id, v_ch.serial_der_content) <> 'VALID' THEN
        RAISE EXCEPTION 'only a valid certificate can be put on precautionary hold'
          USING ERRCODE = '23514';
    END IF;

    v_now := clock_timestamp();
    v_confirm_by := v_now + make_interval(hours => v_policy.precautionary_hold_hours);
    v_actor := v_ch.actor_issuer || '|' || v_ch.actor_subject;
    INSERT INTO certificate_status_change(change_id, ca_id, serial_der_content, action,
        reason_code, invalidity_at, maker_issuer, maker_subject, status, proposed_at,
        decided_at, confirm_by)
    VALUES (v_ch.change_id, v_ch.ca_id, v_ch.serial_der_content, 'SUSPEND', 6, NULL,
        v_ch.actor_issuer, v_ch.actor_subject, 'APPROVED', v_now, v_now, v_confirm_by);
    INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at,
                           invalidity_at, actor_id, change_id)
    VALUES (v_ch.ca_id, v_ch.serial_der_content, 6, v_now, NULL, v_actor, v_ch.change_id);
    INSERT INTO status_change_signature(change_id, role, challenge_id, credential_id,
        public_key_sha256, person_id, claim_sha256, authenticator_data, client_data_json,
        signature_der, sign_count)
    VALUES (v_ch.change_id, 'MAKER', p_challenge, p_credential_id, v_cred.public_key_sha256,
        v_cred.person_id, v_claim, p_authenticator_data, p_client_data_json, p_signature_der,
        (SELECT sign_count FROM officer_credential WHERE credential_id = p_credential_id));
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ch.ca_id, v_request, v_actor,
            'certificate.status.precautionary_hold',
            'SUSPEND:precaution:change=' || v_ch.change_id || ':reason=6:confirm_by='
            || to_char(v_confirm_by AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'));
    RETURN v_ch.change_id;
END $fn$;

-- Holds not yet followed by a dual-controlled revocation or release: the
-- certificate's revocation row is still the one this change wrote.
CREATE FUNCTION precautionary_holds(p_ca UUID)
RETURNS TABLE (change_id UUID, serial_der_content BYTEA, maker_issuer TEXT,
               maker_subject TEXT, held_at TIMESTAMPTZ, confirm_by TIMESTAMPTZ,
               overdue BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT s.change_id, s.serial_der_content, s.maker_issuer, s.maker_subject,
           s.decided_at, s.confirm_by, s.confirm_by <= clock_timestamp()
    FROM certificate_status_change s
    JOIN revocation r ON r.change_id = s.change_id AND r.reason_code = 6
    WHERE s.ca_id = p_ca AND s.confirm_by IS NOT NULL
    ORDER BY s.decided_at, s.change_id
$fn$;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'issue_precautionary_hold_challenge(uuid,bytea,text,text,integer)',
        'apply_precautionary_hold(uuid,bytea,bytea,bytea,bytea)',
        'precautionary_holds(uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_revocation_officer_api', f);
    END LOOP;
END $fns$;
GRANT EXECUTE ON FUNCTION precautionary_holds(uuid) TO trust_crl_operator;

SELECT acknowledge_schema_changes('0036_precautionary_hold');

COMMIT;
