-- v0.39 (lab): signed rejection and withdrawal of status changes (ADR-0007,
-- Proposed; implemented in lab at the owner's request). LAB ONLY.
-- Until now a CA with signed_approvals_required (0029) still let anyone
-- holding trust_revocation_officer_api close a pending proposal by naming
-- an officer: a forged rejection silently dropped a revocation request.
-- * A checker (not the maker) rejects, or the maker withdraws, through a
--   single-use REJECT / WITHDRAW challenge (issue_close_challenge). The
--   officer signs the closing claim: StatusChangeClaim::closing_digest =
--   status_change_close_digest, i.e. its own tag
--   ("trust-platform/status-change-close/v1") and the step before the
--   change's fields, so it never verifies as a maker or checker claim.
-- * close_signed_status_change re-checks everything but the ECDSA signature
--   (verified in Rust first), requires the proposal to have been signed,
--   distinct key and person for a rejection (as for an approval), the
--   maker's person for a withdrawal, then closes the change and stores the
--   CLOSER signature.
-- * With signed_approvals_required the unsigned reject/withdraw refuse
--   (42501); their bodies are kept as status_change_reject_unchecked /
--   status_change_withdraw_unchecked, granted to no service.
-- CA-admin rejection (0024/0028) is still unsigned.
-- Apply after 0038 as a superuser.
BEGIN;

ALTER TABLE status_change_challenge
    DROP CONSTRAINT status_change_challenge_purpose_check,
    ADD CONSTRAINT status_change_challenge_purpose_check
        CHECK (purpose IN ('PROPOSE', 'APPROVE', 'PRECAUTION', 'REJECT', 'WITHDRAW'));

ALTER TABLE status_change_signature
    DROP CONSTRAINT status_change_signature_role_check,
    ADD CONSTRAINT status_change_signature_role_check
        CHECK (role IN ('MAKER', 'CHECKER', 'CLOSER'));

CREATE FUNCTION status_change_close_digest(
    p_step TEXT, p_change UUID, p_ca UUID, p_issuer_sha256 BYTEA, p_serial BYTEA,
    p_action TEXT, p_reason SMALLINT, p_invalidity TIMESTAMPTZ, p_edition TEXT,
    p_challenge_sha256 BYTEA, p_expires TIMESTAMPTZ
)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT sha256(convert_to('trust-platform/status-change-close/v1', 'UTF8') || '\x00'::bytea
        || claim_field(convert_to(p_step, 'UTF8'))
        || claim_field(uuid_send(p_change))
        || claim_field(uuid_send(p_ca))
        || claim_field(p_issuer_sha256)
        || claim_field(p_serial)
        || claim_field(convert_to(p_action, 'UTF8'))
        || claim_field(CASE WHEN p_reason IS NULL THEN NULL
                            ELSE set_byte('\x00'::bytea, 0, p_reason) END)
        || claim_field(int8send((extract(epoch FROM p_invalidity) * 1000000)::bigint))
        || claim_field(convert_to(p_edition, 'UTF8'))
        || claim_field(p_challenge_sha256)
        || claim_field(int8send((extract(epoch FROM p_expires) * 1000000)::bigint)))
$fn$;

-- The 0029 body, with the closing digest for REJECT / WITHDRAW challenges.
CREATE OR REPLACE FUNCTION consume_signed_challenge(
    p_challenge status_change_challenge, p_purpose TEXT, p_credential officer_credential,
    p_authenticator_data BYTEA, p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS BYTEA
LANGUAGE plpgsql AS $fn$
DECLARE
    v_claim BYTEA;
    v_count BIGINT;
BEGIN
    IF p_challenge.purpose <> p_purpose THEN
        RAISE EXCEPTION 'challenge issued for another step' USING ERRCODE = '22023';
    END IF;
    IF p_challenge.consumed_at IS NOT NULL OR p_challenge.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'challenge expired or already used' USING ERRCODE = '23514';
    END IF;
    IF p_credential.credential_id IS NULL OR p_credential.status <> 'ACTIVE'
       OR p_credential.ca_id <> p_challenge.ca_id
       OR (p_credential.issuer, p_credential.subject)
          <> (p_challenge.actor_issuer, p_challenge.actor_subject) THEN
        RAISE EXCEPTION 'credential is not an active credential of the acting officer'
          USING ERRCODE = '42501';
    END IF;
    IF p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80 THEN
        RAISE EXCEPTION 'invalid signature encoding' USING ERRCODE = '22023';
    END IF;
    IF p_challenge.purpose IN ('REJECT', 'WITHDRAW') THEN
        v_claim := status_change_close_digest(p_challenge.purpose, p_challenge.change_id,
            p_challenge.ca_id, p_challenge.issuer_certificate_sha256,
            p_challenge.serial_der_content, p_challenge.action, p_challenge.reason_code,
            p_challenge.invalidity_at, p_challenge.policy_edition, p_challenge.challenge_sha256,
            p_challenge.expires_at);
    ELSE
        v_claim := status_change_claim_digest(p_challenge.change_id, p_challenge.ca_id,
            p_challenge.issuer_certificate_sha256, p_challenge.serial_der_content,
            p_challenge.action, p_challenge.reason_code, p_challenge.invalidity_at,
            p_challenge.policy_edition, p_challenge.challenge_sha256, p_challenge.expires_at);
    END IF;
    v_count := webauthn_precheck(p_authenticator_data, p_client_data_json, v_claim);
    IF NOT ((p_credential.sign_count = 0 AND v_count = 0) OR v_count > p_credential.sign_count) THEN
        RAISE EXCEPTION 'signature counter did not advance' USING ERRCODE = '23514';
    END IF;
    UPDATE status_change_challenge SET consumed_at = clock_timestamp()
    WHERE challenge_id = p_challenge.challenge_id;
    UPDATE officer_credential SET sign_count = v_count
    WHERE credential_id = p_credential.credential_id;
    RETURN v_claim;
END $fn$;

CREATE FUNCTION issue_close_challenge(
    p_purpose TEXT, p_change UUID, p_actor_issuer TEXT, p_actor_subject TEXT,
    p_ttl_seconds INTEGER
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_challenge UUID := gen_random_uuid();
    v_change certificate_status_change%ROWTYPE;
    v_issuer BYTEA;
    v_edition TEXT;
    v_is_maker BOOLEAN;
BEGIN
    IF p_purpose IS NULL OR p_purpose NOT IN ('REJECT', 'WITHDRAW') OR p_change IS NULL
       OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 600
       OR p_actor_issuer IS NULL OR length(p_actor_issuer) NOT BETWEEN 1 AND 1024
       OR p_actor_subject IS NULL OR length(p_actor_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid challenge request' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_change FROM certificate_status_change WHERE change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown status change' USING ERRCODE = '22023';
    END IF;
    IF v_change.status <> 'PROPOSED' THEN
        RAISE EXCEPTION 'status change is closed' USING ERRCODE = '23514';
    END IF;
    v_is_maker := (v_change.maker_issuer, v_change.maker_subject)
                  = (p_actor_issuer, p_actor_subject);
    IF (p_purpose = 'REJECT' AND v_is_maker) OR (p_purpose = 'WITHDRAW' AND NOT v_is_maker) THEN
        RAISE EXCEPTION 'a checker rejects, the maker withdraws' USING ERRCODE = '23514';
    END IF;
    PERFORM 1 FROM revocation_officer_grant g
    WHERE g.ca_id = v_change.ca_id AND (g.issuer, g.subject) = (p_actor_issuer, p_actor_subject);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no revocation officer grant for this CA'
          USING ERRCODE = '42501';
    END IF;
    SELECT certificate_sha256 INTO v_issuer FROM ca_issuer_certificate
    WHERE ca_id = v_change.ca_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no issuer certificate registered for this CA' USING ERRCODE = '42704';
    END IF;
    SELECT policy_version INTO v_edition FROM ca WHERE ca_id = v_change.ca_id;
    INSERT INTO status_change_challenge(challenge_id, ca_id, purpose, change_id,
        serial_der_content, action, reason_code, invalidity_at, actor_issuer, actor_subject,
        issuer_certificate_sha256, policy_edition, challenge_sha256, expires_at)
    VALUES (v_challenge, v_change.ca_id, p_purpose, p_change, v_change.serial_der_content,
        v_change.action, v_change.reason_code, v_change.invalidity_at, p_actor_issuer,
        p_actor_subject, v_issuer, v_edition, sha256(gen_random_bytes(32)),
        clock_timestamp() + make_interval(secs => p_ttl_seconds));
    RETURN v_challenge;
END $fn$;

-- The unsigned paths become *_unchecked; the original names refuse when the
-- CA requires signatures.
ALTER FUNCTION reject_certificate_status_change(uuid,text,text)
    RENAME TO status_change_reject_unchecked;
ALTER FUNCTION withdraw_certificate_status_change(uuid,text,text)
    RENAME TO status_change_withdraw_unchecked;
REVOKE EXECUTE ON FUNCTION status_change_reject_unchecked(uuid,text,text),
    status_change_withdraw_unchecked(uuid,text,text) FROM trust_revocation_officer_api;

CREATE FUNCTION reject_certificate_status_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_approvals_required((SELECT ca_id FROM certificate_status_change
                                  WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed status changes' USING ERRCODE = '42501';
    END IF;
    RETURN status_change_reject_unchecked(p_change, p_checker_issuer, p_checker_subject);
END $fn$;

CREATE FUNCTION withdraw_certificate_status_change(
    p_change UUID, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_approvals_required((SELECT ca_id FROM certificate_status_change
                                  WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed status changes' USING ERRCODE = '42501';
    END IF;
    RETURN status_change_withdraw_unchecked(p_change, p_maker_issuer, p_maker_subject);
END $fn$;

CREATE FUNCTION close_signed_status_change(
    p_challenge UUID, p_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch status_change_challenge%ROWTYPE;
    v_cred officer_credential%ROWTYPE;
    v_maker status_change_signature%ROWTYPE;
    v_claim BYTEA;
    v_result TEXT;
BEGIN
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge;
    IF NOT FOUND OR v_ch.purpose NOT IN ('REJECT', 'WITHDRAW') THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    -- Lock order (0025): certificate, then challenge and credential.
    PERFORM 1 FROM certificate
    WHERE ca_id = v_ch.ca_id AND serial_der_content = v_ch.serial_der_content FOR UPDATE;
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    SELECT * INTO v_cred FROM officer_credential WHERE credential_id = p_credential_id FOR UPDATE;
    SELECT * INTO v_maker FROM status_change_signature
    WHERE change_id = v_ch.change_id AND role = 'MAKER';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the proposal was not signed' USING ERRCODE = '23514';
    END IF;
    IF v_ch.purpose = 'REJECT' AND (v_maker.public_key_sha256 = v_cred.public_key_sha256
                                    OR v_maker.person_id = v_cred.person_id) THEN
        RAISE EXCEPTION 'maker and checker must be distinct people with distinct keys'
          USING ERRCODE = '23514';
    END IF;
    IF v_ch.purpose = 'WITHDRAW' AND v_maker.person_id IS DISTINCT FROM v_cred.person_id THEN
        RAISE EXCEPTION 'only the maker withdraws' USING ERRCODE = '23514';
    END IF;
    v_claim := consume_signed_challenge(v_ch, v_ch.purpose, v_cred, p_authenticator_data,
                                        p_client_data_json, p_signature_der);
    IF v_ch.purpose = 'REJECT' THEN
        v_result := status_change_reject_unchecked(v_ch.change_id, v_ch.actor_issuer,
                                                   v_ch.actor_subject);
    ELSE
        v_result := status_change_withdraw_unchecked(v_ch.change_id, v_ch.actor_issuer,
                                                     v_ch.actor_subject);
    END IF;
    INSERT INTO status_change_signature(change_id, role, challenge_id, credential_id,
        public_key_sha256, person_id, claim_sha256, authenticator_data, client_data_json,
        signature_der, sign_count)
    VALUES (v_ch.change_id, 'CLOSER', p_challenge, p_credential_id, v_cred.public_key_sha256,
        v_cred.person_id, v_claim, p_authenticator_data, p_client_data_json, p_signature_der,
        (SELECT sign_count FROM officer_credential WHERE credential_id = p_credential_id));
    RETURN v_result;
END $fn$;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'status_change_close_digest(text,uuid,uuid,bytea,bytea,text,smallint,timestamptz,text,bytea,timestamptz)',
        'consume_signed_challenge(status_change_challenge,text,officer_credential,bytea,bytea,bytea)',
        'issue_close_challenge(text,uuid,text,text,integer)',
        'reject_certificate_status_change(uuid,text,text)',
        'withdraw_certificate_status_change(uuid,text,text)',
        'close_signed_status_change(uuid,bytea,bytea,bytea,bytea)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'issue_close_challenge(text,uuid,text,text,integer)',
        'reject_certificate_status_change(uuid,text,text)',
        'withdraw_certificate_status_change(uuid,text,text)',
        'close_signed_status_change(uuid,bytea,bytea,bytea,bytea)'] LOOP
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_revocation_officer_api', f);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0039_signed_close');

COMMIT;
