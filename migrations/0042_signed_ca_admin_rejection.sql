-- v0.42 (lab): signed rejection of CA-administration changes (ADR-0007,
-- Proposed; implemented in lab at the owner's request). LAB ONLY.
-- Until now, on a CA requiring signed administration (0037), any holder of
-- trust_ca_admin could still reject a pending change by naming an admin:
-- a forged rejection silently dropped an issuer registration, an officer
-- grant or removal, or a credential change.
-- * A CA admin other than the maker rejects through a single-use REJECT
--   challenge (issue_ca_admin_challenge, re-created) and signs the
--   ca-admin/v1 claim with step REJECT: the step is part of the claim, so it
--   never verifies as the approval of the same change.
-- * reject_signed_admin_change re-checks everything but the ECDSA signature
--   (verified in Rust first), requires a signed proposal and a key and
--   person distinct from the maker's, rejects the change and stores the
--   CLOSER signature.
-- * With signed_admin_required the unsigned reject_ca_admin_change,
--   reject_credential_change and reject_admin_credential_change refuse
--   (42501); their bodies are kept as *_reject_unchecked, granted to no
--   service.
-- Apply after 0041 as a superuser.
BEGIN;

ALTER TABLE ca_admin_challenge
    DROP CONSTRAINT ca_admin_challenge_purpose_check,
    ADD CONSTRAINT ca_admin_challenge_purpose_check
        CHECK (purpose IN ('PROPOSE', 'APPROVE', 'REJECT')),
    DROP CONSTRAINT ca_admin_challenge_check,
    ADD CONSTRAINT ca_admin_challenge_check
        CHECK ((purpose IN ('APPROVE', 'REJECT')) = (change_id IS NOT NULL));
ALTER TABLE ca_admin_signature
    DROP CONSTRAINT ca_admin_signature_role_check,
    ADD CONSTRAINT ca_admin_signature_role_check
        CHECK (role IN ('MAKER', 'CHECKER', 'CLOSER'));

ALTER FUNCTION reject_ca_admin_change(uuid,text,text) RENAME TO ca_admin_reject_unchecked;
ALTER FUNCTION reject_credential_change(uuid,text,text) RENAME TO credential_reject_unchecked;
ALTER FUNCTION reject_admin_credential_change(uuid,text,text)
    RENAME TO admin_credential_reject_unchecked;
REVOKE EXECUTE ON FUNCTION ca_admin_reject_unchecked(uuid,text,text),
    credential_reject_unchecked(uuid,text,text),
    admin_credential_reject_unchecked(uuid,text,text) FROM trust_ca_admin;

CREATE FUNCTION reject_ca_admin_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_admin_required((SELECT ca_id FROM ca_admin_change WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration' USING ERRCODE = '42501';
    END IF;
    RETURN ca_admin_reject_unchecked(p_change, p_checker_issuer, p_checker_subject);
END $fn$;

CREATE FUNCTION reject_credential_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_admin_required((SELECT ca_id FROM officer_credential_change
                              WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration' USING ERRCODE = '42501';
    END IF;
    RETURN credential_reject_unchecked(p_change, p_checker_issuer, p_checker_subject);
END $fn$;

CREATE FUNCTION reject_admin_credential_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_admin_required((SELECT ca_id FROM ca_admin_credential_change
                              WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration' USING ERRCODE = '42501';
    END IF;
    RETURN admin_credential_reject_unchecked(p_change, p_checker_issuer, p_checker_subject);
END $fn$;

CREATE OR REPLACE FUNCTION issue_ca_admin_challenge(
    p_purpose TEXT, p_ca UUID, p_family TEXT, p_kind TEXT, p_content_sha256 BYTEA,
    p_change UUID, p_actor_issuer TEXT, p_actor_subject TEXT, p_ttl_seconds INTEGER
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_challenge UUID := gen_random_uuid();
    v_ca UUID := p_ca;
    v_kind TEXT := p_kind;
    v_content BYTEA := p_content_sha256;
    v_status TEXT;
    v_maker_issuer TEXT;
    v_maker_subject TEXT;
    v_issuer BYTEA;
    v_edition TEXT;
BEGIN
    IF p_purpose IS NULL OR p_purpose NOT IN ('PROPOSE', 'APPROVE', 'REJECT')
       OR p_family IS NULL OR p_family NOT IN ('CA_ADMIN', 'CREDENTIAL', 'ADMIN_CREDENTIAL')
       OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 600
       OR p_actor_issuer IS NULL OR length(p_actor_issuer) NOT BETWEEN 1 AND 1024
       OR p_actor_subject IS NULL OR length(p_actor_subject) NOT BETWEEN 1 AND 512
       OR (p_purpose = 'PROPOSE' AND (p_ca IS NULL OR p_change IS NOT NULL
            OR p_content_sha256 IS NULL OR octet_length(p_content_sha256) <> 32
            OR p_kind IS NULL
            OR (p_family = 'CA_ADMIN'
                AND p_kind NOT IN ('REGISTER_ISSUER', 'GRANT_OFFICER', 'REVOKE_OFFICER'))
            OR (p_family = 'CREDENTIAL'
                AND p_kind NOT IN ('ENROLL_CREDENTIAL', 'REMOVE_CREDENTIAL'))
            OR (p_family = 'ADMIN_CREDENTIAL'
                AND p_kind NOT IN ('ENROLL_ADMIN_CREDENTIAL', 'REMOVE_ADMIN_CREDENTIAL'))))
       OR (p_purpose IN ('APPROVE', 'REJECT') AND (p_change IS NULL OR p_kind IS NOT NULL
            OR p_content_sha256 IS NOT NULL))
    THEN
        RAISE EXCEPTION 'invalid challenge request' USING ERRCODE = '22023';
    END IF;
    IF p_purpose IN ('APPROVE', 'REJECT') THEN
        IF p_family = 'CA_ADMIN' THEN
            SELECT ca_id, kind, content_sha256, status, maker_issuer, maker_subject
              INTO v_ca, v_kind, v_content, v_status, v_maker_issuer, v_maker_subject
            FROM ca_admin_change WHERE change_id = p_change;
        ELSIF p_family = 'ADMIN_CREDENTIAL' THEN
            SELECT ca_id, kind, content_sha256, status, maker_issuer, maker_subject
              INTO v_ca, v_kind, v_content, v_status, v_maker_issuer, v_maker_subject
            FROM ca_admin_credential_change WHERE change_id = p_change;
        ELSE
            SELECT ca_id, kind, content_sha256, status, maker_issuer, maker_subject
              INTO v_ca, v_kind, v_content, v_status, v_maker_issuer, v_maker_subject
            FROM officer_credential_change WHERE change_id = p_change;
        END IF;
        IF NOT FOUND OR v_ca IS DISTINCT FROM coalesce(p_ca, v_ca) THEN
            RAISE EXCEPTION 'unknown CA admin change' USING ERRCODE = '22023';
        END IF;
        IF v_status <> 'PROPOSED' THEN
            RAISE EXCEPTION 'CA admin change is closed' USING ERRCODE = '23514';
        END IF;
        IF (v_maker_issuer, v_maker_subject) = (p_actor_issuer, p_actor_subject) THEN
            RAISE EXCEPTION 'checker must differ from maker' USING ERRCODE = '23514';
        END IF;
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = v_ca AND (g.issuer, g.subject) = (p_actor_issuer, p_actor_subject);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    SELECT certificate_sha256 INTO v_issuer FROM ca_issuer_certificate WHERE ca_id = v_ca;
    SELECT policy_version INTO v_edition FROM ca WHERE ca_id = v_ca;
    INSERT INTO ca_admin_challenge(challenge_id, ca_id, purpose, family, kind, change_id,
        content_sha256, actor_issuer, actor_subject, issuer_certificate_sha256,
        policy_edition, challenge_sha256, expires_at)
    VALUES (v_challenge, v_ca, p_purpose, p_family, v_kind, p_change, v_content,
        p_actor_issuer, p_actor_subject, v_issuer, v_edition, sha256(gen_random_bytes(32)),
        clock_timestamp() + make_interval(secs => p_ttl_seconds));
    RETURN v_challenge;
END $fn$;

CREATE FUNCTION reject_signed_admin_change(
    p_challenge UUID, p_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch ca_admin_challenge%ROWTYPE;
    v_cred ca_admin_credential%ROWTYPE;
    v_maker ca_admin_signature%ROWTYPE;
    v_claim BYTEA;
    v_result TEXT;
BEGIN
    SELECT * INTO v_ch FROM ca_admin_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    IF NOT FOUND OR v_ch.purpose <> 'REJECT' THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_cred FROM ca_admin_credential
    WHERE credential_id = p_credential_id FOR UPDATE;
    SELECT * INTO v_maker FROM ca_admin_signature
    WHERE family = v_ch.family AND change_id = v_ch.change_id AND role = 'MAKER';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the proposal was not signed' USING ERRCODE = '23514';
    END IF;
    IF v_maker.public_key_sha256 = v_cred.public_key_sha256
       OR v_maker.person_id = v_cred.person_id THEN
        RAISE EXCEPTION 'maker and checker must be distinct people with distinct keys'
          USING ERRCODE = '23514';
    END IF;
    v_claim := consume_ca_admin_challenge(v_ch, 'REJECT', v_cred, p_authenticator_data,
                                          p_client_data_json, p_signature_der);
    IF v_ch.family = 'CA_ADMIN' THEN
        v_result := ca_admin_reject_unchecked(v_ch.change_id, v_ch.actor_issuer,
                                              v_ch.actor_subject);
    ELSIF v_ch.family = 'ADMIN_CREDENTIAL' THEN
        v_result := admin_credential_reject_unchecked(v_ch.change_id, v_ch.actor_issuer,
                                                      v_ch.actor_subject);
    ELSE
        v_result := credential_reject_unchecked(v_ch.change_id, v_ch.actor_issuer,
                                                v_ch.actor_subject);
    END IF;
    INSERT INTO ca_admin_signature(family, change_id, role, challenge_id, credential_id,
        public_key_sha256, person_id, claim_sha256, authenticator_data, client_data_json,
        signature_der, sign_count)
    VALUES (v_ch.family, v_ch.change_id, 'CLOSER', p_challenge, p_credential_id,
        v_cred.public_key_sha256, v_cred.person_id, v_claim, p_authenticator_data,
        p_client_data_json, p_signature_der,
        (SELECT sign_count FROM ca_admin_credential WHERE credential_id = p_credential_id));
    RETURN v_result;
END $fn$;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'reject_ca_admin_change(uuid,text,text)',
        'reject_credential_change(uuid,text,text)',
        'reject_admin_credential_change(uuid,text,text)',
        'issue_ca_admin_challenge(text,uuid,text,text,bytea,uuid,text,text,integer)',
        'reject_signed_admin_change(uuid,bytea,bytea,bytea,bytea)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_ca_admin', f);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0042_signed_ca_admin_rejection');

COMMIT;
