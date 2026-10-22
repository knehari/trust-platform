-- v0.45 (lab): minimal break-glass for lost CA-admin keys (ADR-0007 §6,
-- Proposed; lab version chosen by the owner). LAB ONLY.
-- Once a CA requires signed administration (0037) the DBA bootstrap is
-- closed (0040), so losing the admin keys left no way back. This adds the
-- narrowest emergency path:
-- * ca_breakglass_credential: a separate WebAuthn key per CA, enrolled and
--   removed by the DBA only, held by a named custodian (holder_label). Its
--   key is never an officer or admin key (checked on all three registries).
-- * Its only power: enrol ONE CA-admin key (breakglass_enroll_admin_credential),
--   signing a ca-admin/v1 claim with step BREAK_GLASS over the content
--   digest. It cannot revoke, issue, grant officers or remove anything.
--   It works only on a CA with signed_admin_required and only while fewer
--   than two admin keys are active (a genuine loss, checked under the CA
--   lock), and the enrolled identity must hold ca_admin_grant.
-- * Every use is recorded (breakglass_use, with the signature evidence and
--   a review deadline of ca_revocation_policy.breakglass_review_hours,
--   default 24) and audited. Until two admins other than the enrolled
--   identity, with distinct keys and persons, have each signed a REVIEW of
--   it (review_breakglass_use), breakglass_uses() reports it open and
--   crl_housekeeping alerts (overdue past the deadline).
-- * breakglass_evidence(ca): the stored signatures for offline
--   re-verification (trust_audit_verifier, as 0041).
-- Apply after 0044 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD COLUMN breakglass_review_hours SMALLINT NOT NULL DEFAULT 24
        CHECK (breakglass_review_hours BETWEEN 1 AND 168);

CREATE TABLE ca_breakglass_credential (
    credential_id BYTEA PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    holder_label TEXT NOT NULL CHECK (length(holder_label) BETWEEN 1 AND 256),
    public_key_sec1 BYTEA NOT NULL CHECK (octet_length(public_key_sec1) = 33
                                          AND get_byte(public_key_sec1, 0) IN (2, 3)),
    public_key_sha256 BYTEA GENERATED ALWAYS AS (sha256(public_key_sec1)) STORED UNIQUE,
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REMOVED')),
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    removed_at TIMESTAMPTZ,
    CHECK ((status = 'ACTIVE') = (removed_at IS NULL))
);

CREATE FUNCTION guard_breakglass_credential() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ca_breakglass_credential is append-only' USING ERRCODE = '23514';
    END IF;
    IF (NEW.credential_id, NEW.ca_id, NEW.holder_label, NEW.public_key_sec1, NEW.enrolled_at)
       IS DISTINCT FROM (OLD.credential_id, OLD.ca_id, OLD.holder_label, OLD.public_key_sec1,
                         OLD.enrolled_at)
       OR NEW.sign_count < OLD.sign_count
       OR (OLD.status = 'REMOVED' AND NEW IS DISTINCT FROM OLD)
    THEN
        RAISE EXCEPTION 'only the counter may advance and an active key be removed'
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_breakglass_credential_guard
    BEFORE UPDATE OR DELETE ON ca_breakglass_credential
    FOR EACH ROW EXECUTE FUNCTION guard_breakglass_credential();
CREATE TRIGGER ca_breakglass_credential_no_truncate
    BEFORE TRUNCATE ON ca_breakglass_credential
    FOR EACH STATEMENT EXECUTE FUNCTION guard_breakglass_credential();

-- A break-glass key is never an officer or admin key, in either direction.
CREATE FUNCTION guard_breakglass_keys() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_TABLE_NAME = 'ca_breakglass_credential' THEN
        IF EXISTS (SELECT 1 FROM officer_credential
                   WHERE public_key_sha256 = sha256(NEW.public_key_sec1))
           OR EXISTS (SELECT 1 FROM ca_admin_credential
                      WHERE public_key_sha256 = sha256(NEW.public_key_sec1)) THEN
            RAISE EXCEPTION 'key already enrolled as an officer or admin key'
              USING ERRCODE = '23514';
        END IF;
    ELSIF EXISTS (SELECT 1 FROM ca_breakglass_credential
                  WHERE public_key_sha256 = sha256(NEW.public_key_sec1)) THEN
        RAISE EXCEPTION 'key already enrolled as a break-glass key' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_breakglass_credential_keys
    BEFORE INSERT ON ca_breakglass_credential
    FOR EACH ROW EXECUTE FUNCTION guard_breakglass_keys();
CREATE TRIGGER officer_credential_breakglass_keys
    BEFORE INSERT ON officer_credential
    FOR EACH ROW EXECUTE FUNCTION guard_breakglass_keys();
CREATE TRIGGER ca_admin_credential_breakglass_keys
    BEFORE INSERT ON ca_admin_credential
    FOR EACH ROW EXECUTE FUNCTION guard_breakglass_keys();

ALTER TABLE ca_admin_challenge
    DROP CONSTRAINT ca_admin_challenge_purpose_check,
    ADD CONSTRAINT ca_admin_challenge_purpose_check
        CHECK (purpose IN ('PROPOSE', 'APPROVE', 'REJECT', 'BREAK_GLASS', 'REVIEW')),
    DROP CONSTRAINT ca_admin_challenge_check,
    ADD CONSTRAINT ca_admin_challenge_check
        CHECK ((purpose IN ('APPROVE', 'REJECT', 'REVIEW')) = (change_id IS NOT NULL)),
    ADD CONSTRAINT ca_admin_challenge_breakglass_content
        CHECK (purpose NOT IN ('BREAK_GLASS', 'REVIEW')
               OR (family = 'ADMIN_CREDENTIAL' AND kind = 'ENROLL_ADMIN_CREDENTIAL'));

CREATE TABLE breakglass_use (
    use_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    breakglass_credential_id BYTEA NOT NULL REFERENCES ca_breakglass_credential(credential_id),
    challenge_id UUID NOT NULL UNIQUE REFERENCES ca_admin_challenge(challenge_id),
    admin_credential_id BYTEA NOT NULL REFERENCES ca_admin_credential(credential_id),
    admin_issuer TEXT NOT NULL,
    admin_subject TEXT NOT NULL,
    claim_sha256 BYTEA NOT NULL CHECK (octet_length(claim_sha256) = 32),
    authenticator_data BYTEA NOT NULL CHECK (octet_length(authenticator_data) = 37),
    client_data_json BYTEA NOT NULL CHECK (octet_length(client_data_json) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    sign_count BIGINT NOT NULL,
    used_at TIMESTAMPTZ NOT NULL,
    review_by TIMESTAMPTZ NOT NULL,
    reviewed_at TIMESTAMPTZ,
    CHECK (review_by > used_at)
);

-- Only reviewed_at may be set, once; nothing is deleted.
CREATE FUNCTION guard_breakglass_use() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'breakglass_use is append-only' USING ERRCODE = '23514';
    END IF;
    IF OLD.reviewed_at IS NOT NULL OR NEW.reviewed_at IS NULL
       OR (NEW.use_id, NEW.ca_id, NEW.breakglass_credential_id, NEW.challenge_id,
           NEW.admin_credential_id, NEW.admin_issuer, NEW.admin_subject, NEW.claim_sha256,
           NEW.authenticator_data, NEW.client_data_json, NEW.signature_der, NEW.sign_count,
           NEW.used_at, NEW.review_by)
          IS DISTINCT FROM
          (OLD.use_id, OLD.ca_id, OLD.breakglass_credential_id, OLD.challenge_id,
           OLD.admin_credential_id, OLD.admin_issuer, OLD.admin_subject, OLD.claim_sha256,
           OLD.authenticator_data, OLD.client_data_json, OLD.signature_der, OLD.sign_count,
           OLD.used_at, OLD.review_by)
    THEN
        RAISE EXCEPTION 'a break-glass use is only marked reviewed, once' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER breakglass_use_guard
    BEFORE UPDATE OR DELETE ON breakglass_use
    FOR EACH ROW EXECUTE FUNCTION guard_breakglass_use();
CREATE TRIGGER breakglass_use_no_truncate
    BEFORE TRUNCATE ON breakglass_use
    FOR EACH STATEMENT EXECUTE FUNCTION guard_breakglass_use();

CREATE TABLE breakglass_review (
    use_id UUID NOT NULL REFERENCES breakglass_use(use_id),
    reviewer_issuer TEXT NOT NULL,
    reviewer_subject TEXT NOT NULL,
    challenge_id UUID NOT NULL UNIQUE REFERENCES ca_admin_challenge(challenge_id),
    credential_id BYTEA NOT NULL REFERENCES ca_admin_credential(credential_id),
    public_key_sha256 BYTEA NOT NULL CHECK (octet_length(public_key_sha256) = 32),
    person_id TEXT NOT NULL,
    claim_sha256 BYTEA NOT NULL CHECK (octet_length(claim_sha256) = 32),
    authenticator_data BYTEA NOT NULL CHECK (octet_length(authenticator_data) = 37),
    client_data_json BYTEA NOT NULL CHECK (octet_length(client_data_json) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    sign_count BIGINT NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (use_id, reviewer_issuer, reviewer_subject)
);
CREATE FUNCTION guard_breakglass_review() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'breakglass_review is append-only' USING ERRCODE = '23514';
END $fn$;
CREATE TRIGGER breakglass_review_append_only
    BEFORE UPDATE OR DELETE ON breakglass_review
    FOR EACH ROW EXECUTE FUNCTION guard_breakglass_review();
CREATE TRIGGER breakglass_review_no_truncate
    BEFORE TRUNCATE ON breakglass_review
    FOR EACH STATEMENT EXECUTE FUNCTION guard_breakglass_review();

-- DBA only (no service grant): enrol or remove a CA's break-glass key.
CREATE FUNCTION enroll_breakglass_credential(
    p_ca UUID, p_credential_id BYTEA, p_holder_label TEXT, p_public_key_sec1 BYTEA
)
RETURNS VOID
LANGUAGE plpgsql AS $fn$
BEGIN
    BEGIN
        INSERT INTO ca_breakglass_credential(credential_id, ca_id, holder_label, public_key_sec1)
        VALUES (p_credential_id, p_ca, p_holder_label, p_public_key_sec1);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'credential id or public key already enrolled' USING ERRCODE = '23514';
    END;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, session_user, 'ca_admin.breakglass.enrolled',
            'BOOTSTRAP:holder=' || p_holder_label
            || ':key=' || encode(sha256(p_public_key_sec1), 'hex'));
END $fn$;

CREATE FUNCTION remove_breakglass_credential(p_credential_id BYTEA)
RETURNS VOID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
BEGIN
    UPDATE ca_breakglass_credential SET status = 'REMOVED', removed_at = clock_timestamp()
    WHERE credential_id = p_credential_id AND status = 'ACTIVE'
    RETURNING ca_id INTO v_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such active break-glass key' USING ERRCODE = '23514';
    END IF;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, NULL, session_user, 'ca_admin.breakglass.removed',
            'BOOTSTRAP:credential=' || encode(sha256(p_credential_id), 'hex'));
END $fn$;

CREATE FUNCTION breakglass_credential_for(p_ca UUID, p_credential_id BYTEA)
RETURNS TABLE (holder_label TEXT, public_key_sec1 BYTEA, sign_count BIGINT, active BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT c.holder_label, c.public_key_sec1, c.sign_count, c.status = 'ACTIVE'
    FROM ca_breakglass_credential c
    WHERE c.ca_id = p_ca AND c.credential_id = p_credential_id
$fn$;

-- The emergency is real only if fewer than two admin keys are active.
CREATE FUNCTION breakglass_admissible(p_ca UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $fn$
    SELECT signed_admin_required(p_ca)
       AND (SELECT count(*) FROM ca_admin_credential
            WHERE ca_id = p_ca AND status = 'ACTIVE') < 2
$fn$;

CREATE FUNCTION issue_breakglass_challenge(
    p_ca UUID, p_breakglass_credential_id BYTEA, p_content_sha256 BYTEA, p_ttl_seconds INTEGER
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_challenge UUID := gen_random_uuid();
    v_holder TEXT;
    v_issuer BYTEA;
    v_edition TEXT;
BEGIN
    IF p_ca IS NULL OR p_content_sha256 IS NULL OR octet_length(p_content_sha256) <> 32
       OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 600 THEN
        RAISE EXCEPTION 'invalid challenge request' USING ERRCODE = '22023';
    END IF;
    SELECT holder_label INTO v_holder FROM ca_breakglass_credential
    WHERE credential_id = p_breakglass_credential_id AND ca_id = p_ca AND status = 'ACTIVE';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active break-glass key for this CA' USING ERRCODE = '42501';
    END IF;
    IF NOT breakglass_admissible(p_ca) THEN
        RAISE EXCEPTION 'break-glass only on a signed-administration CA with fewer than two admin keys'
          USING ERRCODE = '23514';
    END IF;
    SELECT certificate_sha256 INTO v_issuer FROM ca_issuer_certificate WHERE ca_id = p_ca;
    SELECT policy_version INTO v_edition FROM ca WHERE ca_id = p_ca;
    INSERT INTO ca_admin_challenge(challenge_id, ca_id, purpose, family, kind, change_id,
        content_sha256, actor_issuer, actor_subject, issuer_certificate_sha256,
        policy_edition, challenge_sha256, expires_at)
    VALUES (v_challenge, p_ca, 'BREAK_GLASS', 'ADMIN_CREDENTIAL', 'ENROLL_ADMIN_CREDENTIAL',
        NULL, p_content_sha256, 'urn:trust-platform:break-glass', v_holder, v_issuer,
        v_edition, sha256(gen_random_bytes(32)),
        clock_timestamp() + make_interval(secs => p_ttl_seconds));
    RETURN v_challenge;
END $fn$;

CREATE FUNCTION breakglass_enroll_admin_credential(
    p_challenge UUID, p_breakglass_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA,
    p_credential_id BYTEA, p_admin_issuer TEXT, p_admin_subject TEXT, p_person_id TEXT,
    p_public_key_sec1 BYTEA
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch ca_admin_challenge%ROWTYPE;
    v_bg ca_breakglass_credential%ROWTYPE;
    v_claim BYTEA;
    v_count BIGINT;
    v_use UUID := gen_random_uuid();
    v_hours SMALLINT;
    v_now TIMESTAMPTZ;
BEGIN
    SELECT * INTO v_ch FROM ca_admin_challenge WHERE challenge_id = p_challenge;
    IF NOT FOUND OR v_ch.purpose <> 'BREAK_GLASS' THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    -- The CA lock serialises the "fewer than two admin keys" check.
    PERFORM 1 FROM ca WHERE ca_id = v_ch.ca_id FOR NO KEY UPDATE;
    SELECT * INTO v_ch FROM ca_admin_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    SELECT * INTO v_bg FROM ca_breakglass_credential
    WHERE credential_id = p_breakglass_credential_id FOR UPDATE;
    IF v_ch.consumed_at IS NOT NULL OR v_ch.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'challenge expired or already used' USING ERRCODE = '23514';
    END IF;
    IF v_bg.credential_id IS NULL OR v_bg.status <> 'ACTIVE' OR v_bg.ca_id <> v_ch.ca_id
       OR v_bg.holder_label <> v_ch.actor_subject THEN
        RAISE EXCEPTION 'not the active break-glass key of this challenge' USING ERRCODE = '42501';
    END IF;
    IF NOT breakglass_admissible(v_ch.ca_id) THEN
        RAISE EXCEPTION 'break-glass only on a signed-administration CA with fewer than two admin keys'
          USING ERRCODE = '23514';
    END IF;
    IF p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80
       OR p_public_key_sec1 IS NULL OR octet_length(p_public_key_sec1) <> 33 THEN
        RAISE EXCEPTION 'invalid break-glass input' USING ERRCODE = '22023';
    END IF;
    IF credential_change_digest('ENROLL_ADMIN_CREDENTIAL', v_ch.ca_id, p_credential_id,
            p_admin_issuer, p_admin_subject, p_person_id, p_public_key_sec1)
       IS DISTINCT FROM v_ch.content_sha256 THEN
        RAISE EXCEPTION 'enrolled content differs from the signed content' USING ERRCODE = '23514';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = v_ch.ca_id AND (g.issuer, g.subject) = (p_admin_issuer, p_admin_subject)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity holds no CA admin grant for this CA' USING ERRCODE = '23514';
    END IF;
    v_claim := ca_admin_claim_digest('BREAK_GLASS', v_ch.ca_id, v_ch.issuer_certificate_sha256,
        v_ch.family, v_ch.kind, NULL, v_ch.content_sha256, v_ch.policy_edition,
        v_ch.challenge_sha256, v_ch.expires_at);
    v_count := webauthn_precheck(p_authenticator_data, p_client_data_json, v_claim);
    IF NOT ((v_bg.sign_count = 0 AND v_count = 0) OR v_count > v_bg.sign_count) THEN
        RAISE EXCEPTION 'signature counter did not advance' USING ERRCODE = '23514';
    END IF;
    UPDATE ca_admin_challenge SET consumed_at = clock_timestamp()
    WHERE challenge_id = p_challenge;
    UPDATE ca_breakglass_credential SET sign_count = v_count
    WHERE credential_id = p_breakglass_credential_id;

    IF EXISTS (SELECT 1 FROM ca_admin_credential c
               WHERE c.ca_id = v_ch.ca_id AND c.status = 'ACTIVE'
                 AND ((c.person_id = p_person_id
                       AND (c.issuer, c.subject) <> (p_admin_issuer, p_admin_subject))
                      OR (c.person_id <> p_person_id
                          AND (c.issuer, c.subject) = (p_admin_issuer, p_admin_subject))))
    THEN
        RAISE EXCEPTION 'one person per admin identity and one identity per person'
          USING ERRCODE = '23514';
    END IF;
    BEGIN
        INSERT INTO ca_admin_credential(credential_id, ca_id, issuer, subject, person_id,
                                        public_key_sec1)
        VALUES (p_credential_id, v_ch.ca_id, p_admin_issuer, p_admin_subject, p_person_id,
                p_public_key_sec1);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'credential id or public key already enrolled' USING ERRCODE = '23514';
    END;
    SELECT breakglass_review_hours INTO v_hours FROM ca_revocation_policy
    WHERE ca_id = v_ch.ca_id;
    v_now := clock_timestamp();
    INSERT INTO breakglass_use(use_id, ca_id, breakglass_credential_id, challenge_id,
        admin_credential_id, admin_issuer, admin_subject, claim_sha256, authenticator_data,
        client_data_json, signature_der, sign_count, used_at, review_by)
    VALUES (v_use, v_ch.ca_id, p_breakglass_credential_id, p_challenge, p_credential_id,
        p_admin_issuer, p_admin_subject, v_claim, p_authenticator_data, p_client_data_json,
        p_signature_der, v_count, v_now, v_now + make_interval(hours => coalesce(v_hours, 24)));
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ch.ca_id, NULL,
            'urn:trust-platform:break-glass|' || v_bg.holder_label,
            'ca_admin.breakglass.used',
            'ENROLL_ADMIN_CREDENTIAL:use=' || v_use || ':identity=' || p_admin_issuer || '|'
            || p_admin_subject || ':review_required');
    RETURN v_use;
END $fn$;

CREATE FUNCTION issue_breakglass_review_challenge(
    p_use UUID, p_reviewer_issuer TEXT, p_reviewer_subject TEXT, p_ttl_seconds INTEGER
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_challenge UUID := gen_random_uuid();
    v_use breakglass_use%ROWTYPE;
    v_issuer BYTEA;
    v_edition TEXT;
BEGIN
    IF p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 600
       OR p_reviewer_issuer IS NULL OR p_reviewer_subject IS NULL THEN
        RAISE EXCEPTION 'invalid challenge request' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_use FROM breakglass_use WHERE use_id = p_use;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown break-glass use' USING ERRCODE = '22023';
    END IF;
    IF v_use.reviewed_at IS NOT NULL THEN
        RAISE EXCEPTION 'break-glass use already reviewed' USING ERRCODE = '23514';
    END IF;
    IF (v_use.admin_issuer, v_use.admin_subject) = (p_reviewer_issuer, p_reviewer_subject)
       OR EXISTS (SELECT 1 FROM breakglass_review r
                  WHERE r.use_id = p_use
                    AND (r.reviewer_issuer, r.reviewer_subject)
                        = (p_reviewer_issuer, p_reviewer_subject)) THEN
        RAISE EXCEPTION 'the enrolled admin does not review their own enrolment, nor twice'
          USING ERRCODE = '23514';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = v_use.ca_id AND (g.issuer, g.subject) = (p_reviewer_issuer, p_reviewer_subject);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    SELECT certificate_sha256 INTO v_issuer FROM ca_issuer_certificate WHERE ca_id = v_use.ca_id;
    SELECT policy_version INTO v_edition FROM ca WHERE ca_id = v_use.ca_id;
    -- The reviewed content is the break-glass claim itself.
    INSERT INTO ca_admin_challenge(challenge_id, ca_id, purpose, family, kind, change_id,
        content_sha256, actor_issuer, actor_subject, issuer_certificate_sha256,
        policy_edition, challenge_sha256, expires_at)
    VALUES (v_challenge, v_use.ca_id, 'REVIEW', 'ADMIN_CREDENTIAL', 'ENROLL_ADMIN_CREDENTIAL',
        p_use, v_use.claim_sha256, p_reviewer_issuer, p_reviewer_subject, v_issuer, v_edition,
        sha256(gen_random_bytes(32)), clock_timestamp() + make_interval(secs => p_ttl_seconds));
    RETURN v_challenge;
END $fn$;

CREATE FUNCTION review_breakglass_use(
    p_challenge UUID, p_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch ca_admin_challenge%ROWTYPE;
    v_cred ca_admin_credential%ROWTYPE;
    v_use breakglass_use%ROWTYPE;
    v_claim BYTEA;
    v_reviews BIGINT;
BEGIN
    SELECT * INTO v_ch FROM ca_admin_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    IF NOT FOUND OR v_ch.purpose <> 'REVIEW' THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_cred FROM ca_admin_credential WHERE credential_id = p_credential_id FOR UPDATE;
    SELECT * INTO v_use FROM breakglass_use WHERE use_id = v_ch.change_id FOR UPDATE;
    IF v_use.reviewed_at IS NOT NULL THEN
        RAISE EXCEPTION 'break-glass use already reviewed' USING ERRCODE = '23514';
    END IF;
    IF (v_use.admin_issuer, v_use.admin_subject) = (v_ch.actor_issuer, v_ch.actor_subject)
       OR v_cred.credential_id = v_use.admin_credential_id
       OR EXISTS (SELECT 1 FROM breakglass_review r
                  WHERE r.use_id = v_use.use_id
                    AND (r.public_key_sha256 = v_cred.public_key_sha256
                         OR r.person_id = v_cred.person_id
                         OR (r.reviewer_issuer, r.reviewer_subject)
                            = (v_ch.actor_issuer, v_ch.actor_subject))) THEN
        RAISE EXCEPTION 'reviews need two admins other than the enrolled one, with distinct keys and persons'
          USING ERRCODE = '23514';
    END IF;
    v_claim := consume_ca_admin_challenge(v_ch, 'REVIEW', v_cred, p_authenticator_data,
                                          p_client_data_json, p_signature_der);
    INSERT INTO breakglass_review(use_id, reviewer_issuer, reviewer_subject, challenge_id,
        credential_id, public_key_sha256, person_id, claim_sha256, authenticator_data,
        client_data_json, signature_der, sign_count)
    VALUES (v_use.use_id, v_ch.actor_issuer, v_ch.actor_subject, p_challenge, p_credential_id,
        v_cred.public_key_sha256, v_cred.person_id, v_claim, p_authenticator_data,
        p_client_data_json, p_signature_der,
        (SELECT sign_count FROM ca_admin_credential WHERE credential_id = p_credential_id));
    SELECT count(*) INTO v_reviews FROM breakglass_review WHERE use_id = v_use.use_id;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_use.ca_id, NULL, v_ch.actor_issuer || '|' || v_ch.actor_subject,
            'ca_admin.breakglass.reviewed',
            'use=' || v_use.use_id || ':reviews=' || v_reviews);
    IF v_reviews >= 2 THEN
        UPDATE breakglass_use SET reviewed_at = clock_timestamp() WHERE use_id = v_use.use_id;
        RETURN 'REVIEWED';
    END IF;
    RETURN 'PENDING_SECOND_REVIEW';
END $fn$;

CREATE FUNCTION breakglass_uses(p_ca UUID)
RETURNS TABLE (use_id UUID, admin_credential_id BYTEA, admin_issuer TEXT, admin_subject TEXT,
               used_at TIMESTAMPTZ, review_by TIMESTAMPTZ, reviews BIGINT, reviewed BOOLEAN,
               overdue BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT u.use_id, u.admin_credential_id, u.admin_issuer, u.admin_subject, u.used_at,
           u.review_by,
           (SELECT count(*) FROM breakglass_review r WHERE r.use_id = u.use_id),
           u.reviewed_at IS NOT NULL,
           u.reviewed_at IS NULL AND u.review_by <= clock_timestamp()
    FROM breakglass_use u
    WHERE u.ca_id = p_ca
    ORDER BY u.used_at, u.use_id
$fn$;

-- Offline evidence (as 0041): every break-glass signature and review
-- signature of the CA, with the enrolled content, for the Rust core to
-- re-verify; the database cannot verify ECDSA itself.
CREATE FUNCTION breakglass_evidence(p_ca UUID)
RETURNS TABLE (use_id UUID, role TEXT, challenge_id UUID, public_key_sec1 BYTEA,
               person_id TEXT, claim_sha256 BYTEA, authenticator_data BYTEA,
               client_data_json BYTEA, signature_der BYTEA, admin_credential_id BYTEA,
               admin_issuer TEXT, admin_subject TEXT, admin_person_id TEXT,
               admin_public_key_sec1 BYTEA, use_claim_sha256 BYTEA, reviewed BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT u.use_id, 'BREAK_GLASS', u.challenge_id, b.public_key_sec1, NULL::text,
           u.claim_sha256, u.authenticator_data, u.client_data_json, u.signature_der,
           a.credential_id, a.issuer, a.subject, a.person_id, a.public_key_sec1,
           u.claim_sha256, u.reviewed_at IS NOT NULL
    FROM breakglass_use u
    JOIN ca_breakglass_credential b ON b.credential_id = u.breakglass_credential_id
    JOIN ca_admin_credential a ON a.credential_id = u.admin_credential_id
    WHERE u.ca_id = p_ca
    UNION ALL
    SELECT u.use_id, 'REVIEW', r.challenge_id, c.public_key_sec1, r.person_id,
           r.claim_sha256, r.authenticator_data, r.client_data_json, r.signature_der,
           a.credential_id, a.issuer, a.subject, a.person_id, a.public_key_sec1,
           u.claim_sha256, u.reviewed_at IS NOT NULL
    FROM breakglass_review r
    JOIN breakglass_use u ON u.use_id = r.use_id
    JOIN ca_admin_credential c ON c.credential_id = r.credential_id
    JOIN ca_admin_credential a ON a.credential_id = u.admin_credential_id
    WHERE u.ca_id = p_ca
    ORDER BY 1, 2, 3
$fn$;

ALTER TABLE ca_breakglass_credential OWNER TO trust_revocation_owner;
ALTER TABLE breakglass_use OWNER TO trust_revocation_owner;
ALTER TABLE breakglass_review OWNER TO trust_revocation_owner;
REVOKE ALL ON ca_breakglass_credential, breakglass_use, breakglass_review FROM PUBLIC;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'guard_breakglass_credential()', 'guard_breakglass_keys()', 'guard_breakglass_use()',
        'guard_breakglass_review()',
        'enroll_breakglass_credential(uuid,bytea,text,bytea)',
        'remove_breakglass_credential(bytea)',
        'breakglass_credential_for(uuid,bytea)', 'breakglass_admissible(uuid)',
        'issue_breakglass_challenge(uuid,bytea,bytea,integer)',
        'breakglass_enroll_admin_credential(uuid,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'issue_breakglass_review_challenge(uuid,text,text,integer)',
        'review_breakglass_use(uuid,bytea,bytea,bytea,bytea)',
        'breakglass_uses(uuid)', 'breakglass_evidence(uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'enroll_breakglass_credential(uuid,bytea,text,bytea)',
        'remove_breakglass_credential(bytea)',
        'breakglass_credential_for(uuid,bytea)',
        'issue_breakglass_challenge(uuid,bytea,bytea,integer)',
        'breakglass_enroll_admin_credential(uuid,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'issue_breakglass_review_challenge(uuid,text,text,integer)',
        'review_breakglass_use(uuid,bytea,bytea,bytea,bytea)',
        'breakglass_uses(uuid)', 'breakglass_evidence(uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'breakglass_credential_for(uuid,bytea)',
        'issue_breakglass_challenge(uuid,bytea,bytea,integer)',
        'breakglass_enroll_admin_credential(uuid,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'issue_breakglass_review_challenge(uuid,text,text,integer)',
        'review_breakglass_use(uuid,bytea,bytea,bytea,bytea)',
        'breakglass_uses(uuid)'] LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_ca_admin', f);
    END LOOP;
    GRANT EXECUTE ON FUNCTION breakglass_uses(uuid) TO trust_crl_operator, trust_audit_verifier;
    GRANT EXECUTE ON FUNCTION breakglass_evidence(uuid) TO trust_audit_verifier;
END $fns$;

SELECT acknowledge_schema_changes('0045_break_glass');

COMMIT;
