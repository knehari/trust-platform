-- v0.40 (lab): CA-admin keys under signed dual control (ADR-0007 §5,
-- Proposed; implemented in lab at the owner's request). LAB ONLY.
-- Until now admin WebAuthn keys (0037) were enrolled only by the DBA
-- (enroll_ca_admin_credential), outside dual control, even on a CA that
-- requires signed administration: whoever runs SQL as a superuser could
-- add a key and sign as an admin.
-- * ca_admin_credential_change: enrolment or removal of an admin key,
--   proposed by one CA admin and approved by another, both signing the
--   ca-admin/v1 claim (family ADMIN_CREDENTIAL; kinds ENROLL_ / REMOVE_
--   ADMIN_CREDENTIAL; content digest = credential_change_digest under that
--   kind). Nobody proposes or approves a change to their own key; the
--   enrolled identity must hold ca_admin_grant; one person per admin
--   identity; the registry triggers of 0037 still keep officer and admin
--   keys and persons apart. History is append-only.
-- * There is no unsigned path: the functions doing the work are
--   *_unchecked, granted to no service, and called only from
--   propose_signed_admin_change / approve_signed_admin_change (re-created
--   here with the new family, as are issue_ca_admin_challenge and
--   ca_admin_signatures; definer settings re-applied).
-- * enroll_ca_admin_credential (DBA bootstrap) refuses once the CA requires
--   signed administration. remove_ca_admin_credential stays open to the DBA:
--   it only reduces who can sign (emergency removal of a stolen key).
-- * reject_admin_credential_change (unsigned, like the other CA-admin
--   rejections) lets a second admin drop a pending change.
-- Apply after 0039 as a superuser.
BEGIN;

ALTER TABLE ca_admin_challenge
    DROP CONSTRAINT ca_admin_challenge_family_check,
    ADD CONSTRAINT ca_admin_challenge_family_check
        CHECK (family IN ('CA_ADMIN', 'CREDENTIAL', 'ADMIN_CREDENTIAL')),
    DROP CONSTRAINT ca_admin_challenge_kind_check,
    ADD CONSTRAINT ca_admin_challenge_kind_check
        CHECK (kind IN ('REGISTER_ISSUER', 'GRANT_OFFICER', 'REVOKE_OFFICER',
                        'ENROLL_CREDENTIAL', 'REMOVE_CREDENTIAL',
                        'ENROLL_ADMIN_CREDENTIAL', 'REMOVE_ADMIN_CREDENTIAL')),
    ADD CONSTRAINT ca_admin_challenge_admin_credential_kind
        CHECK ((family = 'ADMIN_CREDENTIAL')
               = (kind IN ('ENROLL_ADMIN_CREDENTIAL', 'REMOVE_ADMIN_CREDENTIAL')));
ALTER TABLE ca_admin_signature
    DROP CONSTRAINT ca_admin_signature_family_check,
    ADD CONSTRAINT ca_admin_signature_family_check
        CHECK (family IN ('CA_ADMIN', 'CREDENTIAL', 'ADMIN_CREDENTIAL'));

CREATE TABLE ca_admin_credential_change (
    change_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    kind TEXT NOT NULL CHECK (kind IN ('ENROLL_ADMIN_CREDENTIAL', 'REMOVE_ADMIN_CREDENTIAL')),
    credential_id BYTEA NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    admin_issuer TEXT NOT NULL CHECK (length(admin_issuer) BETWEEN 1 AND 1024),
    admin_subject TEXT NOT NULL CHECK (length(admin_subject) BETWEEN 1 AND 512),
    person_id TEXT NOT NULL CHECK (length(person_id) BETWEEN 1 AND 256),
    public_key_sec1 BYTEA NOT NULL CHECK (octet_length(public_key_sec1) = 33
                                          AND get_byte(public_key_sec1, 0) IN (2, 3)),
    content_sha256 BYTEA NOT NULL CHECK (octet_length(content_sha256) = 32),
    maker_issuer TEXT NOT NULL,
    maker_subject TEXT NOT NULL,
    checker_issuer TEXT,
    checker_subject TEXT,
    status TEXT NOT NULL DEFAULT 'PROPOSED' CHECK (status IN ('PROPOSED', 'APPROVED', 'REJECTED')),
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    decided_at TIMESTAMPTZ,
    CONSTRAINT ca_admin_credential_change_decision CHECK (
        (status = 'PROPOSED' AND checker_issuer IS NULL AND decided_at IS NULL)
        OR (status <> 'PROPOSED' AND checker_issuer IS NOT NULL AND checker_subject IS NOT NULL
            AND decided_at IS NOT NULL
            AND (checker_issuer, checker_subject) <> (maker_issuer, maker_subject)))
);

-- Only PROPOSED -> APPROVED | REJECTED with the checker and decision time.
CREATE FUNCTION guard_ca_admin_credential_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ca_admin_credential_change is append-only' USING ERRCODE = '23514';
    END IF;
    IF OLD.status <> 'PROPOSED' OR NEW.status NOT IN ('APPROVED', 'REJECTED')
       OR (NEW.change_id, NEW.ca_id, NEW.kind, NEW.credential_id, NEW.admin_issuer,
           NEW.admin_subject, NEW.person_id, NEW.public_key_sec1, NEW.content_sha256,
           NEW.maker_issuer, NEW.maker_subject, NEW.proposed_at)
          IS DISTINCT FROM
          (OLD.change_id, OLD.ca_id, OLD.kind, OLD.credential_id, OLD.admin_issuer,
           OLD.admin_subject, OLD.person_id, OLD.public_key_sec1, OLD.content_sha256,
           OLD.maker_issuer, OLD.maker_subject, OLD.proposed_at)
    THEN
        RAISE EXCEPTION 'only PROPOSED may become APPROVED or REJECTED' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_admin_credential_change_guard
    BEFORE UPDATE OR DELETE ON ca_admin_credential_change
    FOR EACH ROW EXECUTE FUNCTION guard_ca_admin_credential_change();
CREATE TRIGGER ca_admin_credential_change_no_truncate
    BEFORE TRUNCATE ON ca_admin_credential_change
    FOR EACH STATEMENT EXECUTE FUNCTION guard_ca_admin_credential_change();

-- For REMOVE_ADMIN_CREDENTIAL, person and key must be NULL: they are taken
-- from the active credential, so the checker reviews (and signs) them.
CREATE FUNCTION admin_credential_propose_unchecked(
    p_ca UUID, p_kind TEXT, p_credential_id BYTEA, p_admin_issuer TEXT,
    p_admin_subject TEXT, p_person_id TEXT, p_public_key_sec1 BYTEA,
    p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_change UUID := gen_random_uuid();
    v_cred ca_admin_credential%ROWTYPE;
    v_person TEXT := p_person_id;
    v_key BYTEA := p_public_key_sec1;
BEGIN
    IF p_ca IS NULL OR p_kind IS NULL
       OR p_kind NOT IN ('ENROLL_ADMIN_CREDENTIAL', 'REMOVE_ADMIN_CREDENTIAL')
       OR p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1023
       OR p_admin_issuer IS NULL OR length(p_admin_issuer) NOT BETWEEN 1 AND 1024
       OR p_admin_subject IS NULL OR length(p_admin_subject) NOT BETWEEN 1 AND 512
       OR (p_kind = 'ENROLL_ADMIN_CREDENTIAL' AND (p_person_id IS NULL
            OR length(p_person_id) NOT BETWEEN 1 AND 256
            OR p_public_key_sec1 IS NULL OR octet_length(p_public_key_sec1) <> 33
            OR get_byte(p_public_key_sec1, 0) NOT IN (2, 3)))
       OR (p_kind = 'REMOVE_ADMIN_CREDENTIAL'
            AND (p_person_id IS NOT NULL OR p_public_key_sec1 IS NOT NULL))
    THEN
        RAISE EXCEPTION 'invalid admin credential change input' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM ca WHERE ca_id = p_ca FOR NO KEY UPDATE;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = p_ca AND (g.issuer, g.subject) = (p_maker_issuer, p_maker_subject)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF (p_admin_issuer, p_admin_subject) = (p_maker_issuer, p_maker_subject) THEN
        RAISE EXCEPTION 'a CA admin cannot change their own credentials' USING ERRCODE = '23514';
    END IF;
    IF p_kind = 'REMOVE_ADMIN_CREDENTIAL' THEN
        SELECT * INTO v_cred FROM ca_admin_credential
        WHERE credential_id = p_credential_id AND ca_id = p_ca AND status = 'ACTIVE'
          AND (issuer, subject) = (p_admin_issuer, p_admin_subject);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'no such active admin credential' USING ERRCODE = '23514';
        END IF;
        v_person := v_cred.person_id;
        v_key := v_cred.public_key_sec1;
    END IF;
    INSERT INTO ca_admin_credential_change(change_id, ca_id, kind, credential_id,
        admin_issuer, admin_subject, person_id, public_key_sec1, content_sha256,
        maker_issuer, maker_subject)
    VALUES (v_change, p_ca, p_kind, p_credential_id, p_admin_issuer, p_admin_subject,
        v_person, v_key,
        credential_change_digest(p_kind, p_ca, p_credential_id, p_admin_issuer,
                                 p_admin_subject, v_person, v_key),
        p_maker_issuer, p_maker_subject);
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_maker_issuer || '|' || p_maker_subject,
            'ca_admin.credential.proposed', p_kind || ':pending_approval:change=' || v_change);
    RETURN v_change;
END $fn$;

CREATE FUNCTION admin_credential_approve_unchecked(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT, p_expected_sha256 BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_chg ca_admin_credential_change%ROWTYPE;
BEGIN
    IF p_change IS NULL OR p_expected_sha256 IS NULL OR octet_length(p_expected_sha256) <> 32
       OR p_checker_issuer IS NULL OR p_checker_subject IS NULL THEN
        RAISE EXCEPTION 'invalid admin credential approval input' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_chg FROM ca_admin_credential_change WHERE change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown admin credential change' USING ERRCODE = '22023';
    END IF;
    -- Lock order: CA, change, admin grants, credentials.
    PERFORM 1 FROM ca WHERE ca_id = v_chg.ca_id FOR NO KEY UPDATE;
    SELECT * INTO v_chg FROM ca_admin_credential_change WHERE change_id = p_change FOR UPDATE;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = v_chg.ca_id AND (g.issuer, g.subject) = (p_checker_issuer, p_checker_subject)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF (v_chg.maker_issuer, v_chg.maker_subject) = (p_checker_issuer, p_checker_subject) THEN
        RAISE EXCEPTION 'checker must differ from maker' USING ERRCODE = '23514';
    END IF;
    IF (v_chg.admin_issuer, v_chg.admin_subject) = (p_checker_issuer, p_checker_subject) THEN
        RAISE EXCEPTION 'a CA admin cannot change their own credentials' USING ERRCODE = '23514';
    END IF;
    IF v_chg.status <> 'PROPOSED' OR v_chg.content_sha256 <> p_expected_sha256 THEN
        RAISE EXCEPTION 'admin credential approval refused: closed change or different content'
          USING ERRCODE = '23514';
    END IF;

    UPDATE ca_admin_credential_change
    SET status = 'APPROVED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    IF v_chg.kind = 'ENROLL_ADMIN_CREDENTIAL' THEN
        PERFORM 1 FROM ca_admin_grant g
        WHERE g.ca_id = v_chg.ca_id
          AND (g.issuer, g.subject) = (v_chg.admin_issuer, v_chg.admin_subject)
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'identity holds no CA admin grant for this CA' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (SELECT 1 FROM ca_admin_credential c
                   WHERE c.ca_id = v_chg.ca_id AND c.status = 'ACTIVE'
                     AND ((c.person_id = v_chg.person_id
                           AND (c.issuer, c.subject) <> (v_chg.admin_issuer, v_chg.admin_subject))
                          OR (c.person_id <> v_chg.person_id
                              AND (c.issuer, c.subject) = (v_chg.admin_issuer, v_chg.admin_subject))))
        THEN
            RAISE EXCEPTION 'one person per admin identity and one identity per person'
              USING ERRCODE = '23514';
        END IF;
        BEGIN
            INSERT INTO ca_admin_credential(credential_id, ca_id, issuer, subject, person_id,
                                            public_key_sec1)
            VALUES (v_chg.credential_id, v_chg.ca_id, v_chg.admin_issuer, v_chg.admin_subject,
                    v_chg.person_id, v_chg.public_key_sec1);
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION 'credential id or public key already enrolled' USING ERRCODE = '23514';
        END;
    ELSE
        UPDATE ca_admin_credential SET status = 'REMOVED', removed_at = clock_timestamp()
        WHERE credential_id = v_chg.credential_id AND ca_id = v_chg.ca_id AND status = 'ACTIVE'
          AND (issuer, subject) = (v_chg.admin_issuer, v_chg.admin_subject);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'no such active admin credential' USING ERRCODE = '23514';
        END IF;
    END IF;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_chg.ca_id, NULL, p_checker_issuer || '|' || p_checker_subject,
            'ca_admin.credential.approved', v_chg.kind || ':applied:change=' || p_change
            || ':content=' || encode(v_chg.content_sha256, 'hex'));
    RETURN 'APPROVED';
END $fn$;

CREATE FUNCTION reject_admin_credential_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_chg ca_admin_credential_change%ROWTYPE;
BEGIN
    SELECT * INTO v_chg FROM ca_admin_credential_change WHERE change_id = p_change FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown admin credential change' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = v_chg.ca_id AND (g.issuer, g.subject) = (p_checker_issuer, p_checker_subject);
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF v_chg.status <> 'PROPOSED'
       OR (v_chg.maker_issuer, v_chg.maker_subject) = (p_checker_issuer, p_checker_subject) THEN
        RAISE EXCEPTION 'rejection refused: closed change or the maker' USING ERRCODE = '23514';
    END IF;
    UPDATE ca_admin_credential_change
    SET status = 'REJECTED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_chg.ca_id, NULL, p_checker_issuer || '|' || p_checker_subject,
            'ca_admin.credential.rejected', v_chg.kind || ':rejected:change=' || p_change);
    RETURN 'REJECTED';
END $fn$;

CREATE OR REPLACE FUNCTION enroll_ca_admin_credential(
    p_ca UUID, p_credential_id BYTEA, p_issuer TEXT, p_subject TEXT, p_person_id TEXT,
    p_public_key_sec1 BYTEA
)
RETURNS VOID
LANGUAGE plpgsql AS $fn$
BEGIN
    -- Closed once the CA requires signed administration (0040): from then
    -- on admin keys change only through a signed dual-controlled change.
    IF signed_admin_required(p_ca) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration: enrol admin keys through a signed change'
          USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = p_ca AND (g.issuer, g.subject) = (p_issuer, p_subject) FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'identity holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM ca_admin_credential c
               WHERE c.ca_id = p_ca AND c.status = 'ACTIVE'
                 AND ((c.person_id = p_person_id AND (c.issuer, c.subject) <> (p_issuer, p_subject))
                      OR (c.person_id <> p_person_id AND (c.issuer, c.subject) = (p_issuer, p_subject))))
    THEN
        RAISE EXCEPTION 'one person per admin identity and one identity per person'
          USING ERRCODE = '23514';
    END IF;
    BEGIN
        INSERT INTO ca_admin_credential(credential_id, ca_id, issuer, subject, person_id,
                                        public_key_sec1)
        VALUES (p_credential_id, p_ca, p_issuer, p_subject, p_person_id, p_public_key_sec1);
    EXCEPTION WHEN unique_violation THEN
        RAISE EXCEPTION 'credential id or public key already enrolled' USING ERRCODE = '23514';
    END;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, session_user, 'ca_admin.credential.enrolled',
            'BOOTSTRAP:identity=' || p_issuer || '|' || p_subject
            || ':key=' || encode(sha256(p_public_key_sec1), 'hex'));
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
    IF p_purpose IS NULL OR p_purpose NOT IN ('PROPOSE', 'APPROVE')
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
       OR (p_purpose = 'APPROVE' AND (p_change IS NULL OR p_kind IS NOT NULL
            OR p_content_sha256 IS NOT NULL))
    THEN
        RAISE EXCEPTION 'invalid challenge request' USING ERRCODE = '22023';
    END IF;
    IF p_purpose = 'APPROVE' THEN
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

CREATE OR REPLACE FUNCTION propose_signed_admin_change(
    p_challenge UUID, p_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA,
    p_certificate_der BYTEA, p_target_credential_id BYTEA, p_officer_issuer TEXT,
    p_officer_subject TEXT, p_person_id TEXT, p_public_key_sec1 BYTEA
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch ca_admin_challenge%ROWTYPE;
    v_cred ca_admin_credential%ROWTYPE;
    v_claim BYTEA;
    v_change UUID;
    v_kind TEXT;
    v_content BYTEA;
BEGIN
    SELECT * INTO v_ch FROM ca_admin_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_cred FROM ca_admin_credential
    WHERE credential_id = p_credential_id FOR UPDATE;
    v_claim := consume_ca_admin_challenge(v_ch, 'PROPOSE', v_cred, p_authenticator_data,
                                          p_client_data_json, p_signature_der);
    IF v_ch.family = 'CA_ADMIN' THEN
        v_change := ca_admin_propose_unchecked(v_ch.ca_id, v_ch.kind, p_certificate_der,
            p_officer_issuer, p_officer_subject, v_ch.actor_issuer, v_ch.actor_subject);
        SELECT kind, content_sha256 INTO v_kind, v_content
        FROM ca_admin_change WHERE change_id = v_change;
    ELSIF v_ch.family = 'ADMIN_CREDENTIAL' THEN
        v_change := admin_credential_propose_unchecked(v_ch.ca_id, v_ch.kind,
            p_target_credential_id, p_officer_issuer, p_officer_subject, p_person_id,
            p_public_key_sec1, v_ch.actor_issuer, v_ch.actor_subject);
        SELECT kind, content_sha256 INTO v_kind, v_content
        FROM ca_admin_credential_change WHERE change_id = v_change;
    ELSE
        v_change := credential_propose_unchecked(v_ch.ca_id, v_ch.kind, p_target_credential_id,
            p_officer_issuer, p_officer_subject, p_person_id, p_public_key_sec1,
            v_ch.actor_issuer, v_ch.actor_subject);
        SELECT kind, content_sha256 INTO v_kind, v_content
        FROM officer_credential_change WHERE change_id = v_change;
    END IF;
    IF v_kind IS DISTINCT FROM v_ch.kind OR v_content IS DISTINCT FROM v_ch.content_sha256 THEN
        RAISE EXCEPTION 'proposed content differs from the signed content'
          USING ERRCODE = '23514';
    END IF;
    INSERT INTO ca_admin_signature(family, change_id, role, challenge_id, credential_id,
        public_key_sha256, person_id, claim_sha256, authenticator_data, client_data_json,
        signature_der, sign_count)
    VALUES (v_ch.family, v_change, 'MAKER', p_challenge, p_credential_id,
        v_cred.public_key_sha256, v_cred.person_id, v_claim, p_authenticator_data,
        p_client_data_json, p_signature_der,
        (SELECT sign_count FROM ca_admin_credential WHERE credential_id = p_credential_id));
    RETURN v_change;
END $fn$;

CREATE OR REPLACE FUNCTION approve_signed_admin_change(
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
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_cred FROM ca_admin_credential
    WHERE credential_id = p_credential_id FOR UPDATE;
    SELECT * INTO v_maker FROM ca_admin_signature
    WHERE family = v_ch.family AND change_id = v_ch.change_id AND role = 'MAKER';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the proposal was not signed' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM ca_admin_credential
                   WHERE credential_id = v_maker.credential_id AND status = 'ACTIVE') THEN
        RAISE EXCEPTION 'the maker''s credential was removed' USING ERRCODE = '23514';
    END IF;
    IF v_maker.public_key_sha256 = v_cred.public_key_sha256
       OR v_maker.person_id = v_cred.person_id THEN
        RAISE EXCEPTION 'maker and checker must be distinct people with distinct keys'
          USING ERRCODE = '23514';
    END IF;
    v_claim := consume_ca_admin_challenge(v_ch, 'APPROVE', v_cred, p_authenticator_data,
                                          p_client_data_json, p_signature_der);
    IF v_ch.family = 'CA_ADMIN' THEN
        v_result := ca_admin_approve_unchecked(v_ch.change_id, v_ch.actor_issuer,
            v_ch.actor_subject, v_ch.content_sha256);
    ELSIF v_ch.family = 'ADMIN_CREDENTIAL' THEN
        v_result := admin_credential_approve_unchecked(v_ch.change_id, v_ch.actor_issuer,
            v_ch.actor_subject, v_ch.content_sha256);
    ELSE
        v_result := credential_approve_unchecked(v_ch.change_id, v_ch.actor_issuer,
            v_ch.actor_subject, v_ch.content_sha256);
    END IF;
    INSERT INTO ca_admin_signature(family, change_id, role, challenge_id, credential_id,
        public_key_sha256, person_id, claim_sha256, authenticator_data, client_data_json,
        signature_der, sign_count)
    VALUES (v_ch.family, v_ch.change_id, 'CHECKER', p_challenge, p_credential_id,
        v_cred.public_key_sha256, v_cred.person_id, v_claim, p_authenticator_data,
        p_client_data_json, p_signature_der,
        (SELECT sign_count FROM ca_admin_credential WHERE credential_id = p_credential_id));
    RETURN v_result;
END $fn$;

CREATE OR REPLACE FUNCTION ca_admin_signatures(p_family TEXT, p_change UUID)
RETURNS TABLE (role TEXT, challenge_id UUID, public_key_sec1 BYTEA, person_id TEXT,
               claim_sha256 BYTEA, authenticator_data BYTEA, client_data_json BYTEA,
               signature_der BYTEA, change_ca UUID, change_kind TEXT,
               change_content_sha256 BYTEA)
LANGUAGE sql STABLE AS $fn$
    SELECT s.role, s.challenge_id, c.public_key_sec1, s.person_id, s.claim_sha256,
           s.authenticator_data, s.client_data_json, s.signature_der,
           coalesce(a.ca_id, o.ca_id, k.ca_id), coalesce(a.kind, o.kind, k.kind),
           coalesce(a.content_sha256, o.content_sha256, k.content_sha256)
    FROM ca_admin_signature s
    JOIN ca_admin_credential c USING (credential_id)
    LEFT JOIN ca_admin_change a ON s.family = 'CA_ADMIN' AND a.change_id = s.change_id
    LEFT JOIN officer_credential_change o
           ON s.family = 'CREDENTIAL' AND o.change_id = s.change_id
    LEFT JOIN ca_admin_credential_change k
           ON s.family = 'ADMIN_CREDENTIAL' AND k.change_id = s.change_id
    WHERE s.family = p_family AND s.change_id = p_change
    ORDER BY s.role DESC
$fn$;

ALTER TABLE ca_admin_credential_change OWNER TO trust_revocation_owner;
REVOKE ALL ON ca_admin_credential_change FROM PUBLIC;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'guard_ca_admin_credential_change()',
        'admin_credential_propose_unchecked(uuid,text,bytea,text,text,text,bytea,text,text)',
        'admin_credential_approve_unchecked(uuid,text,text,bytea)',
        'reject_admin_credential_change(uuid,text,text)',
        'enroll_ca_admin_credential(uuid,bytea,text,text,text,bytea)',
        'issue_ca_admin_challenge(text,uuid,text,text,bytea,uuid,text,text,integer)',
        'propose_signed_admin_change(uuid,bytea,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'approve_signed_admin_change(uuid,bytea,bytea,bytea,bytea)',
        'ca_admin_signatures(text,uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    -- Definer like every other *_unchecked (no grant), and re-applied where
    -- CREATE OR REPLACE reset it on the re-created entry points.
    FOREACH f IN ARRAY ARRAY[
        'admin_credential_propose_unchecked(uuid,text,bytea,text,text,text,bytea,text,text)',
        'admin_credential_approve_unchecked(uuid,text,text,bytea)',
        'reject_admin_credential_change(uuid,text,text)',
        'enroll_ca_admin_credential(uuid,bytea,text,text,text,bytea)',
        'issue_ca_admin_challenge(text,uuid,text,text,bytea,uuid,text,text,integer)',
        'propose_signed_admin_change(uuid,bytea,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'approve_signed_admin_change(uuid,bytea,bytea,bytea,bytea)',
        'ca_admin_signatures(text,uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
    END LOOP;
    -- Grants survive CREATE OR REPLACE; only the new rejection is added.
    GRANT EXECUTE ON FUNCTION reject_admin_credential_change(uuid,text,text) TO trust_ca_admin;
END $fns$;

SELECT acknowledge_schema_changes('0040_admin_credential_dual_control');

COMMIT;
