-- v0.28 (lab): officer credential registry under CA-admin dual control
-- (ADR-0007 step 1, status Proposed; implemented in lab at the owner's
-- request). LAB ONLY. No approval is signed yet: this migration only
-- records which person and which P-256 key may sign for an officer.
-- * officer_credential binds a WebAuthn credential id and its public key to
--   an officer identity (issuer, subject) on a CA and to a unique person
--   identifier from the IAM. The key is stored in compressed SEC1 form as
--   canonicalised by the Rust core (trust_pki_crypto::
--   canonical_p256_public_key_sec1, which also checks the point is on the
--   curve); its SHA-256 is unique across every credential ever enrolled, so
--   one key can never stand for two officers or be re-enrolled, whatever
--   its encoding or credential id.
-- * A person holds active credentials under one officer identity per CA,
--   and an identity's active credentials belong to one person, so two
--   identities of one person cannot act as maker and checker.
-- * Enrolment and removal go through officer_credential_change: proposed by
--   one CA admin, approved by a second, distinct CA admin for the exact
--   content digest it reviewed (length-prefixed kind, CA, credential id,
--   officer identity, person, key; trust_pki_core::officer_credential::
--   credential_change_digest computes the same bytes). No CA admin enrols
--   or removes a credential of their own identity. Enrolment needs the
--   officer's current grant. History is append-only.
-- Apply after 0027 as a superuser.
BEGIN;

CREATE TABLE officer_credential (
    credential_id BYTEA PRIMARY KEY CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    person_id TEXT NOT NULL CHECK (length(person_id) BETWEEN 1 AND 256),
    public_key_sec1 BYTEA NOT NULL CHECK (octet_length(public_key_sec1) = 33
                                          AND get_byte(public_key_sec1, 0) IN (2, 3)),
    public_key_sha256 BYTEA GENERATED ALWAYS AS (sha256(public_key_sec1)) STORED UNIQUE,
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REMOVED')),
    enrolled_change UUID NOT NULL,
    removed_change UUID,
    CHECK ((status = 'ACTIVE') = (removed_change IS NULL))
);
CREATE INDEX officer_credential_identity ON officer_credential (ca_id, issuer, subject)
    WHERE status = 'ACTIVE';
CREATE INDEX officer_credential_person ON officer_credential (ca_id, person_id)
    WHERE status = 'ACTIVE';

-- Only ACTIVE -> REMOVED (setting removed_change) and a non-decreasing
-- signature counter (ADR-0007 step 2); nothing else changes, nothing is
-- deleted.
CREATE FUNCTION guard_officer_credential() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE')
       OR (NEW.credential_id, NEW.ca_id, NEW.issuer, NEW.subject, NEW.person_id,
           NEW.public_key_sec1, NEW.enrolled_change)
          IS DISTINCT FROM
          (OLD.credential_id, OLD.ca_id, OLD.issuer, OLD.subject, OLD.person_id,
           OLD.public_key_sec1, OLD.enrolled_change)
       OR NEW.sign_count < OLD.sign_count
       OR (OLD.status = 'REMOVED' AND (NEW.status, NEW.removed_change, NEW.sign_count)
                                      IS DISTINCT FROM
                                      (OLD.status, OLD.removed_change, OLD.sign_count))
    THEN
        RAISE EXCEPTION 'officer_credential change not allowed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER officer_credential_guard
    BEFORE UPDATE OR DELETE ON officer_credential
    FOR EACH ROW EXECUTE FUNCTION guard_officer_credential();
CREATE TRIGGER officer_credential_no_truncate
    BEFORE TRUNCATE ON officer_credential
    FOR EACH STATEMENT EXECUTE FUNCTION guard_officer_credential();

CREATE TABLE officer_credential_change (
    change_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    kind TEXT NOT NULL CHECK (kind IN ('ENROLL_CREDENTIAL', 'REMOVE_CREDENTIAL')),
    credential_id BYTEA NOT NULL CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    officer_issuer TEXT NOT NULL CHECK (length(officer_issuer) BETWEEN 1 AND 1024),
    officer_subject TEXT NOT NULL CHECK (length(officer_subject) BETWEEN 1 AND 512),
    person_id TEXT NOT NULL CHECK (length(person_id) BETWEEN 1 AND 256),
    public_key_sec1 BYTEA NOT NULL CHECK (octet_length(public_key_sec1) = 33
                                          AND get_byte(public_key_sec1, 0) IN (2, 3)),
    content_sha256 BYTEA NOT NULL CHECK (octet_length(content_sha256) = 32),
    maker_issuer TEXT NOT NULL,
    maker_subject TEXT NOT NULL,
    checker_issuer TEXT,
    checker_subject TEXT,
    status TEXT NOT NULL DEFAULT 'PROPOSED'
        CHECK (status IN ('PROPOSED', 'APPROVED', 'REJECTED')),
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    decided_at TIMESTAMPTZ,
    CONSTRAINT officer_credential_change_decision CHECK (
        (status = 'PROPOSED' AND checker_issuer IS NULL AND decided_at IS NULL)
        OR (status <> 'PROPOSED' AND checker_issuer IS NOT NULL
             AND checker_subject IS NOT NULL AND decided_at IS NOT NULL))
);

CREATE FUNCTION guard_officer_credential_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE')
       OR OLD.status <> 'PROPOSED' OR NEW.status NOT IN ('APPROVED', 'REJECTED')
       OR (NEW.change_id, NEW.ca_id, NEW.kind, NEW.credential_id, NEW.officer_issuer,
           NEW.officer_subject, NEW.person_id, NEW.public_key_sec1, NEW.content_sha256,
           NEW.maker_issuer, NEW.maker_subject, NEW.proposed_at)
          IS DISTINCT FROM
          (OLD.change_id, OLD.ca_id, OLD.kind, OLD.credential_id, OLD.officer_issuer,
           OLD.officer_subject, OLD.person_id, OLD.public_key_sec1, OLD.content_sha256,
           OLD.maker_issuer, OLD.maker_subject, OLD.proposed_at)
    THEN
        RAISE EXCEPTION 'officer_credential_change is append-only' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER officer_credential_change_guard
    BEFORE UPDATE OR DELETE ON officer_credential_change
    FOR EACH ROW EXECUTE FUNCTION guard_officer_credential_change();
CREATE TRIGGER officer_credential_change_no_truncate
    BEFORE TRUNCATE ON officer_credential_change
    FOR EACH STATEMENT EXECUTE FUNCTION guard_officer_credential_change();

-- Length-prefixed fields: 4-byte big-endian length, then the bytes (the CA
-- as its 16 UUID bytes).
CREATE FUNCTION credential_change_digest(
    p_kind TEXT, p_ca UUID, p_credential_id BYTEA, p_officer_issuer TEXT,
    p_officer_subject TEXT, p_person_id TEXT, p_public_key_sec1 BYTEA
)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT sha256(
        int4send(octet_length(convert_to(p_kind, 'UTF8'))) || convert_to(p_kind, 'UTF8')
        || int4send(16) || uuid_send(p_ca)
        || int4send(octet_length(p_credential_id)) || p_credential_id
        || int4send(octet_length(convert_to(p_officer_issuer, 'UTF8')))
        || convert_to(p_officer_issuer, 'UTF8')
        || int4send(octet_length(convert_to(p_officer_subject, 'UTF8')))
        || convert_to(p_officer_subject, 'UTF8')
        || int4send(octet_length(convert_to(p_person_id, 'UTF8')))
        || convert_to(p_person_id, 'UTF8')
        || int4send(octet_length(p_public_key_sec1)) || p_public_key_sec1)
$fn$;

-- For REMOVE_CREDENTIAL, p_person_id and p_public_key_sec1 must be NULL:
-- they are taken from the active credential, so the checker reviews them.
CREATE FUNCTION propose_credential_change(
    p_ca UUID, p_kind TEXT, p_credential_id BYTEA,
    p_officer_issuer TEXT, p_officer_subject TEXT,
    p_person_id TEXT, p_public_key_sec1 BYTEA,
    p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_change UUID := gen_random_uuid();
    v_cred officer_credential%ROWTYPE;
    v_person TEXT := p_person_id;
    v_key BYTEA := p_public_key_sec1;
BEGIN
    IF p_ca IS NULL OR p_kind IS NULL
       OR p_kind NOT IN ('ENROLL_CREDENTIAL', 'REMOVE_CREDENTIAL')
       OR p_credential_id IS NULL OR octet_length(p_credential_id) NOT BETWEEN 16 AND 1023
       OR p_officer_issuer IS NULL OR length(p_officer_issuer) NOT BETWEEN 1 AND 1024
       OR p_officer_subject IS NULL OR length(p_officer_subject) NOT BETWEEN 1 AND 512
       OR p_maker_issuer IS NULL OR length(p_maker_issuer) NOT BETWEEN 1 AND 1024
       OR p_maker_subject IS NULL OR length(p_maker_subject) NOT BETWEEN 1 AND 512
       OR (p_kind = 'ENROLL_CREDENTIAL' AND (p_person_id IS NULL
            OR length(p_person_id) NOT BETWEEN 1 AND 256
            OR p_public_key_sec1 IS NULL OR octet_length(p_public_key_sec1) <> 33
            OR get_byte(p_public_key_sec1, 0) NOT IN (2, 3)))
       OR (p_kind = 'REMOVE_CREDENTIAL'
            AND (p_person_id IS NOT NULL OR p_public_key_sec1 IS NOT NULL))
    THEN
        RAISE EXCEPTION 'invalid credential change input' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM ca WHERE ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject AND g.ca_id = p_ca
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF (p_officer_issuer, p_officer_subject) = (p_maker_issuer, p_maker_subject) THEN
        RAISE EXCEPTION 'a CA admin cannot change their own credentials' USING ERRCODE = '23514';
    END IF;
    IF p_kind = 'REMOVE_CREDENTIAL' THEN
        SELECT * INTO v_cred FROM officer_credential
        WHERE credential_id = p_credential_id AND ca_id = p_ca AND status = 'ACTIVE'
          AND (issuer, subject) = (p_officer_issuer, p_officer_subject);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'no such active credential' USING ERRCODE = '23514';
        END IF;
        v_person := v_cred.person_id;
        v_key := v_cred.public_key_sec1;
    END IF;
    INSERT INTO officer_credential_change(change_id, ca_id, kind, credential_id,
        officer_issuer, officer_subject, person_id, public_key_sec1, content_sha256,
        maker_issuer, maker_subject)
    VALUES (v_change, p_ca, p_kind, p_credential_id, p_officer_issuer, p_officer_subject,
        v_person, v_key,
        credential_change_digest(p_kind, p_ca, p_credential_id, p_officer_issuer,
                                 p_officer_subject, v_person, v_key),
        p_maker_issuer, p_maker_subject);
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_maker_issuer || '|' || p_maker_subject,
            'officer.credential.proposed', p_kind || ':pending_approval:change=' || v_change);
    RETURN v_change;
END $fn$;

CREATE FUNCTION approve_credential_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT, p_expected_sha256 BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_chg officer_credential_change%ROWTYPE;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
       OR p_expected_sha256 IS NULL OR octet_length(p_expected_sha256) <> 32
    THEN
        RAISE EXCEPTION 'invalid credential approval input' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_chg FROM officer_credential_change WHERE change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown credential change' USING ERRCODE = '22023';
    END IF;
    -- Lock order: CA, change, admin grant, officer grant, credentials.
    PERFORM 1 FROM ca WHERE ca_id = v_chg.ca_id FOR NO KEY UPDATE;
    SELECT * INTO v_chg FROM officer_credential_change WHERE change_id = p_change FOR UPDATE;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
      AND g.ca_id = v_chg.ca_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF (v_chg.maker_issuer, v_chg.maker_subject) = (p_checker_issuer, p_checker_subject) THEN
        RAISE EXCEPTION 'checker must differ from maker' USING ERRCODE = '23514';
    END IF;
    IF v_chg.status <> 'PROPOSED' OR v_chg.content_sha256 <> p_expected_sha256 THEN
        RAISE EXCEPTION 'credential approval refused: closed change or different content'
          USING ERRCODE = '23514';
    END IF;
    IF (v_chg.officer_issuer, v_chg.officer_subject) = (p_checker_issuer, p_checker_subject) THEN
        RAISE EXCEPTION 'a CA admin cannot change their own credentials' USING ERRCODE = '23514';
    END IF;

    UPDATE officer_credential_change
    SET status = 'APPROVED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    IF v_chg.kind = 'ENROLL_CREDENTIAL' THEN
        PERFORM 1 FROM revocation_officer_grant g
        WHERE g.ca_id = v_chg.ca_id
          AND (g.issuer, g.subject) = (v_chg.officer_issuer, v_chg.officer_subject)
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'officer holds no grant for this CA' USING ERRCODE = '23514';
        END IF;
        IF EXISTS (SELECT 1 FROM officer_credential c
                   WHERE c.ca_id = v_chg.ca_id AND c.status = 'ACTIVE'
                     AND ((c.person_id = v_chg.person_id
                           AND (c.issuer, c.subject) <> (v_chg.officer_issuer, v_chg.officer_subject))
                          OR (c.person_id <> v_chg.person_id
                              AND (c.issuer, c.subject) = (v_chg.officer_issuer, v_chg.officer_subject))))
        THEN
            RAISE EXCEPTION 'one person per officer identity and one identity per person'
              USING ERRCODE = '23514';
        END IF;
        BEGIN
            INSERT INTO officer_credential(credential_id, ca_id, issuer, subject, person_id,
                public_key_sec1, enrolled_change)
            VALUES (v_chg.credential_id, v_chg.ca_id, v_chg.officer_issuer,
                    v_chg.officer_subject, v_chg.person_id, v_chg.public_key_sec1, p_change);
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION 'credential id or public key already enrolled'
              USING ERRCODE = '23514';
        END;
    ELSE
        UPDATE officer_credential
        SET status = 'REMOVED', removed_change = p_change
        WHERE credential_id = v_chg.credential_id AND ca_id = v_chg.ca_id
          AND status = 'ACTIVE'
          AND (issuer, subject) = (v_chg.officer_issuer, v_chg.officer_subject);
        IF NOT FOUND THEN
            RAISE EXCEPTION 'no such active credential' USING ERRCODE = '23514';
        END IF;
    END IF;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_chg.ca_id, NULL, p_checker_issuer || '|' || p_checker_subject,
            'officer.credential.approved', v_chg.kind || ':applied:change=' || p_change
            || ':content=' || encode(v_chg.content_sha256, 'hex'));
    RETURN 'APPROVED';
END $fn$;

CREATE FUNCTION reject_credential_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_chg officer_credential_change%ROWTYPE;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid credential rejection input' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_chg FROM officer_credential_change WHERE change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown credential change' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM ca WHERE ca_id = v_chg.ca_id FOR NO KEY UPDATE;
    SELECT * INTO v_chg FROM officer_credential_change WHERE change_id = p_change FOR UPDATE;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
      AND g.ca_id = v_chg.ca_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF v_chg.status <> 'PROPOSED' THEN
        RAISE EXCEPTION 'credential change is closed' USING ERRCODE = '23514';
    END IF;
    UPDATE officer_credential_change
    SET status = 'REJECTED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_chg.ca_id, NULL, p_checker_issuer || '|' || p_checker_subject,
            'officer.credential.rejected', v_chg.kind || ':rejected:change=' || p_change);
    RETURN 'REJECTED';
END $fn$;

ALTER TABLE officer_credential OWNER TO trust_revocation_owner;
ALTER TABLE officer_credential_change OWNER TO trust_revocation_owner;
REVOKE ALL ON officer_credential, officer_credential_change FROM PUBLIC;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'propose_credential_change(uuid,text,bytea,text,text,text,bytea,text,text)',
        'approve_credential_change(uuid,text,text,bytea)',
        'reject_credential_change(uuid,text,text)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'guard_officer_credential()',
        'guard_officer_credential_change()',
        'credential_change_digest(text,uuid,bytea,text,text,text,bytea)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END $fns$;

GRANT EXECUTE ON FUNCTION
    propose_credential_change(uuid,text,bytea,text,text,text,bytea,text,text),
    approve_credential_change(uuid,text,text,bytea),
    reject_credential_change(uuid,text,text)
TO trust_ca_admin;

SELECT acknowledge_schema_changes('0028_officer_credentials');

COMMIT;
