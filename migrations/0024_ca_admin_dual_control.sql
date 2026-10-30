-- v0.24 (lab): dual control of CA administration (ADR-0006). LAB ONLY.
-- Registering a CA's issuer certificate (which key's CRLs count) and granting
-- or removing revocation officers (who may revoke) were single-actor
-- operations. They now go through ca_admin_change: one CA admin proposes,
-- a second, distinct CA admin approves the exact content digest.
-- * ca_admin_grant lists the CA admins. It is bootstrapped by the DBA under
--   change control (no service can write it), like revocation_officer_grant
--   before this migration.
-- * A CA admin can never grant an officer role to themselves (as maker or
--   checker), so administration and revocation stay separate duties.
-- * trust_ca_admin loses EXECUTE on register_ca_issuer; the direct function
--   stays for superuser bootstrap and tests only.
-- Identities are still asserted by the calling service (textual), as for
-- status changes; key-distinct signatures are ADR-0007.
-- Apply after 0023 as a superuser.
BEGIN;

CREATE TABLE ca_admin_grant (
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    ca_id UUID NOT NULL REFERENCES ca(ca_id) ON DELETE CASCADE,
    PRIMARY KEY (issuer, subject, ca_id)
);

CREATE TABLE ca_admin_change (
    change_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    kind TEXT NOT NULL CHECK (kind IN ('REGISTER_ISSUER','GRANT_OFFICER','REVOKE_OFFICER')),
    certificate_der BYTEA CHECK (octet_length(certificate_der) BETWEEN 1 AND 65536),
    officer_issuer TEXT CHECK (length(officer_issuer) BETWEEN 1 AND 1024),
    officer_subject TEXT CHECK (length(officer_subject) BETWEEN 1 AND 512),
    content_sha256 BYTEA NOT NULL CHECK (octet_length(content_sha256) = 32),
    maker_issuer TEXT NOT NULL,
    maker_subject TEXT NOT NULL,
    checker_issuer TEXT,
    checker_subject TEXT,
    status TEXT NOT NULL DEFAULT 'PROPOSED'
        CHECK (status IN ('PROPOSED','APPROVED','REJECTED')),
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    decided_at TIMESTAMPTZ,
    CONSTRAINT ca_admin_change_payload CHECK (
        (kind = 'REGISTER_ISSUER' AND certificate_der IS NOT NULL
             AND officer_issuer IS NULL AND officer_subject IS NULL)
        OR (kind IN ('GRANT_OFFICER','REVOKE_OFFICER') AND certificate_der IS NULL
             AND officer_issuer IS NOT NULL AND officer_subject IS NOT NULL)),
    CONSTRAINT ca_admin_change_decision CHECK (
        (status = 'PROPOSED' AND checker_issuer IS NULL AND decided_at IS NULL)
        OR (status <> 'PROPOSED' AND checker_issuer IS NOT NULL
             AND checker_subject IS NOT NULL AND decided_at IS NOT NULL))
);

-- Only PROPOSED -> APPROVED | REJECTED, setting the checker and decision
-- time; nothing else ever changes and nothing is deleted.
CREATE FUNCTION guard_ca_admin_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE','TRUNCATE')
       OR OLD.status <> 'PROPOSED' OR NEW.status NOT IN ('APPROVED','REJECTED')
       OR (NEW.change_id, NEW.ca_id, NEW.kind, NEW.certificate_der, NEW.officer_issuer,
           NEW.officer_subject, NEW.content_sha256, NEW.maker_issuer, NEW.maker_subject,
           NEW.proposed_at)
          IS DISTINCT FROM
          (OLD.change_id, OLD.ca_id, OLD.kind, OLD.certificate_der, OLD.officer_issuer,
           OLD.officer_subject, OLD.content_sha256, OLD.maker_issuer, OLD.maker_subject,
           OLD.proposed_at)
    THEN
        RAISE EXCEPTION 'ca_admin_change is append-only' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_admin_change_guard
    BEFORE UPDATE OR DELETE ON ca_admin_change
    FOR EACH ROW EXECUTE FUNCTION guard_ca_admin_change();
CREATE TRIGGER ca_admin_change_no_truncate
    BEFORE TRUNCATE ON ca_admin_change
    FOR EACH STATEMENT EXECUTE FUNCTION guard_ca_admin_change();

-- What the checker approves: SHA-256 of the issuer certificate DER, or of
-- the length-prefixed (kind, officer issuer, officer subject) for grants
-- (crate::revocation_store::officer_grant_digest computes the same bytes).
CREATE FUNCTION ca_admin_content_digest(
    p_kind TEXT, p_certificate_der BYTEA, p_officer_issuer TEXT, p_officer_subject TEXT
)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT CASE WHEN p_kind = 'REGISTER_ISSUER' THEN sha256(p_certificate_der)
           ELSE sha256(int4send(octet_length(convert_to(p_kind, 'UTF8')))
                       || convert_to(p_kind, 'UTF8')
                       || int4send(octet_length(convert_to(p_officer_issuer, 'UTF8')))
                       || convert_to(p_officer_issuer, 'UTF8')
                       || int4send(octet_length(convert_to(p_officer_subject, 'UTF8')))
                       || convert_to(p_officer_subject, 'UTF8'))
           END
$fn$;

CREATE FUNCTION propose_ca_admin_change(
    p_ca UUID, p_kind TEXT, p_certificate_der BYTEA,
    p_officer_issuer TEXT, p_officer_subject TEXT,
    p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_change UUID := gen_random_uuid();
BEGIN
    IF p_ca IS NULL OR p_kind IS NULL
       OR p_kind NOT IN ('REGISTER_ISSUER','GRANT_OFFICER','REVOKE_OFFICER')
       OR p_maker_issuer IS NULL OR length(p_maker_issuer) NOT BETWEEN 1 AND 1024
       OR p_maker_subject IS NULL OR length(p_maker_subject) NOT BETWEEN 1 AND 512
       OR (p_kind = 'REGISTER_ISSUER' AND (p_certificate_der IS NULL
            OR p_officer_issuer IS NOT NULL OR p_officer_subject IS NOT NULL))
       OR (p_kind <> 'REGISTER_ISSUER' AND (p_certificate_der IS NOT NULL
            OR p_officer_issuer IS NULL OR p_officer_subject IS NULL))
    THEN
        RAISE EXCEPTION 'invalid CA admin change input' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM ca WHERE ca_id = p_ca FOR NO KEY UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.issuer = p_maker_issuer AND g.subject = p_maker_subject AND g.ca_id = p_ca
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE='42501';
    END IF;
    IF p_kind = 'REGISTER_ISSUER'
       AND EXISTS (SELECT 1 FROM ca_issuer_certificate WHERE ca_id = p_ca) THEN
        RAISE EXCEPTION 'CA already has an issuer certificate' USING ERRCODE='23514';
    END IF;
    IF p_kind = 'GRANT_OFFICER' AND (p_officer_issuer, p_officer_subject)
                                    = (p_maker_issuer, p_maker_subject) THEN
        RAISE EXCEPTION 'a CA admin cannot grant an officer role to themselves'
          USING ERRCODE='23514';
    END IF;
    IF p_kind = 'GRANT_OFFICER' AND EXISTS (
        SELECT 1 FROM revocation_officer_grant g WHERE g.ca_id = p_ca
          AND (g.issuer, g.subject) = (p_officer_issuer, p_officer_subject)) THEN
        RAISE EXCEPTION 'officer already holds a grant for this CA' USING ERRCODE='23514';
    END IF;
    IF p_kind = 'REVOKE_OFFICER' AND NOT EXISTS (
        SELECT 1 FROM revocation_officer_grant g WHERE g.ca_id = p_ca
          AND (g.issuer, g.subject) = (p_officer_issuer, p_officer_subject)) THEN
        RAISE EXCEPTION 'officer holds no grant for this CA' USING ERRCODE='23514';
    END IF;
    INSERT INTO ca_admin_change(change_id, ca_id, kind, certificate_der, officer_issuer,
        officer_subject, content_sha256, maker_issuer, maker_subject)
    VALUES (v_change, p_ca, p_kind, p_certificate_der, p_officer_issuer, p_officer_subject,
        ca_admin_content_digest(p_kind, p_certificate_der, p_officer_issuer, p_officer_subject),
        p_maker_issuer, p_maker_subject);
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), p_ca, NULL, p_maker_issuer || '|' || p_maker_subject,
            'ca.admin.proposed', p_kind || ':pending_approval:change=' || v_change);
    RETURN v_change;
END $fn$;

-- p_expected_sha256 is the digest of the content the checker reviewed; a
-- different pending content is refused.
CREATE FUNCTION approve_ca_admin_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT, p_expected_sha256 BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_chg ca_admin_change%ROWTYPE;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
       OR p_expected_sha256 IS NULL OR octet_length(p_expected_sha256) <> 32
    THEN
        RAISE EXCEPTION 'invalid CA admin approval input' USING ERRCODE='22023';
    END IF;
    SELECT * INTO v_chg FROM ca_admin_change WHERE change_id = p_change;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA admin change' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM ca WHERE ca_id = v_chg.ca_id FOR NO KEY UPDATE;
    SELECT * INTO v_chg FROM ca_admin_change WHERE change_id = p_change FOR UPDATE;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
      AND g.ca_id = v_chg.ca_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE='42501';
    END IF;
    IF (v_chg.maker_issuer, v_chg.maker_subject) = (p_checker_issuer, p_checker_subject) THEN
        RAISE EXCEPTION 'checker must differ from maker' USING ERRCODE='23514';
    END IF;
    IF v_chg.status <> 'PROPOSED' OR v_chg.content_sha256 <> p_expected_sha256 THEN
        RAISE EXCEPTION 'CA admin approval refused: closed change or different content'
          USING ERRCODE='23514';
    END IF;
    IF v_chg.kind = 'GRANT_OFFICER' AND (v_chg.officer_issuer, v_chg.officer_subject)
                                         = (p_checker_issuer, p_checker_subject) THEN
        RAISE EXCEPTION 'a CA admin cannot grant an officer role to themselves'
          USING ERRCODE='23514';
    END IF;

    UPDATE ca_admin_change
    SET status = 'APPROVED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    IF v_chg.kind = 'REGISTER_ISSUER' THEN
        IF EXISTS (SELECT 1 FROM ca_issuer_certificate WHERE ca_id = v_chg.ca_id) THEN
            RAISE EXCEPTION 'CA already has an issuer certificate' USING ERRCODE='23514';
        END IF;
        INSERT INTO ca_issuer_certificate(ca_id, certificate_der, registered_by)
        VALUES (v_chg.ca_id, v_chg.certificate_der,
                v_chg.maker_issuer || '|' || v_chg.maker_subject || ' + '
                || p_checker_issuer || '|' || p_checker_subject);
    ELSIF v_chg.kind = 'GRANT_OFFICER' THEN
        INSERT INTO revocation_officer_grant(issuer, subject, ca_id)
        VALUES (v_chg.officer_issuer, v_chg.officer_subject, v_chg.ca_id);
    ELSE
        DELETE FROM revocation_officer_grant
        WHERE ca_id = v_chg.ca_id AND issuer = v_chg.officer_issuer
          AND subject = v_chg.officer_subject;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'officer holds no grant for this CA' USING ERRCODE='23514';
        END IF;
    END IF;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_chg.ca_id, NULL, p_checker_issuer || '|' || p_checker_subject,
            'ca.admin.approved', v_chg.kind || ':applied:change=' || p_change
            || ':content=' || encode(v_chg.content_sha256, 'hex'));
    RETURN 'APPROVED';
END $fn$;

CREATE FUNCTION reject_ca_admin_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_chg ca_admin_change%ROWTYPE;
BEGIN
    IF p_change IS NULL
       OR p_checker_issuer IS NULL OR length(p_checker_issuer) NOT BETWEEN 1 AND 1024
       OR p_checker_subject IS NULL OR length(p_checker_subject) NOT BETWEEN 1 AND 512
    THEN
        RAISE EXCEPTION 'invalid CA admin rejection input' USING ERRCODE='22023';
    END IF;
    SELECT * INTO v_chg FROM ca_admin_change WHERE change_id = p_change FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA admin change' USING ERRCODE='22023';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.issuer = p_checker_issuer AND g.subject = p_checker_subject
      AND g.ca_id = v_chg.ca_id FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE='42501';
    END IF;
    IF v_chg.status <> 'PROPOSED' THEN
        RAISE EXCEPTION 'CA admin change is closed' USING ERRCODE='23514';
    END IF;
    UPDATE ca_admin_change
    SET status = 'REJECTED', checker_issuer = p_checker_issuer,
        checker_subject = p_checker_subject, decided_at = clock_timestamp()
    WHERE change_id = p_change;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_chg.ca_id, NULL, p_checker_issuer || '|' || p_checker_subject,
            'ca.admin.rejected', v_chg.kind || ':rejected:change=' || p_change);
    RETURN 'REJECTED';
END $fn$;

ALTER TABLE ca_admin_grant OWNER TO trust_revocation_owner;
ALTER TABLE ca_admin_change OWNER TO trust_revocation_owner;
REVOKE ALL ON ca_admin_grant, ca_admin_change FROM PUBLIC;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'propose_ca_admin_change(uuid,text,bytea,text,text,text,text)',
        'approve_ca_admin_change(uuid,text,text,bytea)',
        'reject_ca_admin_change(uuid,text,text)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'guard_ca_admin_change()',
        'ca_admin_content_digest(text,bytea,text,text)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END $fns$;

REVOKE EXECUTE ON FUNCTION register_ca_issuer(uuid,bytea,text) FROM trust_ca_admin;
GRANT EXECUTE ON FUNCTION
    propose_ca_admin_change(uuid,text,bytea,text,text,text,text),
    approve_ca_admin_change(uuid,text,text,bytea),
    reject_ca_admin_change(uuid,text,text)
TO trust_ca_admin;

COMMIT;
