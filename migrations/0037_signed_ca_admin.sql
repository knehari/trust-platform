-- v0.37 (lab): signed CA-admin changes (ADR-0007 §1-§5 for
-- `trust-platform/ca-admin/v1`, status Proposed; implemented in lab at the
-- owner's request). LAB ONLY.
-- Until now CA administration (0024: issuer registration, officer grants;
-- 0028: officer credential enrolment and removal) used textual identities
-- asserted by the calling service, so one service holding trust_ca_admin
-- could play both admins.
-- * ca_admin_credential registers CA admins' WebAuthn P-256 keys, bound to
--   an admin identity holding ca_admin_grant and to a person. Like
--   ca_admin_grant itself it is bootstrapped by the DBA
--   (enroll_ca_admin_credential / remove_ca_admin_credential, granted to no
--   service). A key is never both an officer key and an admin key, and a
--   person never holds both an active officer and an active admin
--   credential on one CA (checked on both registries).
-- * ca_revocation_policy.signed_admin_required (one-way) makes the unsigned
--   propose/approve functions of both change families refuse (42501). The
--   original bodies are kept as *_unchecked, granted to no service.
-- * An admin asks for a single-use challenge (issue_ca_admin_challenge) and
--   signs the canonical claim (trust_pki_core::officer_credential::
--   CaAdminClaim; ca_admin_claim_digest computes the same bytes): step, CA,
--   registered issuer certificate digest (absent before the first
--   registration), family, kind, change id (approval only), content digest,
--   policy edition, challenge digest and expiry.
-- * Deviation from ADR-0007 §2, recorded: a proposal claim carries no change
--   id. The proposal functions of 0024/0028 allocate it; the signed proposal
--   instead binds the content digest and kind, which the database checks
--   against the change it has just created, in the same transaction, and
--   the stored signature row links the challenge to the change.
-- * propose_signed_admin_change / approve_signed_admin_change re-check
--   everything but the ECDSA signature (verified in Rust before the call):
--   challenge unexpired and consumed once, credential active and the
--   acting admin's, user presence and verification, advancing counter,
--   clientDataJSON for this claim; on approval, a signed proposal, distinct
--   keys and persons, maker credential still active. Rejection stays
--   unsigned (it applies nothing), as for status changes.
-- Apply after 0036 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD COLUMN signed_admin_required BOOLEAN NOT NULL DEFAULT false;

CREATE FUNCTION guard_signed_admin_required() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF OLD.signed_admin_required AND NOT NEW.signed_admin_required THEN
        RAISE EXCEPTION 'signed CA administration cannot be switched off' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_revocation_policy_signed_admin_one_way
    BEFORE UPDATE ON ca_revocation_policy
    FOR EACH ROW EXECUTE FUNCTION guard_signed_admin_required();

CREATE TABLE ca_admin_credential (
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
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    removed_at TIMESTAMPTZ,
    CHECK ((status = 'ACTIVE') = (removed_at IS NULL))
);

-- Only the counter may advance and ACTIVE may become REMOVED, once.
CREATE FUNCTION guard_ca_admin_credential() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ca_admin_credential is append-only' USING ERRCODE = '23514';
    END IF;
    IF (NEW.credential_id, NEW.ca_id, NEW.issuer, NEW.subject, NEW.person_id,
        NEW.public_key_sec1, NEW.enrolled_at)
       IS DISTINCT FROM (OLD.credential_id, OLD.ca_id, OLD.issuer, OLD.subject,
        OLD.person_id, OLD.public_key_sec1, OLD.enrolled_at)
       OR NEW.sign_count < OLD.sign_count
       OR (OLD.status = 'REMOVED' AND NEW IS DISTINCT FROM OLD)
    THEN
        RAISE EXCEPTION 'only the counter may advance and an active credential be removed'
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_admin_credential_guard
    BEFORE UPDATE OR DELETE ON ca_admin_credential
    FOR EACH ROW EXECUTE FUNCTION guard_ca_admin_credential();
CREATE TRIGGER ca_admin_credential_no_truncate
    BEFORE TRUNCATE ON ca_admin_credential
    FOR EACH STATEMENT EXECUTE FUNCTION guard_ca_admin_credential();

-- One key is an officer key or an admin key, never both; one person holds
-- active officer or admin credentials on a CA, never both.
CREATE FUNCTION guard_credential_registries() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_TABLE_NAME = 'ca_admin_credential' THEN
        IF EXISTS (SELECT 1 FROM officer_credential c
                   WHERE c.public_key_sha256 = sha256(NEW.public_key_sec1)
                      OR (c.ca_id = NEW.ca_id AND c.status = 'ACTIVE'
                          AND c.person_id = NEW.person_id)) THEN
            RAISE EXCEPTION 'key or person already holds an officer credential'
              USING ERRCODE = '23514';
        END IF;
    ELSIF EXISTS (SELECT 1 FROM ca_admin_credential c
                  WHERE c.public_key_sha256 = sha256(NEW.public_key_sec1)
                     OR (c.ca_id = NEW.ca_id AND c.status = 'ACTIVE'
                         AND c.person_id = NEW.person_id)) THEN
        RAISE EXCEPTION 'key or person already holds a CA admin credential'
          USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_admin_credential_registries
    BEFORE INSERT ON ca_admin_credential
    FOR EACH ROW EXECUTE FUNCTION guard_credential_registries();
CREATE TRIGGER officer_credential_registries
    BEFORE INSERT ON officer_credential
    FOR EACH ROW EXECUTE FUNCTION guard_credential_registries();

CREATE TABLE ca_admin_challenge (
    challenge_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    purpose TEXT NOT NULL CHECK (purpose IN ('PROPOSE', 'APPROVE')),
    family TEXT NOT NULL CHECK (family IN ('CA_ADMIN', 'CREDENTIAL')),
    kind TEXT NOT NULL CHECK (kind IN ('REGISTER_ISSUER', 'GRANT_OFFICER', 'REVOKE_OFFICER',
                                       'ENROLL_CREDENTIAL', 'REMOVE_CREDENTIAL')),
    change_id UUID,
    content_sha256 BYTEA NOT NULL CHECK (octet_length(content_sha256) = 32),
    actor_issuer TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    issuer_certificate_sha256 BYTEA CHECK (octet_length(issuer_certificate_sha256) = 32),
    policy_edition TEXT NOT NULL,
    challenge_sha256 BYTEA NOT NULL UNIQUE CHECK (octet_length(challenge_sha256) = 32),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CHECK ((purpose = 'APPROVE') = (change_id IS NOT NULL)),
    CHECK ((family = 'CREDENTIAL') = (kind IN ('ENROLL_CREDENTIAL', 'REMOVE_CREDENTIAL')))
);

-- Only consumed_at may be set, once; nothing is deleted.
CREATE FUNCTION guard_ca_admin_challenge() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'ca_admin_challenge is append-only' USING ERRCODE = '23514';
    END IF;
    IF OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
       OR (NEW.challenge_id, NEW.ca_id, NEW.purpose, NEW.family, NEW.kind, NEW.change_id,
           NEW.content_sha256, NEW.actor_issuer, NEW.actor_subject,
           NEW.issuer_certificate_sha256, NEW.policy_edition, NEW.challenge_sha256,
           NEW.issued_at, NEW.expires_at)
          IS DISTINCT FROM
          (OLD.challenge_id, OLD.ca_id, OLD.purpose, OLD.family, OLD.kind, OLD.change_id,
           OLD.content_sha256, OLD.actor_issuer, OLD.actor_subject,
           OLD.issuer_certificate_sha256, OLD.policy_edition, OLD.challenge_sha256,
           OLD.issued_at, OLD.expires_at)
    THEN
        RAISE EXCEPTION 'a challenge is only consumed, once' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_admin_challenge_guard
    BEFORE UPDATE OR DELETE ON ca_admin_challenge
    FOR EACH ROW EXECUTE FUNCTION guard_ca_admin_challenge();
CREATE TRIGGER ca_admin_challenge_no_truncate
    BEFORE TRUNCATE ON ca_admin_challenge
    FOR EACH STATEMENT EXECUTE FUNCTION guard_ca_admin_challenge();

CREATE TABLE ca_admin_signature (
    family TEXT NOT NULL CHECK (family IN ('CA_ADMIN', 'CREDENTIAL')),
    change_id UUID NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('MAKER', 'CHECKER')),
    challenge_id UUID NOT NULL UNIQUE REFERENCES ca_admin_challenge(challenge_id),
    credential_id BYTEA NOT NULL REFERENCES ca_admin_credential(credential_id),
    public_key_sha256 BYTEA NOT NULL CHECK (octet_length(public_key_sha256) = 32),
    person_id TEXT NOT NULL,
    claim_sha256 BYTEA NOT NULL CHECK (octet_length(claim_sha256) = 32),
    authenticator_data BYTEA NOT NULL CHECK (octet_length(authenticator_data) = 37),
    client_data_json BYTEA NOT NULL CHECK (octet_length(client_data_json) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    sign_count BIGINT NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (family, change_id, role)
);
CREATE FUNCTION guard_ca_admin_signature() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'ca_admin_signature is append-only' USING ERRCODE = '23514';
END $fn$;
CREATE TRIGGER ca_admin_signature_append_only
    BEFORE UPDATE OR DELETE ON ca_admin_signature
    FOR EACH ROW EXECUTE FUNCTION guard_ca_admin_signature();
CREATE TRIGGER ca_admin_signature_no_truncate
    BEFORE TRUNCATE ON ca_admin_signature
    FOR EACH STATEMENT EXECUTE FUNCTION guard_ca_admin_signature();

CREATE FUNCTION ca_admin_claim_digest(
    p_purpose TEXT, p_ca UUID, p_issuer_sha256 BYTEA, p_family TEXT, p_kind TEXT,
    p_change UUID, p_content_sha256 BYTEA, p_edition TEXT, p_challenge_sha256 BYTEA,
    p_expires TIMESTAMPTZ
)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT sha256(convert_to('trust-platform/ca-admin/v1', 'UTF8') || '\x00'::bytea
        || claim_field(convert_to(p_purpose, 'UTF8'))
        || claim_field(uuid_send(p_ca))
        || claim_field(p_issuer_sha256)
        || claim_field(convert_to(p_family, 'UTF8'))
        || claim_field(convert_to(p_kind, 'UTF8'))
        || claim_field(uuid_send(p_change))
        || claim_field(p_content_sha256)
        || claim_field(convert_to(p_edition, 'UTF8'))
        || claim_field(p_challenge_sha256)
        || claim_field(int8send((extract(epoch FROM p_expires) * 1000000)::bigint)))
$fn$;

CREATE FUNCTION signed_admin_required(p_ca UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $fn$
    SELECT coalesce((SELECT signed_admin_required FROM ca_revocation_policy
                     WHERE ca_id = p_ca), false)
$fn$;

-- DBA bootstrap of admin credentials (granted to no service), like
-- ca_admin_grant. The key must be the Rust core's canonical compressed form.
CREATE FUNCTION enroll_ca_admin_credential(
    p_ca UUID, p_credential_id BYTEA, p_issuer TEXT, p_subject TEXT, p_person_id TEXT,
    p_public_key_sec1 BYTEA
)
RETURNS VOID
LANGUAGE plpgsql AS $fn$
BEGIN
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

CREATE FUNCTION remove_ca_admin_credential(p_credential_id BYTEA)
RETURNS VOID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ca UUID;
BEGIN
    UPDATE ca_admin_credential SET status = 'REMOVED', removed_at = clock_timestamp()
    WHERE credential_id = p_credential_id AND status = 'ACTIVE'
    RETURNING ca_id INTO v_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such active credential' USING ERRCODE = '23514';
    END IF;
    INSERT INTO audit_event(event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (gen_random_uuid(), v_ca, NULL, session_user, 'ca_admin.credential.removed',
            'BOOTSTRAP:credential=' || encode(sha256(p_credential_id), 'hex'));
END $fn$;

-- The unsigned paths of 0024/0028 become *_unchecked (no service grant);
-- the original names refuse when the CA requires signed administration.
ALTER FUNCTION propose_ca_admin_change(uuid,text,bytea,text,text,text,text)
    RENAME TO ca_admin_propose_unchecked;
ALTER FUNCTION approve_ca_admin_change(uuid,text,text,bytea)
    RENAME TO ca_admin_approve_unchecked;
ALTER FUNCTION propose_credential_change(uuid,text,bytea,text,text,text,bytea,text,text)
    RENAME TO credential_propose_unchecked;
ALTER FUNCTION approve_credential_change(uuid,text,text,bytea)
    RENAME TO credential_approve_unchecked;
REVOKE EXECUTE ON FUNCTION ca_admin_propose_unchecked(uuid,text,bytea,text,text,text,text),
    ca_admin_approve_unchecked(uuid,text,text,bytea),
    credential_propose_unchecked(uuid,text,bytea,text,text,text,bytea,text,text),
    credential_approve_unchecked(uuid,text,text,bytea)
    FROM trust_ca_admin;

CREATE FUNCTION propose_ca_admin_change(
    p_ca UUID, p_kind TEXT, p_certificate_der BYTEA, p_officer_issuer TEXT,
    p_officer_subject TEXT, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_admin_required(p_ca) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration' USING ERRCODE = '42501';
    END IF;
    RETURN ca_admin_propose_unchecked(p_ca, p_kind, p_certificate_der, p_officer_issuer,
                                      p_officer_subject, p_maker_issuer, p_maker_subject);
END $fn$;

CREATE FUNCTION approve_ca_admin_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT, p_expected_sha256 BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_admin_required((SELECT ca_id FROM ca_admin_change WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration' USING ERRCODE = '42501';
    END IF;
    RETURN ca_admin_approve_unchecked(p_change, p_checker_issuer, p_checker_subject,
                                      p_expected_sha256);
END $fn$;

CREATE FUNCTION propose_credential_change(
    p_ca UUID, p_kind TEXT, p_credential_id BYTEA,
    p_officer_issuer TEXT, p_officer_subject TEXT,
    p_person_id TEXT, p_public_key_sec1 BYTEA,
    p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_admin_required(p_ca) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration' USING ERRCODE = '42501';
    END IF;
    RETURN credential_propose_unchecked(p_ca, p_kind, p_credential_id, p_officer_issuer,
        p_officer_subject, p_person_id, p_public_key_sec1, p_maker_issuer, p_maker_subject);
END $fn$;

CREATE FUNCTION approve_credential_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT, p_expected_sha256 BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_admin_required((SELECT ca_id FROM officer_credential_change
                              WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed CA administration' USING ERRCODE = '42501';
    END IF;
    RETURN credential_approve_unchecked(p_change, p_checker_issuer, p_checker_subject,
                                        p_expected_sha256);
END $fn$;

-- A proposal challenge names the content digest the maker will sign (the
-- Rust core computes it from the content it shows the admin); an approval
-- challenge takes kind and digest from the pending change.
CREATE FUNCTION issue_ca_admin_challenge(
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
       OR p_family IS NULL OR p_family NOT IN ('CA_ADMIN', 'CREDENTIAL')
       OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 600
       OR p_actor_issuer IS NULL OR length(p_actor_issuer) NOT BETWEEN 1 AND 1024
       OR p_actor_subject IS NULL OR length(p_actor_subject) NOT BETWEEN 1 AND 512
       OR (p_purpose = 'PROPOSE' AND (p_ca IS NULL OR p_change IS NOT NULL
            OR p_content_sha256 IS NULL OR octet_length(p_content_sha256) <> 32
            OR p_kind IS NULL
            OR (p_family = 'CA_ADMIN'
                AND p_kind NOT IN ('REGISTER_ISSUER', 'GRANT_OFFICER', 'REVOKE_OFFICER'))
            OR (p_family = 'CREDENTIAL'
                AND p_kind NOT IN ('ENROLL_CREDENTIAL', 'REMOVE_CREDENTIAL'))))
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

-- What the Rust core rebuilds the claim from (never from the caller).
CREATE FUNCTION ca_admin_challenge_claim(p_challenge UUID)
RETURNS TABLE (purpose TEXT, ca_id UUID, family TEXT, kind TEXT, change_id UUID,
               issuer_certificate_sha256 BYTEA, content_sha256 BYTEA, policy_edition TEXT,
               challenge_sha256 BYTEA, expires_us BIGINT, actor_issuer TEXT,
               actor_subject TEXT, consumed BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT c.purpose, c.ca_id, c.family, c.kind, c.change_id, c.issuer_certificate_sha256,
           c.content_sha256, c.policy_edition, c.challenge_sha256,
           (extract(epoch FROM c.expires_at) * 1000000)::bigint, c.actor_issuer,
           c.actor_subject, c.consumed_at IS NOT NULL
    FROM ca_admin_challenge c WHERE c.challenge_id = p_challenge
$fn$;

CREATE FUNCTION ca_admin_credential_for(p_ca UUID, p_credential_id BYTEA)
RETURNS TABLE (issuer TEXT, subject TEXT, person_id TEXT, public_key_sec1 BYTEA,
               sign_count BIGINT, active BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT c.issuer, c.subject, c.person_id, c.public_key_sec1, c.sign_count,
           c.status = 'ACTIVE'
    FROM ca_admin_credential c
    WHERE c.ca_id = p_ca AND c.credential_id = p_credential_id
$fn$;

-- Shared checks for a signed admin submission (as consume_signed_challenge).
CREATE FUNCTION consume_ca_admin_challenge(
    p_challenge ca_admin_challenge, p_purpose TEXT, p_credential ca_admin_credential,
    p_authenticator_data BYTEA, p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS BYTEA
LANGUAGE plpgsql AS $fn$
DECLARE
    v_claim BYTEA;
    v_count BIGINT;
BEGIN
    IF p_challenge.challenge_id IS NULL OR p_challenge.purpose <> p_purpose THEN
        RAISE EXCEPTION 'challenge issued for another step' USING ERRCODE = '22023';
    END IF;
    IF p_challenge.consumed_at IS NOT NULL OR p_challenge.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'challenge expired or already used' USING ERRCODE = '23514';
    END IF;
    IF p_credential.credential_id IS NULL OR p_credential.status <> 'ACTIVE'
       OR p_credential.ca_id <> p_challenge.ca_id
       OR (p_credential.issuer, p_credential.subject)
          <> (p_challenge.actor_issuer, p_challenge.actor_subject) THEN
        RAISE EXCEPTION 'credential is not an active credential of the acting admin'
          USING ERRCODE = '42501';
    END IF;
    PERFORM 1 FROM ca_admin_grant g
    WHERE g.ca_id = p_challenge.ca_id
      AND (g.issuer, g.subject) = (p_challenge.actor_issuer, p_challenge.actor_subject)
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'actor holds no CA admin grant for this CA' USING ERRCODE = '42501';
    END IF;
    IF p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80 THEN
        RAISE EXCEPTION 'invalid signature encoding' USING ERRCODE = '22023';
    END IF;
    v_claim := ca_admin_claim_digest(p_challenge.purpose, p_challenge.ca_id,
        p_challenge.issuer_certificate_sha256, p_challenge.family, p_challenge.kind,
        p_challenge.change_id, p_challenge.content_sha256, p_challenge.policy_edition,
        p_challenge.challenge_sha256, p_challenge.expires_at);
    v_count := webauthn_precheck(p_authenticator_data, p_client_data_json, v_claim);
    IF NOT ((p_credential.sign_count = 0 AND v_count = 0) OR v_count > p_credential.sign_count) THEN
        RAISE EXCEPTION 'signature counter did not advance' USING ERRCODE = '23514';
    END IF;
    UPDATE ca_admin_challenge SET consumed_at = clock_timestamp()
    WHERE challenge_id = p_challenge.challenge_id;
    UPDATE ca_admin_credential SET sign_count = v_count
    WHERE credential_id = p_credential.credential_id;
    RETURN v_claim;
END $fn$;

-- The content parameters are those of the family's proposal function; the
-- change created from them must carry the signed kind and content digest.
CREATE FUNCTION propose_signed_admin_change(
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

CREATE FUNCTION approve_signed_admin_change(
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

-- Both signatures of a change with the enrolled keys and the change's own
-- CA, kind and content, for offline re-verification.
CREATE FUNCTION ca_admin_signatures(p_family TEXT, p_change UUID)
RETURNS TABLE (role TEXT, challenge_id UUID, public_key_sec1 BYTEA, person_id TEXT,
               claim_sha256 BYTEA, authenticator_data BYTEA, client_data_json BYTEA,
               signature_der BYTEA, change_ca UUID, change_kind TEXT,
               change_content_sha256 BYTEA)
LANGUAGE sql STABLE AS $fn$
    SELECT s.role, s.challenge_id, c.public_key_sec1, s.person_id, s.claim_sha256,
           s.authenticator_data, s.client_data_json, s.signature_der,
           coalesce(a.ca_id, o.ca_id), coalesce(a.kind, o.kind),
           coalesce(a.content_sha256, o.content_sha256)
    FROM ca_admin_signature s
    JOIN ca_admin_credential c USING (credential_id)
    LEFT JOIN ca_admin_change a ON s.family = 'CA_ADMIN' AND a.change_id = s.change_id
    LEFT JOIN officer_credential_change o
           ON s.family = 'CREDENTIAL' AND o.change_id = s.change_id
    WHERE s.family = p_family AND s.change_id = p_change
    ORDER BY s.role DESC
$fn$;

ALTER TABLE ca_admin_credential OWNER TO trust_revocation_owner;
ALTER TABLE ca_admin_challenge OWNER TO trust_revocation_owner;
ALTER TABLE ca_admin_signature OWNER TO trust_revocation_owner;
REVOKE ALL ON ca_admin_credential, ca_admin_challenge, ca_admin_signature FROM PUBLIC;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    -- Every new function, granted or not, is owned and pinned like 0023.
    FOREACH f IN ARRAY ARRAY[
        'guard_signed_admin_required()', 'guard_ca_admin_credential()',
        'guard_credential_registries()', 'guard_ca_admin_challenge()',
        'guard_ca_admin_signature()',
        'ca_admin_claim_digest(text,uuid,bytea,text,text,uuid,bytea,text,bytea,timestamptz)',
        'signed_admin_required(uuid)',
        'enroll_ca_admin_credential(uuid,bytea,text,text,text,bytea)',
        'remove_ca_admin_credential(bytea)',
        'propose_ca_admin_change(uuid,text,bytea,text,text,text,text)',
        'approve_ca_admin_change(uuid,text,text,bytea)',
        'propose_credential_change(uuid,text,bytea,text,text,text,bytea,text,text)',
        'approve_credential_change(uuid,text,text,bytea)',
        'issue_ca_admin_challenge(text,uuid,text,text,bytea,uuid,text,text,integer)',
        'ca_admin_challenge_claim(uuid)', 'ca_admin_credential_for(uuid,bytea)',
        'consume_ca_admin_challenge(ca_admin_challenge,text,ca_admin_credential,bytea,bytea,bytea)',
        'propose_signed_admin_change(uuid,bytea,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'approve_signed_admin_change(uuid,bytea,bytea,bytea,bytea)',
        'ca_admin_signatures(text,uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    -- The service entry points run with the owner's rights.
    FOREACH f IN ARRAY ARRAY[
        'enroll_ca_admin_credential(uuid,bytea,text,text,text,bytea)',
        'remove_ca_admin_credential(bytea)',
        'propose_ca_admin_change(uuid,text,bytea,text,text,text,text)',
        'approve_ca_admin_change(uuid,text,text,bytea)',
        'propose_credential_change(uuid,text,bytea,text,text,text,bytea,text,text)',
        'approve_credential_change(uuid,text,text,bytea)',
        'issue_ca_admin_challenge(text,uuid,text,text,bytea,uuid,text,text,integer)',
        'ca_admin_challenge_claim(uuid)', 'ca_admin_credential_for(uuid,bytea)',
        'propose_signed_admin_change(uuid,bytea,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'approve_signed_admin_change(uuid,bytea,bytea,bytea,bytea)',
        'ca_admin_signatures(text,uuid)'] LOOP
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'propose_ca_admin_change(uuid,text,bytea,text,text,text,text)',
        'approve_ca_admin_change(uuid,text,text,bytea)',
        'propose_credential_change(uuid,text,bytea,text,text,text,bytea,text,text)',
        'approve_credential_change(uuid,text,text,bytea)',
        'issue_ca_admin_challenge(text,uuid,text,text,bytea,uuid,text,text,integer)',
        'ca_admin_challenge_claim(uuid)', 'ca_admin_credential_for(uuid,bytea)',
        'propose_signed_admin_change(uuid,bytea,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
        'approve_signed_admin_change(uuid,bytea,bytea,bytea,bytea)',
        'ca_admin_signatures(text,uuid)'] LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO trust_ca_admin', f);
    END LOOP;
END $fns$;

SELECT acknowledge_schema_changes('0037_signed_ca_admin');

COMMIT;
