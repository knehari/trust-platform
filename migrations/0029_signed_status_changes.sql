-- v0.29 (lab): signed status-change approvals (ADR-0007 step 2, status
-- Proposed; implemented in lab at the owner's request). LAB ONLY.
-- * A maker or checker first asks for a single-use challenge
--   (issue_status_change_challenge): a random 256-bit value (pgcrypto
--   gen_random_bytes, only its SHA-256 is kept) bound to the CA, the
--   registered issuer certificate, the change (pre-allocated for a
--   proposal), its exact content, the acting officer and an expiry of at
--   most 10 minutes.
-- * The officer's authenticator signs the canonical claim
--   (trust_pki_core::officer_credential::StatusChangeClaim; its SHA-256 is
--   the WebAuthn challenge). The Rust core verifies the WebAuthn assertion
--   (trust_pki_core::webauthn) and only then calls
--   propose_signed_status_change / approve_signed_status_change. PostgreSQL
--   cannot verify ECDSA; it re-checks everything else and stores the
--   evidence for offline re-verification:
--     - the challenge is unexpired and consumed exactly once;
--     - the credential is active and belongs to the acting officer, who
--       holds the grant;
--     - the authenticator data has user presence and verification and a
--       counter that advances (stored on the credential);
--     - clientDataJSON is a webauthn.get ceremony for the claim digest
--       recomputed here from the stored fields (status_change_claim_digest
--       = StatusChangeClaim::digest);
--     - on approval, the maker signed the proposal, maker and checker
--       keys and persons differ, and the maker's credential is still
--       active (removing a credential voids its pending proposals).
-- * ca_revocation_policy.signed_approvals_required (default false, one-way:
--   it can be set, never cleared) makes the unsigned propose/approve refuse
--   (42501) for that CA. Reject and withdraw stay unsigned: they change no
--   certificate status.
-- * The original bodies are kept as status_change_propose_unchecked (now
--   taking the change id) and status_change_approve_unchecked (renamed),
--   granted to no service.
-- A service holding trust_revocation_officer_api could still submit a forged
-- assertion directly (the database cannot check the signature); ADR-0007 §7
-- confines that role to the Rust core, and re-verification of the stored
-- evidence (PgRevocationStore::reverify_signed_change) exposes it.
-- Apply after 0028 as a superuser.
BEGIN;

ALTER TABLE ca_revocation_policy
    ADD COLUMN signed_approvals_required BOOLEAN NOT NULL DEFAULT false;

CREATE FUNCTION guard_signed_approvals_required() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF OLD.signed_approvals_required AND NOT NEW.signed_approvals_required THEN
        RAISE EXCEPTION 'signed approvals cannot be switched off' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER ca_revocation_policy_signed_one_way
    BEFORE UPDATE ON ca_revocation_policy
    FOR EACH ROW EXECUTE FUNCTION guard_signed_approvals_required();

CREATE TABLE status_change_challenge (
    challenge_id UUID PRIMARY KEY,
    ca_id UUID NOT NULL REFERENCES ca(ca_id),
    purpose TEXT NOT NULL CHECK (purpose IN ('PROPOSE', 'APPROVE')),
    change_id UUID NOT NULL,
    serial_der_content BYTEA NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('SUSPEND', 'RELEASE', 'REVOKE')),
    reason_code SMALLINT,
    invalidity_at TIMESTAMPTZ,
    actor_issuer TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    issuer_certificate_sha256 BYTEA NOT NULL CHECK (octet_length(issuer_certificate_sha256) = 32),
    policy_edition TEXT NOT NULL,
    challenge_sha256 BYTEA NOT NULL UNIQUE CHECK (octet_length(challenge_sha256) = 32),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX status_change_challenge_proposal
    ON status_change_challenge (change_id) WHERE purpose = 'PROPOSE';

-- Only consumed_at may be set, once; nothing is deleted.
CREATE FUNCTION guard_status_change_challenge() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE')
       OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
       OR (NEW.challenge_id, NEW.ca_id, NEW.purpose, NEW.change_id, NEW.serial_der_content,
           NEW.action, NEW.reason_code, NEW.invalidity_at, NEW.actor_issuer,
           NEW.actor_subject, NEW.issuer_certificate_sha256, NEW.policy_edition,
           NEW.challenge_sha256, NEW.issued_at, NEW.expires_at)
          IS DISTINCT FROM
          (OLD.challenge_id, OLD.ca_id, OLD.purpose, OLD.change_id, OLD.serial_der_content,
           OLD.action, OLD.reason_code, OLD.invalidity_at, OLD.actor_issuer,
           OLD.actor_subject, OLD.issuer_certificate_sha256, OLD.policy_edition,
           OLD.challenge_sha256, OLD.issued_at, OLD.expires_at)
    THEN
        RAISE EXCEPTION 'a challenge is consumed once and never changed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER status_change_challenge_guard
    BEFORE UPDATE OR DELETE ON status_change_challenge
    FOR EACH ROW EXECUTE FUNCTION guard_status_change_challenge();
CREATE TRIGGER status_change_challenge_no_truncate
    BEFORE TRUNCATE ON status_change_challenge
    FOR EACH STATEMENT EXECUTE FUNCTION guard_status_change_challenge();

CREATE TABLE status_change_signature (
    change_id UUID NOT NULL REFERENCES certificate_status_change(change_id),
    role TEXT NOT NULL CHECK (role IN ('MAKER', 'CHECKER')),
    challenge_id UUID NOT NULL UNIQUE REFERENCES status_change_challenge(challenge_id),
    credential_id BYTEA NOT NULL REFERENCES officer_credential(credential_id),
    public_key_sha256 BYTEA NOT NULL CHECK (octet_length(public_key_sha256) = 32),
    person_id TEXT NOT NULL,
    claim_sha256 BYTEA NOT NULL CHECK (octet_length(claim_sha256) = 32),
    authenticator_data BYTEA NOT NULL CHECK (octet_length(authenticator_data) = 37),
    client_data_json BYTEA NOT NULL CHECK (octet_length(client_data_json) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    sign_count BIGINT NOT NULL,
    signed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (change_id, role)
);

CREATE FUNCTION guard_status_change_signature() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION 'status_change_signature is append-only' USING ERRCODE = '23514';
END $fn$;
CREATE TRIGGER status_change_signature_append_only
    BEFORE UPDATE OR DELETE ON status_change_signature
    FOR EACH ROW EXECUTE FUNCTION guard_status_change_signature();
CREATE TRIGGER status_change_signature_no_truncate
    BEFORE TRUNCATE ON status_change_signature
    FOR EACH STATEMENT EXECUTE FUNCTION guard_status_change_signature();

-- One claim field: 0x00 for NULL, or 0x01, a 4-byte big-endian length and
-- the bytes (StatusChangeClaim::canonical_bytes).
CREATE FUNCTION claim_field(p BYTEA)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT CASE WHEN p IS NULL THEN '\x00'::bytea
                ELSE '\x01'::bytea || int4send(octet_length(p)) || p END
$fn$;

CREATE FUNCTION status_change_claim_digest(
    p_change UUID, p_ca UUID, p_issuer_sha256 BYTEA, p_serial BYTEA, p_action TEXT,
    p_reason SMALLINT, p_invalidity TIMESTAMPTZ, p_edition TEXT, p_challenge_sha256 BYTEA,
    p_expires TIMESTAMPTZ
)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE AS $fn$
    SELECT sha256(convert_to('trust-platform/status-change/v1', 'UTF8') || '\x00'::bytea
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

-- The checks PostgreSQL can make on an assertion: user present and
-- verified, no attested data or extensions, and clientDataJSON naming a
-- webauthn.get ceremony for this claim. Returns the signature counter.
CREATE FUNCTION webauthn_precheck(p_authenticator_data BYTEA, p_client_data_json BYTEA,
                                  p_claim_sha256 BYTEA)
RETURNS BIGINT
LANGUAGE plpgsql IMMUTABLE AS $fn$
DECLARE
    v_client JSONB;
BEGIN
    IF octet_length(p_authenticator_data) <> 37
       OR get_byte(p_authenticator_data, 32) & 5 <> 5
       OR get_byte(p_authenticator_data, 32) & 192 <> 0 THEN
        RAISE EXCEPTION 'authenticator data refused' USING ERRCODE = '23514';
    END IF;
    BEGIN
        v_client := convert_from(p_client_data_json, 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RAISE EXCEPTION 'clientDataJSON is not JSON' USING ERRCODE = '23514';
    END;
    IF jsonb_typeof(v_client) <> 'object'
       OR v_client->>'type' IS DISTINCT FROM 'webauthn.get'
       OR v_client->>'challenge' IS DISTINCT FROM
          rtrim(translate(encode(p_claim_sha256, 'base64'), '+/', '-_'), '=')
       OR coalesce(v_client->'crossOrigin', 'false'::jsonb) <> 'false'::jsonb THEN
        RAISE EXCEPTION 'clientDataJSON does not sign this claim' USING ERRCODE = '23514';
    END IF;
    RETURN (get_byte(p_authenticator_data, 33)::bigint << 24)
         | (get_byte(p_authenticator_data, 34)::bigint << 16)
         | (get_byte(p_authenticator_data, 35)::bigint << 8)
         | get_byte(p_authenticator_data, 36)::bigint;
END $fn$;

-- The original proposal body (0025), taking the change id.
CREATE FUNCTION status_change_propose_unchecked(
    p_change UUID, p_ca UUID, p_serial BYTEA, p_action TEXT, p_reason SMALLINT,
    p_invalidity TIMESTAMPTZ, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_request UUID;
    v_status TEXT;
    v_suspension BOOLEAN;
    v_change UUID := p_change;
BEGIN
    IF p_change IS NULL OR p_ca IS NULL OR p_serial IS NULL
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

ALTER FUNCTION approve_certificate_status_change(uuid,text,text,text,smallint)
    RENAME TO status_change_approve_unchecked;
REVOKE ALL ON FUNCTION status_change_approve_unchecked(uuid,text,text,text,smallint)
    FROM trust_revocation_officer_api;

CREATE FUNCTION signed_approvals_required(p_ca UUID)
RETURNS BOOLEAN
LANGUAGE sql STABLE AS $fn$
    SELECT coalesce((SELECT signed_approvals_required FROM ca_revocation_policy
                     WHERE ca_id = p_ca), false)
$fn$;

CREATE OR REPLACE FUNCTION propose_certificate_status_change(
    p_ca UUID, p_serial BYTEA, p_action TEXT, p_reason SMALLINT,
    p_invalidity TIMESTAMPTZ, p_maker_issuer TEXT, p_maker_subject TEXT
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_approvals_required(p_ca) THEN
        RAISE EXCEPTION 'this CA requires signed status-change approvals'
          USING ERRCODE = '42501';
    END IF;
    RETURN status_change_propose_unchecked(gen_random_uuid(), p_ca, p_serial, p_action,
        p_reason, p_invalidity, p_maker_issuer, p_maker_subject);
END $fn$;
-- CREATE OR REPLACE resets the definer settings (see 0025).
ALTER FUNCTION propose_certificate_status_change(uuid,bytea,text,smallint,timestamp with time zone,text,text)
    SECURITY DEFINER;
ALTER FUNCTION propose_certificate_status_change(uuid,bytea,text,smallint,timestamp with time zone,text,text)
    SET search_path = pg_catalog, public, pg_temp;

CREATE FUNCTION approve_certificate_status_change(
    p_change UUID, p_checker_issuer TEXT, p_checker_subject TEXT,
    p_expected_action TEXT, p_expected_reason SMALLINT
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
BEGIN
    IF signed_approvals_required((SELECT ca_id FROM certificate_status_change
                                  WHERE change_id = p_change)) THEN
        RAISE EXCEPTION 'this CA requires signed status-change approvals'
          USING ERRCODE = '42501';
    END IF;
    RETURN status_change_approve_unchecked(p_change, p_checker_issuer, p_checker_subject,
        p_expected_action, p_expected_reason);
END $fn$;

CREATE FUNCTION issue_status_change_challenge(
    p_purpose TEXT, p_ca UUID, p_change UUID, p_serial BYTEA, p_action TEXT,
    p_reason SMALLINT, p_invalidity TIMESTAMPTZ, p_actor_issuer TEXT, p_actor_subject TEXT,
    p_ttl_seconds INTEGER
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_challenge UUID := gen_random_uuid();
    v_change certificate_status_change%ROWTYPE;
    v_issuer BYTEA;
    v_edition TEXT;
BEGIN
    IF p_purpose IS NULL OR p_purpose NOT IN ('PROPOSE', 'APPROVE')
       OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 1 AND 600
       OR p_actor_issuer IS NULL OR length(p_actor_issuer) NOT BETWEEN 1 AND 1024
       OR p_actor_subject IS NULL OR length(p_actor_subject) NOT BETWEEN 1 AND 512
       OR (p_purpose = 'PROPOSE' AND (p_ca IS NULL OR p_change IS NOT NULL
            OR p_serial IS NULL OR octet_length(p_serial) NOT BETWEEN 1 AND 20
            OR p_action IS NULL OR p_action NOT IN ('SUSPEND', 'RELEASE', 'REVOKE')))
       OR (p_purpose = 'APPROVE' AND (p_change IS NULL OR p_serial IS NOT NULL
            OR p_action IS NOT NULL OR p_reason IS NOT NULL OR p_invalidity IS NOT NULL))
    THEN
        RAISE EXCEPTION 'invalid challenge request' USING ERRCODE = '22023';
    END IF;
    IF p_purpose = 'APPROVE' THEN
        SELECT * INTO v_change FROM certificate_status_change WHERE change_id = p_change;
        IF NOT FOUND OR v_change.ca_id IS DISTINCT FROM coalesce(p_ca, v_change.ca_id) THEN
            RAISE EXCEPTION 'unknown status change' USING ERRCODE = '22023';
        END IF;
        IF v_change.status <> 'PROPOSED' THEN
            RAISE EXCEPTION 'status change is closed' USING ERRCODE = '23514';
        END IF;
        IF (v_change.maker_issuer, v_change.maker_subject) = (p_actor_issuer, p_actor_subject) THEN
            RAISE EXCEPTION 'checker must differ from maker' USING ERRCODE = '23514';
        END IF;
    ELSE
        v_change.change_id := gen_random_uuid();
        v_change.ca_id := p_ca;
        v_change.serial_der_content := p_serial;
        v_change.action := p_action;
        v_change.reason_code := p_reason;
        v_change.invalidity_at := p_invalidity;
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
    VALUES (v_challenge, v_change.ca_id, p_purpose, v_change.change_id,
        v_change.serial_der_content, v_change.action, v_change.reason_code,
        v_change.invalidity_at, p_actor_issuer, p_actor_subject, v_issuer, v_edition,
        sha256(gen_random_bytes(32)),
        clock_timestamp() + make_interval(secs => p_ttl_seconds));
    RETURN v_challenge;
END $fn$;

-- What the Rust core rebuilds the claim from (never from the caller).
CREATE FUNCTION status_change_challenge_claim(p_challenge UUID)
RETURNS TABLE (purpose TEXT, ca_id UUID, change_id UUID, issuer_certificate_sha256 BYTEA,
               serial_der_content BYTEA, action TEXT, reason_code SMALLINT,
               invalidity_us BIGINT, policy_edition TEXT, challenge_sha256 BYTEA,
               expires_us BIGINT, actor_issuer TEXT, actor_subject TEXT, consumed BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT c.purpose, c.ca_id, c.change_id, c.issuer_certificate_sha256,
           c.serial_der_content, c.action, c.reason_code,
           (extract(epoch FROM c.invalidity_at) * 1000000)::bigint, c.policy_edition,
           c.challenge_sha256, (extract(epoch FROM c.expires_at) * 1000000)::bigint,
           c.actor_issuer, c.actor_subject, c.consumed_at IS NOT NULL
    FROM status_change_challenge c WHERE c.challenge_id = p_challenge
$fn$;

CREATE FUNCTION officer_credential_for(p_ca UUID, p_credential_id BYTEA)
RETURNS TABLE (issuer TEXT, subject TEXT, person_id TEXT, public_key_sec1 BYTEA,
               sign_count BIGINT, active BOOLEAN)
LANGUAGE sql STABLE AS $fn$
    SELECT c.issuer, c.subject, c.person_id, c.public_key_sec1, c.sign_count,
           c.status = 'ACTIVE'
    FROM officer_credential c
    WHERE c.ca_id = p_ca AND c.credential_id = p_credential_id
$fn$;

-- Shared checks for a signed submission: consumes the challenge and
-- advances the credential counter; returns the claim digest.
CREATE FUNCTION consume_signed_challenge(
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
    v_claim := status_change_claim_digest(p_challenge.change_id, p_challenge.ca_id,
        p_challenge.issuer_certificate_sha256, p_challenge.serial_der_content,
        p_challenge.action, p_challenge.reason_code, p_challenge.invalidity_at,
        p_challenge.policy_edition, p_challenge.challenge_sha256, p_challenge.expires_at);
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

CREATE FUNCTION propose_signed_status_change(
    p_challenge UUID, p_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS UUID
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch status_change_challenge%ROWTYPE;
    v_cred officer_credential%ROWTYPE;
    v_claim BYTEA;
    v_change UUID;
BEGIN
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    -- Certificate first (0025 lock order), then challenge and credential.
    PERFORM 1 FROM certificate
    WHERE ca_id = v_ch.ca_id AND serial_der_content = v_ch.serial_der_content FOR UPDATE;
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    SELECT * INTO v_cred FROM officer_credential WHERE credential_id = p_credential_id FOR UPDATE;
    v_claim := consume_signed_challenge(v_ch, 'PROPOSE', v_cred, p_authenticator_data,
                                        p_client_data_json, p_signature_der);
    v_change := status_change_propose_unchecked(v_ch.change_id, v_ch.ca_id,
        v_ch.serial_der_content, v_ch.action, v_ch.reason_code, v_ch.invalidity_at,
        v_ch.actor_issuer, v_ch.actor_subject);
    INSERT INTO status_change_signature(change_id, role, challenge_id, credential_id,
        public_key_sha256, person_id, claim_sha256, authenticator_data, client_data_json,
        signature_der, sign_count)
    VALUES (v_change, 'MAKER', p_challenge, p_credential_id, v_cred.public_key_sha256,
        v_cred.person_id, v_claim, p_authenticator_data, p_client_data_json, p_signature_der,
        (SELECT sign_count FROM officer_credential WHERE credential_id = p_credential_id));
    RETURN v_change;
END $fn$;

CREATE FUNCTION approve_signed_status_change(
    p_challenge UUID, p_credential_id BYTEA, p_authenticator_data BYTEA,
    p_client_data_json BYTEA, p_signature_der BYTEA
)
RETURNS TEXT
LANGUAGE plpgsql AS $fn$
DECLARE
    v_ch status_change_challenge%ROWTYPE;
    v_cred officer_credential%ROWTYPE;
    v_chg certificate_status_change%ROWTYPE;
    v_maker status_change_signature%ROWTYPE;
    v_claim BYTEA;
    v_result TEXT;
BEGIN
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown challenge' USING ERRCODE = '22023';
    END IF;
    PERFORM 1 FROM certificate
    WHERE ca_id = v_ch.ca_id AND serial_der_content = v_ch.serial_der_content FOR UPDATE;
    SELECT * INTO v_ch FROM status_change_challenge WHERE challenge_id = p_challenge FOR UPDATE;
    SELECT * INTO v_cred FROM officer_credential WHERE credential_id = p_credential_id FOR UPDATE;
    SELECT * INTO v_chg FROM certificate_status_change WHERE change_id = v_ch.change_id;
    SELECT * INTO v_maker FROM status_change_signature
    WHERE change_id = v_ch.change_id AND role = 'MAKER';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the proposal was not signed' USING ERRCODE = '23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM officer_credential
                   WHERE credential_id = v_maker.credential_id AND status = 'ACTIVE') THEN
        RAISE EXCEPTION 'the maker''s credential was removed' USING ERRCODE = '23514';
    END IF;
    IF v_maker.public_key_sha256 = v_cred.public_key_sha256
       OR v_maker.person_id = v_cred.person_id THEN
        RAISE EXCEPTION 'maker and checker must be distinct people with distinct keys'
          USING ERRCODE = '23514';
    END IF;
    v_claim := consume_signed_challenge(v_ch, 'APPROVE', v_cred, p_authenticator_data,
                                        p_client_data_json, p_signature_der);
    v_result := status_change_approve_unchecked(v_ch.change_id, v_ch.actor_issuer,
        v_ch.actor_subject, v_chg.action, v_chg.reason_code);
    INSERT INTO status_change_signature(change_id, role, challenge_id, credential_id,
        public_key_sha256, person_id, claim_sha256, authenticator_data, client_data_json,
        signature_der, sign_count)
    VALUES (v_ch.change_id, 'CHECKER', p_challenge, p_credential_id, v_cred.public_key_sha256,
        v_cred.person_id, v_claim, p_authenticator_data, p_client_data_json, p_signature_der,
        (SELECT sign_count FROM officer_credential WHERE credential_id = p_credential_id));
    RETURN v_result;
END $fn$;

-- Both signatures of a change, with the enrolled keys, for re-verification.
CREATE FUNCTION status_change_signatures(p_change UUID)
RETURNS TABLE (role TEXT, challenge_id UUID, credential_id BYTEA, public_key_sec1 BYTEA,
               person_id TEXT, claim_sha256 BYTEA, authenticator_data BYTEA,
               client_data_json BYTEA, signature_der BYTEA)
LANGUAGE sql STABLE AS $fn$
    SELECT s.role, s.challenge_id, s.credential_id, c.public_key_sec1, s.person_id,
           s.claim_sha256, s.authenticator_data, s.client_data_json, s.signature_der
    FROM status_change_signature s JOIN officer_credential c USING (credential_id)
    WHERE s.change_id = p_change ORDER BY s.role DESC
$fn$;

ALTER TABLE status_change_challenge OWNER TO trust_revocation_owner;
ALTER TABLE status_change_signature OWNER TO trust_revocation_owner;
REVOKE ALL ON status_change_challenge, status_change_signature FROM PUBLIC;

DO $fns$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'approve_certificate_status_change(uuid,text,text,text,smallint)',
        'issue_status_change_challenge(text,uuid,uuid,bytea,text,smallint,timestamp with time zone,text,text,integer)',
        'status_change_challenge_claim(uuid)',
        'officer_credential_for(uuid,bytea)',
        'propose_signed_status_change(uuid,bytea,bytea,bytea,bytea)',
        'approve_signed_status_change(uuid,bytea,bytea,bytea,bytea)',
        'status_change_signatures(uuid)',
        'status_change_propose_unchecked(uuid,uuid,bytea,text,smallint,timestamp with time zone,text,text)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'guard_signed_approvals_required()',
        'guard_status_change_challenge()',
        'guard_status_change_signature()',
        'claim_field(bytea)',
        'status_change_claim_digest(uuid,uuid,bytea,bytea,text,smallint,timestamp with time zone,text,bytea,timestamp with time zone)',
        'webauthn_precheck(bytea,bytea,bytea)',
        'signed_approvals_required(uuid)',
        'consume_signed_challenge(status_change_challenge,text,officer_credential,bytea,bytea,bytea)'] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO trust_revocation_owner', f);
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, public, pg_temp', f);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
END $fns$;

GRANT EXECUTE ON FUNCTION
    approve_certificate_status_change(uuid,text,text,text,smallint),
    issue_status_change_challenge(text,uuid,uuid,bytea,text,smallint,timestamp with time zone,text,text,integer),
    status_change_challenge_claim(uuid),
    officer_credential_for(uuid,bytea),
    propose_signed_status_change(uuid,bytea,bytea,bytea,bytea),
    approve_signed_status_change(uuid,bytea,bytea,bytea,bytea),
    status_change_signatures(uuid)
TO trust_revocation_officer_api;

SELECT acknowledge_schema_changes('0029_signed_status_changes');

COMMIT;
