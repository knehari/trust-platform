-- Migration 0026: signed two-person approval of a CA proposal, and its
-- activation (MVP criterion 6, CA lifecycle, second slice; ADR-0014,
-- Proposed). Laboratory only.
--
-- Two separately authenticated CA approvers, each holding an owner-managed
-- ca-approver platform grant and their own registered P-256 key, sign the
-- exact claim the database builds for a KEY_ATTESTED proposal. Neither may
-- be the proposer or the registrant of the certificate, the two approvals
-- must use different keys, and a CA approver key can never also be a
-- profile approver key. One rejection is final.
--
-- A CA administrator who did not decide on the proposal then activates the
-- APPROVED proposal by naming its certificate digest. Activation creates the
-- ca row, and declares the proposal's suite as the CA's signing capability.
-- From then on, the CA's capabilities can only be its attested suite, so
-- profile activation (0024) checks the attested key instead of an owner
-- statement. The API verifies the stored certificate again before commit.
--
-- PostgreSQL does not verify ECDSA or X.509. The API verifies inside the
-- recording transaction and rolls back on failure; the stored claims,
-- signatures, keys and certificates let lab_verify_ca_lifecycle check every
-- decision and certificate again. Suspension and retirement come later; no
-- issuance path uses the new CA.
BEGIN;

ALTER TABLE management_platform_grant DROP CONSTRAINT management_platform_grant_platform_role_check;
ALTER TABLE management_platform_grant ADD CONSTRAINT management_platform_grant_platform_role_check
    CHECK (platform_role IN ('ca-administrator', 'ca-approver'));

ALTER TABLE ca_lifecycle_event DROP CONSTRAINT ca_lifecycle_event_action_check;
ALTER TABLE ca_lifecycle_event ADD CONSTRAINT ca_lifecycle_event_action_check
    CHECK (action IN ('ca.proposed', 'ca.certificate_registered', 'ca.approval', 'ca.rejection', 'ca.activation'));

-- Owner-registered CA approver keys, as profile_approver_key (0023): one
-- active uncompressed P-256 point per approver, never registered twice,
-- append-only with a single revocation.
CREATE TABLE ca_approver_key (
    key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    public_key_sec1 BYTEA NOT NULL UNIQUE
        CHECK (octet_length(public_key_sec1) = 65 AND get_byte(public_key_sec1, 0) = 4),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ CHECK (revoked_at IS NULL OR revoked_at >= registered_at)
);
CREATE UNIQUE INDEX ca_approver_key_one_active ON ca_approver_key (issuer, subject) WHERE revoked_at IS NULL;
REVOKE ALL ON ca_approver_key FROM PUBLIC;
CREATE TRIGGER ca_approver_key_append_only
    BEFORE UPDATE OR DELETE ON ca_approver_key
    FOR EACH ROW EXECUTE FUNCTION profile_approver_key_guard();

-- A point approves either profiles or CAs, never both: two powers, two keys.
-- Both tables take the same lock, so concurrent registrations cannot race.
CREATE FUNCTION approver_point_single_power() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended('approver-points', 0));
    IF (TG_TABLE_NAME = 'ca_approver_key'
        AND EXISTS (SELECT 1 FROM profile_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1))
       OR (TG_TABLE_NAME = 'profile_approver_key'
        AND EXISTS (SELECT 1 FROM ca_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)) THEN
        RAISE EXCEPTION 'this key is already registered for the other approval power' USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION approver_point_single_power() FROM PUBLIC;
CREATE TRIGGER ca_approver_key_single_power BEFORE INSERT ON ca_approver_key
    FOR EACH ROW EXECUTE FUNCTION approver_point_single_power();
CREATE TRIGGER profile_approver_key_single_power BEFORE INSERT ON profile_approver_key
    FOR EACH ROW EXECUTE FUNCTION approver_point_single_power();

CREATE TABLE ca_decision (
    ca_id UUID NOT NULL REFERENCES ca_issuer_certificate (ca_id),
    approver_issuer TEXT NOT NULL,
    approver_subject TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    key_id TEXT NOT NULL REFERENCES ca_approver_key (key_id),
    public_key_sec1 BYTEA NOT NULL,
    claim TEXT NOT NULL CHECK (length(claim) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    claim_issued_at TIMESTAMPTZ NOT NULL,
    event_id UUID NOT NULL UNIQUE REFERENCES ca_lifecycle_event (event_id),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ca_id, approver_issuer, approver_subject),
    UNIQUE (ca_id, public_key_sec1)
);
REVOKE ALL ON ca_decision FROM PUBLIC;
CREATE TRIGGER immutable_ca_decision
    BEFORE UPDATE OR DELETE ON ca_decision
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The activation of a proposal. Its ca_id is also the new ca row's.
CREATE TABLE ca_activation (
    ca_id UUID PRIMARY KEY REFERENCES ca_issuer_certificate (ca_id),
    event_id UUID NOT NULL UNIQUE REFERENCES ca_lifecycle_event (event_id),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_activation FROM PUBLIC;
CREATE TRIGGER immutable_ca_activation
    BEFORE UPDATE OR DELETE ON ca_activation
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- An activated CA can only declare its attested suite: profile activation
-- then checks the key the approvers approved, not an owner statement.
CREATE FUNCTION ca_signing_capability_attested() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF EXISTS (SELECT 1 FROM ca_activation a WHERE a.ca_id = NEW.ca_id)
       AND NOT EXISTS (SELECT 1 FROM ca_proposal p WHERE p.ca_id = NEW.ca_id AND p.suite_id = NEW.suite_id) THEN
        RAISE EXCEPTION 'an activated CA can only sign with its attested suite' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION ca_signing_capability_attested() FROM PUBLIC;
CREATE TRIGGER ca_signing_capability_attested BEFORE INSERT ON ca_signing_capability
    FOR EACH ROW EXECUTE FUNCTION ca_signing_capability_attested();

CREATE FUNCTION ca_platform_granted(p_issuer TEXT, p_subject TEXT, p_role TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT EXISTS (SELECT 1 FROM management_platform_grant g
                   WHERE g.issuer = p_issuer AND g.subject = p_subject AND g.platform_role = p_role)
$fn$;
REVOKE ALL ON FUNCTION ca_platform_granted(TEXT, TEXT, TEXT) FROM PUBLIC;

-- PROPOSED → KEY_ATTESTED → APPROVED (two approvals) or REJECTED (one
-- rejection) → ACTIVE.
CREATE FUNCTION ca_lifecycle_status(p_ca UUID) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE
        WHEN NOT EXISTS (SELECT 1 FROM ca_proposal p WHERE p.ca_id = p_ca) THEN NULL
        WHEN EXISTS (SELECT 1 FROM ca_activation a WHERE a.ca_id = p_ca) THEN 'ACTIVE'
        WHEN EXISTS (SELECT 1 FROM ca_decision d WHERE d.ca_id = p_ca AND d.decision = 'reject') THEN 'REJECTED'
        WHEN (SELECT count(*) FROM ca_decision d WHERE d.ca_id = p_ca AND d.decision = 'approve') >= 2 THEN 'APPROVED'
        WHEN EXISTS (SELECT 1 FROM ca_issuer_certificate c WHERE c.ca_id = p_ca) THEN 'KEY_ATTESTED'
        ELSE 'PROPOSED'
    END
$fn$;
REVOKE ALL ON FUNCTION ca_lifecycle_status(UUID) FROM PUBLIC;

-- The exact text a CA approver signs: one line, fields in a fixed order.
-- Identities with ';' or control characters are refused, so the line has
-- one parse. It binds the exact certificate and key, not the display name.
CREATE FUNCTION ca_decision_claim(
    p_decision TEXT, p_ca UUID, p_certificate_sha256 BYTEA, p_spki_sha256 BYTEA, p_registration_event UUID,
    p_issuer TEXT, p_subject TEXT, p_key_id TEXT, p_issued_at TIMESTAMPTZ
) RETURNS TEXT LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
    SELECT concat_ws(';',
        'trust-platform/ca-decision/v1',
        'decision=' || p_decision,
        'ca_id=' || p_ca::text,
        'certificate_sha256=' || encode(p_certificate_sha256, 'hex'),
        'spki_sha256=' || encode(p_spki_sha256, 'hex'),
        'registration_event_id=' || p_registration_event::text,
        'approver_issuer=' || p_issuer,
        'approver_subject=' || p_subject,
        'key_id=' || p_key_id,
        'issued_at=' || to_char(p_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
$fn$;
REVOKE ALL ON FUNCTION ca_decision_claim(TEXT, UUID, BYTEA, BYTEA, UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- Checks shared by preparing and recording a decision.
CREATE FUNCTION ca_decision_context(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_decision TEXT, p_issued_at TIMESTAMPTZ
) RETURNS TABLE (claim TEXT, key_id TEXT, public_key_sec1 BYTEA, policy_version TEXT)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_certificate ca_issuer_certificate%ROWTYPE;
    v_key ca_approver_key%ROWTYPE;
    v_status TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_decision IS NULL
       OR p_decision NOT IN ('approve', 'reject') OR p_issued_at IS NULL
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024
       OR p_issuer ~ '[;[:cntrl:]]' OR p_subject ~ '[;[:cntrl:]]' THEN
        RAISE EXCEPTION 'invalid CA decision parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_platform_granted(p_issuer, p_subject, 'ca-approver') THEN
        RAISE EXCEPTION 'no ca-approver grant' USING ERRCODE = '42501';
    END IF;
    v_status := ca_lifecycle_status(p_ca);
    IF v_status IS NULL THEN
        RAISE EXCEPTION 'unknown CA proposal' USING ERRCODE = 'P0002';
    END IF;
    IF v_status <> 'KEY_ATTESTED' THEN
        RAISE EXCEPTION 'only a key-attested, undecided proposal can be decided' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM ca_decision d
               WHERE d.ca_id = p_ca AND d.approver_issuer = p_issuer AND d.approver_subject = p_subject) THEN
        RAISE EXCEPTION 'this approver already decided on the proposal' USING ERRCODE = 'TP409';
    END IF;
    -- Separation of duties: the proposer and the registrant cannot decide.
    IF EXISTS (SELECT 1 FROM ca_lifecycle_event e
               WHERE e.ca_id = p_ca AND e.action IN ('ca.proposed', 'ca.certificate_registered')
                 AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject) THEN
        RAISE EXCEPTION 'the proposer or registrant of a CA cannot decide on it' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_key FROM ca_approver_key k
    WHERE k.issuer = p_issuer AND k.subject = p_subject AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no active CA approver key' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_certificate FROM ca_issuer_certificate c WHERE c.ca_id = p_ca;
    IF v_certificate.not_after <= clock_timestamp() THEN
        RAISE EXCEPTION 'the issuer certificate has expired' USING ERRCODE = 'TP422';
    END IF;
    RETURN QUERY SELECT
        ca_decision_claim(p_decision, p_ca, v_certificate.certificate_sha256, v_certificate.spki_sha256,
                          v_certificate.registered_event_id, p_issuer, p_subject, v_key.key_id, p_issued_at),
        v_key.key_id, v_key.public_key_sec1,
        (SELECT p.policy_version FROM ca_proposal p WHERE p.ca_id = p_ca);
END
$fn$;
REVOKE ALL ON FUNCTION ca_decision_context(TEXT, TEXT, UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- Returns the claim to sign now. Records nothing.
CREATE FUNCTION prepare_ca_decision_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_decision TEXT)
RETURNS TABLE (claim TEXT, key_id TEXT, issued_at TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_now TIMESTAMPTZ := date_trunc('milliseconds', clock_timestamp());
BEGIN
    RETURN QUERY SELECT c.claim, c.key_id, to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        FROM ca_decision_context(p_issuer, p_subject, p_ca, p_decision, v_now) c;
END
$fn$;
REVOKE ALL ON FUNCTION prepare_ca_decision_lab(TEXT, TEXT, UUID, TEXT) FROM PUBLIC;

-- Records a decision whose claim was issued less than ten minutes ago. The
-- API verifies the returned signature over the returned claim with the
-- returned key in the same transaction, and rolls back when it fails.
CREATE FUNCTION record_ca_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_decision TEXT, p_issued_at TIMESTAMPTZ,
    p_signature_der BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (claim TEXT, public_key_sec1 BYTEA, signature_der BYTEA, lifecycle_status TEXT,
                 approval_count INTEGER, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_context RECORD;
    v_event UUID;
    v_now TIMESTAMPTZ := clock_timestamp();
    v_action TEXT := CASE p_decision WHEN 'approve' THEN 'ca.approval' ELSE 'ca.rejection' END;
BEGIN
    IF p_ca IS NULL OR p_operation IS NULL OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80 THEN
        RAISE EXCEPTION 'invalid CA decision parameters' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca:' || p_ca::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = v_action AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT d.claim, d.public_key_sec1, d.signature_der, ca_lifecycle_status(p_ca),
                (SELECT count(*)::integer FROM ca_decision y WHERE y.ca_id = p_ca AND y.decision = 'approve'), true
                FROM ca_decision d WHERE d.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    IF p_issued_at IS NULL OR p_issued_at > v_now + interval '5 seconds'
       OR p_issued_at < v_now - interval '10 minutes' THEN
        RAISE EXCEPTION 'decision claim expired or not yet valid' USING ERRCODE = 'TP409';
    END IF;
    SELECT * INTO v_context FROM ca_decision_context(p_issuer, p_subject, p_ca, p_decision, p_issued_at);

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, v_action, p_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca_decision (ca_id, approver_issuer, approver_subject, decision, key_id, public_key_sec1, claim,
                             signature_der, claim_issued_at, event_id)
    VALUES (p_ca, p_issuer, p_subject, p_decision, v_context.key_id, v_context.public_key_sec1, v_context.claim,
            p_signature_der, p_issued_at, v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, NULL, p_subject, v_action, 'allow', v_context.policy_version);

    RETURN QUERY SELECT v_context.claim, v_context.public_key_sec1, p_signature_der, ca_lifecycle_status(p_ca),
        (SELECT count(*)::integer FROM ca_decision y WHERE y.ca_id = p_ca AND y.decision = 'approve'), false;
END
$fn$;
REVOKE ALL ON FUNCTION record_ca_decision_lab(TEXT, TEXT, UUID, TEXT, TIMESTAMPTZ, BYTEA, UUID, BYTEA) FROM PUBLIC;

-- Activates an APPROVED proposal: creates the ca row and its attested
-- capability. Returns the stored certificate, which the API verifies again
-- before commit. Errors: 42501 forbidden, P0002 unknown, TP409 state or
-- digest conflict, TP422 expired certificate.
CREATE FUNCTION activate_ca_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_certificate_sha256 BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (lifecycle_status TEXT, suite_id TEXT, certificate_der BYTEA, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_proposal ca_proposal%ROWTYPE;
    v_certificate ca_issuer_certificate%ROWTYPE;
    v_event UUID;
    v_status TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR p_certificate_sha256 IS NULL OR octet_length(p_certificate_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid CA activation parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_platform_granted(p_issuer, p_subject, 'ca-administrator') THEN
        RAISE EXCEPTION 'no ca-administrator grant' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca:' || p_ca::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'ca.activation' AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT ca_lifecycle_status(p_ca), p.suite_id, c.certificate_der, true
                FROM ca_proposal p JOIN ca_issuer_certificate c ON c.ca_id = p.ca_id WHERE p.ca_id = p_ca;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    v_status := ca_lifecycle_status(p_ca);
    IF v_status IS NULL THEN
        RAISE EXCEPTION 'unknown CA proposal' USING ERRCODE = 'P0002';
    END IF;
    -- Separation of duties: no one activates a CA they decided on.
    IF EXISTS (SELECT 1 FROM ca_decision d
               WHERE d.ca_id = p_ca AND d.approver_issuer = p_issuer AND d.approver_subject = p_subject) THEN
        RAISE EXCEPTION 'an approver of a CA cannot activate it' USING ERRCODE = '42501';
    END IF;
    IF v_status <> 'APPROVED' THEN
        RAISE EXCEPTION 'only an approved, never activated proposal can be activated' USING ERRCODE = 'TP409';
    END IF;
    SELECT * INTO v_certificate FROM ca_issuer_certificate c WHERE c.ca_id = p_ca;
    IF v_certificate.certificate_sha256 IS DISTINCT FROM p_certificate_sha256 THEN
        RAISE EXCEPTION 'certificate digest does not match the approved certificate' USING ERRCODE = 'TP409';
    END IF;
    IF v_certificate.not_after <= clock_timestamp() THEN
        RAISE EXCEPTION 'the issuer certificate has expired' USING ERRCODE = 'TP422';
    END IF;
    IF EXISTS (SELECT 1 FROM ca c WHERE c.ca_id = p_ca) THEN
        RAISE EXCEPTION 'a CA with this identifier already exists' USING ERRCODE = 'TP409';
    END IF;
    SELECT * INTO v_proposal FROM ca_proposal p WHERE p.ca_id = p_ca;

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'ca.activation', p_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca (ca_id, display_name, policy_version)
    VALUES (p_ca, v_proposal.display_name, v_proposal.policy_version);
    INSERT INTO ca_activation (ca_id, event_id) VALUES (p_ca, v_event);
    INSERT INTO ca_signing_capability (ca_id, suite_id) VALUES (p_ca, v_proposal.suite_id);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'ca.activation', 'allow', v_proposal.policy_version);

    RETURN QUERY SELECT 'ACTIVE'::text, v_proposal.suite_id, v_certificate.certificate_der, false;
END
$fn$;
REVOKE ALL ON FUNCTION activate_ca_lab(TEXT, TEXT, UUID, BYTEA, UUID, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION prepare_ca_decision_lab(TEXT, TEXT, UUID, TEXT) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION record_ca_decision_lab(TEXT, TEXT, UUID, TEXT, TIMESTAMPTZ, BYTEA, UUID, BYTEA)
    TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION activate_ca_lab(TEXT, TEXT, UUID, BYTEA, UUID, BYTEA) TO trust_profile_writer;

-- Administrators and approvers see every proposal, its state, the number of
-- approvals and the times; approver identities, claims and signatures stay
-- owner-only. The status logic is inlined (a view's functions run with the
-- reader's privileges). New columns are appended.
CREATE OR REPLACE VIEW management_ca_proposal WITH (security_barrier = true) AS
SELECT p.ca_id::text AS ca_id, p.display_name, p.policy_version, p.suite_id,
       CASE WHEN a.ca_id IS NOT NULL THEN 'ACTIVE'
            WHEN x.rejections > 0 THEN 'REJECTED'
            WHEN x.approvals >= 2 THEN 'APPROVED'
            WHEN c.ca_id IS NOT NULL THEN 'KEY_ATTESTED'
            ELSE 'PROPOSED' END AS lifecycle_status,
       to_char(p.proposed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS proposed_at,
       encode(c.certificate_sha256, 'hex') AS certificate_sha256,
       encode(c.spki_sha256, 'hex') AS spki_sha256,
       to_char(c.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_before,
       to_char(c.not_after AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_after,
       c.custody,
       to_char(c.registered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS registered_at,
       x.approvals AS approval_count,
       CASE WHEN x.rejections > 0 OR x.approvals >= 2
            THEN to_char(x.last_decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') END AS decided_at,
       to_char(a.activated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS activated_at
FROM ca_proposal p
LEFT JOIN ca_issuer_certificate c ON c.ca_id = p.ca_id
LEFT JOIN ca_activation a ON a.ca_id = p.ca_id
CROSS JOIN LATERAL (
    SELECT count(*) FILTER (WHERE d.decision = 'approve')::integer AS approvals,
           count(*) FILTER (WHERE d.decision = 'reject')::integer AS rejections,
           max(d.decided_at) AS last_decided_at
    FROM ca_decision d WHERE d.ca_id = p.ca_id
) x
WHERE EXISTS (
    SELECT 1 FROM management_platform_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.platform_role IN ('ca-administrator', 'ca-approver')
);

CREATE FUNCTION management_ca_activation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ca_activation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ca_activation_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
