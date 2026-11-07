-- Migration 0025: CA proposals and their issuer certificate (MVP criterion 6,
-- CA lifecycle, first slice; ADR-0013, Proposed). Laboratory only.
--
-- A CA administrator, holding an owner-managed platform grant, proposes a
-- root CA (PROPOSED), then registers its self-signed issuer certificate
-- (KEY_ATTESTED). The API parses and verifies the certificate before the
-- database records it; the database binds the stored bytes to their digest,
-- refuses a public key already used by another proposal, and records
-- lifecycle and audit events.
--
-- A proposal is NOT a CA: it has no row in the ca table, so no profile,
-- grant, issuance or read path can use it. Approval and activation (which
-- create the ca row) come in the next slice. The private key never reaches
-- the API or the database; custody is recorded as a laboratory software
-- file, which is a statement, not attestation.
BEGIN;

-- Owner-managed platform-wide grants, for actions not tied to an existing CA.
CREATE TABLE management_platform_grant (
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    platform_role TEXT NOT NULL CHECK (platform_role IN ('ca-administrator')),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (issuer, subject, platform_role)
);
REVOKE ALL ON management_platform_grant FROM PUBLIC;

-- One row per CA lifecycle operation; operation_id is the idempotency key.
CREATE TABLE ca_lifecycle_event (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL UNIQUE,
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    action TEXT NOT NULL CHECK (action IN ('ca.proposed', 'ca.certificate_registered')),
    ca_id UUID NOT NULL,
    actor_issuer TEXT NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 1024),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_lifecycle_event FROM PUBLIC;
CREATE TRIGGER immutable_ca_lifecycle_event
    BEFORE UPDATE OR DELETE ON ca_lifecycle_event
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The proposed CA. Its identifier is reserved now and becomes the ca row's
-- identifier on activation; it never collides with an existing CA.
CREATE TABLE ca_proposal (
    ca_id UUID PRIMARY KEY,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 255 AND display_name !~ '[[:cntrl:]]'),
    policy_version TEXT NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128 AND policy_version !~ '[[:cntrl:]]'),
    suite_id TEXT NOT NULL CHECK (suite_id ~ '^[a-z0-9][a-z0-9-]{2,63}$'),
    proposed_event_id UUID NOT NULL UNIQUE REFERENCES ca_lifecycle_event (event_id),
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_proposal FROM PUBLIC;
CREATE TRIGGER immutable_ca_proposal
    BEFORE UPDATE OR DELETE ON ca_proposal
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The verified issuer certificate of a proposal. One certificate per
-- proposal, and one public key per proposal across the platform.
CREATE TABLE ca_issuer_certificate (
    ca_id UUID PRIMARY KEY REFERENCES ca_proposal (ca_id),
    certificate_der BYTEA NOT NULL CHECK (octet_length(certificate_der) BETWEEN 64 AND 16384),
    certificate_sha256 BYTEA GENERATED ALWAYS AS (digest(certificate_der, 'sha256')) STORED,
    spki_sha256 BYTEA NOT NULL UNIQUE CHECK (octet_length(spki_sha256) = 32),
    subject_cn TEXT NOT NULL CHECK (length(subject_cn) BETWEEN 1 AND 255),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL CHECK (not_after > not_before),
    key_parameter TEXT NOT NULL CHECK (key_parameter IN ('p256')),
    custody TEXT NOT NULL CHECK (custody IN ('lab-software-file')),
    registered_event_id UUID NOT NULL UNIQUE REFERENCES ca_lifecycle_event (event_id),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_issuer_certificate FROM PUBLIC;
CREATE TRIGGER immutable_ca_issuer_certificate
    BEFORE UPDATE OR DELETE ON ca_issuer_certificate
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE FUNCTION ca_administrator_granted(p_issuer TEXT, p_subject TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT EXISTS (SELECT 1 FROM management_platform_grant g
                   WHERE g.issuer = p_issuer AND g.subject = p_subject AND g.platform_role = 'ca-administrator')
$fn$;
REVOKE ALL ON FUNCTION ca_administrator_granted(TEXT, TEXT) FROM PUBLIC;

-- Proposes a root CA. The API generates the identifier; the database
-- refuses one that names an existing CA or proposal. Errors: 42501
-- forbidden, TP409 conflict, 22023 or 23514 invalid input.
CREATE FUNCTION propose_ca_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_display_name TEXT, p_policy_version TEXT, p_suite TEXT,
    p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (ca_id UUID, proposed_at TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_event UUID;
    v_ca UUID;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid CA proposal parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_administrator_granted(p_issuer, p_subject) THEN
        RAISE EXCEPTION 'no ca-administrator grant' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca-proposal:' || p_operation::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'ca.proposed' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT p.ca_id,
                to_char(p.proposed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), true
                FROM ca_proposal p WHERE p.proposed_event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;
    -- The API passes NULL and the database draws the identifier.
    v_ca := coalesce(p_ca, gen_random_uuid());
    IF EXISTS (SELECT 1 FROM ca c WHERE c.ca_id = v_ca) OR EXISTS (SELECT 1 FROM ca_proposal p WHERE p.ca_id = v_ca) THEN
        RAISE EXCEPTION 'CA identifier already in use' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'ca.proposed', v_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca_proposal (ca_id, display_name, policy_version, suite_id, proposed_event_id)
    VALUES (v_ca, p_display_name, p_policy_version, p_suite, v_event);
    -- audit_event.ca_id references ca, which a proposal is not part of yet.
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, NULL, p_subject, 'ca.proposed', 'allow', p_policy_version);

    RETURN QUERY SELECT p.ca_id, to_char(p.proposed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), false
        FROM ca_proposal p WHERE p.ca_id = v_ca;
END
$fn$;
REVOKE ALL ON FUNCTION propose_ca_lab(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, UUID, BYTEA) FROM PUBLIC;

-- Records the issuer certificate the API verified: self-signed with the
-- proposal's suite, subject CN equal to the display name, currently valid.
-- The database re-checks what it can without parsing X.509: state, binding
-- of the facts to this proposal, digest of the stored bytes (returned to the
-- caller), key reuse across proposals and validity times.
CREATE FUNCTION register_ca_issuer_certificate_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_certificate_der BYTEA, p_spki_sha256 BYTEA,
    p_subject_cn TEXT, p_not_before TIMESTAMPTZ, p_not_after TIMESTAMPTZ, p_key_parameter TEXT,
    p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (state TEXT, certificate_sha256 BYTEA, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior ca_lifecycle_event%ROWTYPE;
    v_proposal ca_proposal%ROWTYPE;
    v_event UUID;
    v_expected_key TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_operation IS NULL OR p_certificate_der IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR p_spki_sha256 IS NULL OR octet_length(p_spki_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid certificate registration parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT ca_administrator_granted(p_issuer, p_subject) THEN
        RAISE EXCEPTION 'no ca-administrator grant' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('ca:' || p_ca::text, 0));

    SELECT * INTO v_prior FROM ca_lifecycle_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'ca.certificate_registered' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT 'KEY_ATTESTED'::text, c.certificate_sha256, true
                FROM ca_issuer_certificate c WHERE c.registered_event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_proposal FROM ca_proposal p WHERE p.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown CA proposal' USING ERRCODE = 'P0002';
    END IF;
    IF EXISTS (SELECT 1 FROM ca_issuer_certificate c WHERE c.ca_id = p_ca) THEN
        RAISE EXCEPTION 'the proposal already has an issuer certificate' USING ERRCODE = 'TP409';
    END IF;
    IF EXISTS (SELECT 1 FROM ca_issuer_certificate c WHERE c.spki_sha256 = p_spki_sha256) THEN
        RAISE EXCEPTION 'this public key is already registered for another CA' USING ERRCODE = 'TP409';
    END IF;
    -- The facts the API extracted must match the proposal it names.
    IF p_subject_cn IS DISTINCT FROM v_proposal.display_name THEN
        RAISE EXCEPTION 'certificate subject CN is not the proposed display name' USING ERRCODE = 'TP422';
    END IF;
    -- Only suites with a reviewed lab key type map to a key parameter; any other suite fails closed.
    v_expected_key := CASE v_proposal.suite_id WHEN 'ecdsa-p256-sha256' THEN 'p256' END;
    IF v_expected_key IS NULL OR p_key_parameter IS DISTINCT FROM v_expected_key THEN
        RAISE EXCEPTION 'certificate key does not match the proposed suite' USING ERRCODE = 'TP422';
    END IF;
    IF p_not_before IS NULL OR p_not_after IS NULL OR p_not_before > clock_timestamp() + interval '5 minutes'
       OR p_not_after <= clock_timestamp() THEN
        RAISE EXCEPTION 'certificate is not currently valid' USING ERRCODE = 'TP422';
    END IF;

    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'ca.certificate_registered', p_ca, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO ca_issuer_certificate (ca_id, certificate_der, spki_sha256, subject_cn, not_before, not_after,
                                       key_parameter, custody, registered_event_id)
    VALUES (p_ca, p_certificate_der, p_spki_sha256, p_subject_cn, p_not_before, p_not_after, p_key_parameter,
            'lab-software-file', v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, NULL, p_subject, 'ca.certificate_registered', 'allow', v_proposal.policy_version);

    RETURN QUERY SELECT 'KEY_ATTESTED'::text, c.certificate_sha256, false
        FROM ca_issuer_certificate c WHERE c.ca_id = p_ca;
END
$fn$;
REVOKE ALL ON FUNCTION register_ca_issuer_certificate_lab(TEXT, TEXT, UUID, BYTEA, BYTEA, TEXT, TIMESTAMPTZ,
    TIMESTAMPTZ, TEXT, UUID, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION propose_ca_lab(TEXT, TEXT, UUID, TEXT, TEXT, TEXT, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION register_ca_issuer_certificate_lab(TEXT, TEXT, UUID, BYTEA, BYTEA, TEXT, TIMESTAMPTZ,
    TIMESTAMPTZ, TEXT, UUID, BYTEA) TO trust_profile_writer;

-- CA administrators (the declared principal holds the platform grant) see
-- every proposal, its state and its certificate facts; others see none.
CREATE VIEW management_ca_proposal WITH (security_barrier = true) AS
SELECT p.ca_id::text AS ca_id, p.display_name, p.policy_version, p.suite_id,
       CASE WHEN c.ca_id IS NULL THEN 'PROPOSED' ELSE 'KEY_ATTESTED' END AS lifecycle_status,
       to_char(p.proposed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS proposed_at,
       encode(c.certificate_sha256, 'hex') AS certificate_sha256,
       encode(c.spki_sha256, 'hex') AS spki_sha256,
       to_char(c.not_before AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_before,
       to_char(c.not_after AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_after,
       c.custody,
       to_char(c.registered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS registered_at
FROM ca_proposal p
LEFT JOIN ca_issuer_certificate c ON c.ca_id = p.ca_id
WHERE EXISTS (
    SELECT 1 FROM management_platform_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.platform_role = 'ca-administrator'
);
GRANT SELECT ON management_ca_proposal TO trust_api_reader;

CREATE FUNCTION management_ca_proposal_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ca_proposal_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ca_proposal_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
