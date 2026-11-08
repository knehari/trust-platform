-- Migration 0029: certificate applications and their registration decision
-- (MVP criterion 7, application issuance, first slice; ADR-0016, Proposed).
-- Laboratory only. NOTHING HERE SIGNS: an APPROVED application is the input
-- of the signing slice, which will hand it to the core issuance state machine
-- (certificate_request, 0001-0003). No certificate exists because of this.
--
-- A requester, with a certificate-requester grant for the CA, submits a
-- PKCS#10 CSR for the CA's ACTIVE revision of a profile. The API verifies the
-- CSR (DER, proof of possession, P-256, subject CN) and passes its facts; the
-- database binds the application to the active revision and checks the
-- requested names and validity against it. The CA must be a lifecycle-managed
-- ACTIVE CA (0027-0028). A registration officer, with a registration-officer
-- grant and who is not the requester, then approves or rejects the exact
-- application. The CSR's own extensions and names are never used: the names
-- are those the requester asked for and the profile allows.
BEGIN;

ALTER TABLE management_role_grant DROP CONSTRAINT management_role_grant_lifecycle_role_check;
ALTER TABLE management_role_grant ADD CONSTRAINT management_role_grant_lifecycle_role_check
    CHECK (lifecycle_role IN ('profile-editor', 'policy-approver', 'ca-operator',
                              'certificate-requester', 'registration-officer'));

CREATE TABLE certificate_application_event (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operation_id UUID NOT NULL UNIQUE,
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    action TEXT NOT NULL CHECK (action IN ('application.submitted', 'application.approved', 'application.rejected')),
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    application_id UUID NOT NULL,
    actor_issuer TEXT NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 1024),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 256),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON certificate_application_event FROM PUBLIC;
CREATE TRIGGER immutable_certificate_application_event
    BEFORE UPDATE OR DELETE ON certificate_application_event
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- A lowercase LDH DNS name of at least two labels, no wildcard.
CREATE FUNCTION certificate_dns_name_valid(p_name TEXT) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
    SELECT p_name IS NOT NULL AND length(p_name) BETWEEN 3 AND 253
       AND p_name ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
$fn$;

-- Whether a name is a zone itself or inside it (label boundary).
CREATE FUNCTION certificate_name_in_zone(p_name TEXT, p_zone TEXT) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$
    SELECT p_name = lower(p_zone) OR right(p_name, length(p_zone) + 1) = '.' || lower(p_zone)
$fn$;

CREATE TABLE certificate_application (
    application_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    profile_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    csr_der BYTEA NOT NULL CHECK (octet_length(csr_der) BETWEEN 64 AND 16384),
    csr_sha256 BYTEA GENERATED ALWAYS AS (digest(csr_der, 'sha256')) STORED,
    spki_sha256 BYTEA NOT NULL CHECK (octet_length(spki_sha256) = 32),
    subject_cn TEXT NOT NULL,
    dns_names TEXT[] NOT NULL CHECK (cardinality(dns_names) BETWEEN 1 AND 100),
    validity_days INTEGER NOT NULL CHECK (validity_days BETWEEN 1 AND 825),
    submitted_event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id),
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (subject_cn = ANY (dns_names)),
    FOREIGN KEY (ca_id, profile_id, revision)
        REFERENCES certificate_profile_submission (ca_id, profile_id, revision)
);
REVOKE ALL ON certificate_application FROM PUBLIC;
CREATE TRIGGER immutable_certificate_application
    BEFORE UPDATE OR DELETE ON certificate_application
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TABLE certificate_application_decision (
    application_id UUID PRIMARY KEY REFERENCES certificate_application (application_id),
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500 AND reason !~ '[[:cntrl:]]'),
    event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON certificate_application_decision FROM PUBLIC;
CREATE TRIGGER immutable_certificate_application_decision
    BEFORE UPDATE OR DELETE ON certificate_application_decision
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE FUNCTION certificate_role_granted(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_role TEXT) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT EXISTS (SELECT 1 FROM management_role_grant g
                   WHERE g.issuer = p_issuer AND g.subject = p_subject AND g.ca_id = p_ca
                     AND g.lifecycle_role = p_role)
$fn$;
REVOKE ALL ON FUNCTION certificate_role_granted(TEXT, TEXT, UUID, TEXT) FROM PUBLIC;

-- The CA can be applied to: lifecycle-managed (an attested key) and ACTIVE.
CREATE FUNCTION certificate_ca_usable(p_ca UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT EXISTS (SELECT 1 FROM ca_operational_state s WHERE s.ca_id = p_ca AND s.state = 'ACTIVE')
$fn$;
REVOKE ALL ON FUNCTION certificate_ca_usable(UUID) FROM PUBLIC;

-- Submits an application against the ACTIVE revision of a profile. The API
-- verified the CSR and passes its SPKI digest and subject CN. Errors: 42501
-- forbidden, P0002 unknown profile, TP409 conflict, TP422 the CA, profile or
-- request is not acceptable, 22023/23514 invalid input.
CREATE FUNCTION submit_certificate_application_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_profile TEXT, p_csr_der BYTEA, p_spki_sha256 BYTEA,
    p_subject_cn TEXT, p_dns_names TEXT[], p_validity_days INTEGER, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (application_id UUID, revision INTEGER, status TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
    v_revision INTEGER;
    v_draft certificate_profile_draft%ROWTYPE;
    v_event UUID;
    v_application UUID := gen_random_uuid();
    v_outside TEXT;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_profile IS NULL OR p_csr_der IS NULL
       OR p_spki_sha256 IS NULL OR octet_length(p_spki_sha256) <> 32 OR p_subject_cn IS NULL
       OR p_dns_names IS NULL OR p_validity_days IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid certificate application parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'certificate-requester') THEN
        RAISE EXCEPTION 'no certificate-requester grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('application-op:' || p_operation::text, 0));

    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'application.submitted' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT a.application_id, a.revision, certificate_application_status(a.application_id), true
                FROM certificate_application a WHERE a.submitted_event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    IF NOT certificate_ca_usable(p_ca) THEN
        RAISE EXCEPTION 'the CA is not an ACTIVE lifecycle-managed CA' USING ERRCODE = 'TP422';
    END IF;
    SELECT a.revision INTO v_revision FROM certificate_profile_active a WHERE a.ca_id = p_ca AND a.profile_id = p_profile;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the profile has no active revision for this CA' USING ERRCODE = 'P0002';
    END IF;
    SELECT * INTO v_draft FROM certificate_profile_draft d
    WHERE d.ca_id = p_ca AND d.profile_id = p_profile AND d.revision = v_revision;

    -- The names and validity the profile allows. The subject key may not be
    -- the CA's own key.
    IF cardinality(p_dns_names) < 1 OR cardinality(p_dns_names) > v_draft.max_dns_sans
       OR cardinality(p_dns_names) <> (SELECT count(DISTINCT n) FROM unnest(p_dns_names) n)
       OR EXISTS (SELECT 1 FROM unnest(p_dns_names) n WHERE NOT certificate_dns_name_valid(n)) THEN
        RAISE EXCEPTION 'the DNS names are invalid, repeated or too many for the profile' USING ERRCODE = 'TP422';
    END IF;
    SELECT string_agg(n, ', ') INTO v_outside FROM unnest(p_dns_names) n
    WHERE NOT EXISTS (SELECT 1 FROM unnest(v_draft.proposed_dns_zones) z WHERE certificate_name_in_zone(n, z));
    IF v_outside IS NOT NULL THEN
        RAISE EXCEPTION 'DNS names outside the profile zones: %', v_outside USING ERRCODE = 'TP422';
    END IF;
    IF NOT (p_subject_cn = ANY (p_dns_names)) THEN
        RAISE EXCEPTION 'the subject CN must be one of the DNS names' USING ERRCODE = 'TP422';
    END IF;
    IF p_validity_days < 1 OR p_validity_days > v_draft.max_validity_days THEN
        RAISE EXCEPTION 'the validity exceeds the profile' USING ERRCODE = 'TP422';
    END IF;
    IF EXISTS (SELECT 1 FROM ca_issuer_certificate c WHERE c.ca_id = p_ca AND c.spki_sha256 = p_spki_sha256) THEN
        RAISE EXCEPTION 'the subject key is the CA key' USING ERRCODE = 'TP422';
    END IF;

    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, 'application.submitted', p_ca, v_application, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_application (application_id, ca_id, profile_id, revision, csr_der, spki_sha256, subject_cn,
                                         dns_names, validity_days, submitted_event_id)
    VALUES (v_application, p_ca, p_profile, v_revision, p_csr_der, p_spki_sha256, p_subject_cn, p_dns_names,
            p_validity_days, v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, 'certificate.application.submitted', 'allow', v_draft.policy_version);

    RETURN QUERY SELECT v_application, v_revision, 'SUBMITTED'::text, false;
END
$fn$;

-- SUBMITTED → APPROVED or REJECTED.
CREATE FUNCTION certificate_application_status(p_application UUID) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE (SELECT d.decision FROM certificate_application_decision d WHERE d.application_id = p_application)
        WHEN 'approve' THEN 'APPROVED' WHEN 'reject' THEN 'REJECTED' ELSE 'SUBMITTED' END
$fn$;
REVOKE ALL ON FUNCTION certificate_application_status(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION submit_certificate_application_lab(TEXT, TEXT, UUID, TEXT, BYTEA, BYTEA, TEXT, TEXT[], INTEGER,
    UUID, BYTEA) FROM PUBLIC;

-- Approves or rejects a SUBMITTED application. Approval also requires the CA
-- to be ACTIVE and the application's revision to be still the active one.
CREATE FUNCTION decide_certificate_application_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_decision TEXT, p_reason TEXT,
    p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (status TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
    v_application certificate_application%ROWTYPE;
    v_event UUID;
    v_action TEXT := CASE p_decision WHEN 'approve' THEN 'application.approved' ELSE 'application.rejected' END;
    v_audit TEXT := CASE p_decision WHEN 'approve' THEN 'certificate.application.approved'
                                    ELSE 'certificate.application.rejected' END;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_application IS NULL OR p_reason IS NULL
       OR p_decision IS NULL OR p_decision NOT IN ('approve', 'reject') OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid certificate application decision parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));

    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = v_action AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.application_id = p_application
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT certificate_application_status(p_application), true;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;

    SELECT * INTO v_application FROM certificate_application a WHERE a.application_id = p_application AND a.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown certificate application' USING ERRCODE = 'P0002';
    END IF;
    -- Separation of duties: the requester cannot decide on their application.
    IF EXISTS (SELECT 1 FROM certificate_application_event e
               WHERE e.event_id = v_application.submitted_event_id
                 AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject) THEN
        RAISE EXCEPTION 'the requester cannot decide on their application' USING ERRCODE = '42501';
    END IF;
    IF certificate_application_status(p_application) <> 'SUBMITTED' THEN
        RAISE EXCEPTION 'the application was already decided' USING ERRCODE = 'TP409';
    END IF;
    IF p_decision = 'approve' AND (
        NOT certificate_ca_usable(p_ca)
        OR NOT EXISTS (SELECT 1 FROM certificate_profile_active a
                       WHERE a.ca_id = p_ca AND a.profile_id = v_application.profile_id
                         AND a.revision = v_application.revision)) THEN
        RAISE EXCEPTION 'the CA or the profile revision is no longer active' USING ERRCODE = 'TP409';
    END IF;

    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (p_operation, p_request_sha256, v_action, p_ca, p_application, p_issuer, p_subject)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_application_decision (application_id, decision, reason, event_id)
    VALUES (p_application, p_decision, p_reason, v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    VALUES (v_event, p_ca, p_subject, v_audit, CASE p_decision WHEN 'approve' THEN 'allow' ELSE 'deny' END,
            (SELECT d.policy_version FROM certificate_profile_draft d
             WHERE d.ca_id = p_ca AND d.profile_id = v_application.profile_id AND d.revision = v_application.revision));

    RETURN QUERY SELECT certificate_application_status(p_application), false;
END
$fn$;
REVOKE ALL ON FUNCTION decide_certificate_application_lab(TEXT, TEXT, UUID, UUID, TEXT, TEXT, UUID, BYTEA) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION submit_certificate_application_lab(TEXT, TEXT, UUID, TEXT, BYTEA, BYTEA, TEXT, TEXT[],
    INTEGER, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION decide_certificate_application_lab(TEXT, TEXT, UUID, UUID, TEXT, TEXT, UUID, BYTEA)
    TO trust_profile_writer;

-- Readers of a CA see its applications and their status; requester and
-- officer identities stay owner-only, as actor identities do elsewhere.
CREATE VIEW management_certificate_application WITH (security_barrier = true) AS
SELECT a.application_id::text AS application_id, a.ca_id::text AS ca_id, a.profile_id, a.revision,
       encode(a.csr_sha256, 'hex') AS csr_sha256, a.subject_cn, a.dns_names, a.validity_days,
       CASE d.decision WHEN 'approve' THEN 'APPROVED' WHEN 'reject' THEN 'REJECTED' ELSE 'SUBMITTED' END AS status,
       d.reason AS decision_reason,
       to_char(a.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS submitted_at,
       to_char(d.decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS decided_at
FROM certificate_application a
LEFT JOIN certificate_application_decision d ON d.application_id = a.application_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = a.ca_id
);
GRANT SELECT ON management_certificate_application TO trust_api_reader;

CREATE FUNCTION management_certificate_application_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_certificate_application_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_certificate_application_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
