-- Migration 0030: signing approved certificate applications through the core
-- issuance state machine and a separate laboratory signer (MVP criterion 7,
-- second slice; ADR-0017, Proposed). Laboratory only.
--
-- The API (writer login) drives the core functions of 0002-0003 and 0015
-- through the wrappers below, which check the application, its CA and its
-- profile revision at every step:
--   begin   -> certificate_request (idempotency key = the application),
--              RECEIVED -> CSR_VALIDATED -> AUTHORIZED, serial reservation;
--   intent  -> the durable signing intent with the TBS digest, BEFORE signing;
--   store   -> the independently verified certificate, or
--   uncertain -> RECONCILIATION_REQUIRED, never a second signature.
--
-- The signer is a separate process and the only one that reads the CA key.
-- Its login (trust_lab_signer) can only read lab_signer_intent and claim an
-- intent once (claim_lab_signing_intent): the database refuses a second
-- claim, so a compromised API cannot get the same intent signed twice. The
-- signer re-verifies the CSR and checks the TBS against the application
-- before it claims and signs.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_lab_signer') THEN
        CREATE ROLE trust_lab_signer NOLOGIN;
    END IF;
END
$roles$;

ALTER TABLE certificate_application_event DROP CONSTRAINT certificate_application_event_action_check;
ALTER TABLE certificate_application_event ADD CONSTRAINT certificate_application_event_action_check
    CHECK (action IN ('application.submitted', 'application.approved', 'application.rejected',
                      'application.issuance_started'));

-- One issuance per application: the core request it created and the
-- operation reference its signing intent uses.
CREATE TABLE certificate_application_issuance (
    application_id UUID PRIMARY KEY REFERENCES certificate_application (application_id),
    ca_id UUID NOT NULL,
    request_id UUID NOT NULL UNIQUE,
    operation_ref TEXT NOT NULL UNIQUE CHECK (length(operation_ref) BETWEEN 1 AND 128),
    started_event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id),
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (ca_id, request_id) REFERENCES certificate_request (ca_id, request_id)
);
REVOKE ALL ON certificate_application_issuance FROM PUBLIC;
CREATE TRIGGER immutable_certificate_application_issuance
    BEFORE UPDATE OR DELETE ON certificate_application_issuance
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The signer's one claim per signing intent.
CREATE TABLE lab_signer_claim (
    intent_id UUID PRIMARY KEY REFERENCES signing_intent (intent_id),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON lab_signer_claim FROM PUBLIC;
CREATE TRIGGER immutable_lab_signer_claim
    BEFORE UPDATE OR DELETE ON lab_signer_claim
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- SUBMITTED, REJECTED, APPROVED, then ISSUING, ISSUED or
-- RECONCILIATION_REQUIRED once issuance started.
CREATE FUNCTION certificate_application_issuance_status(p_application UUID) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT CASE
        WHEN i.application_id IS NULL THEN certificate_application_status(p_application)
        WHEN r.state = 'SIGNED' THEN 'ISSUED'
        WHEN r.state = 'RECONCILIATION_REQUIRED' THEN 'RECONCILIATION_REQUIRED'
        ELSE 'ISSUING'
    END
    FROM (SELECT p_application AS application_id) a
    LEFT JOIN certificate_application_issuance i USING (application_id)
    LEFT JOIN certificate_request r ON r.ca_id = i.ca_id AND r.request_id = i.request_id
$fn$;
REVOKE ALL ON FUNCTION certificate_application_issuance_status(UUID) FROM PUBLIC;

-- Who may run issuance: a registration officer of the CA, or the
-- application's own requester while they hold the requester grant.
CREATE FUNCTION certificate_issuance_permitted(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID)
RETURNS BOOLEAN LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer')
        OR (certificate_role_granted(p_issuer, p_subject, p_ca, 'certificate-requester')
            AND EXISTS (SELECT 1 FROM certificate_application a
                        JOIN certificate_application_event e ON e.event_id = a.submitted_event_id
                        WHERE a.application_id = p_application
                          AND e.actor_issuer = p_issuer AND e.actor_subject = p_subject))
$fn$;
REVOKE ALL ON FUNCTION certificate_issuance_permitted(TEXT, TEXT, UUID, UUID) FROM PUBLIC;

-- The application must be APPROVED, its CA ACTIVE and its revision still the
-- profile's active one, at every step until the certificate is stored.
CREATE FUNCTION certificate_issuance_still_allowed(p_ca UUID, p_application UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT certificate_application_status(p_application) = 'APPROVED'
       AND certificate_ca_usable(p_ca)
       AND EXISTS (SELECT 1 FROM certificate_application a
                   JOIN certificate_profile_active p
                     ON p.ca_id = a.ca_id AND p.profile_id = a.profile_id AND p.revision = a.revision
                   WHERE a.application_id = p_application AND a.ca_id = p_ca)
$fn$;
REVOKE ALL ON FUNCTION certificate_issuance_still_allowed(UUID, UUID) FROM PUBLIC;

-- Starts (or returns) the issuance of an APPROVED application: the core
-- request, its authorized transitions and a reserved serial. Returns what
-- the API needs to build the TBS. Errors: 42501 forbidden, P0002 unknown,
-- TP409 not approved or the CA, revision or issuance state does not allow it.
CREATE FUNCTION begin_application_issuance_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (request_id UUID, request_state TEXT, serial BYTEA, operation_ref TEXT, policy_version TEXT,
                 csr_der BYTEA, subject_cn TEXT, dns_names TEXT[], validity_days INTEGER,
                 issuer_certificate_der BYTEA, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_application certificate_application%ROWTYPE;
    v_issuance certificate_application_issuance%ROWTYPE;
    v_policy TEXT;
    v_requester TEXT;
    v_request UUID;
    v_event UUID;
    v_replayed BOOLEAN := false;
BEGIN
    IF p_issuer IS NULL OR p_subject IS NULL OR p_ca IS NULL OR p_application IS NULL OR p_operation IS NULL
       OR p_request_sha256 IS NULL OR octet_length(p_request_sha256) <> 32
       OR length(p_subject) NOT BETWEEN 1 AND 256 OR length(p_issuer) NOT BETWEEN 1 AND 1024 THEN
        RAISE EXCEPTION 'invalid issuance parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));

    SELECT * INTO v_application FROM certificate_application a WHERE a.application_id = p_application AND a.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown certificate application' USING ERRCODE = 'P0002';
    END IF;
    SELECT * INTO v_issuance FROM certificate_application_issuance i WHERE i.application_id = p_application;
    IF FOUND THEN
        -- Started before: return the same request and serial, whatever the key.
        v_request := v_issuance.request_id;
        v_replayed := true;
    ELSE
        IF NOT certificate_issuance_still_allowed(p_ca, p_application) THEN
            RAISE EXCEPTION 'the application is not approved, or its CA or revision is no longer active'
                USING ERRCODE = 'TP409';
        END IF;
        SELECT d.policy_version INTO v_policy FROM certificate_profile_draft d
        WHERE d.ca_id = p_ca AND d.profile_id = v_application.profile_id AND d.revision = v_application.revision;
        SELECT e.actor_subject INTO v_requester FROM certificate_application_event e
        WHERE e.event_id = v_application.submitted_event_id;
        SELECT c.request_id INTO v_request
        FROM create_issuance_request(p_ca, 'application:' || p_application::text, v_application.csr_sha256,
                                     v_requester, v_policy) c;
        PERFORM transition_issuance_request(p_ca, v_request, 'RECEIVED', 'CSR_VALIDATED', p_subject);
        PERFORM transition_issuance_request(p_ca, v_request, 'CSR_VALIDATED', 'AUTHORIZED', p_subject);
        PERFORM reserve_issuance_serial(p_ca, v_request, p_subject);
        INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                                   actor_issuer, actor_subject)
        VALUES (p_operation, p_request_sha256, 'application.issuance_started', p_ca, p_application, p_issuer, p_subject)
        RETURNING event_id INTO v_event;
        INSERT INTO certificate_application_issuance (application_id, ca_id, request_id, operation_ref, started_event_id)
        VALUES (p_application, p_ca, v_request, 'application-issuance:' || p_application::text, v_event);
        INSERT INTO audit_event (event_id, ca_id, request_id, actor_id, event_type, decision, policy_version)
        VALUES (v_event, p_ca, v_request, p_subject, 'certificate.application.issuance_started', 'allow', v_policy);
    END IF;

    RETURN QUERY
    SELECT r.request_id, r.state, s.serial_der_content, i.operation_ref, r.policy_version,
           a.csr_der, a.subject_cn, a.dns_names, a.validity_days, c.certificate_der, v_replayed
    FROM certificate_application_issuance i
    JOIN certificate_request r ON r.ca_id = i.ca_id AND r.request_id = i.request_id
    JOIN serial_reservation s ON s.ca_id = i.ca_id AND s.request_id = i.request_id
    JOIN certificate_application a ON a.application_id = i.application_id
    JOIN ca_issuer_certificate c ON c.ca_id = i.ca_id
    WHERE i.application_id = p_application;
END
$fn$;
REVOKE ALL ON FUNCTION begin_application_issuance_lab(TEXT, TEXT, UUID, UUID, UUID, BYTEA) FROM PUBLIC;

-- Records the durable signing intent for the TBS the API built, BEFORE the
-- signer is called. A second call never permits a second signature: it
-- returns replayed = true, and the API must not sign.
CREATE FUNCTION record_application_signing_intent_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_signer_key_ref TEXT, p_tbs_sha256 BYTEA
) RETURNS TABLE (intent_id UUID, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuance certificate_application_issuance%ROWTYPE;
    v_policy TEXT;
BEGIN
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));
    SELECT * INTO v_issuance FROM certificate_application_issuance i
    WHERE i.application_id = p_application AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'issuance has not started' USING ERRCODE = 'P0002';
    END IF;
    IF EXISTS (SELECT 1 FROM signing_intent si WHERE si.ca_id = p_ca AND si.request_id = v_issuance.request_id) THEN
        RETURN QUERY SELECT si.intent_id, true FROM signing_intent si
            WHERE si.ca_id = p_ca AND si.request_id = v_issuance.request_id;
        RETURN;
    END IF;
    IF NOT certificate_issuance_still_allowed(p_ca, p_application) THEN
        RAISE EXCEPTION 'the application, its CA or its revision is no longer active' USING ERRCODE = 'TP409';
    END IF;
    SELECT r.policy_version INTO v_policy FROM certificate_request r
    WHERE r.ca_id = p_ca AND r.request_id = v_issuance.request_id;
    RETURN QUERY SELECT c.intent_id, c.replay
        FROM create_signing_intent(p_ca, v_issuance.request_id, p_subject, p_signer_key_ref, p_tbs_sha256,
                                   v_policy, v_issuance.operation_ref) c;
END
$fn$;
REVOKE ALL ON FUNCTION record_application_signing_intent_lab(TEXT, TEXT, UUID, UUID, TEXT, BYTEA) FROM PUBLIC;

-- Persists the certificate the API verified independently. The names and
-- CN the API extracted must be the application's.
CREATE FUNCTION store_application_certificate_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_tbs_sha256 BYTEA, p_certificate_der BYTEA,
    p_subject_cn TEXT, p_not_before TEXT, p_not_after TEXT, p_dns_names TEXT[]
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuance certificate_application_issuance%ROWTYPE;
    v_application certificate_application%ROWTYPE;
    v_serial BYTEA;
BEGIN
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended('application:' || p_application::text, 0));
    SELECT * INTO v_issuance FROM certificate_application_issuance i
    WHERE i.application_id = p_application AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'issuance has not started' USING ERRCODE = 'P0002';
    END IF;
    SELECT * INTO v_application FROM certificate_application a WHERE a.application_id = p_application;
    IF p_subject_cn IS DISTINCT FROM v_application.subject_cn OR p_dns_names IS DISTINCT FROM v_application.dns_names THEN
        RAISE EXCEPTION 'the certificate names are not the application''s' USING ERRCODE = 'TP422';
    END IF;
    SELECT s.serial_der_content INTO v_serial FROM serial_reservation s
    WHERE s.ca_id = p_ca AND s.request_id = v_issuance.request_id;
    RETURN store_signed_certificate(p_ca, v_issuance.request_id, p_subject, v_serial, p_tbs_sha256,
        digest(p_certificate_der, 'sha256'), p_certificate_der, p_subject_cn, p_not_before, p_not_after, p_dns_names);
END
$fn$;
REVOKE ALL ON FUNCTION store_application_certificate_lab(TEXT, TEXT, UUID, UUID, BYTEA, BYTEA, TEXT, TEXT, TEXT, TEXT[])
    FROM PUBLIC;

-- After a signer failure or timeout, or a certificate that does not verify:
-- the outcome is ambiguous and needs reconciliation, never a re-sign.
CREATE FUNCTION mark_application_signing_uncertain_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuance certificate_application_issuance%ROWTYPE;
BEGIN
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_issuance FROM certificate_application_issuance i
    WHERE i.application_id = p_application AND i.ca_id = p_ca;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'issuance has not started' USING ERRCODE = 'P0002';
    END IF;
    RETURN mark_signing_uncertain(p_ca, v_issuance.request_id, p_subject);
END
$fn$;
REVOKE ALL ON FUNCTION mark_application_signing_uncertain_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION begin_application_issuance_lab(TEXT, TEXT, UUID, UUID, UUID, BYTEA) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION record_application_signing_intent_lab(TEXT, TEXT, UUID, UUID, TEXT, BYTEA)
    TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION store_application_certificate_lab(TEXT, TEXT, UUID, UUID, BYTEA, BYTEA, TEXT, TEXT, TEXT,
    TEXT[]) TO trust_profile_writer;
GRANT EXECUTE ON FUNCTION mark_application_signing_uncertain_lab(TEXT, TEXT, UUID, UUID) TO trust_profile_writer;

-- What the signer may know about an intent: the application it serves (CSR,
-- names, validity), the reserved serial, the CA's registered certificate,
-- and whether everything still allows signing. Nothing else.
CREATE VIEW lab_signer_intent WITH (security_barrier = true) AS
SELECT si.intent_id::text AS intent_id, si.ca_id::text AS ca_id, si.tbs_sha256, si.operation_ref,
       s.serial_der_content AS serial, a.csr_der, a.spki_sha256, a.subject_cn, a.dns_names, a.validity_days,
       c.certificate_der AS issuer_certificate_der, c.spki_sha256 AS issuer_spki_sha256,
       -- Inlined: a view's functions run with the reader's privileges.
       si.outcome = 'UNCONFIRMED' AND r.state = 'SIGNING'
           AND EXISTS (SELECT 1 FROM certificate_application_decision d
                       WHERE d.application_id = a.application_id AND d.decision = 'approve')
           AND EXISTS (SELECT 1 FROM ca_operational_state o WHERE o.ca_id = a.ca_id AND o.state = 'ACTIVE')
           AND EXISTS (SELECT 1 FROM certificate_profile_active p
                       WHERE p.ca_id = a.ca_id AND p.profile_id = a.profile_id AND p.revision = a.revision)
           AS signable,
       EXISTS (SELECT 1 FROM lab_signer_claim k WHERE k.intent_id = si.intent_id) AS claimed
FROM signing_intent si
JOIN certificate_application_issuance i ON i.ca_id = si.ca_id AND i.request_id = si.request_id
JOIN certificate_request r ON r.ca_id = si.ca_id AND r.request_id = si.request_id
JOIN serial_reservation s ON s.ca_id = si.ca_id AND s.request_id = si.request_id
JOIN certificate_application a ON a.application_id = i.application_id
JOIN ca_issuer_certificate c ON c.ca_id = si.ca_id;
GRANT SELECT ON lab_signer_intent TO trust_lab_signer;

-- The signer's single write: claim an intent before signing it, once.
CREATE FUNCTION claim_lab_signing_intent(p_intent UUID, p_tbs_sha256 BYTEA) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_intent signing_intent%ROWTYPE;
    v_issuance certificate_application_issuance%ROWTYPE;
BEGIN
    SELECT * INTO v_intent FROM signing_intent si WHERE si.intent_id = p_intent FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown signing intent' USING ERRCODE = 'P0002';
    END IF;
    SELECT * INTO v_issuance FROM certificate_application_issuance i
    WHERE i.ca_id = v_intent.ca_id AND i.request_id = v_intent.request_id;
    IF NOT FOUND OR v_intent.tbs_sha256 IS DISTINCT FROM p_tbs_sha256 OR v_intent.outcome <> 'UNCONFIRMED'
       OR NOT certificate_issuance_still_allowed(v_issuance.ca_id, v_issuance.application_id) THEN
        RAISE EXCEPTION 'this intent cannot be signed' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO lab_signer_claim (intent_id) VALUES (p_intent);
    RETURN true;
EXCEPTION WHEN unique_violation THEN
    RAISE EXCEPTION 'this intent was already claimed by the signer' USING ERRCODE = 'TP409';
END
$fn$;
REVOKE ALL ON FUNCTION claim_lab_signing_intent(UUID, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_lab_signing_intent(UUID, BYTEA) TO trust_lab_signer;

-- Readers of the CA see the issuance state and the certificate it produced.
CREATE OR REPLACE VIEW management_certificate_application WITH (security_barrier = true) AS
SELECT a.application_id::text AS application_id, a.ca_id::text AS ca_id, a.profile_id, a.revision,
       encode(a.csr_sha256, 'hex') AS csr_sha256, a.subject_cn, a.dns_names, a.validity_days,
       CASE WHEN i.application_id IS NOT NULL THEN
                CASE r.state WHEN 'SIGNED' THEN 'ISSUED'
                             WHEN 'RECONCILIATION_REQUIRED' THEN 'RECONCILIATION_REQUIRED'
                             ELSE 'ISSUING' END
            WHEN d.decision = 'approve' THEN 'APPROVED' WHEN d.decision = 'reject' THEN 'REJECTED'
            ELSE 'SUBMITTED' END AS status,
       d.reason AS decision_reason,
       to_char(a.submitted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS submitted_at,
       to_char(d.decided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS decided_at,
       encode(cert.serial_der_content, 'hex') AS certificate_serial_hex,
       encode(cert.fingerprint_sha256, 'hex') AS certificate_sha256,
       cert.request_id::text AS certificate_request_id
FROM certificate_application a
LEFT JOIN certificate_application_decision d ON d.application_id = a.application_id
LEFT JOIN certificate_application_issuance i ON i.application_id = a.application_id
LEFT JOIN certificate_request r ON r.ca_id = i.ca_id AND r.request_id = i.request_id
LEFT JOIN certificate cert ON cert.ca_id = i.ca_id AND cert.request_id = i.request_id
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = a.ca_id
);

CREATE FUNCTION management_application_issuance_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_application_issuance_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_application_issuance_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
