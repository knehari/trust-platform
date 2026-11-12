-- Migration 0048: short-lived certificates without revocation (ADR-0042,
-- Proposed).
--
-- The owner may mark a profile of a CA as short-lived, with a maximum
-- validity of 1 to 7 days. An application under such a profile:
-- - may not ask for a longer validity (TP422);
-- - is recorded as short-lived when it is submitted (a snapshot: a later
--   change of the policy affects new applications only);
-- - gets a certificate with the noRevAvail extension (id-ce-noRevAvail,
--   2.5.29.56, non-critical, NULL) and without a CRL distribution point;
-- - cannot be revoked (TP409): relying parties are told no revocation
--   information is available, so a revocation would not reach them; the
--   short validity is the control.
-- A void of an ambiguous issuance still lists the serial, as for any other
-- application (ADR-0020).
BEGIN;

CREATE TABLE profile_short_lived_policy (
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    profile_id TEXT NOT NULL CHECK (profile_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    max_validity_days INTEGER NOT NULL CHECK (max_validity_days BETWEEN 1 AND 7),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ca_id, profile_id)
);
REVOKE ALL ON profile_short_lived_policy FROM PUBLIC;

-- The applications submitted as short-lived, and their bound.
CREATE TABLE certificate_application_short_lived (
    application_id UUID PRIMARY KEY REFERENCES certificate_application (application_id),
    max_validity_days INTEGER NOT NULL CHECK (max_validity_days BETWEEN 1 AND 7)
);
REVOKE ALL ON certificate_application_short_lived FROM PUBLIC;
CREATE TRIGGER immutable_certificate_application_short_lived
    BEFORE UPDATE OR DELETE ON certificate_application_short_lived
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE FUNCTION certificate_application_short_lived_check() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_max INTEGER;
BEGIN
    SELECT p.max_validity_days INTO v_max FROM profile_short_lived_policy p
    WHERE p.ca_id = NEW.ca_id AND p.profile_id = NEW.profile_id;
    IF v_max IS NOT NULL AND NEW.validity_days > v_max THEN
        RAISE EXCEPTION 'the profile issues short-lived certificates of at most % days', v_max
            USING ERRCODE = 'TP422';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION certificate_application_short_lived_check() FROM PUBLIC;
CREATE TRIGGER certificate_application_short_lived_check
    BEFORE INSERT ON certificate_application
    FOR EACH ROW EXECUTE FUNCTION certificate_application_short_lived_check();

CREATE FUNCTION certificate_application_short_lived_record() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    INSERT INTO certificate_application_short_lived (application_id, max_validity_days)
    SELECT NEW.application_id, p.max_validity_days FROM profile_short_lived_policy p
    WHERE p.ca_id = NEW.ca_id AND p.profile_id = NEW.profile_id;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION certificate_application_short_lived_record() FROM PUBLIC;
CREATE TRIGGER certificate_application_short_lived_record
    AFTER INSERT ON certificate_application
    FOR EACH ROW EXECUTE FUNCTION certificate_application_short_lived_record();

-- A short-lived certificate is never revoked.
CREATE FUNCTION certificate_revocation_short_lived_refusal() RETURNS TRIGGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF EXISTS (SELECT 1 FROM certificate_application_short_lived s WHERE s.application_id = NEW.application_id) THEN
        RAISE EXCEPTION 'a short-lived certificate carries no revocation information and is not revoked'
            USING ERRCODE = 'TP409';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION certificate_revocation_short_lived_refusal() FROM PUBLIC;
CREATE TRIGGER certificate_revocation_short_lived_refusal
    BEFORE INSERT ON certificate_revocation_request
    FOR EACH ROW EXECUTE FUNCTION certificate_revocation_short_lived_refusal();

-- Whether an application is short-lived, for the API to build the TBS. Same
-- callers as issuance (an officer, or the application's own requester).
CREATE FUNCTION application_short_lived_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    RETURN EXISTS (SELECT 1 FROM certificate_application_short_lived s WHERE s.application_id = p_application);
END
$fn$;
REVOKE ALL ON FUNCTION application_short_lived_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION application_short_lived_lab(TEXT, TEXT, UUID, UUID) TO trust_profile_writer;

-- No distribution point for a short-lived application: in what the API puts
-- in the TBS, and in the intent's snapshot.
CREATE OR REPLACE FUNCTION application_crl_distribution_point_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    IF EXISTS (SELECT 1 FROM certificate_application_short_lived s WHERE s.application_id = p_application) THEN
        RETURN NULL;
    END IF;
    RETURN crl_distribution_point_url(p_ca);
END
$fn$;

-- Migration 0032's journal, unchanged except that a short-lived application
-- snapshots no distribution point.
CREATE OR REPLACE FUNCTION record_application_signing_intent_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_signer_key_ref TEXT, p_tbs_sha256 BYTEA
) RETURNS TABLE (intent_id UUID, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuance certificate_application_issuance%ROWTYPE;
    v_policy TEXT;
    v_intent UUID;
    v_replay BOOLEAN;
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
    SELECT c.intent_id, c.replay INTO v_intent, v_replay
        FROM create_signing_intent(p_ca, v_issuance.request_id, p_subject, p_signer_key_ref, p_tbs_sha256,
                                   v_policy, v_issuance.operation_ref) c;
    IF NOT v_replay AND NOT EXISTS (SELECT 1 FROM certificate_application_short_lived s
                                    WHERE s.application_id = p_application) THEN
        INSERT INTO signing_intent_crl_distribution_point (intent_id, url)
        SELECT v_intent, crl_distribution_point_url(p_ca)
        WHERE crl_distribution_point_url(p_ca) IS NOT NULL;
    END IF;
    RETURN QUERY SELECT v_intent, v_replay;
END
$fn$;

-- The signer's view gains the short-lived flag (appended).
CREATE OR REPLACE VIEW lab_signer_intent WITH (security_barrier = true) AS
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
       EXISTS (SELECT 1 FROM lab_signer_claim k WHERE k.intent_id = si.intent_id) AS claimed,
       dp.url AS crl_distribution_point,
       EXISTS (SELECT 1 FROM certificate_application_short_lived sl WHERE sl.application_id = a.application_id)
           AS no_rev_avail
FROM signing_intent si
LEFT JOIN signing_intent_crl_distribution_point dp ON dp.intent_id = si.intent_id
JOIN certificate_application_issuance i ON i.ca_id = si.ca_id AND i.request_id = si.request_id
JOIN certificate_request r ON r.ca_id = si.ca_id AND r.request_id = si.request_id
JOIN serial_reservation s ON s.ca_id = si.ca_id AND s.request_id = si.request_id
JOIN certificate_application a ON a.application_id = i.application_id
JOIN ca_issuer_certificate c ON c.ca_id = si.ca_id;

CREATE FUNCTION management_short_lived_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_short_lived_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_short_lived_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
