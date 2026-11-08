-- Migration 0031: public CRL publication (MVP criterion 8, second slice;
-- ADR-0019, Proposed). Laboratory only.
--
-- The database owner publishes a CA's CRLs by recording one base URL for it
-- (no API route writes it). From then on:
-- - certificates whose signing intent is journaled carry a CRL distribution
--   point <base>/v1/public/crls/<ca_id>/latest.crl, snapshotted with the
--   intent so the signer and the audit tool check the same URL;
-- - the API serves that CA's latest published CRL there without
--   authentication, through a view limited to CRLs of published CAs;
-- - readers of the CA see whether its CRL must be renewed (nextUpdate
--   within two days, or no CRL yet) or has expired.
BEGIN;

-- One base URL per CA, set once by the owner: http(s), a lowercase host and
-- an optional port; no credentials, path, query or fragment.
CREATE TABLE ca_crl_distribution_point (
    ca_id UUID PRIMARY KEY REFERENCES ca_activation (ca_id),
    base_url TEXT NOT NULL CHECK (length(base_url) <= 200
        AND base_url ~ '^https?://[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ca_crl_distribution_point FROM PUBLIC;
CREATE TRIGGER immutable_ca_crl_distribution_point
    BEFORE UPDATE OR DELETE ON ca_crl_distribution_point
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE FUNCTION crl_distribution_point_url(p_ca UUID) RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT d.base_url || '/v1/public/crls/' || d.ca_id::text || '/latest.crl'
    FROM ca_crl_distribution_point d WHERE d.ca_id = p_ca
$fn$;
REVOKE ALL ON FUNCTION crl_distribution_point_url(UUID) FROM PUBLIC;

-- The distribution point each journaled intent was recorded under.
CREATE TABLE signing_intent_crl_distribution_point (
    intent_id UUID PRIMARY KEY REFERENCES signing_intent (intent_id),
    url TEXT NOT NULL CHECK (length(url) BETWEEN 1 AND 300)
);
REVOKE ALL ON signing_intent_crl_distribution_point FROM PUBLIC;
CREATE TRIGGER immutable_signing_intent_crl_distribution_point
    BEFORE UPDATE OR DELETE ON signing_intent_crl_distribution_point
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- What the API puts in the TBS before journaling it. Same callers as
-- issuance (an officer, or the application's own requester).
CREATE FUNCTION application_crl_distribution_point_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID
) RETURNS TEXT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NOT certificate_issuance_permitted(p_issuer, p_subject, p_ca, p_application) THEN
        RAISE EXCEPTION 'no registration-officer grant, and not the requester' USING ERRCODE = '42501';
    END IF;
    RETURN crl_distribution_point_url(p_ca);
END
$fn$;
REVOKE ALL ON FUNCTION application_crl_distribution_point_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION application_crl_distribution_point_lab(TEXT, TEXT, UUID, UUID) TO trust_profile_writer;

-- Migration 0029's journal, unchanged except that it snapshots the
-- distribution point with a new intent.
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
    -- The distribution point in effect when the intent is journaled is the
    -- one the certificate must carry (migration 0031).
    IF NOT v_replay THEN
        INSERT INTO signing_intent_crl_distribution_point (intent_id, url)
        SELECT v_intent, crl_distribution_point_url(p_ca)
        WHERE crl_distribution_point_url(p_ca) IS NOT NULL;
    END IF;
    RETURN QUERY SELECT v_intent, v_replay;
END
$fn$;

-- The signer's view gains the snapshotted distribution point.
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
       dp.url AS crl_distribution_point
FROM signing_intent si
LEFT JOIN signing_intent_crl_distribution_point dp ON dp.intent_id = si.intent_id
JOIN certificate_application_issuance i ON i.ca_id = si.ca_id AND i.request_id = si.request_id
JOIN certificate_request r ON r.ca_id = si.ca_id AND r.request_id = si.request_id
JOIN serial_reservation s ON s.ca_id = si.ca_id AND s.request_id = si.request_id
JOIN certificate_application a ON a.application_id = i.application_id
JOIN ca_issuer_certificate c ON c.ca_id = si.ca_id;

-- The latest published CRL of each CA whose owner configured publication.
-- Deliberately not filtered on a reader principal: CRLs are public, and
-- this view exposes nothing else (no names, no applications).
CREATE VIEW public_crl_latest WITH (security_barrier = true) AS
SELECT d.ca_id::text AS ca_id, d.crl_number, d.crl_der
FROM crl_document d
WHERE EXISTS (SELECT 1 FROM ca_crl_distribution_point p WHERE p.ca_id = d.ca_id)
  AND d.crl_number = (SELECT max(l.crl_number) FROM crl_document l WHERE l.ca_id = d.ca_id);
GRANT SELECT ON public_crl_latest TO trust_api_reader;

-- Readers of the CA: where its CRL is published and whether it is due.
CREATE VIEW management_crl_status WITH (security_barrier = true) AS
SELECT c.ca_id::text AS ca_id,
       CASE WHEN p.ca_id IS NOT NULL
            THEN p.base_url || '/v1/public/crls/' || c.ca_id::text || '/latest.crl' END AS distribution_point,
       latest.crl_number AS latest_crl_number,
       to_char(latest.next_update AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_update,
       latest.crl_number IS NULL OR latest.next_update <= now() + interval '2 days' AS renewal_due,
       latest.crl_number IS NOT NULL AND latest.next_update <= now() AS expired
FROM ca_activation c
LEFT JOIN ca_crl_distribution_point p ON p.ca_id = c.ca_id
LEFT JOIN LATERAL (
    SELECT d.crl_number, i.next_update
    FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
    WHERE d.ca_id = c.ca_id ORDER BY d.crl_number DESC LIMIT 1
) latest ON true
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = c.ca_id
);
GRANT SELECT ON management_crl_status TO trust_api_reader;

CREATE FUNCTION management_crl_publication_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_crl_publication_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_crl_publication_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
