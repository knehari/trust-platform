-- Migration 0038: the issuance channel for registration authorities in the
-- laboratory (ADR-0025, Proposed; boundary of ADR-0024).
--
-- A registered RA system (a light RA, or the CLM) has validated the
-- subscriber and the names. It submits a CSR in a request it signs with its
-- own P-256 key, and receives the certificate. The CA:
-- - does not repeat identity or domain checks;
-- - still applies its profile, as for any application (migration 0029);
-- - signs once, through the journaled path of migration 0030.
--
-- The database owner registers each RA system and its public key, and grants
-- it the profiles it may request per CA. The RA's principal is
-- (urn:trust-platform:ra, ra_id). It holds the certificate-requester role of
-- that CA, and is the requester of record.
--
-- The RA's signed request is its registration decision. The application is
-- submitted and approved in one transaction, with the RA as decider. The
-- separation of duties of migration 0029 applies between people; here the RA
-- system is accountable, through its signature, which is stored with the
-- exact signed bytes.
--
-- PostgreSQL does not verify ECDSA. The API verifies the signature before
-- calling submit_ra_issuance_lab, and lab_verify_issued_certificates
-- verifies every stored request again with the registered key.
BEGIN;

CREATE TABLE ra_system (
    ra_id TEXT PRIMARY KEY CHECK (ra_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200 AND display_name !~ '[[:cntrl:]]'),
    -- Uncompressed SEC1 P-256 point.
    public_key_sec1 BYTEA NOT NULL UNIQUE
        CHECK (octet_length(public_key_sec1) = 65 AND get_byte(public_key_sec1, 0) = 4),
    enabled BOOLEAN NOT NULL DEFAULT true,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON ra_system FROM PUBLIC;

-- The profiles an RA may request, per CA. The owner grants them.
CREATE TABLE ra_profile_grant (
    ra_id TEXT NOT NULL REFERENCES ra_system (ra_id),
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    profile_id TEXT NOT NULL,
    PRIMARY KEY (ra_id, ca_id, profile_id)
);
REVOKE ALL ON ra_profile_grant FROM PUBLIC;

-- Each accepted request: the exact bytes the RA signed, and its signature.
CREATE TABLE ra_issuance_request (
    ra_id TEXT NOT NULL REFERENCES ra_system (ra_id),
    request_id UUID NOT NULL,
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    application_id UUID NOT NULL UNIQUE REFERENCES certificate_application (application_id),
    message BYTEA NOT NULL CHECK (octet_length(message) BETWEEN 64 AND 16384),
    signature BYTEA NOT NULL CHECK (octet_length(signature) BETWEEN 8 AND 72),
    signed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ra_id, request_id)
);
REVOKE ALL ON ra_issuance_request FROM PUBLIC;
CREATE TRIGGER immutable_ra_issuance_request
    BEFORE UPDATE OR DELETE ON ra_issuance_request
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The signed bytes, version 1: the same as
-- trust_pki_core::ra_request::ra_issuance_message.
CREATE FUNCTION ra_issuance_message(
    p_ra TEXT, p_ca UUID, p_profile TEXT, p_request UUID, p_csr_sha256 BYTEA, p_dns_names TEXT[],
    p_validity_days INTEGER, p_signed_at_unix BIGINT
) RETURNS BYTEA
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $fn$
    SELECT convert_to('trust-platform:ra-issuance-request:v1', 'UTF8') || '\x00'::bytea
        || int4send(octet_length(convert_to(p_ra, 'UTF8'))) || convert_to(p_ra, 'UTF8')
        || uuid_send(p_ca)
        || int4send(octet_length(convert_to(p_profile, 'UTF8'))) || convert_to(p_profile, 'UTF8')
        || uuid_send(p_request)
        || p_csr_sha256
        || int4send(cardinality(p_dns_names))
        || coalesce((SELECT string_agg(int4send(octet_length(convert_to(n, 'UTF8'))) || convert_to(n, 'UTF8'),
                                       '' ORDER BY i)
                     FROM unnest(p_dns_names) WITH ORDINALITY AS t(n, i)), '\x'::bytea)
        || int4send(p_validity_days)
        || int8send(p_signed_at_unix)
$fn$;
REVOKE ALL ON FUNCTION ra_issuance_message(TEXT, UUID, TEXT, UUID, BYTEA, TEXT[], INTEGER, BIGINT) FROM PUBLIC;

-- The public key of an enabled RA system, or nothing.
CREATE FUNCTION ra_system_key_lab(p_ra TEXT) RETURNS BYTEA
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT r.public_key_sec1 FROM ra_system r WHERE r.ra_id = p_ra AND r.enabled
$fn$;
REVOKE ALL ON FUNCTION ra_system_key_lab(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ra_system_key_lab(TEXT) TO trust_profile_writer;

-- Records an RA's signed request: the application, submitted under the
-- profile's rules and approved by the RA, in one transaction. Replaying the
-- same signed bytes returns the same application. Errors: 42501 RA unknown,
-- disabled or not granted; TP409 the request id was used for other bytes;
-- TP422 stale or out of policy (and those of submit_certificate_application_lab).
CREATE FUNCTION submit_ra_issuance_lab(
    p_ra TEXT, p_ca UUID, p_profile TEXT, p_request UUID, p_csr_der BYTEA, p_spki_sha256 BYTEA,
    p_subject_cn TEXT, p_dns_names TEXT[], p_validity_days INTEGER, p_signed_at_unix BIGINT,
    p_signature BYTEA
) RETURNS TABLE (application_id UUID, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuer CONSTANT TEXT := 'urn:trust-platform:ra';
    v_message BYTEA;
    v_prior ra_issuance_request%ROWTYPE;
    v_application UUID;
    v_event UUID;
BEGIN
    IF p_ra IS NULL OR p_ca IS NULL OR p_profile IS NULL OR p_request IS NULL OR p_csr_der IS NULL
       OR p_dns_names IS NULL OR p_validity_days IS NULL OR p_signed_at_unix IS NULL
       OR p_signature IS NULL OR octet_length(p_signature) NOT BETWEEN 8 AND 72 THEN
        RAISE EXCEPTION 'invalid RA issuance parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM ra_system r WHERE r.ra_id = p_ra AND r.enabled)
       OR NOT EXISTS (SELECT 1 FROM ra_profile_grant g
                      WHERE g.ra_id = p_ra AND g.ca_id = p_ca AND g.profile_id = p_profile) THEN
        RAISE EXCEPTION 'unknown or disabled RA, or profile not granted' USING ERRCODE = '42501';
    END IF;
    v_message := ra_issuance_message(p_ra, p_ca, p_profile, p_request, sha256(p_csr_der), p_dns_names,
                                     p_validity_days, p_signed_at_unix);
    PERFORM pg_advisory_xact_lock(hashtextextended('ra-request:' || p_ra || ':' || p_request::text, 0));

    SELECT * INTO v_prior FROM ra_issuance_request r WHERE r.ra_id = p_ra AND r.request_id = p_request;
    IF FOUND THEN
        IF v_prior.message = v_message AND v_prior.ca_id = p_ca THEN
            RETURN QUERY SELECT v_prior.application_id, true;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request id already used for another request' USING ERRCODE = 'TP409';
    END IF;
    -- A narrow window: a captured request cannot be replayed under a new id.
    IF abs(extract(epoch FROM clock_timestamp()) - p_signed_at_unix) > 300 THEN
        RAISE EXCEPTION 'the request is not fresh' USING ERRCODE = 'TP422';
    END IF;

    -- The profile's rules, exactly as for any application.
    SELECT s.application_id INTO v_application
    FROM submit_certificate_application_lab(v_issuer, p_ra, p_ca, p_profile, p_csr_der, p_spki_sha256,
                                            p_subject_cn, p_dns_names, p_validity_days, p_request,
                                            sha256(v_message)) s;
    -- The RA's signed request is its registration decision.
    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), sha256(v_message), 'application.approved', p_ca, v_application, v_issuer, p_ra)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_application_decision (application_id, decision, reason, event_id)
    VALUES (v_application, 'approve', 'registered by RA ' || p_ra, v_event);
    INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
    SELECT v_event, p_ca, p_ra, 'certificate.application.approved', 'allow', d.policy_version
    FROM certificate_application a
    JOIN certificate_profile_draft d ON d.ca_id = a.ca_id AND d.profile_id = a.profile_id AND d.revision = a.revision
    WHERE a.application_id = v_application;
    INSERT INTO ra_issuance_request (ra_id, request_id, ca_id, application_id, message, signature, signed_at)
    VALUES (p_ra, p_request, p_ca, v_application, v_message, p_signature, to_timestamp(p_signed_at_unix));

    RETURN QUERY SELECT v_application, false;
END
$fn$;
REVOKE ALL ON FUNCTION submit_ra_issuance_lab(TEXT, UUID, TEXT, UUID, BYTEA, BYTEA, TEXT, TEXT[], INTEGER, BIGINT,
    BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION submit_ra_issuance_lab(TEXT, UUID, TEXT, UUID, BYTEA, BYTEA, TEXT, TEXT[], INTEGER, BIGINT,
    BYTEA) TO trust_profile_writer;

-- The certificate issued for an RA's request, for an idempotent replay.
CREATE FUNCTION ra_issued_certificate_lab(p_ra TEXT, p_request UUID) RETURNS BYTEA
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT c.certificate_der
    FROM ra_issuance_request r
    JOIN certificate_application_issuance i ON i.application_id = r.application_id
    JOIN certificate c ON c.ca_id = i.ca_id AND c.request_id = i.request_id
    WHERE r.ra_id = p_ra AND r.request_id = p_request
$fn$;
REVOKE ALL ON FUNCTION ra_issued_certificate_lab(TEXT, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ra_issued_certificate_lab(TEXT, UUID) TO trust_profile_writer;

CREATE FUNCTION management_ra_channel_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ra_channel_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ra_channel_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
