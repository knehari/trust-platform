-- Migration 0039: revocation through the RA channel in the laboratory
-- (ADR-0026, Proposed; follows ADR-0025).
--
-- A registered RA system revokes a certificate it obtained through the
-- channel (migration 0038), with a request it signs. That request is both the
-- revocation request and its approval, as the RA's issuance request was both
-- the application and its registration decision. The RA is accountable
-- through its stored signature. The rules of migration 0031 still hold:
-- - a reason code from the closed list;
-- - an issued certificate, not already revoked, with no open request;
-- - a publishing CA;
-- - the core revocation instant taken under the CA's CRL lock.
--
-- The revocation appears on the next CRL; publishing it stays the officers'
-- or the renewer's (ADR-0018, ADR-0021).
--
-- PostgreSQL does not verify ECDSA. The API verifies the signature first,
-- and lab_verify_issued_certificates verifies every stored request again.
BEGIN;

CREATE TABLE ra_revocation_request (
    ra_id TEXT NOT NULL REFERENCES ra_system (ra_id),
    request_id UUID NOT NULL,
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    revocation_id UUID NOT NULL UNIQUE REFERENCES certificate_revocation_request (revocation_id),
    message BYTEA NOT NULL CHECK (octet_length(message) BETWEEN 64 AND 4096),
    signature BYTEA NOT NULL CHECK (octet_length(signature) BETWEEN 8 AND 72),
    signed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (ra_id, request_id)
);
REVOKE ALL ON ra_revocation_request FROM PUBLIC;
CREATE TRIGGER immutable_ra_revocation_request
    BEFORE UPDATE OR DELETE ON ra_revocation_request
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The signed bytes, version 1: the same as
-- trust_pki_core::ra_request::ra_revocation_message.
CREATE FUNCTION ra_revocation_message(
    p_ra TEXT, p_ca UUID, p_request UUID, p_serial BYTEA, p_reason_code SMALLINT, p_reason TEXT,
    p_signed_at_unix BIGINT
) RETURNS BYTEA
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $fn$
    SELECT convert_to('trust-platform:ra-revocation-request:v1', 'UTF8') || '\x00'::bytea
        || int4send(octet_length(convert_to(p_ra, 'UTF8'))) || convert_to(p_ra, 'UTF8')
        || uuid_send(p_ca)
        || uuid_send(p_request)
        || int4send(octet_length(p_serial)) || p_serial
        || int2send(p_reason_code)
        || int4send(octet_length(convert_to(p_reason, 'UTF8'))) || convert_to(p_reason, 'UTF8')
        || int8send(p_signed_at_unix)
$fn$;
REVOKE ALL ON FUNCTION ra_revocation_message(TEXT, UUID, UUID, BYTEA, SMALLINT, TEXT, BIGINT) FROM PUBLIC;

-- Records an RA's signed revocation of a certificate it obtained, and
-- revokes it. Replaying the same signed bytes returns the same revocation.
-- Errors:
-- - 42501: RA unknown or disabled;
-- - P0002: no certificate this RA obtained with that serial;
-- - TP409: request id used for other bytes, already revoked, request open,
--   or CA retired;
-- - TP422: stale;
-- - 22023: invalid parameters or reason code.
CREATE FUNCTION submit_ra_revocation_lab(
    p_ra TEXT, p_ca UUID, p_request UUID, p_serial BYTEA, p_reason_code SMALLINT, p_reason TEXT,
    p_signed_at_unix BIGINT, p_signature BYTEA
) RETURNS TABLE (revocation_id UUID, revoked_at TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_issuer CONSTANT TEXT := 'urn:trust-platform:ra';
    v_message BYTEA;
    v_prior ra_revocation_request%ROWTYPE;
    v_application UUID;
    v_core_request UUID;
    v_revocation UUID;
    v_event UUID;
BEGIN
    IF p_ra IS NULL OR p_ca IS NULL OR p_request IS NULL OR p_serial IS NULL
       OR octet_length(p_serial) NOT BETWEEN 1 AND 20 OR p_reason_code IS NULL
       OR NOT certificate_revocation_reason_allowed(p_reason_code) OR p_reason IS NULL
       OR length(p_reason) NOT BETWEEN 1 AND 500 OR p_reason ~ '[[:cntrl:]]'
       OR p_signed_at_unix IS NULL OR p_signature IS NULL OR octet_length(p_signature) NOT BETWEEN 8 AND 72 THEN
        RAISE EXCEPTION 'invalid RA revocation parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM ra_system r WHERE r.ra_id = p_ra AND r.enabled) THEN
        RAISE EXCEPTION 'unknown or disabled RA' USING ERRCODE = '42501';
    END IF;
    v_message := ra_revocation_message(p_ra, p_ca, p_request, p_serial, p_reason_code, p_reason, p_signed_at_unix);
    PERFORM pg_advisory_xact_lock(hashtextextended('ra-revocation:' || p_ra || ':' || p_request::text, 0));

    SELECT * INTO v_prior FROM ra_revocation_request r WHERE r.ra_id = p_ra AND r.request_id = p_request;
    IF FOUND THEN
        IF v_prior.message = v_message AND v_prior.ca_id = p_ca THEN
            RETURN QUERY
            SELECT v_prior.revocation_id,
                   to_char(x.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), true
            FROM revocation x WHERE x.ca_id = p_ca AND x.serial_der_content = p_serial;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request id already used for another request' USING ERRCODE = 'TP409';
    END IF;
    IF abs(extract(epoch FROM clock_timestamp()) - p_signed_at_unix) > 300 THEN
        RAISE EXCEPTION 'the request is not fresh' USING ERRCODE = 'TP422';
    END IF;

    -- Only a certificate this RA obtained through the channel.
    SELECT i.application_id, i.request_id INTO v_application, v_core_request
    FROM ra_issuance_request q
    JOIN certificate_application_issuance i ON i.application_id = q.application_id
    JOIN certificate c ON c.ca_id = i.ca_id AND c.request_id = i.request_id
    WHERE q.ra_id = p_ra AND q.ca_id = p_ca AND c.serial_der_content = p_serial;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no certificate this RA obtained has this serial' USING ERRCODE = 'P0002';
    END IF;

    -- The request, under the rules of migration 0031 (the RA is the
    -- requester of record).
    SELECT r.revocation_id INTO v_revocation
    FROM request_certificate_revocation_lab(v_issuer, p_ra, p_ca, v_application, p_reason_code, p_reason,
                                            p_request, sha256(v_message)) r;
    -- The RA's signed request is also its approval.
    IF NOT certificate_ca_publishes(p_ca) THEN
        RAISE EXCEPTION 'the CA is retired' USING ERRCODE = 'TP409';
    END IF;
    INSERT INTO certificate_application_event (operation_id, request_sha256, action, ca_id, application_id,
                                               actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), sha256(v_message), 'revocation.approved', p_ca, v_application, v_issuer, p_ra)
    RETURNING event_id INTO v_event;
    INSERT INTO certificate_revocation_decision (revocation_id, decision, reason, decided_event_id)
    VALUES (v_revocation, 'approve', 'revoked by RA ' || p_ra, v_event);
    PERFORM crl_lock(p_ca);
    -- The instant is taken under the CRL lock, as in migration 0031.
    INSERT INTO revocation (ca_id, serial_der_content, reason_code, revoked_at, actor_id)
    VALUES (p_ca, p_serial, p_reason_code, clock_timestamp(), p_ra);
    INSERT INTO audit_event (event_id, ca_id, request_id, actor_id, event_type, decision)
    VALUES (v_event, p_ca, v_core_request, p_ra, 'certificate.revoked', 'allow');
    INSERT INTO ra_revocation_request (ra_id, request_id, ca_id, revocation_id, message, signature, signed_at)
    VALUES (p_ra, p_request, p_ca, v_revocation, v_message, p_signature, to_timestamp(p_signed_at_unix));

    RETURN QUERY
    SELECT v_revocation, to_char(x.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), false
    FROM revocation x WHERE x.ca_id = p_ca AND x.serial_der_content = p_serial;
END
$fn$;
REVOKE ALL ON FUNCTION submit_ra_revocation_lab(TEXT, UUID, UUID, BYTEA, SMALLINT, TEXT, BIGINT, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION submit_ra_revocation_lab(TEXT, UUID, UUID, BYTEA, SMALLINT, TEXT, BIGINT, BYTEA)
    TO trust_profile_writer;

CREATE FUNCTION management_ra_revocation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ra_revocation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ra_revocation_version() TO trust_api_reader, trust_profile_writer;

COMMIT;
