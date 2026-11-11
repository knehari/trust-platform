-- Migration 0041: authorization proofs the laboratory signer verifies before
-- it signs (ADR-0028, Proposed).
--
-- Until now the signer trusted the database's "APPROVED" state, which the API
-- writes with its writer login. The functions take the acting identity as a
-- parameter, so a compromised API could approve and issue in any officer's
-- name.
--
-- From now on, every issuance carries a proof signed by a key the API cannot
-- register: the database owner registers it. A proof is one of:
-- - a registered RA system's signed request (migration 0038), in version 1, or
--   in version 2 below;
-- - a registration officer's signed decision over a claim the database builds
--   from the stored application, as for profile and CA decisions (migrations
--   0023 and 0027).
--
-- The signer rebuilds the signed bytes from the application facts and checks
-- the signature with the registered key; PostgreSQL verifies no ECDSA.
--
-- The RA keeps the right to set the certificate's subject, correcting the
-- CSR's, and to add optional extensions from a closed catalogue that the
-- profile allows (version 2 requests). The CA ignores the CSR's subject and
-- extensions; the signature binds what will be issued.
BEGIN;

-- Registration officers' public keys, registered by the database owner. One
-- active key per officer; a key never doubles as an approver's or an RA's.
CREATE TABLE registration_officer_key (
    key_id TEXT PRIMARY KEY CHECK (key_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 1024),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    public_key_sec1 BYTEA NOT NULL UNIQUE
        CHECK (octet_length(public_key_sec1) = 65 AND get_byte(public_key_sec1, 0) = 4),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    revoked_at TIMESTAMPTZ CHECK (revoked_at IS NULL OR revoked_at >= registered_at)
);
CREATE UNIQUE INDEX registration_officer_key_one_active
    ON registration_officer_key (issuer, subject) WHERE revoked_at IS NULL;
REVOKE ALL ON registration_officer_key FROM PUBLIC;
-- The same append-only rule as approver keys: only one revocation.
CREATE TRIGGER registration_officer_key_append_only
    BEFORE UPDATE OR DELETE ON registration_officer_key
    FOR EACH ROW EXECUTE FUNCTION profile_approver_key_guard();

CREATE FUNCTION registration_officer_key_single_power() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF EXISTS (SELECT 1 FROM profile_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM ca_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM ra_system r WHERE r.public_key_sec1 = NEW.public_key_sec1) THEN
        RAISE EXCEPTION 'this key already approves profiles or CAs, or belongs to an RA';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION registration_officer_key_single_power() FROM PUBLIC;
CREATE TRIGGER registration_officer_key_single_power BEFORE INSERT ON registration_officer_key
    FOR EACH ROW EXECUTE FUNCTION registration_officer_key_single_power();

-- The optional extensions a profile allows, per CA, from the closed catalogue
-- of trust_pki_core::application_leaf::OPTIONAL_EXTENSIONS. The owner sets it.
CREATE TABLE profile_optional_extension (
    ca_id UUID NOT NULL REFERENCES ca (ca_id),
    profile_id TEXT NOT NULL,
    extension TEXT NOT NULL CHECK (extension IN ('client-auth')),
    PRIMARY KEY (ca_id, profile_id, extension)
);
REVOKE ALL ON profile_optional_extension FROM PUBLIC;

-- The optional extensions an application asks for, in catalogue order. No
-- row means none. Append-only, like the application.
CREATE TABLE certificate_application_option (
    application_id UUID PRIMARY KEY REFERENCES certificate_application (application_id),
    optional_extensions TEXT[] NOT NULL
        CHECK (cardinality(optional_extensions) BETWEEN 1 AND 1
               AND optional_extensions <@ ARRAY['client-auth'])
);
REVOKE ALL ON certificate_application_option FROM PUBLIC;
CREATE TRIGGER immutable_certificate_application_option
    BEFORE UPDATE OR DELETE ON certificate_application_option
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE FUNCTION certificate_application_extensions(p_application UUID) RETURNS TEXT[]
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT coalesce((SELECT o.optional_extensions FROM certificate_application_option o
                     WHERE o.application_id = p_application), '{}')
$fn$;
REVOKE ALL ON FUNCTION certificate_application_extensions(UUID) FROM PUBLIC;

-- Officers' signed decisions: the claim, the key and the signature.
CREATE TABLE certificate_application_authorization (
    application_id UUID PRIMARY KEY REFERENCES certificate_application (application_id),
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    key_id TEXT NOT NULL REFERENCES registration_officer_key (key_id),
    public_key_sec1 BYTEA NOT NULL,
    claim TEXT NOT NULL CHECK (length(claim) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    claim_issued_at TIMESTAMPTZ NOT NULL,
    event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id)
);
REVOKE ALL ON certificate_application_authorization FROM PUBLIC;
CREATE TRIGGER immutable_certificate_application_authorization
    BEFORE UPDATE OR DELETE ON certificate_application_authorization
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The claim text, version 1: the same as
-- trust_pki_core::authorization::officer_decision_claim.
CREATE FUNCTION certificate_decision_claim(p_decision TEXT, p_application UUID, p_key_id TEXT, p_issued_at TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT 'trust-platform/issuance-authorization/v1;decision=' || p_decision
        || ';ca=' || a.ca_id::text || ';application=' || a.application_id::text
        || ';profile=' || a.profile_id || ';revision=' || a.revision
        || ';csr_sha256=' || encode(sha256(a.csr_der), 'hex')
        || ';subject_cn=' || a.subject_cn || ';dns_names=' || array_to_string(a.dns_names, ',')
        || ';validity_days=' || a.validity_days
        || ';extensions=' || array_to_string(certificate_application_extensions(a.application_id), ',')
        || ';key=' || p_key_id
        || ';issued_at=' || to_char(p_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
    FROM certificate_application a WHERE a.application_id = p_application
$fn$;
REVOKE ALL ON FUNCTION certificate_decision_claim(TEXT, UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- The officer's active key and the claim for this decision. Errors: 42501 no
-- registration-officer grant or no registered key, P0002 unknown application.
CREATE FUNCTION certificate_decision_context(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_decision TEXT, p_issued_at TIMESTAMPTZ
) RETURNS TABLE (claim TEXT, key_id TEXT, public_key_sec1 BYTEA)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_key registration_officer_key%ROWTYPE;
BEGIN
    IF p_decision IS NULL OR p_decision NOT IN ('approve', 'reject') THEN
        RAISE EXCEPTION 'invalid decision' USING ERRCODE = '22023';
    END IF;
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_key FROM registration_officer_key k
    WHERE k.issuer = p_issuer AND k.subject = p_subject AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no registered officer key' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM certificate_application a WHERE a.application_id = p_application AND a.ca_id = p_ca) THEN
        RAISE EXCEPTION 'unknown certificate application' USING ERRCODE = 'P0002';
    END IF;
    RETURN QUERY SELECT certificate_decision_claim(p_decision, p_application, v_key.key_id, p_issued_at),
                        v_key.key_id, v_key.public_key_sec1;
END
$fn$;
REVOKE ALL ON FUNCTION certificate_decision_context(TEXT, TEXT, UUID, UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- Returns the claim to sign now. Records nothing.
CREATE FUNCTION prepare_certificate_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_decision TEXT
) RETURNS TABLE (claim TEXT, key_id TEXT, issued_at TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_now TIMESTAMPTZ := date_trunc('milliseconds', clock_timestamp());
BEGIN
    RETURN QUERY SELECT c.claim, c.key_id,
        to_char(v_now AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
        FROM certificate_decision_context(p_issuer, p_subject, p_ca, p_application, p_decision, v_now) c;
END
$fn$;
REVOKE ALL ON FUNCTION prepare_certificate_decision_lab(TEXT, TEXT, UUID, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prepare_certificate_decision_lab(TEXT, TEXT, UUID, UUID, TEXT) TO trust_profile_writer;

-- Records an officer's signed decision on a claim issued less than ten
-- minutes ago, under the rules of decide_certificate_application_lab
-- (migration 0029: grant, the requester never decides, one decision, CA and
-- revision active to approve). The API verifies the returned signature
-- against the returned claim and key in the same transaction, and rolls back
-- when it does not verify.
CREATE FUNCTION record_signed_certificate_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_decision TEXT, p_reason TEXT,
    p_issued_at TIMESTAMPTZ, p_signature_der BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (claim TEXT, public_key_sec1 BYTEA, status TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
    v_context RECORD;
    v_decided RECORD;
    v_event UUID;
    v_now TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_operation IS NULL OR p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80 THEN
        RAISE EXCEPTION 'invalid signed decision parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action IN ('application.approved', 'application.rejected')
           AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.application_id = p_application
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY SELECT x.claim, x.public_key_sec1, certificate_application_status(p_application), true
                FROM certificate_application_authorization x WHERE x.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;
    IF p_issued_at IS NULL OR p_issued_at > v_now + interval '5 seconds'
       OR p_issued_at < v_now - interval '10 minutes' THEN
        RAISE EXCEPTION 'decision claim expired or not yet valid' USING ERRCODE = 'TP409';
    END IF;
    SELECT * INTO v_context
    FROM certificate_decision_context(p_issuer, p_subject, p_ca, p_application, p_decision, p_issued_at);
    SELECT * INTO v_decided
    FROM decide_certificate_application_lab(p_issuer, p_subject, p_ca, p_application, p_decision, p_reason,
                                            p_operation, p_request_sha256);
    SELECT e.event_id INTO v_event FROM certificate_application_event e WHERE e.operation_id = p_operation;
    INSERT INTO certificate_application_authorization
        (application_id, decision, key_id, public_key_sec1, claim, signature_der, claim_issued_at, event_id)
    VALUES (p_application, p_decision, v_context.key_id, v_context.public_key_sec1, v_context.claim,
            p_signature_der, p_issued_at, v_event);
    RETURN QUERY SELECT v_context.claim, v_context.public_key_sec1, v_decided.status, false;
END
$fn$;
REVOKE ALL ON FUNCTION record_signed_certificate_decision_lab(TEXT, TEXT, UUID, UUID, TEXT, TEXT, TIMESTAMPTZ, BYTEA,
    UUID, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_signed_certificate_decision_lab(TEXT, TEXT, UUID, UUID, TEXT, TEXT, TIMESTAMPTZ,
    BYTEA, UUID, BYTEA) TO trust_profile_writer;

-- Whether an application carries a proof the signer will accept as such: an
-- RA request, or an officer's signed approval. The API asks before it starts
-- an issuance, so an unproven approval never reaches a signing intent.
CREATE FUNCTION application_authorization_present_lab(p_ca UUID, p_application UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT EXISTS (SELECT 1 FROM ra_issuance_request q WHERE q.application_id = p_application AND q.ca_id = p_ca)
        OR EXISTS (SELECT 1 FROM certificate_application_authorization z
                   JOIN certificate_application a ON a.application_id = z.application_id
                   WHERE z.application_id = p_application AND a.ca_id = p_ca AND z.decision = 'approve')
$fn$;
REVOKE ALL ON FUNCTION application_authorization_present_lab(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION application_authorization_present_lab(UUID, UUID) TO trust_profile_writer;

-- RA requests, version 2: the subject and the optional extensions are signed.
ALTER TABLE ra_issuance_request
    ADD COLUMN message_version SMALLINT NOT NULL DEFAULT 1 CHECK (message_version IN (1, 2));

-- The same bytes as trust_pki_core::ra_request::ra_issuance_message_v2.
CREATE FUNCTION ra_issuance_message_v2(
    p_ra TEXT, p_ca UUID, p_profile TEXT, p_request UUID, p_csr_sha256 BYTEA, p_dns_names TEXT[],
    p_validity_days INTEGER, p_signed_at_unix BIGINT, p_subject_cn TEXT, p_extensions TEXT[]
) RETURNS BYTEA
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, public AS $fn$
    SELECT convert_to('trust-platform:ra-issuance-request:v2', 'UTF8') || '\x00'::bytea
        || substring(ra_issuance_message(p_ra, p_ca, p_profile, p_request, p_csr_sha256, p_dns_names,
                                         p_validity_days, p_signed_at_unix)
                     FROM octet_length('trust-platform:ra-issuance-request:v1') + 2)
        || int4send(octet_length(convert_to(p_subject_cn, 'UTF8'))) || convert_to(p_subject_cn, 'UTF8')
        || int4send(cardinality(p_extensions))
        || coalesce((SELECT string_agg(int4send(octet_length(convert_to(e, 'UTF8'))) || convert_to(e, 'UTF8'),
                                       '' ORDER BY i)
                     FROM unnest(p_extensions) WITH ORDINALITY AS t(e, i)), '\x'::bytea)
$fn$;
REVOKE ALL ON FUNCTION ra_issuance_message_v2(TEXT, UUID, TEXT, UUID, BYTEA, TEXT[], INTEGER, BIGINT, TEXT, TEXT[])
    FROM PUBLIC;

-- A version 2 RA request: as submit_ra_issuance_lab (migration 0038), with a
-- subject CN the RA chose among the names and optional extensions the
-- profile allows for this CA. Errors as in 0038, plus TP422 for an extension
-- the profile does not allow.
CREATE FUNCTION submit_ra_issuance_v2_lab(
    p_ra TEXT, p_ca UUID, p_profile TEXT, p_request UUID, p_csr_der BYTEA, p_spki_sha256 BYTEA,
    p_subject_cn TEXT, p_dns_names TEXT[], p_validity_days INTEGER, p_signed_at_unix BIGINT,
    p_extensions TEXT[], p_signature BYTEA
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
       OR p_subject_cn IS NULL OR p_dns_names IS NULL OR p_validity_days IS NULL OR p_signed_at_unix IS NULL
       OR p_extensions IS NULL OR cardinality(p_extensions) > 1 OR NOT (p_extensions <@ ARRAY['client-auth'])
       OR p_signature IS NULL OR octet_length(p_signature) NOT BETWEEN 8 AND 72 THEN
        RAISE EXCEPTION 'invalid RA issuance parameters' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM ra_system r WHERE r.ra_id = p_ra AND r.enabled)
       OR NOT EXISTS (SELECT 1 FROM ra_profile_grant g
                      WHERE g.ra_id = p_ra AND g.ca_id = p_ca AND g.profile_id = p_profile) THEN
        RAISE EXCEPTION 'unknown or disabled RA, or profile not granted' USING ERRCODE = '42501';
    END IF;
    v_message := ra_issuance_message_v2(p_ra, p_ca, p_profile, p_request, sha256(p_csr_der), p_dns_names,
                                        p_validity_days, p_signed_at_unix, p_subject_cn, p_extensions);
    PERFORM pg_advisory_xact_lock(hashtextextended('ra-request:' || p_ra || ':' || p_request::text, 0));

    SELECT * INTO v_prior FROM ra_issuance_request r WHERE r.ra_id = p_ra AND r.request_id = p_request;
    IF FOUND THEN
        IF v_prior.message = v_message AND v_prior.ca_id = p_ca THEN
            RETURN QUERY SELECT v_prior.application_id, true;
            RETURN;
        END IF;
        RAISE EXCEPTION 'request id already used for another request' USING ERRCODE = 'TP409';
    END IF;
    IF abs(extract(epoch FROM clock_timestamp()) - p_signed_at_unix) > 300 THEN
        RAISE EXCEPTION 'the request is not fresh' USING ERRCODE = 'TP422';
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p_extensions) e
               WHERE NOT EXISTS (SELECT 1 FROM profile_optional_extension x
                                 WHERE x.ca_id = p_ca AND x.profile_id = p_profile AND x.extension = e)) THEN
        RAISE EXCEPTION 'an extension the profile does not allow' USING ERRCODE = 'TP422';
    END IF;

    SELECT s.application_id INTO v_application
    FROM submit_certificate_application_lab(v_issuer, p_ra, p_ca, p_profile, p_csr_der, p_spki_sha256,
                                            p_subject_cn, p_dns_names, p_validity_days, p_request,
                                            sha256(v_message)) s;
    IF cardinality(p_extensions) > 0 THEN
        INSERT INTO certificate_application_option (application_id, optional_extensions)
        VALUES (v_application, p_extensions);
    END IF;
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
    INSERT INTO ra_issuance_request (ra_id, request_id, ca_id, application_id, message, signature, signed_at,
                                     message_version)
    VALUES (p_ra, p_request, p_ca, v_application, v_message, p_signature, to_timestamp(p_signed_at_unix), 2);

    RETURN QUERY SELECT v_application, false;
END
$fn$;
REVOKE ALL ON FUNCTION submit_ra_issuance_v2_lab(TEXT, UUID, TEXT, UUID, BYTEA, BYTEA, TEXT, TEXT[], INTEGER, BIGINT,
    TEXT[], BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION submit_ra_issuance_v2_lab(TEXT, UUID, TEXT, UUID, BYTEA, BYTEA, TEXT, TEXT[], INTEGER, BIGINT,
    TEXT[], BYTEA) TO trust_profile_writer;

-- The optional extensions of the application an issuance is for, for the API
-- to build the certificate (the signer reads them from its own view).
CREATE FUNCTION application_extensions_lab(p_ca UUID, p_application UUID) RETURNS TEXT[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT certificate_application_extensions(a.application_id)
    FROM certificate_application a WHERE a.application_id = p_application AND a.ca_id = p_ca
$fn$;
REVOKE ALL ON FUNCTION application_extensions_lab(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION application_extensions_lab(UUID, UUID) TO trust_profile_writer;

-- What the signer needs to verify an intent's authorization: the application
-- facts the proof covers, and the proof with its registered key. Exactly one
-- of the RA or officer columns is set for an issuance the API started.
CREATE VIEW lab_signer_authorization WITH (security_barrier = true) AS
SELECT si.intent_id::text AS intent_id,
       a.application_id::text AS application_id, a.profile_id, a.revision,
       -- Inlined: a view's functions run with the reader's privileges.
       coalesce(o.optional_extensions, '{}') AS optional_extensions,
       q.ra_id, q.request_id::text AS ra_request_id, q.message_version AS ra_message_version,
       extract(epoch FROM q.signed_at)::bigint AS ra_signed_at, q.signature AS ra_signature,
       rs.public_key_sec1 AS ra_public_key, coalesce(rs.enabled, false) AS ra_enabled,
       z.decision AS officer_decision, z.key_id AS officer_key_id,
       to_char(z.claim_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS officer_issued_at,
       z.signature_der AS officer_signature, k.public_key_sec1 AS officer_public_key,
       coalesce(k.revoked_at IS NULL, false) AS officer_key_active
FROM signing_intent si
JOIN certificate_application_issuance i ON i.ca_id = si.ca_id AND i.request_id = si.request_id
JOIN certificate_application a ON a.application_id = i.application_id
LEFT JOIN certificate_application_option o ON o.application_id = a.application_id
LEFT JOIN ra_issuance_request q ON q.application_id = a.application_id
LEFT JOIN ra_system rs ON rs.ra_id = q.ra_id
LEFT JOIN certificate_application_authorization z ON z.application_id = a.application_id
LEFT JOIN registration_officer_key k ON k.key_id = z.key_id;
REVOKE ALL ON lab_signer_authorization FROM PUBLIC;
GRANT SELECT ON lab_signer_authorization TO trust_lab_signer;

CREATE FUNCTION management_authorization_proofs_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_authorization_proofs_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_authorization_proofs_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
