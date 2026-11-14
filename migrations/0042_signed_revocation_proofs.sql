-- Migration 0042: signed proofs for what a CRL lists (ADR-0029, Proposed).
--
-- Migration 0041 made the signer verify a signed authorization before it
-- signs a certificate. A CRL entry is the other half: until now the signer
-- listed every revocation and void the database held, and an officer's
-- revocation approval or void confirmation was recorded on the API's word
-- (the acting identity is a parameter). A compromised API could revoke any
-- certificate in an officer's name.
--
-- From now on every CRL entry recorded after this migration carries a proof
-- signed by a key the API cannot register:
-- - an RA's signed revocation (migration 0039), checked with the RA's key;
-- - a registration officer's signed approval of the revocation request,
--   over a claim the database builds (revocation, application, serial,
--   reason code);
-- - for a voided serial (migration 0034), the confirming officer's signed
--   claim (application, serial, whether the signer had claimed the intent).
--
-- The signer rebuilds every claim from the entry's facts and verifies it
-- before it claims the CRL intent. Entries recorded before this migration
-- were never signed: they stay listed (a CRL never drops a revocation) and
-- are marked as such.
--
-- A key revoked later does not unlist what it authorized: the key must only
-- have been active when the claim was issued. Disabling an RA likewise.
BEGIN;

-- The instant from which CRL entries need a signed proof. Owner-held, one row.
CREATE TABLE crl_entry_proof_policy (
    singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    required_since TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON crl_entry_proof_policy FROM PUBLIC;
CREATE TRIGGER immutable_crl_entry_proof_policy
    BEFORE UPDATE OR DELETE ON crl_entry_proof_policy
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
INSERT INTO crl_entry_proof_policy DEFAULT VALUES;

-- Officers' signed revocation decisions.
CREATE TABLE certificate_revocation_authorization (
    revocation_id UUID PRIMARY KEY REFERENCES certificate_revocation_request (revocation_id),
    decision TEXT NOT NULL CHECK (decision IN ('approve', 'reject')),
    key_id TEXT NOT NULL REFERENCES registration_officer_key (key_id),
    public_key_sec1 BYTEA NOT NULL,
    claim TEXT NOT NULL CHECK (length(claim) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    claim_issued_at TIMESTAMPTZ NOT NULL,
    event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id)
);
REVOKE ALL ON certificate_revocation_authorization FROM PUBLIC;
CREATE TRIGGER immutable_certificate_revocation_authorization
    BEFORE UPDATE OR DELETE ON certificate_revocation_authorization
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

-- The confirming officer's signed void confirmations.
CREATE TABLE certificate_void_authorization (
    application_id UUID PRIMARY KEY REFERENCES certificate_application_void (application_id),
    key_id TEXT NOT NULL REFERENCES registration_officer_key (key_id),
    public_key_sec1 BYTEA NOT NULL,
    claim TEXT NOT NULL CHECK (length(claim) BETWEEN 1 AND 4096),
    signature_der BYTEA NOT NULL CHECK (octet_length(signature_der) BETWEEN 8 AND 80),
    claim_issued_at TIMESTAMPTZ NOT NULL,
    event_id UUID NOT NULL UNIQUE REFERENCES certificate_application_event (event_id)
);
REVOKE ALL ON certificate_void_authorization FROM PUBLIC;
CREATE TRIGGER immutable_certificate_void_authorization
    BEFORE UPDATE OR DELETE ON certificate_void_authorization
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE FUNCTION lab_claim_instant(p_at TIMESTAMPTZ) RETURNS TEXT
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog AS $fn$
    SELECT to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
$fn$;
REVOKE ALL ON FUNCTION lab_claim_instant(TIMESTAMPTZ) FROM PUBLIC;

-- The claim texts, version 1: the same as
-- trust_pki_core::authorization::{revocation_decision_claim, void_confirmation_claim}.
CREATE FUNCTION revocation_decision_claim(p_decision TEXT, p_revocation UUID, p_key_id TEXT, p_issued_at TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT 'trust-platform/revocation-authorization/v1;decision=' || p_decision
        || ';ca=' || q.ca_id::text || ';application=' || q.application_id::text
        || ';revocation=' || q.revocation_id::text
        || ';serial=' || encode(q.serial_der_content, 'hex')
        || ';reason_code=' || q.reason_code
        || ';key=' || p_key_id || ';issued_at=' || lab_claim_instant(p_issued_at)
    FROM certificate_revocation_request q WHERE q.revocation_id = p_revocation
$fn$;
REVOKE ALL ON FUNCTION revocation_decision_claim(TEXT, UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;

CREATE FUNCTION void_confirmation_claim(p_application UUID, p_key_id TEXT, p_issued_at TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $fn$
    SELECT 'trust-platform/void-authorization/v1;ca=' || v.ca_id::text
        || ';application=' || v.application_id::text
        || ';serial=' || encode(v.serial_der_content, 'hex')
        || ';signer_claimed=' || CASE WHEN v.signer_claimed THEN 'true' ELSE 'false' END
        || ';key=' || p_key_id || ';issued_at=' || lab_claim_instant(p_issued_at)
    FROM certificate_application_void v WHERE v.application_id = p_application
$fn$;
REVOKE ALL ON FUNCTION void_confirmation_claim(UUID, TEXT, TIMESTAMPTZ) FROM PUBLIC;

-- The acting officer's active key. 42501 without a grant or a key.
CREATE FUNCTION officer_active_key(p_issuer TEXT, p_subject TEXT, p_ca UUID) RETURNS registration_officer_key
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_key registration_officer_key%ROWTYPE;
BEGIN
    IF NOT certificate_role_granted(p_issuer, p_subject, p_ca, 'registration-officer') THEN
        RAISE EXCEPTION 'no registration-officer grant for this CA' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO v_key FROM registration_officer_key k
    WHERE k.issuer = p_issuer AND k.subject = p_subject AND k.revoked_at IS NULL;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no registered officer key' USING ERRCODE = '42501';
    END IF;
    RETURN v_key;
END
$fn$;
REVOKE ALL ON FUNCTION officer_active_key(TEXT, TEXT, UUID) FROM PUBLIC;

CREATE FUNCTION signed_claim_fresh(p_issued_at TIMESTAMPTZ) RETURNS VOID
LANGUAGE plpgsql STABLE SET search_path = pg_catalog AS $fn$
BEGIN
    IF p_issued_at IS NULL OR p_issued_at > clock_timestamp() + interval '5 seconds'
       OR p_issued_at < clock_timestamp() - interval '10 minutes' THEN
        RAISE EXCEPTION 'decision claim expired or not yet valid' USING ERRCODE = 'TP409';
    END IF;
END
$fn$;
REVOKE ALL ON FUNCTION signed_claim_fresh(TIMESTAMPTZ) FROM PUBLIC;

-- Revocation decisions: the claim to sign now. Records nothing. Errors:
-- 42501 grant or key, P0002 unknown revocation request, 22023 decision.
CREATE FUNCTION prepare_revocation_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_revocation UUID, p_decision TEXT
) RETURNS TABLE (claim TEXT, key_id TEXT, issued_at TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_key registration_officer_key%ROWTYPE;
    v_now TIMESTAMPTZ := date_trunc('milliseconds', clock_timestamp());
BEGIN
    IF p_decision IS NULL OR p_decision NOT IN ('approve', 'reject') THEN
        RAISE EXCEPTION 'invalid decision' USING ERRCODE = '22023';
    END IF;
    v_key := officer_active_key(p_issuer, p_subject, p_ca);
    IF NOT EXISTS (SELECT 1 FROM certificate_revocation_request q WHERE q.revocation_id = p_revocation
                   AND q.application_id = p_application AND q.ca_id = p_ca) THEN
        RAISE EXCEPTION 'unknown revocation request' USING ERRCODE = 'P0002';
    END IF;
    RETURN QUERY SELECT revocation_decision_claim(p_decision, p_revocation, v_key.key_id, v_now), v_key.key_id,
                        lab_claim_instant(v_now);
END
$fn$;
REVOKE ALL ON FUNCTION prepare_revocation_decision_lab(TEXT, TEXT, UUID, UUID, UUID, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prepare_revocation_decision_lab(TEXT, TEXT, UUID, UUID, UUID, TEXT) TO trust_profile_writer;

-- Records an officer's signed revocation decision under the rules of
-- decide_certificate_revocation_lab (migration 0031). The API verifies the
-- returned signature against the returned claim and key in the same
-- transaction and rolls back when it does not verify.
CREATE FUNCTION record_signed_revocation_decision_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_revocation UUID, p_decision TEXT,
    p_reason TEXT, p_issued_at TIMESTAMPTZ, p_signature_der BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (claim TEXT, public_key_sec1 BYTEA, status TEXT, revoked_at TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
    v_key registration_officer_key%ROWTYPE;
    v_claim TEXT;
    v_decided RECORD;
    v_event UUID;
BEGIN
    IF p_operation IS NULL OR p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80
       OR p_decision IS NULL OR p_decision NOT IN ('approve', 'reject') THEN
        RAISE EXCEPTION 'invalid signed revocation decision parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action IN ('revocation.approved', 'revocation.rejected')
           AND v_prior.request_sha256 = p_request_sha256 AND v_prior.ca_id = p_ca
           AND v_prior.application_id = p_application
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY
            SELECT x.claim, x.public_key_sec1, d.status, d.revoked_at, true
            FROM certificate_revocation_authorization x
            CROSS JOIN LATERAL decide_certificate_revocation_lab(p_issuer, p_subject, p_ca, p_application,
                p_revocation, p_decision, p_reason, p_operation, p_request_sha256) d
            WHERE x.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;
    PERFORM signed_claim_fresh(p_issued_at);
    v_key := officer_active_key(p_issuer, p_subject, p_ca);
    v_claim := revocation_decision_claim(p_decision, p_revocation, v_key.key_id, p_issued_at);
    SELECT * INTO v_decided
    FROM decide_certificate_revocation_lab(p_issuer, p_subject, p_ca, p_application, p_revocation, p_decision,
                                           p_reason, p_operation, p_request_sha256);
    SELECT e.event_id INTO v_event FROM certificate_application_event e WHERE e.operation_id = p_operation;
    INSERT INTO certificate_revocation_authorization
        (revocation_id, decision, key_id, public_key_sec1, claim, signature_der, claim_issued_at, event_id)
    VALUES (p_revocation, p_decision, v_key.key_id, v_key.public_key_sec1, v_claim, p_signature_der,
            p_issued_at, v_event);
    RETURN QUERY SELECT v_claim, v_key.public_key_sec1, v_decided.status, v_decided.revoked_at, false;
END
$fn$;
REVOKE ALL ON FUNCTION record_signed_revocation_decision_lab(TEXT, TEXT, UUID, UUID, UUID, TEXT, TEXT, TIMESTAMPTZ,
    BYTEA, UUID, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_signed_revocation_decision_lab(TEXT, TEXT, UUID, UUID, UUID, TEXT, TEXT,
    TIMESTAMPTZ, BYTEA, UUID, BYTEA) TO trust_profile_writer;

-- Void confirmations: the claim to sign now. Records nothing. Errors: 42501
-- grant or key, P0002 no proposed void for this application.
CREATE FUNCTION prepare_void_confirmation_lab(p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID)
RETURNS TABLE (claim TEXT, key_id TEXT, issued_at TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_key registration_officer_key%ROWTYPE;
    v_now TIMESTAMPTZ := date_trunc('milliseconds', clock_timestamp());
BEGIN
    v_key := officer_active_key(p_issuer, p_subject, p_ca);
    IF NOT EXISTS (SELECT 1 FROM certificate_application_void v
                   WHERE v.application_id = p_application AND v.ca_id = p_ca) THEN
        RAISE EXCEPTION 'no void was proposed for this issuance' USING ERRCODE = 'P0002';
    END IF;
    RETURN QUERY SELECT void_confirmation_claim(p_application, v_key.key_id, v_now), v_key.key_id,
                        lab_claim_instant(v_now);
END
$fn$;
REVOKE ALL ON FUNCTION prepare_void_confirmation_lab(TEXT, TEXT, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prepare_void_confirmation_lab(TEXT, TEXT, UUID, UUID) TO trust_profile_writer;

-- Records a signed void confirmation under the rules of
-- confirm_application_void_lab (migration 0034).
CREATE FUNCTION record_signed_void_confirmation_lab(
    p_issuer TEXT, p_subject TEXT, p_ca UUID, p_application UUID, p_reason TEXT, p_issued_at TIMESTAMPTZ,
    p_signature_der BYTEA, p_operation UUID, p_request_sha256 BYTEA
) RETURNS TABLE (claim TEXT, public_key_sec1 BYTEA, status TEXT, serial BYTEA, voided_at TEXT, replayed BOOLEAN)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
DECLARE
    v_prior certificate_application_event%ROWTYPE;
    v_key registration_officer_key%ROWTYPE;
    v_claim TEXT;
    v_done RECORD;
    v_event UUID;
BEGIN
    IF p_operation IS NULL OR p_signature_der IS NULL OR octet_length(p_signature_der) NOT BETWEEN 8 AND 80 THEN
        RAISE EXCEPTION 'invalid signed void confirmation parameters' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO v_prior FROM certificate_application_event e WHERE e.operation_id = p_operation;
    IF FOUND THEN
        IF v_prior.action = 'issuance.voided' AND v_prior.request_sha256 = p_request_sha256
           AND v_prior.ca_id = p_ca AND v_prior.application_id = p_application
           AND v_prior.actor_issuer = p_issuer AND v_prior.actor_subject = p_subject THEN
            RETURN QUERY
            SELECT x.claim, x.public_key_sec1, c.status, c.serial, c.voided_at, true
            FROM certificate_void_authorization x
            CROSS JOIN LATERAL confirm_application_void_lab(p_issuer, p_subject, p_ca, p_application, p_reason,
                p_operation, p_request_sha256) c
            WHERE x.event_id = v_prior.event_id;
            RETURN;
        END IF;
        RAISE EXCEPTION 'idempotency key already used for another request' USING ERRCODE = 'TP409';
    END IF;
    PERFORM signed_claim_fresh(p_issued_at);
    v_key := officer_active_key(p_issuer, p_subject, p_ca);
    v_claim := void_confirmation_claim(p_application, v_key.key_id, p_issued_at);
    IF v_claim IS NULL THEN
        RAISE EXCEPTION 'no void was proposed for this issuance' USING ERRCODE = 'P0002';
    END IF;
    SELECT * INTO v_done
    FROM confirm_application_void_lab(p_issuer, p_subject, p_ca, p_application, p_reason, p_operation,
                                      p_request_sha256);
    SELECT e.event_id INTO v_event FROM certificate_application_event e WHERE e.operation_id = p_operation;
    INSERT INTO certificate_void_authorization
        (application_id, key_id, public_key_sec1, claim, signature_der, claim_issued_at, event_id)
    VALUES (p_application, v_key.key_id, v_key.public_key_sec1, v_claim, p_signature_der, p_issued_at, v_event);
    RETURN QUERY SELECT v_claim, v_key.public_key_sec1, v_done.status, v_done.serial, v_done.voided_at, false;
END
$fn$;
REVOKE ALL ON FUNCTION record_signed_void_confirmation_lab(TEXT, TEXT, UUID, UUID, TEXT, TIMESTAMPTZ, BYTEA, UUID,
    BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION record_signed_void_confirmation_lab(TEXT, TEXT, UUID, UUID, TEXT, TIMESTAMPTZ, BYTEA,
    UUID, BYTEA) TO trust_profile_writer;

-- What the signer needs to verify each entry of a CRL intent: the entry, the
-- facts its proof covers, and the proof with its key (functions inlined: a
-- view's functions run with the reader's privileges). `legacy` marks an entry
-- recorded before this migration, which has no proof. A key counts if it was
-- active when its claim was issued.
CREATE VIEW lab_signer_crl_entry_proof WITH (security_barrier = true) AS
SELECT i.intent_id::text AS intent_id, 'revocation'::text AS kind, r.serial_der_content AS serial,
       to_char(r.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at, r.reason_code,
       r.revoked_at < p.required_since AS legacy,
       i.ca_id::text AS ca_id, q.application_id::text AS application_id, q.revocation_id::text AS revocation_id,
       rr.ra_id, rr.request_id::text AS ra_request_id, q.reason AS ra_reason,
       extract(epoch FROM rr.signed_at)::bigint AS ra_signed_at, rr.signature AS ra_signature,
       rs.public_key_sec1 AS ra_public_key,
       z.decision AS officer_decision, z.key_id AS officer_key_id, to_char(z.claim_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS officer_issued_at,
       z.signature_der AS officer_signature, k.public_key_sec1 AS officer_public_key,
       (k.key_id IS NOT NULL AND (k.revoked_at IS NULL OR k.revoked_at > z.claim_issued_at)) AS officer_key_valid,
       NULL::boolean AS void_signer_claimed
FROM crl_signing_intent i
CROSS JOIN crl_entry_proof_policy p
JOIN revocation r ON r.ca_id = i.ca_id AND r.revoked_at <= i.entries_until
LEFT JOIN LATERAL (
    SELECT q.* FROM certificate_revocation_request q
    JOIN certificate_revocation_decision d ON d.revocation_id = q.revocation_id AND d.decision = 'approve'
    WHERE q.ca_id = r.ca_id AND q.serial_der_content = r.serial_der_content
) q ON true
LEFT JOIN ra_revocation_request rr ON rr.revocation_id = q.revocation_id
LEFT JOIN ra_system rs ON rs.ra_id = rr.ra_id
LEFT JOIN certificate_revocation_authorization z ON z.revocation_id = q.revocation_id
LEFT JOIN registration_officer_key k ON k.key_id = z.key_id
UNION ALL
SELECT i.intent_id::text, 'void', v.serial_der_content,
       to_char(v.voided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 0::smallint,
       v.voided_at < p.required_since,
       i.ca_id::text, v.application_id::text, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
       CASE WHEN z.application_id IS NULL THEN NULL ELSE 'approve' END, z.key_id,
       to_char(z.claim_issued_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), z.signature_der, k.public_key_sec1,
       (k.key_id IS NOT NULL AND (k.revoked_at IS NULL OR k.revoked_at > z.claim_issued_at)),
       v.signer_claimed
FROM crl_signing_intent i
CROSS JOIN crl_entry_proof_policy p
JOIN certificate_application_void v ON v.ca_id = i.ca_id AND v.voided_at <= i.entries_until
LEFT JOIN certificate_void_authorization z ON z.application_id = v.application_id
LEFT JOIN registration_officer_key k ON k.key_id = z.key_id;
REVOKE ALL ON lab_signer_crl_entry_proof FROM PUBLIC;
GRANT SELECT ON lab_signer_crl_entry_proof TO trust_lab_signer;

CREATE FUNCTION management_revocation_proofs_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_revocation_proofs_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_revocation_proofs_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
