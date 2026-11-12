-- Migration 0047: RA key rotation (ADR-0040, Proposed).
--
-- Until now an RA had a single key, ra_system.public_key_sec1, and every
-- verifier (the API, the signer, the audit tool) read the RA's current key.
-- Replacing it would have orphaned the RA's past requests: the signer
-- re-verifies every RA-signed revocation listed on a CRL and never drops an
-- entry, so the CA's next CRL would have been blocked, and the audit tool
-- would have reported every past request as forged.
--
-- Keys now live in ra_system_key, append-only, numbered per RA:
-- - the owner adds a key (at most two unretired keys per RA, so a new key
--   and the old one overlap during the switch);
-- - the owner retires a key once; retirement is final and dated by the
--   database;
-- - a key is never changed or deleted, and never doubles as an approver's,
--   an officer's or another RA's key.
--
-- Which keys verify what:
-- - a new request (API): the RA's unretired keys;
-- - an issuance (signer): the RA's keys active when the request was recorded
--   and still unretired, so retiring a key stops the issuance still pending
--   under it;
-- - a listed revocation (signer, audit tool) and a past request (audit
--   tool): the RA's keys active when the request was recorded, retired since
--   or not, so a rotation never invalidates the evidence already accepted.
--
-- Registering an RA still takes its first key in ra_system.public_key_sec1,
-- which becomes key 1 and can no longer be changed there.
BEGIN;

CREATE TABLE ra_system_key (
    ra_id TEXT NOT NULL REFERENCES ra_system (ra_id),
    key_id INTEGER NOT NULL CHECK (key_id BETWEEN 1 AND 1000000),
    public_key_sec1 BYTEA NOT NULL UNIQUE
        CHECK (octet_length(public_key_sec1) = 65 AND get_byte(public_key_sec1, 0) = 4),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    retired_at TIMESTAMPTZ CHECK (retired_at IS NULL OR retired_at >= activated_at),
    PRIMARY KEY (ra_id, key_id)
);
REVOKE ALL ON ra_system_key FROM PUBLIC;

-- Every existing RA's key becomes its key 1, active since the RA was
-- registered (so before any request it signed).
INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1, activated_at)
SELECT r.ra_id, 1, r.public_key_sec1, r.registered_at FROM ra_system r;

-- A new key: numbered after the RA's last one, dated now, unretired, at most
-- two unretired per RA, and not used by anyone else.
CREATE FUNCTION ra_system_key_insert() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    -- One key change per RA at a time.
    PERFORM 1 FROM ra_system r WHERE r.ra_id = NEW.ra_id FOR UPDATE;
    NEW.key_id := coalesce((SELECT max(k.key_id) FROM ra_system_key k WHERE k.ra_id = NEW.ra_id), 0) + 1;
    NEW.activated_at := clock_timestamp();
    IF NEW.retired_at IS NOT NULL THEN
        RAISE EXCEPTION 'a new RA key cannot be retired' USING ERRCODE = '22023';
    END IF;
    IF (SELECT count(*) FROM ra_system_key k WHERE k.ra_id = NEW.ra_id AND k.retired_at IS NULL) >= 2 THEN
        RAISE EXCEPTION 'the RA already has two unretired keys; retire one first' USING ERRCODE = '55000';
    END IF;
    IF EXISTS (SELECT 1 FROM profile_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM ca_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM registration_officer_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM ra_system r WHERE r.public_key_sec1 = NEW.public_key_sec1
                  AND r.ra_id <> NEW.ra_id) THEN
        RAISE EXCEPTION 'this key already approves profiles or CAs, or belongs to an officer or another RA'
            USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION ra_system_key_insert() FROM PUBLIC;
CREATE TRIGGER ra_system_key_insert BEFORE INSERT ON ra_system_key
    FOR EACH ROW EXECUTE FUNCTION ra_system_key_insert();

-- A key is never deleted or changed; it is retired once, dated now.
CREATE FUNCTION ra_system_key_guard() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF TG_OP = 'DELETE' OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
       OR (NEW.ra_id, NEW.key_id, NEW.public_key_sec1, NEW.activated_at)
          IS DISTINCT FROM (OLD.ra_id, OLD.key_id, OLD.public_key_sec1, OLD.activated_at) THEN
        RAISE EXCEPTION 'RA keys are append-only; only a single retirement is allowed' USING ERRCODE = '55000';
    END IF;
    NEW.retired_at := clock_timestamp();
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION ra_system_key_guard() FROM PUBLIC;
CREATE TRIGGER ra_system_key_append_only BEFORE UPDATE OR DELETE ON ra_system_key
    FOR EACH ROW EXECUTE FUNCTION ra_system_key_guard();

-- Registering an RA registers its first key; the column is then frozen.
CREATE FUNCTION ra_system_first_key() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1) VALUES (NEW.ra_id, 1, NEW.public_key_sec1);
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION ra_system_first_key() FROM PUBLIC;
CREATE TRIGGER ra_system_first_key AFTER INSERT ON ra_system
    FOR EACH ROW EXECUTE FUNCTION ra_system_first_key();

CREATE FUNCTION ra_system_key_frozen() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF NEW.public_key_sec1 IS DISTINCT FROM OLD.public_key_sec1 THEN
        RAISE EXCEPTION 'add a key to ra_system_key and retire the old one instead' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$fn$;
REVOKE ALL ON FUNCTION ra_system_key_frozen() FROM PUBLIC;
CREATE TRIGGER ra_system_key_frozen BEFORE UPDATE ON ra_system
    FOR EACH ROW EXECUTE FUNCTION ra_system_key_frozen();

-- An officer key must not be any RA key either (it was checked against
-- ra_system only).
CREATE OR REPLACE FUNCTION registration_officer_key_single_power() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $fn$
BEGIN
    IF EXISTS (SELECT 1 FROM profile_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM ca_approver_key k WHERE k.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM ra_system r WHERE r.public_key_sec1 = NEW.public_key_sec1)
       OR EXISTS (SELECT 1 FROM ra_system_key k WHERE k.public_key_sec1 = NEW.public_key_sec1) THEN
        RAISE EXCEPTION 'this key already approves profiles or CAs, or belongs to an RA';
    END IF;
    RETURN NEW;
END
$fn$;

-- The keys a new request may be signed with: an enabled RA's unretired keys.
CREATE FUNCTION ra_system_keys_lab(p_ra TEXT) RETURNS BYTEA[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT array_agg(k.public_key_sec1 ORDER BY k.key_id)
    FROM ra_system r JOIN ra_system_key k ON k.ra_id = r.ra_id
    WHERE r.ra_id = p_ra AND r.enabled AND k.retired_at IS NULL
$fn$;
REVOKE ALL ON FUNCTION ra_system_keys_lab(TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ra_system_keys_lab(TEXT) TO trust_profile_writer;

-- The previous single-key lookup now answers the RA's newest unretired key.
CREATE OR REPLACE FUNCTION ra_system_key_lab(p_ra TEXT) RETURNS BYTEA
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $fn$
    SELECT k.public_key_sec1
    FROM ra_system r JOIN ra_system_key k ON k.ra_id = r.ra_id
    WHERE r.ra_id = p_ra AND r.enabled AND k.retired_at IS NULL
    ORDER BY k.key_id DESC LIMIT 1
$fn$;

-- The signer's views: ra_public_key (the RA's single key) becomes
-- ra_public_keys, the keys that may have signed the request.
DROP VIEW lab_signer_authorization;
CREATE VIEW lab_signer_authorization WITH (security_barrier = true) AS
SELECT si.intent_id::text AS intent_id,
       a.application_id::text AS application_id, a.profile_id, a.revision,
       -- Inlined: a view's functions run with the reader's privileges.
       coalesce(o.optional_extensions, '{}') AS optional_extensions,
       q.ra_id, q.request_id::text AS ra_request_id, q.message_version AS ra_message_version,
       extract(epoch FROM q.signed_at)::bigint AS ra_signed_at, q.signature AS ra_signature,
       -- Active when the request was recorded, and not retired since.
       CASE WHEN q.ra_id IS NOT NULL THEN ARRAY(
           SELECT k2.public_key_sec1 FROM ra_system_key k2
           WHERE k2.ra_id = q.ra_id AND k2.activated_at <= q.recorded_at AND k2.retired_at IS NULL
           ORDER BY k2.key_id) END AS ra_public_keys,
       coalesce(rs.enabled, false) AS ra_enabled,
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

DROP VIEW lab_signer_crl_entry_proof;
CREATE VIEW lab_signer_crl_entry_proof WITH (security_barrier = true) AS
SELECT i.intent_id::text AS intent_id, 'revocation'::text AS kind, r.serial_der_content AS serial,
       to_char(r.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS revoked_at, r.reason_code,
       r.revoked_at < p.required_since AS legacy,
       i.ca_id::text AS ca_id, q.application_id::text AS application_id, q.revocation_id::text AS revocation_id,
       rr.ra_id, rr.request_id::text AS ra_request_id, q.reason AS ra_reason,
       extract(epoch FROM rr.signed_at)::bigint AS ra_signed_at, rr.signature AS ra_signature,
       -- Active when the request was recorded, retired since or not: a
       -- listed revocation is never dropped.
       CASE WHEN rr.ra_id IS NOT NULL THEN ARRAY(
           SELECT k2.public_key_sec1 FROM ra_system_key k2
           WHERE k2.ra_id = rr.ra_id AND k2.activated_at <= rr.recorded_at
             AND (k2.retired_at IS NULL OR k2.retired_at > rr.recorded_at)
           ORDER BY k2.key_id) END AS ra_public_keys,
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
LEFT JOIN certificate_revocation_authorization z ON z.revocation_id = q.revocation_id
LEFT JOIN registration_officer_key k ON k.key_id = z.key_id
UNION ALL
SELECT i.intent_id::text, 'void', v.serial_der_content,
       to_char(v.voided_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 0::smallint,
       v.voided_at < p.required_since,
       i.ca_id::text, v.application_id::text, NULL, NULL, NULL, NULL, NULL, NULL, NULL::bytea[],
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

CREATE FUNCTION management_ra_key_rotation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_ra_key_rotation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_ra_key_rotation_version()
    TO trust_api_reader, trust_profile_writer, trust_lab_signer;

COMMIT;
