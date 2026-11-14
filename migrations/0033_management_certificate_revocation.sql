-- Show revocation in the certificate inventory. Until now management_certificate
-- exposed the issuance state only (SIGNED), so a revoked certificate looked
-- current in every management read. This migration appends two columns, read
-- from the core revocation table that an approved revocation (migration 0031)
-- writes:
--   revoked_at          the recorded revocation time, UTC, or NULL
--   revocation_reason   the RFC 5280 CRLReason code, or NULL
-- The row filter (migration 0021) is unchanged: a reader sees revocations of
-- granted authorities only. Revocation here is the platform's record; it
-- reaches relying parties through the next published CRL (migration 0032).
BEGIN;

CREATE OR REPLACE VIEW management_certificate WITH (security_barrier = true) AS
SELECT c.ca_id::text AS ca_id, encode(c.serial_der_content, 'hex') AS serial_hex,
       encode(c.fingerprint_sha256, 'hex') AS fingerprint_sha256,
       c.request_id::text AS request_id, r.state,
       to_char(c.signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS signed_at,
       to_char(c.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS published_at,
       c.subject_cn,
       to_char(c.not_before_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_before,
       to_char(c.not_after_utc AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS not_after,
       c.san_dns,
       date_trunc('milliseconds', c.signed_at AT TIME ZONE 'UTC') AS signed_at_window,
       c.subject_cn_lower,
       to_char(v.revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS revoked_at,
       v.reason_code AS revocation_reason
FROM certificate c
JOIN certificate_request r ON (r.ca_id = c.ca_id AND r.request_id = c.request_id)
LEFT JOIN revocation v ON (v.ca_id = c.ca_id AND v.serial_der_content = c.serial_der_content)
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = c.ca_id
);

CREATE FUNCTION management_certificate_revocation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_certificate_revocation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_certificate_revocation_version() TO trust_api_reader;

COMMIT;
