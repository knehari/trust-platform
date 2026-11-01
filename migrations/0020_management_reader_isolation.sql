-- Isolate certificate authorities in the database, not only in the API
-- (docs/adr/ADR-0008-database-reader-isolation.md, Proposed). Until now the
-- management views filtered no rows: a session holding trust_api_reader read
-- every authority, and isolation rested on each API query carrying its CA
-- predicate and grant check.
--
-- Every management view now returns only the rows of authorities granted to
-- the reader principal that the session declares, in the custom settings
-- trust.reader_issuer and trust.reader_subject. The API sets both, from the
-- verified OIDC token, on every connection it opens. A session that declares
-- no principal, or one without grants, reads nothing (fail closed).
--
-- Limit, stated in the ADR: the database cannot authenticate the OIDC
-- principal. Whoever holds the reader login can declare any principal, so this
-- protects against API queries that miss a predicate and against direct use
-- of the login without a declared principal, not against a compromised API
-- process.
--
-- The filter is written into each view, so it runs with the view owner's
-- privileges on management_reader_grant, inside the security barrier and
-- before any predicate of the caller.
BEGIN;

CREATE OR REPLACE VIEW management_ca WITH (security_barrier = true) AS
SELECT ca.ca_id::text AS ca_id, ca.parent_ca_id::text AS parent_ca_id,
       ca.display_name, ca.policy_version,
       to_char(ca.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM ca
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = ca.ca_id
);

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
       c.subject_cn_lower
FROM certificate c
JOIN certificate_request r ON (r.ca_id = c.ca_id AND r.request_id = c.request_id)
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = c.ca_id
);

CREATE OR REPLACE VIEW management_audit WITH (security_barrier = true) AS
SELECT a.event_id::text AS event_id, a.ca_id::text AS ca_id,
       a.event_type, a.decision, a.policy_version,
       to_char(a.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS recorded_at,
       date_trunc('milliseconds', a.recorded_at AT TIME ZONE 'UTC') AS recorded_at_window
FROM audit_event a
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = a.ca_id
);

-- A principal sees its own grants only.
CREATE OR REPLACE VIEW management_reader_scope WITH (security_barrier = true) AS
SELECT g.issuer, g.subject, g.ca_id::text AS ca_id
FROM management_reader_grant g
WHERE g.issuer = current_setting('trust.reader_issuer', true)
  AND g.subject = current_setting('trust.reader_subject', true);

CREATE OR REPLACE VIEW management_certificate_san WITH (security_barrier = true) AS
SELECT s.ca_id::text AS ca_id, s.request_id::text AS request_id, s.name_lower AS san_dns,
       to_char(s.signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS signed_at,
       date_trunc('milliseconds', s.signed_at AT TIME ZONE 'UTC') AS signed_at_window
FROM certificate_san_dns s
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = s.ca_id
);

CREATE OR REPLACE VIEW management_history_bounds WITH (security_barrier = true) AS
SELECT ca.ca_id::text AS ca_id,
       date_trunc('milliseconds',
           (SELECT max(c.signed_at) FROM certificate c WHERE c.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS newest_signed_window,
       date_trunc('milliseconds',
           (SELECT min(c.signed_at) FROM certificate c WHERE c.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS oldest_signed_window,
       date_trunc('milliseconds',
           (SELECT max(a.recorded_at) FROM audit_event a WHERE a.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS newest_recorded_window,
       date_trunc('milliseconds',
           (SELECT min(a.recorded_at) FROM audit_event a WHERE a.ca_id = ca.ca_id) AT TIME ZONE 'UTC')
           AS oldest_recorded_window
FROM ca
WHERE EXISTS (
    SELECT 1 FROM management_reader_grant g
    WHERE g.issuer = current_setting('trust.reader_issuer', true)
      AND g.subject = current_setting('trust.reader_subject', true)
      AND g.ca_id = ca.ca_id
);

-- Lets the API refuse to start against views that do not filter by principal.
CREATE FUNCTION management_reader_isolation_version() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog AS $fn$ SELECT 1 $fn$;
REVOKE ALL ON FUNCTION management_reader_isolation_version() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION management_reader_isolation_version() TO trust_api_reader;

COMMIT;
