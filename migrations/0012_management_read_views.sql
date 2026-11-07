-- Laboratory management API boundary. Apply after 0011. The role is NOLOGIN;
-- deployment creates a separate login and grants this role to it.
BEGIN;

DO $role$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_api_reader') THEN
        CREATE ROLE trust_api_reader NOLOGIN;
    END IF;
END $role$;

CREATE VIEW management_ca WITH (security_barrier = true) AS
SELECT ca_id::text AS ca_id, parent_ca_id::text AS parent_ca_id,
       display_name, policy_version,
       to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM ca;

CREATE VIEW management_certificate WITH (security_barrier = true) AS
SELECT c.ca_id::text AS ca_id, encode(c.serial_der_content, 'hex') AS serial_hex,
       encode(c.fingerprint_sha256, 'hex') AS fingerprint_sha256,
       c.request_id::text AS request_id, r.state,
       to_char(c.signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS signed_at,
       to_char(c.published_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS published_at
FROM certificate c
JOIN certificate_request r ON (r.ca_id = c.ca_id AND r.request_id = c.request_id);

CREATE VIEW management_audit WITH (security_barrier = true) AS
SELECT event_id::text AS event_id, ca_id::text AS ca_id,
       event_type, decision, policy_version,
       to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS recorded_at
FROM audit_event;

GRANT USAGE ON SCHEMA public TO trust_api_reader;
GRANT SELECT ON management_ca, management_certificate, management_audit TO trust_api_reader;

COMMIT;
