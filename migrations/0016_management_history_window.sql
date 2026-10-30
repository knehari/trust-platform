-- Let history pages read a bounded time range through the security-barrier
-- views (docs/operations/lab-history-time-window.md). PostgreSQL does not push
-- ORDER BY ... LIMIT into a security_barrier view, so every page used to scan
-- the whole authority. The views stay security_barrier. Each gains one column,
-- the signing or recording time truncated to the millisecond in UTC: the same
-- instant as the existing text column, with no added precision. Comparing it
-- is leakproof, so a range on it reaches the new expression indexes.
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
       date_trunc('milliseconds', c.signed_at AT TIME ZONE 'UTC') AS signed_at_window
FROM certificate c
JOIN certificate_request r ON (r.ca_id = c.ca_id AND r.request_id = c.request_id);

CREATE OR REPLACE VIEW management_audit WITH (security_barrier = true) AS
SELECT event_id::text AS event_id, ca_id::text AS ca_id,
       event_type, decision, policy_version,
       to_char(recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS recorded_at,
       date_trunc('milliseconds', recorded_at AT TIME ZONE 'UTC') AS recorded_at_window
FROM audit_event;

-- Both expressions are IMMUTABLE built-ins (timezone with a fixed zone,
-- date_trunc on timestamp without time zone, uuid to text).
CREATE INDEX certificate_management_history_window
    ON certificate ((ca_id::text), (date_trunc('milliseconds', signed_at AT TIME ZONE 'UTC')));
CREATE INDEX audit_event_management_history_window
    ON audit_event ((ca_id::text), (date_trunc('milliseconds', recorded_at AT TIME ZONE 'UTC')));

COMMIT;
