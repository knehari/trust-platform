-- Let the history CN prefix filter read an index through the security-barrier
-- certificate view (docs/operations/lab-history-cn-lower.md). Option 3.1 of
-- the scale study; every management view keeps its barrier.
--
-- The API used to filter with lower(subject_cn) LIKE 'prefix%', and neither
-- lower() nor LIKE is leakproof, so that filter ran above the barrier on every
-- row of the authority. subject_cn_lower is a stored generated column:
-- PostgreSQL computes it from subject_cn on every write and nobody can write
-- it directly, so it cannot disagree with the CN. Its "C" collation orders
-- it by code point, so starts_with (^@, leakproof) is answered by a btree
-- range on its index.
BEGIN;

ALTER TABLE certificate
    ADD COLUMN subject_cn_lower TEXT COLLATE "C" GENERATED ALWAYS AS (lower(subject_cn)) STORED;

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
JOIN certificate_request r ON (r.ca_id = c.ca_id AND r.request_id = c.request_id);

-- On the CN alone, like the window index of 0017: an index that also covers
-- ca_id::text changes the planner's statistics for the view's CA predicate
-- and slows the unsliced filters.
CREATE INDEX certificate_management_cn_lower ON certificate (subject_cn_lower);

COMMIT;
