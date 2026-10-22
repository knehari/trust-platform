-- Read-only EXPLAIN rehearsal for the exact CA scope used by the management API.
-- Run only against disposable data as a migration owner/member of trust_api_reader:
-- psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 \
--   -v ca_id=... -v issuer=... -v subject=... \
--   -f tests/management_history_filter_plan.sql
-- EXPLAIN ANALYZE executes the SELECT; this transaction cannot write.
\set ON_ERROR_STOP on
BEGIN READ ONLY;
SET LOCAL ROLE trust_api_reader;
SET LOCAL statement_timeout = '3s';

SELECT count(*) AS scoped_fixture_rows FROM management_certificate
WHERE ca_id = :'ca_id';

\echo 'PLAN: certificate CN prefix'
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT ca_id, serial_hex, fingerprint_sha256, request_id, state,
       signed_at, published_at, subject_cn, not_before, not_after, san_dns
FROM management_certificate
WHERE ca_id = :'ca_id'
  AND EXISTS (SELECT 1 FROM management_reader_scope
              WHERE issuer = :'issuer' AND subject = :'subject' AND ca_id = :'ca_id')
  AND lower(subject_cn) LIKE 'paged-%' ESCAPE '\'
ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo 'PLAN: exact DNS SAN'
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT ca_id, serial_hex, fingerprint_sha256, request_id, state,
       signed_at, published_at, subject_cn, not_before, not_after, san_dns
FROM management_certificate
WHERE ca_id = :'ca_id'
  AND EXISTS (SELECT 1 FROM management_reader_scope
              WHERE issuer = :'issuer' AND subject = :'subject' AND ca_id = :'ca_id')
  AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name)
              WHERE lower(entry.name) = 'paged-0102.lab.invalid')
ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo 'PLAN: recorded validity end'
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
SELECT ca_id, serial_hex, fingerprint_sha256, request_id, state,
       signed_at, published_at, subject_cn, not_before, not_after, san_dns
FROM management_certificate
WHERE ca_id = :'ca_id'
  AND EXISTS (SELECT 1 FROM management_reader_scope
              WHERE issuer = :'issuer' AND subject = :'subject' AND ca_id = :'ca_id')
  AND not_after < '2028-01-01T00:00:00.000Z'
ORDER BY signed_at DESC, request_id DESC LIMIT 101;

ROLLBACK;
