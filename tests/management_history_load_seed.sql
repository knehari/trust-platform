-- Disposable, deterministic load fixture for the management history query
-- plans (docs/operations/lab-history-load-query-plans.md). LAB ONLY: run it
-- only on an empty, throwaway database migrated to 0015, as its owner.
--   psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 [-v big=200000] \
--     -f tests/management_history_load_seed.sql
-- No randomness: every identifier, time and name is derived from the row
-- number, so two runs build the same data. Certificate DER is a two-byte
-- placeholder; no certificate is issued or verified.
--
-- Authorities (issuer https://issuer.load.invalid, subject reader):
-- * A  cccccccc-0000-4000-8000-00000000000a  :big certificates and audit
--      events; granted to the reader.
-- * C  cccccccc-0000-4000-8000-00000000000c  half as many; NOT granted (the
--      reader must never see it; it shares the tables and their indexes).
-- * 300 small CAs (20 certificates, 20 events each), 250 granted, for the CA
--   list.
-- Certificate rows: signed_at rises with the row number over about two
-- years, two rows share each millisecond (cursor ties); 90% carry verified
-- metadata (CN host-<n>.lab.invalid, 1% svc-<n>.lab.invalid; SAN
-- host-<n>.lab.invalid and alt-<n mod 1000>.lab.invalid; notAfter one year
-- after signing); 10% are historical rows without metadata (0014/0015).
-- Audit rows: recorded_at rises with the row number; event_type among eight
-- values (one of them 1%), decision DENY for 5%, policy_version v1..v4.
\set ON_ERROR_STOP on
\if :{?big}
\else
  \set big 200000
\endif

DO $guard$ BEGIN
  IF EXISTS (SELECT 1 FROM ca) THEN
    RAISE EXCEPTION 'the load fixture needs an empty, disposable database';
  END IF;
END $guard$;

BEGIN;

CREATE TEMP TABLE load_ca (k int PRIMARY KEY, ca_id uuid NOT NULL, size int NOT NULL,
                           granted boolean NOT NULL) ON COMMIT DROP;
INSERT INTO load_ca VALUES
    (10, 'cccccccc-0000-4000-8000-00000000000a', :big, true),
    (12, 'cccccccc-0000-4000-8000-00000000000c', :big / 2, false);
INSERT INTO load_ca
SELECT 100 + s, ('cccccccc-0000-4000-8000-' || lpad(to_hex(100 + s), 12, '0'))::uuid, 20, s <= 250
FROM generate_series(1, 300) AS s;

INSERT INTO ca (ca_id, display_name, policy_version, created_at)
SELECT ca_id,
       CASE k WHEN 10 THEN 'Load Authority A' WHEN 12 THEN 'Load Authority C'
              ELSE 'Load CA ' || lpad((k - 100)::text, 3, '0') END,
       'v' || (1 + k % 4), '2024-01-01T00:00:00Z'::timestamptz + k * interval '1 minute'
FROM load_ca;

INSERT INTO certificate_request
    (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state,
     created_at, updated_at)
SELECT (lpad(to_hex(l.k), 8, '0') || '-0000-4000-8000-' || lpad(to_hex(n), 12, '0'))::uuid,
       l.ca_id, 'load-' || n, decode(repeat('01', 32), 'hex'), 'load-fixture', 'v1',
       CASE WHEN n % 3 = 0 THEN 'PUBLISHED' ELSE 'SIGNED' END,
       '2024-06-01T00:00:00Z', '2024-06-01T00:00:00Z'
FROM load_ca l, generate_series(1, l.size) AS n;

INSERT INTO serial_reservation (ca_id, serial_der_content, request_id, reserved_at)
SELECT l.ca_id, decode('01' || lpad(to_hex(n), 8, '0'), 'hex'),
       (lpad(to_hex(l.k), 8, '0') || '-0000-4000-8000-' || lpad(to_hex(n), 12, '0'))::uuid,
       '2024-06-01T00:00:00Z'
FROM load_ca l, generate_series(1, l.size) AS n;

INSERT INTO certificate
    (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der,
     signed_at, published_at, subject_cn, not_before_utc, not_after_utc, san_dns)
SELECT l.ca_id, decode('01' || lpad(to_hex(n), 8, '0'), 'hex'),
       (lpad(to_hex(l.k), 8, '0') || '-0000-4000-8000-' || lpad(to_hex(n), 12, '0'))::uuid,
       decode(repeat('02', 32), 'hex'), decode('3000', 'hex'),
       t.signed_at,
       CASE WHEN n % 3 = 0 THEN t.signed_at + interval '1 minute' END,
       CASE WHEN n % 10 = 0 THEN NULL
            WHEN n % 100 = 1 THEN 'svc-' || n || '.lab.invalid'
            ELSE 'host-' || n || '.lab.invalid' END,
       CASE WHEN n % 10 <> 0 THEN t.signed_at END,
       CASE WHEN n % 10 <> 0 THEN t.signed_at + interval '365 days' END,
       CASE WHEN n % 10 <> 0
            THEN ARRAY['host-' || n || '.lab.invalid', 'alt-' || n % 1000 || '.lab.invalid'] END
FROM load_ca l, generate_series(1, l.size) AS n,
     LATERAL (SELECT '2024-07-01T00:00:00Z'::timestamptz
                     + (n / 2) * interval '300 milliseconds' AS signed_at) AS t;

INSERT INTO audit_event
    (event_id, ca_id, request_id, actor_id, event_type, decision, policy_version, recorded_at)
SELECT (lpad(to_hex(l.k), 8, '0') || '-0000-4000-9000-' || lpad(to_hex(n), 12, '0'))::uuid,
       l.ca_id,
       CASE WHEN n <= l.size AND n % 2 = 0
            THEN (lpad(to_hex(l.k), 8, '0') || '-0000-4000-8000-' || lpad(to_hex(n), 12, '0'))::uuid END,
       'load-fixture',
       CASE WHEN n % 100 = 7 THEN 'certificate.revoked'
            ELSE (ARRAY['request.received', 'csr.validated', 'policy.authorized',
                        'serial.reserved', 'signing.intent', 'certificate.signed',
                        'certificate.published'])[1 + n % 7] END,
       CASE WHEN n % 20 = 3 THEN 'DENY' ELSE 'ALLOW' END,
       'v' || (1 + n % 4),
       '2024-07-01T00:00:00Z'::timestamptz + (n / 2) * interval '300 milliseconds'
FROM load_ca l, generate_series(1, l.size) AS n;

INSERT INTO management_reader_grant (issuer, subject, ca_id)
SELECT 'https://issuer.load.invalid', 'reader', ca_id FROM load_ca WHERE granted;

COMMIT;

ANALYZE ca;
ANALYZE certificate_request;
ANALYZE serial_reservation;
ANALYZE certificate;
ANALYZE audit_event;
ANALYZE management_reader_grant;

SELECT (SELECT count(*) FROM ca) AS cas,
       (SELECT count(*) FROM certificate) AS certificates,
       (SELECT count(*) FROM audit_event) AS audit_events,
       (SELECT count(*) FROM management_reader_grant) AS reader_grants;
