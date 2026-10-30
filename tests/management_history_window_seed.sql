-- Disposable fixture for the sliced history reads (migration 0016). LAB ONLY:
-- synthetic rows, a two-byte placeholder instead of any certificate DER.
-- Times are relative to now() so that the API's first-page anchor (the
-- current time) falls between them. They cover every slice path:
-- * 3 rows in the future (the open far side of a newest-first first slice);
-- * 120 rows signed in the same millisecond (cursor ties across a page);
-- * 60 rows one hour apart (rows across the 1, 4, 16 and 64 hour slices);
-- * 40 rows 30 days apart about three years back, and 2 rows in the year
--   1601 (beyond the bounded slices: the open last slice);
-- * 1 row 25 years back. It and the 1601 rows predate the authority's
--   creation, which anchors an oldest-first page (its open first slice).
-- Every 17th row has the CN prefix "needle-" (a sparse filter).
-- Run on a database migrated to 0016, as its owner, before the API test
-- history_slices_read_every_row_in_order.
BEGIN;

INSERT INTO ca (ca_id, display_name, policy_version, created_at) VALUES
    ('abababab-0000-4000-8000-0000000000ab', 'Sliced Lab CA', 'v1', now() - interval '20 years');
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.example.test', 'operator', 'abababab-0000-4000-8000-0000000000ab');

CREATE TEMP TABLE window_row ON COMMIT DROP AS
SELECT n, ('abababab-0000-4000-8000-' || lpad(to_hex(n), 12, '0'))::uuid AS id,
       CASE
           WHEN n <= 3 THEN now() + n * interval '1 day'
           WHEN n <= 123 THEN date_trunc('milliseconds', now() - interval '90 minutes')
           WHEN n <= 183 THEN now() - interval '3 hours' - (n - 123) * interval '1 hour'
           WHEN n <= 223 THEN now() - interval '3 years' - (n - 183) * interval '30 days'
           WHEN n <= 225 THEN '1601-06-01T00:00:00Z'::timestamptz + (n - 224) * interval '1 day'
           ELSE now() - interval '25 years'
       END AS at
FROM generate_series(1, 226) AS n;

INSERT INTO certificate_request
    (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
SELECT id, 'abababab-0000-4000-8000-0000000000ab', 'window-' || n,
       decode(repeat('01', 32), 'hex'), 'window-fixture', 'v1', 'SIGNED'
FROM window_row;

INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
SELECT 'abababab-0000-4000-8000-0000000000ab', decode('02' || lpad(to_hex(n), 4, '0'), 'hex'), id
FROM window_row;

INSERT INTO certificate
    (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at, subject_cn)
SELECT 'abababab-0000-4000-8000-0000000000ab', decode('02' || lpad(to_hex(n), 4, '0'), 'hex'), id,
       decode(repeat('02', 32), 'hex'), decode('3000', 'hex'), at,
       CASE WHEN n % 17 = 0 THEN 'needle-' ELSE 'hay-' END || n || '.lab.invalid'
FROM window_row;

INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version, recorded_at)
SELECT id, 'abababab-0000-4000-8000-0000000000ab', 'window-fixture-actor',
       CASE WHEN n % 17 = 0 THEN 'certificate.revoked' ELSE 'certificate.signed' END,
       'allow', 'v1', at
FROM window_row;

COMMIT;

ANALYZE certificate;
ANALYZE audit_event;
