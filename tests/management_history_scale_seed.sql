-- Disposable, deterministic scale fixture for the history filter study
-- (docs/operations/lab-history-scale-study.md). LAB ONLY: synthetic data, a
-- two-byte placeholder instead of any certificate DER. Run on an empty
-- database migrated to 0015, as its owner:
--   psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -v total=1000000 -v seed=42 \
--     -f tests/management_history_scale_seed.sql
-- Determinism: every value derives from the row number and the fixed seed
-- through hashint8() (no random(), no clock), so the same total and seed
-- build the same rows on the same PostgreSQL major version.
--
-- Authorities (reader: issuer https://issuer.scale.invalid, subject reader):
-- * A  dddddddd-0000-4000-8000-0000000000a1  80% of the rows, granted
-- * S1..S8 dddddddd-0000-4000-8000-0000000000b1..b8  2% each, granted
-- * U  dddddddd-0000-4000-8000-0000000000c1  4%, NOT granted
-- Per certificate (u, v: independent hashes in 0..9999):
-- * signed_at spreads each authority's rows over 730 days from 2024-01-01,
--   two rows per millisecond step (cursor ties);
-- * 10% historical rows without verified metadata (CN, SAN, validity NULL);
-- * CN prefix: svc- for 0.1%, app- for 10%, host- otherwise (zzz-: none);
-- * SAN: host-<n>.lab.invalid, grp-<v mod 10>.lab.invalid (10% each),
--   pool-<v mod 1000>.lab.invalid (0.1% each); absent.lab.invalid: none;
-- * notAfter = signed_at + 365 days (2024-12-31 .. 2026-12-30).
\set ON_ERROR_STOP on
\if :{?total}
\else
  \set total 100000
\endif
\if :{?seed}
\else
  \set seed 42
\endif

DO $guard$ BEGIN
  IF EXISTS (SELECT 1 FROM ca) THEN
    RAISE EXCEPTION 'the scale fixture needs an empty, disposable database';
  END IF;
END $guard$;

BEGIN;

CREATE TEMP TABLE scale_ca (k int PRIMARY KEY, ca_id uuid NOT NULL, size bigint NOT NULL,
                            granted boolean NOT NULL) ON COMMIT DROP;
INSERT INTO scale_ca VALUES
    (161, 'dddddddd-0000-4000-8000-0000000000a1', :total * 80 / 100, true),
    (193, 'dddddddd-0000-4000-8000-0000000000c1', :total * 4 / 100, false);
INSERT INTO scale_ca
SELECT 176 + s, ('dddddddd-0000-4000-8000-0000000000b' || s)::uuid, :total * 2 / 100, true
FROM generate_series(1, 8) AS s;

INSERT INTO ca (ca_id, display_name, policy_version, created_at)
SELECT ca_id, 'Scale CA ' || to_hex(k), 'v1', '2023-12-01T00:00:00Z'
FROM scale_ca;

CREATE TEMP TABLE scale_row ON COMMIT DROP AS
SELECT l.k, l.ca_id, n,
       (lpad(to_hex(l.k), 8, '0') || '-0000-4000-8000-' || lpad(to_hex(n), 12, '0'))::uuid AS request_id,
       decode('01' || lpad(to_hex(n), 8, '0'), 'hex') AS serial,
       '2024-01-01T00:00:00Z'::timestamptz
         + ((n / 2) * (730::bigint * 86400000 / greatest(l.size / 2, 1))) * interval '1 millisecond' AS signed_at,
       abs(hashint8(n * 1000003 + l.k * 7919 + :seed)) % 10000 AS u,
       abs(hashint8(n * 999983 + l.k * 104729 + :seed * 31)) % 10000 AS v
FROM scale_ca l, generate_series(1, l.size) AS n;

INSERT INTO certificate_request
    (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state,
     created_at, updated_at)
SELECT request_id, ca_id, 'scale-' || n, decode(repeat('01', 32), 'hex'), 'scale-fixture', 'v1',
       CASE WHEN n % 3 = 0 THEN 'PUBLISHED' ELSE 'SIGNED' END,
       '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z'
FROM scale_row;

INSERT INTO serial_reservation (ca_id, serial_der_content, request_id, reserved_at)
SELECT ca_id, serial, request_id, '2024-01-01T00:00:00Z' FROM scale_row;

INSERT INTO certificate
    (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der,
     signed_at, published_at, subject_cn, not_before_utc, not_after_utc, san_dns)
SELECT ca_id, serial, request_id, decode(repeat('02', 32), 'hex'), decode('3000', 'hex'),
       signed_at,
       CASE WHEN n % 3 = 0 THEN signed_at + interval '1 minute' END,
       CASE WHEN u < 1000 THEN NULL
            WHEN u < 1010 THEN 'svc-' || n || '.lab.invalid'
            WHEN u < 2010 THEN 'app-' || n || '.lab.invalid'
            ELSE 'host-' || n || '.lab.invalid' END,
       CASE WHEN u >= 1000 THEN signed_at END,
       CASE WHEN u >= 1000 THEN signed_at + interval '365 days' END,
       CASE WHEN u >= 1000
            THEN ARRAY['host-' || n || '.lab.invalid', 'grp-' || v % 10 || '.lab.invalid',
                       'pool-' || v % 1000 || '.lab.invalid'] END
FROM scale_row;

INSERT INTO management_reader_grant (issuer, subject, ca_id)
SELECT 'https://issuer.scale.invalid', 'reader', ca_id FROM scale_ca WHERE granted;

COMMIT;

ANALYZE ca;
ANALYZE certificate_request;
ANALYZE serial_reservation;
ANALYZE certificate;
ANALYZE management_reader_grant;

SELECT (SELECT count(*) FROM ca) AS cas,
       (SELECT count(*) FROM certificate) AS certificates,
       (SELECT count(*) FROM certificate WHERE ca_id = 'dddddddd-0000-4000-8000-0000000000a1') AS authority_a,
       (SELECT count(*) FROM management_reader_grant) AS reader_grants;
