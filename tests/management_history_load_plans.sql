-- EXPLAIN (ANALYZE, BUFFERS) of every filtered history query of the read-only
-- management API, on the load fixture (tests/management_history_load_seed.sql).
-- LAB ONLY, disposable data. Run as the database owner (a member of
-- trust_api_reader):
--   psql "$DATABASE_URL" -X -v ON_ERROR_STOP=1 -f tests/management_history_load_plans.sql
-- Everything runs in one READ ONLY transaction under SET ROLE
-- trust_api_reader, through the security-barrier views and the server-owned
-- grant, with the SQL text of crates/management-api/src/main.rs. Parameters
-- are written as literals: the Rust client sends each query as an unnamed
-- statement, which PostgreSQL plans with the actual parameter values.
-- The script also fails if the reader can see the ungranted authority C.
\set ON_ERROR_STOP on
\set a 'cccccccc-0000-4000-8000-00000000000a'
\set c 'cccccccc-0000-4000-8000-00000000000c'
\set iss 'https://issuer.load.invalid'
\set sub 'reader'
-- The CA ids a token names (the API passes up to 1024 of them): here all 302.
SELECT '{' || string_agg(ca_id::text, ',' ORDER BY ca_id) || '}' AS token_cas FROM ca \gset
BEGIN READ ONLY;
SET LOCAL ROLE trust_api_reader;
SET LOCAL statement_timeout = '30s';

-- Isolation: the reader holds no grant on C and reads nothing of it.
SELECT EXISTS(SELECT 1 FROM management_reader_scope
              WHERE issuer = :'iss' AND subject = :'sub' AND ca_id = :'c') AS c_granted \gset
\if :c_granted
  \echo 'FAIL: the reader is granted authority C'
  SELECT 1/0;
\endif
SELECT count(*) AS c_rows FROM management_certificate WHERE ca_id = :'c' AND EXISTS
  (SELECT 1 FROM management_reader_scope WHERE issuer = :'iss' AND subject = :'sub' AND ca_id = :'c') \gset
SELECT count(*) AS c_audit FROM management_audit WHERE ca_id = :'c' AND EXISTS
  (SELECT 1 FROM management_reader_scope WHERE issuer = :'iss' AND subject = :'sub' AND ca_id = :'c') \gset
SELECT (:c_rows + :c_audit) = 0 AS isolated \gset
\if :isolated
  \echo 'ISOLATION: authority C invisible to the reader (0 certificates, 0 events)'
\else
  \echo 'FAIL: rows of authority C reached the reader'
  SELECT 1/0;
\endif

-- Cursors as the API would hand them out (newest first): the boundary row
-- in the middle of A's history and 200 rows before its end, whatever the
-- fixture size.
SELECT count(*) / 2 AS cert_mid_off, greatest(count(*) - 200, 0) AS cert_deep_off
FROM management_certificate WHERE ca_id = :'a' \gset
SELECT count(*) / 2 AS audit_mid_off, greatest(count(*) - 200, 0) AS audit_deep_off
FROM management_audit WHERE ca_id = :'a' \gset
SELECT signed_at AS cert_mid_t, request_id AS cert_mid_id FROM management_certificate
WHERE ca_id = :'a' ORDER BY signed_at DESC, request_id DESC OFFSET :cert_mid_off LIMIT 1 \gset
SELECT signed_at AS cert_deep_t, request_id AS cert_deep_id FROM management_certificate
WHERE ca_id = :'a' ORDER BY signed_at DESC, request_id DESC OFFSET :cert_deep_off LIMIT 1 \gset
SELECT recorded_at AS audit_mid_t, event_id AS audit_mid_id FROM management_audit
WHERE ca_id = :'a' ORDER BY recorded_at DESC, event_id DESC OFFSET :audit_mid_off LIMIT 1 \gset
SELECT recorded_at AS audit_deep_t, event_id AS audit_deep_id FROM management_audit
WHERE ca_id = :'a' ORDER BY recorded_at DESC, event_id DESC OFFSET :audit_deep_off LIMIT 1 \gset
\echo 'FIXTURE: authority A rows (certificates, audit events): ' :cert_mid_off ' x2, ' :audit_mid_off ' x2'

-- ---------------------------------------------------------------- grant
\echo '### G1 grant check'
EXPLAIN (ANALYZE, BUFFERS)
SELECT EXISTS(SELECT 1 FROM management_reader_scope WHERE issuer=:'iss' AND subject=:'sub' AND ca_id=:'a');

-- ---------------------------------------------------------- certificates
\set certsel 'SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns FROM management_certificate WHERE ca_id=' :'a' ' AND EXISTS (SELECT 1 FROM management_reader_scope WHERE issuer=' :'iss' ' AND subject=' :'sub' ' AND ca_id=' :'a' ')'

\echo '### C1 certificates, no filter, newest first, first page'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C2 certificates, no filter, oldest first, first page'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) > (NULL, NULL))
  ORDER BY signed_at ASC, request_id ASC LIMIT 101;

\echo '### C3 certificates, CN prefix svc- (1%)'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  AND lower(subject_cn) LIKE 'svc-%' ESCAPE '\'
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C4 certificates, CN prefix host-1 (about 10%)'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  AND lower(subject_cn) LIKE 'host-1%' ESCAPE '\'
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C5 certificates, CN prefix matching one row (host-123457 exists from big >= 123457)'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  AND lower(subject_cn) LIKE 'host-123457.%' ESCAPE '\'
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C6 certificates, exact DNS SAN alt-7 (0.1%)'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name) WHERE lower(entry.name) = 'alt-7.lab.invalid')
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C7 certificates, exact DNS SAN with no match'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name) WHERE lower(entry.name) = 'absent.lab.invalid')
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C8 certificates, notAfter before an early cutoff (about 5%)'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  AND not_after < '2025-07-25T00:00:00.000Z'
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C9 certificates, CN + SAN + notAfter combined'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (NULL::text IS NULL OR (signed_at, request_id) < (NULL, NULL))
  AND lower(subject_cn) LIKE 'host-%' ESCAPE '\'
  AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name) WHERE lower(entry.name) = 'alt-7.lab.invalid')
  AND not_after < '2026-01-01T00:00:00.000Z'
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C10 certificates, no filter, cursor in the middle'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (:'cert_mid_t'::text IS NULL OR (signed_at, request_id) < (:'cert_mid_t', :'cert_mid_id'))
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C11 certificates, no filter, cursor near the end'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (:'cert_deep_t'::text IS NULL OR (signed_at, request_id) < (:'cert_deep_t', :'cert_deep_id'))
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C12 certificates, SAN alt-7, cursor in the middle'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (:'cert_mid_t'::text IS NULL OR (signed_at, request_id) < (:'cert_mid_t', :'cert_mid_id'))
  AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name) WHERE lower(entry.name) = 'alt-7.lab.invalid')
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### C13 certificate detail by serial (row 123456)'
EXPLAIN (ANALYZE, BUFFERS)
SELECT ca_id,serial_hex,fingerprint_sha256,request_id,state,signed_at,published_at,subject_cn,not_before,not_after,san_dns
FROM management_certificate WHERE ca_id=:'a' AND serial_hex='010001e240' AND EXISTS
(SELECT 1 FROM management_reader_scope WHERE issuer=:'iss' AND subject=:'sub' AND ca_id=:'a');

-- ------------------------------------------------------------------ audit
\set auditsel 'SELECT event_id,ca_id,event_type,decision,policy_version,recorded_at FROM management_audit WHERE ca_id=' :'a' ' AND EXISTS (SELECT 1 FROM management_reader_scope WHERE issuer=' :'iss' ' AND subject=' :'sub' ' AND ca_id=' :'a' ')'

\echo '### A1 audit, no filter, newest first, first page'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (NULL::text IS NULL OR (recorded_at, event_id) < (NULL, NULL))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND (NULL::text IS NULL OR event_type = NULL) AND (NULL::text IS NULL OR decision = NULL)
  AND (NULL::text IS NULL OR policy_version = NULL)
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A2 audit, event_type certificate.revoked (1%)'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (NULL::text IS NULL OR (recorded_at, event_id) < (NULL, NULL))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND ('certificate.revoked'::text IS NULL OR event_type = 'certificate.revoked')
  AND (NULL::text IS NULL OR decision = NULL) AND (NULL::text IS NULL OR policy_version = NULL)
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A3 audit, decision DENY (5%)'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (NULL::text IS NULL OR (recorded_at, event_id) < (NULL, NULL))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND (NULL::text IS NULL OR event_type = NULL) AND ('DENY'::text IS NULL OR decision = 'DENY')
  AND (NULL::text IS NULL OR policy_version = NULL)
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A4 audit, policy_version v3 (25%)'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (NULL::text IS NULL OR (recorded_at, event_id) < (NULL, NULL))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND (NULL::text IS NULL OR event_type = NULL) AND (NULL::text IS NULL OR decision = NULL)
  AND ('v3'::text IS NULL OR policy_version = 'v3')
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A5 audit, one-day recorded window early in the history'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (NULL::text IS NULL OR (recorded_at, event_id) < (NULL, NULL))
  AND ('2024-07-02T00:00:00.000Z'::text IS NULL OR recorded_at >= '2024-07-02T00:00:00.000Z')
  AND ('2024-07-03T00:00:00.000Z'::text IS NULL OR recorded_at < '2024-07-03T00:00:00.000Z')
  AND (NULL::text IS NULL OR event_type = NULL) AND (NULL::text IS NULL OR decision = NULL)
  AND (NULL::text IS NULL OR policy_version = NULL)
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A6 audit, window + event_type + decision + policy_version combined'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (NULL::text IS NULL OR (recorded_at, event_id) < (NULL, NULL))
  AND ('2024-07-01T00:00:00.000Z'::text IS NULL OR recorded_at >= '2024-07-01T00:00:00.000Z')
  AND ('2024-07-15T00:00:00.000Z'::text IS NULL OR recorded_at < '2024-07-15T00:00:00.000Z')
  AND ('certificate.revoked'::text IS NULL OR event_type = 'certificate.revoked')
  AND ('ALLOW'::text IS NULL OR decision = 'ALLOW') AND ('v4'::text IS NULL OR policy_version = 'v4')
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A7 audit, no filter, cursor in the middle'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (:'audit_mid_t'::text IS NULL OR (recorded_at, event_id) < (:'audit_mid_t', :'audit_mid_id'))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND (NULL::text IS NULL OR event_type = NULL) AND (NULL::text IS NULL OR decision = NULL)
  AND (NULL::text IS NULL OR policy_version = NULL)
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A8 audit, no filter, cursor near the end'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (:'audit_deep_t'::text IS NULL OR (recorded_at, event_id) < (:'audit_deep_t', :'audit_deep_id'))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND (NULL::text IS NULL OR event_type = NULL) AND (NULL::text IS NULL OR decision = NULL)
  AND (NULL::text IS NULL OR policy_version = NULL)
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### A9 audit, event_type, cursor in the middle, oldest first'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (:'audit_mid_t'::text IS NULL OR (recorded_at, event_id) > (:'audit_mid_t', :'audit_mid_id'))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND ('certificate.revoked'::text IS NULL OR event_type = 'certificate.revoked')
  AND (NULL::text IS NULL OR decision = NULL) AND (NULL::text IS NULL OR policy_version = NULL)
  ORDER BY recorded_at ASC, event_id ASC LIMIT 101;

-- ---------------------------------------------------------------- CA list
\echo '### L1 CA list, first page (251 granted of 302)'
EXPLAIN (ANALYZE, BUFFERS)
SELECT c.ca_id,c.parent_ca_id,c.display_name,c.policy_version,c.created_at
FROM management_ca c JOIN management_reader_scope g ON g.ca_id=c.ca_id
WHERE c.ca_id=ANY(:'token_cas'::text[]) AND g.issuer=:'iss' AND g.subject=:'sub'
AND (NULL::text IS NULL OR (c.display_name,c.ca_id) > (NULL,NULL))
AND (NULL::text IS NULL OR lower(c.display_name) LIKE NULL ESCAPE '\' OR lower(c.policy_version) LIKE NULL ESCAPE '\')
ORDER BY c.display_name,c.ca_id LIMIT 101;

\echo '### L2 CA list, second page, search load ca%'
EXPLAIN (ANALYZE, BUFFERS)
SELECT c.ca_id,c.parent_ca_id,c.display_name,c.policy_version,c.created_at
FROM management_ca c JOIN management_reader_scope g ON g.ca_id=c.ca_id
WHERE c.ca_id=ANY(:'token_cas'::text[]) AND g.issuer=:'iss' AND g.subject=:'sub'
AND ('Load CA 100'::text IS NULL OR (c.display_name,c.ca_id) > ('Load CA 100','cccccccc-0000-4000-8000-0000000000c8'))
AND ('load ca%'::text IS NULL OR lower(c.display_name) LIKE 'load ca%' ESCAPE '\' OR lower(c.policy_version) LIKE 'load ca%' ESCAPE '\')
ORDER BY c.display_name,c.ca_id LIMIT 101;

-- ------------------------------------------------- sliced reads (0016)
-- The API reads a page in time slices on the views' window columns (see
-- docs/operations/lab-history-time-window.md): the same SELECT plus a range
-- outward from the cursor. A bounded slice must reach the window index
-- through the barrier; the open last slice is the unsliced query above with
-- one more leakproof bound.
\set wslice ' AND signed_at_window <= ' :'cert_mid_t' '::text::timestamp - 0::float8 * interval ''1 second'' AND signed_at_window > ' :'cert_mid_t' '::text::timestamp - 3600::float8 * interval ''1 second'''
\set aslice ' AND recorded_at_window <= ' :'audit_mid_t' '::text::timestamp - 0::float8 * interval ''1 second'' AND recorded_at_window > ' :'audit_mid_t' '::text::timestamp - 3600::float8 * interval ''1 second'''

\echo '### W1 certificates, no filter, cursor in the middle, first slice (1 hour)'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (:'cert_mid_t'::text IS NULL OR (signed_at, request_id) < (:'cert_mid_t', :'cert_mid_id'))
  :wslice
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

\echo '### W2 audit, no filter, cursor in the middle, first slice (1 hour)'
EXPLAIN (ANALYZE, BUFFERS) :auditsel
  AND (:'audit_mid_t'::text IS NULL OR (recorded_at, event_id) < (:'audit_mid_t', :'audit_mid_id'))
  AND (NULL::text IS NULL OR recorded_at >= NULL) AND (NULL::text IS NULL OR recorded_at < NULL)
  AND (NULL::text IS NULL OR event_type = NULL)
  AND (NULL::text IS NULL OR decision = NULL) AND (NULL::text IS NULL OR policy_version = NULL)
  :aslice
  ORDER BY recorded_at DESC, event_id DESC LIMIT 101;

\echo '### W3 certificates, SAN with no match, cursor in the middle, open last slice (beyond 85 hours)'
EXPLAIN (ANALYZE, BUFFERS) :certsel
  AND (:'cert_mid_t'::text IS NULL OR (signed_at, request_id) < (:'cert_mid_t', :'cert_mid_id'))
  AND EXISTS (SELECT 1 FROM unnest(san_dns) AS entry(name) WHERE lower(entry.name) = 'absent.lab.invalid')
  AND signed_at_window <= :'cert_mid_t'::text::timestamp - 306000::float8 * interval '1 second'
  ORDER BY signed_at DESC, request_id DESC LIMIT 101;

-- Fail if a bounded slice stops reaching its window index.
SELECT :'certsel' || ' AND (signed_at, request_id) < (' || quote_literal(:'cert_mid_t') || ', '
       || quote_literal(:'cert_mid_id') || ')' || :'wslice'
       || ' ORDER BY signed_at DESC, request_id DESC LIMIT 101' AS w1_sql \gset
SELECT set_config('trust.w1_sql', :'w1_sql', true) IS NOT NULL AS w1_set \gset
SELECT :'auditsel' || ' AND (recorded_at, event_id) < (' || quote_literal(:'audit_mid_t') || ', '
       || quote_literal(:'audit_mid_id') || ')' || :'aslice'
       || ' ORDER BY recorded_at DESC, event_id DESC LIMIT 101' AS w2_sql \gset
SELECT set_config('trust.w2_sql', :'w2_sql', true) IS NOT NULL AS w2_set \gset
DO $slice$
DECLARE
    line text;
    plan text;
    sql text;
    index_name text;
BEGIN
    FOR sql, index_name IN VALUES
        (current_setting('trust.w1_sql'), 'certificate_management_history_window'),
        (current_setting('trust.w2_sql'), 'audit_event_management_history_window')
    LOOP
        plan := '';
        FOR line IN EXECUTE 'EXPLAIN ' || sql LOOP
            plan := plan || line || E'\n';
        END LOOP;
        IF position(index_name IN plan) = 0 THEN
            RAISE EXCEPTION 'a bounded history slice does not use %:%', index_name, plan;
        END IF;
    END LOOP;
END
$slice$;
\echo 'SLICES: bounded certificate and audit slices use their window indexes'

ROLLBACK;
