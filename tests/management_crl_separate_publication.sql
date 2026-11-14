-- Migration 0043: CRL publication separated from the management API
-- (ADR-0030). Run as the migration owner after 0043 on a disposable database;
-- every change is rolled back. Before 0043 the first statement fails.
BEGIN;

SELECT management_crl_separate_publication_version();

CREATE FUNCTION pg_temp.expect_state(p_sql text, p_state text) RETURNS void
LANGUAGE plpgsql AS $fn$
BEGIN
    EXECUTE p_sql;
    RAISE EXCEPTION 'expected SQLSTATE % from: %', p_state, p_sql USING ERRCODE = 'TP000';
EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE <> p_state THEN
        RAISE EXCEPTION 'expected SQLSTATE %, got % (%) from: %', p_state, SQLSTATE, SQLERRM, p_sql;
    END IF;
END
$fn$;
GRANT EXECUTE ON FUNCTION pg_temp.expect_state(text, text) TO PUBLIC;

-- The feed is the public view, with the issuer certificate to verify each CRL.
DO $test$ BEGIN
    IF EXISTS (
        (SELECT ca_id, crl_number, crl_der FROM crl_publisher_feed
         EXCEPT SELECT ca_id, crl_number, crl_der FROM public_crl_latest)
        UNION ALL
        (SELECT ca_id, crl_number, crl_der FROM public_crl_latest
         EXCEPT SELECT ca_id, crl_number, crl_der FROM crl_publisher_feed)) THEN
        RAISE EXCEPTION 'the publisher feed differs from the public view';
    END IF;
    IF EXISTS (SELECT 1 FROM crl_publisher_feed f
               JOIN ca_issuer_certificate c ON c.ca_id::text = f.ca_id
               WHERE f.issuer_certificate_der <> c.certificate_der) THEN
        RAISE EXCEPTION 'the feed carries another issuer certificate';
    END IF;
END $test$;

-- The API's reader serves nothing public any more; the writer reads no feed.
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state('SELECT 1 FROM public_crl_latest', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM crl_publisher_feed', '42501');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM crl_publisher_feed', '42501');
RESET ROLE;

-- The publisher reads its feed and nothing else: no table, no other view, no
-- function that writes.
SET LOCAL ROLE trust_crl_publisher;
SELECT count(*) >= 0 AS feed_readable FROM crl_publisher_feed;
SELECT pg_temp.expect_state('SELECT 1 FROM crl_document', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM public_crl_latest', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM management_crl_status', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM lab_signer_crl_intent', '42501');
SELECT pg_temp.expect_state($$SELECT * FROM begin_crl_publication_lab('i', 's', gen_random_uuid(), gen_random_uuid(), decode(repeat('00', 32), 'hex'))$$, '42501');
RESET ROLE;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'm', 'f')
                 AND has_table_privilege('trust_crl_publisher', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')) THEN
        RAISE EXCEPTION 'the publisher holds a table privilege';
    END IF;
    IF (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'trust_crl_publisher') THEN
        RAISE EXCEPTION 'the publisher group role can log in';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: CRL publication separated from the management API (0043)'
