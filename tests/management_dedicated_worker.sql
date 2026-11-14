-- Migration 0044: the dedicated background worker (ADR-0037). Run as the
-- migration owner after 0045 (whose read-only metrics the role also holds,
-- ADR-0038) on a disposable database; every change is
-- rolled back. Before 0044 the first statement fails.
BEGIN;

SELECT management_dedicated_worker_version();

CREATE FUNCTION pg_temp.expect_state(p_sql text, p_state text) RETURNS void
LANGUAGE plpgsql AS $fn$
BEGIN
    EXECUTE p_sql;
    -- A distinct code: success must never pass for an expected P0001.
    RAISE EXCEPTION 'expected SQLSTATE % from: %', p_state, p_sql USING ERRCODE = 'TP000';
EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE <> p_state THEN
        RAISE EXCEPTION 'expected SQLSTATE %, got % (%) from: %', p_state, SQLSTATE, SQLERRM, p_sql;
    END IF;
END
$fn$;

-- The role itself: NOLOGIN, no attribute, no table, exactly its functions.
DO $test$
DECLARE
    expected text[] := ARRAY[
        'begin_crl_publication_lab(text,text,uuid,uuid,bytea)',
        'crl_publication_entries_lab(text,text,uuid,uuid)',
        'crl_renewal_candidates_lab(text,text)',
        'management_dedicated_worker_version()',
        'management_operational_metrics_version()',
        'mark_crl_signing_uncertain_lab(text,text,uuid,uuid)',
        'operational_metrics_lab()',
        'record_crl_signing_intent_lab(text,text,uuid,uuid,bytea)',
        'seal_audit_events_lab(integer)',
        'store_crl_lab(text,text,uuid,uuid,bytea)'];
    actual text[];
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'trust_worker' AND NOT rolcanlogin
                   AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls) THEN
        RAISE EXCEPTION 'trust_worker must be a plain NOLOGIN role';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
                 AND has_table_privilege('trust_worker', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')) THEN
        RAISE EXCEPTION 'trust_worker reaches a table or view';
    END IF;
    -- Functions it may run beyond PUBLIC's (an EXECUTE granted to PUBLIC is
    -- everyone's and not counted).
    SELECT array_agg(f ORDER BY f) INTO actual
    FROM (SELECT regexp_replace(p.oid::regprocedure::text, ' ', '', 'g') AS f
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'public'
      AND has_function_privilege('trust_worker', p.oid, 'EXECUTE')
      AND NOT has_function_privilege('public', p.oid, 'EXECUTE')) AS granted;
    IF actual IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'trust_worker functions: %', actual;
    END IF;
    -- The API's writer lost sealing and the renewal candidates.
    IF has_function_privilege('trust_profile_writer', 'seal_audit_events_lab(integer)', 'EXECUTE')
       OR has_function_privilege('trust_profile_writer', 'crl_renewal_candidates_lab(text,text)', 'EXECUTE') THEN
        RAISE EXCEPTION 'the writer can still seal or list renewal candidates';
    END IF;
    IF has_function_privilege('public', 'session_is_worker()', 'EXECUTE') THEN
        RAISE EXCEPTION 'session_is_worker is public';
    END IF;
END $test$;

-- A CA granted to the renewer. The positive renewal path is in
-- management_crl_renewal.sql and management_crl_on_revocation.sql.
INSERT INTO ca (ca_id, display_name, policy_version)
VALUES ('c7c7c7c7-0000-4000-8000-00000000000c', 'Worker CA', 'v1');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('urn:trust-platform:system', 'crl-renewer', 'c7c7c7c7-0000-4000-8000-00000000000c', 'crl-publisher');
CREATE ROLE trust_test_worker LOGIN;
GRANT trust_worker TO trust_test_worker;
CREATE ROLE trust_test_not_worker LOGIN;
GRANT trust_profile_writer TO trust_test_not_worker;

-- session_is_worker follows the login, not SET ROLE: the owner (a
-- superuser) setting the role is not a worker, nor is a writer login.
DO $test$ BEGIN
    IF session_is_worker() THEN RAISE EXCEPTION 'the owner is a worker by implication'; END IF;
END $test$;
SET LOCAL ROLE trust_worker;
DO $test$ BEGIN
    -- current_user is trust_worker, the session is still the owner's.
    PERFORM pg_temp.expect_state($$SELECT * FROM begin_crl_publication_lab('urn:trust-platform:system', 'crl-renewer',
        'c7c7c7c7-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('44', 32), 'hex'))$$, '42501');
    IF EXISTS (SELECT 1 FROM crl_renewal_candidates_lab('urn:trust-platform:system', 'crl-renewer')) THEN
        RAISE EXCEPTION 'SET ROLE trust_worker made the owner a worker';
    END IF;
END $test$;
RESET ROLE;

SET LOCAL SESSION AUTHORIZATION trust_test_not_worker;
DO $test$ BEGIN
    PERFORM pg_temp.expect_state($$SELECT * FROM begin_crl_publication_lab('urn:trust-platform:system', 'crl-renewer',
        'c7c7c7c7-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('44', 32), 'hex'))$$, '42501');
    PERFORM pg_temp.expect_state($$SELECT * FROM seal_audit_events_lab(10)$$, '42501');
END $test$;
RESET SESSION AUTHORIZATION;

-- The worker login: the system principal only, and only with its grant.
SET LOCAL SESSION AUTHORIZATION trust_test_worker;
DO $test$ BEGIN
    -- session_is_worker is not callable by the login itself.
    PERFORM pg_temp.expect_state($$SELECT session_is_worker()$$, '42501');
    -- Another system subject, or a human issuer, is refused.
    PERFORM pg_temp.expect_state($$SELECT * FROM begin_crl_publication_lab('urn:trust-platform:system', 'someone-else',
        'c7c7c7c7-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('44', 32), 'hex'))$$, '42501');
    PERFORM pg_temp.expect_state($$SELECT * FROM begin_crl_publication_lab('https://issuer.invalid', 'crl-renewer',
        'c7c7c7c7-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('44', 32), 'hex'))$$, '42501');
    IF EXISTS (SELECT 1 FROM crl_renewal_candidates_lab('https://issuer.invalid', 'crl-renewer')) THEN
        RAISE EXCEPTION 'candidates for a non-system principal';
    END IF;
    -- No table, no management view, no other writer function.
    PERFORM pg_temp.expect_state($$SELECT * FROM audit_event$$, '42501');
    PERFORM pg_temp.expect_state($$SELECT * FROM crl_document$$, '42501');
    PERFORM pg_temp.expect_state($$SELECT * FROM management_crl_status$$, '42501');
    PERFORM pg_temp.expect_state($$SELECT * FROM request_certificate_revocation_lab('https://issuer.invalid', 'x',
        'c7c7c7c7-0000-4000-8000-00000000000c', gen_random_uuid(), 1::smallint, 'r', gen_random_uuid(),
        decode(repeat('44', 32), 'hex'))$$, '42501');
    -- Sealing works from the worker.
    PERFORM 1 FROM seal_audit_events_lab(10);
    IF management_dedicated_worker_version() <> 1 THEN RAISE EXCEPTION 'unexpected version'; END IF;
END $test$;
RESET SESSION AUTHORIZATION;

ROLLBACK;
\echo 'PASS: dedicated background worker (0044)'
