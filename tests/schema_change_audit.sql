-- Lab-only: schema-change audit (migration 0026, ADR-0006 condition 3).
-- DDL by any role is recorded (append-only, no SQL text), temporary objects
-- are not, replica mode does not silence it, services cannot read, write or
-- acknowledge it, and reviewed migrations reset the unreviewed count.
-- Single transaction, rolled back. Run as a superuser.
\set ON_ERROR_STOP 1
BEGIN;

CREATE FUNCTION pg_temp.expect_err(p_sql TEXT, p_state TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE <> p_state THEN
            RAISE EXCEPTION 'expected SQLSTATE % but got % (%) for: %',
                p_state, SQLSTATE, SQLERRM, p_sql;
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'expected SQLSTATE % but statement succeeded: %', p_state, p_sql;
END $f$;

CREATE FUNCTION pg_temp.must(p_ok BOOLEAN, p_what TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'assertion failed: %', p_what;
    END IF;
END $f$;

-- Installation: both event triggers fire always, the recorder runs with
-- definer rights and a pinned search_path.
SELECT pg_temp.must((SELECT count(*) = 2 FROM pg_event_trigger
                     WHERE evtname IN ('schema_change_audit_ddl', 'schema_change_audit_drop')
                       AND evtenabled = 'A'), 'event triggers enabled ALWAYS');
SELECT pg_temp.must((SELECT p.prosecdef
                            AND p.proowner = 'trust_schema_audit_owner'::regrole
                            AND p.proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
                     FROM pg_proc p WHERE p.oid = 'record_schema_change()'::regprocedure),
                    'recorder is SECURITY DEFINER with pinned search_path');
SELECT pg_temp.must((SELECT p.prosecdef
                            AND p.proowner = 'trust_schema_audit_owner'::regrole
                            AND p.proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp']
                     FROM pg_proc p WHERE p.oid = 'unreviewed_schema_changes()'::regprocedure),
                    'report is SECURITY DEFINER with pinned search_path');
SELECT pg_temp.must((SELECT NOT p.prosecdef FROM pg_proc p
                     WHERE p.oid = 'acknowledge_schema_changes(text)'::regprocedure),
                    'acknowledgement runs with the caller''s rights');
-- No column can hold statement text.
SELECT pg_temp.must((SELECT array_agg(attname::text ORDER BY attnum) FROM pg_attribute
                     WHERE attrelid = 'schema_change_audit'::regclass AND attnum > 0
                       AND NOT attisdropped)
                    = ARRAY['change_seq', 'recorded_at', 'event', 'command_tag', 'object_type',
                            'schema_name', 'object_identity', 'session_user_name',
                            'transaction_id'],
                    'audit columns (no statement text)');

-- Start from a reviewed state.
SELECT acknowledge_schema_changes('9999_test_baseline');
SELECT pg_temp.must(unreviewed_schema_changes() = 0, 'baseline reviewed');

-- Superuser DDL: create, alter, drop are recorded with the session user.
CREATE TABLE audit_probe (a INT);
ALTER TABLE audit_probe ADD COLUMN b INT;
DROP TABLE audit_probe;
SELECT pg_temp.must((SELECT array_agg(command_tag || ':' || object_identity ORDER BY change_seq)
                     FROM schema_change_audit
                     WHERE object_type = 'table' AND object_identity = 'public.audit_probe'
                       AND session_user_name = session_user
                       AND transaction_id = pg_current_xact_id())
                    = ARRAY['CREATE TABLE:public.audit_probe', 'ALTER TABLE:public.audit_probe',
                            'DROP TABLE:public.audit_probe'],
                    'create/alter/drop recorded');
SELECT pg_temp.must(unreviewed_schema_changes() >= 3, 'changes unreviewed until acknowledged');

-- Temporary objects are not recorded.
CREATE TEMP TABLE audit_temp_probe (a INT);
DROP TABLE audit_temp_probe;
SELECT pg_temp.must(NOT EXISTS (SELECT 1 FROM schema_change_audit
                                WHERE object_identity LIKE '%audit_temp_probe%'),
                    'temporary objects not recorded');

-- Replica mode does not silence the audit.
SET LOCAL session_replication_role = replica;
CREATE TABLE audit_replica_probe (a INT);
SELECT pg_temp.must(EXISTS (SELECT 1 FROM schema_change_audit
                            WHERE object_identity = 'public.audit_replica_probe'),
                    'DDL recorded in replica mode');
-- ... and the append-only guards still hold there.
SELECT pg_temp.expect_err('DELETE FROM schema_change_audit', '23001');
SET LOCAL session_replication_role = origin;

-- A non-superuser's DDL is recorded too (definer rights), under the login.
CREATE ROLE audit_probe_ddl NOLOGIN;
GRANT CREATE ON SCHEMA public TO audit_probe_ddl;
SET LOCAL ROLE audit_probe_ddl;
CREATE TABLE audit_role_probe (a INT);
RESET ROLE;
SELECT pg_temp.must(EXISTS (SELECT 1 FROM schema_change_audit
                            WHERE object_identity = 'public.audit_role_probe'
                              AND session_user_name = session_user),
                    'non-superuser DDL recorded under the session user');
SELECT pg_temp.must(EXISTS (SELECT 1 FROM schema_change_audit
                            WHERE command_tag = 'GRANT' AND object_type = 'SCHEMA'),
                    'GRANT recorded (object type only)');

-- Append-only, even for a superuser.
SELECT pg_temp.expect_err('UPDATE schema_change_audit SET command_tag = ''x''', '23001');
SELECT pg_temp.expect_err('DELETE FROM schema_change_audit', '23001');
SELECT pg_temp.expect_err('TRUNCATE schema_change_audit', '23001');
SELECT pg_temp.expect_err('UPDATE schema_change_review SET migration_ref = ''0000x''', '23001');
SELECT pg_temp.expect_err('DELETE FROM schema_change_review', '23001');
SELECT pg_temp.expect_err('TRUNCATE schema_change_review', '23001');

-- Disabling a guard is itself a recorded change.
ALTER TABLE schema_change_audit DISABLE TRIGGER schema_change_audit_append_only;
SELECT pg_temp.must(EXISTS (SELECT 1 FROM schema_change_audit
                            WHERE command_tag = 'ALTER TABLE'
                              AND object_identity = 'public.schema_change_audit'),
                    'disabling the guard is recorded');
ALTER TABLE schema_change_audit ENABLE ALWAYS TRIGGER schema_change_audit_append_only;

-- Service roles: no direct access, no acknowledgement; only the CRL
-- operator reads the unreviewed count.
DO $svc$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_crl_signer',
                             'trust_crl_operator', 'trust_ca_admin'] LOOP
        EXECUTE format('SET LOCAL ROLE %I', r);
        PERFORM pg_temp.expect_err('SELECT count(*) FROM schema_change_audit', '42501');
        PERFORM pg_temp.expect_err('SELECT count(*) FROM schema_change_review', '42501');
        PERFORM pg_temp.expect_err(
            'INSERT INTO schema_change_review (reviewed_up_to, migration_ref, reviewed_by)
             VALUES (2147483647, ''9999x'', ''svc'')', '42501');
        PERFORM pg_temp.expect_err('SELECT acknowledge_schema_changes(''9999_svc'')', '42501');
        IF r = 'trust_crl_operator' THEN
            PERFORM pg_temp.must(unreviewed_schema_changes() > 0, 'operator sees unreviewed changes');
        ELSE
            PERFORM pg_temp.expect_err('SELECT unreviewed_schema_changes()', '42501');
        END IF;
        RESET ROLE;
    END LOOP;
END $svc$;

-- A reviewed migration acknowledges everything recorded so far.
SELECT pg_temp.expect_err('SELECT acknowledge_schema_changes(''not a ref'')', '23514');
SELECT acknowledge_schema_changes('9999_test_review');
SELECT pg_temp.must(unreviewed_schema_changes() = 0, 'acknowledged');
SELECT pg_temp.must((SELECT reviewed_by = session_user::text FROM schema_change_review
                     ORDER BY review_seq DESC LIMIT 1), 'reviewer recorded');
DROP TABLE audit_role_probe;
SELECT pg_temp.must(unreviewed_schema_changes() > 0, 'later change unreviewed again');

ROLLBACK;
