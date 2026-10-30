-- Lab-only: sealed audit chain (migration 0027, ADR-0006 condition 5).
-- Sealing is idempotent and validated, the chain is append-only (also in
-- replica mode, also for a superuser), the functions run with definer
-- rights and a pinned search_path, and each role holds only its function.
-- Verification itself is in crates/pki-core/tests/audit_chain_postgres.rs.
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

SELECT pg_temp.must((SELECT bool_and(p.prosecdef
                              AND p.proowner = 'trust_audit_owner'::regrole
                              AND p.proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp'])
                     FROM pg_proc p
                     WHERE p.oid IN ('seal_audit_chain(integer)'::regprocedure,
                                     'audit_chain_entries(bigint,integer)'::regprocedure,
                                     'unsealed_audit_records(interval)'::regprocedure)),
                    'chain functions are SECURITY DEFINER with pinned search_path');

INSERT INTO audit_event(event_id, actor_id, event_type, decision)
VALUES (gen_random_uuid(), 'chain-sql', 'audit.chain.probe', 'ok');
SELECT pg_temp.must(unsealed_audit_records('0') > 0, 'new record unsealed');
SELECT pg_temp.expect_err('SELECT seal_audit_chain(0)', '22023');
SELECT pg_temp.expect_err('SELECT seal_audit_chain(NULL)', '22023');
SELECT pg_temp.expect_err('SELECT seal_audit_chain(100001)', '22023');
SELECT seal_audit_chain(100000);
SELECT pg_temp.must(unsealed_audit_records('0') = 0, 'everything sealed');
SELECT pg_temp.must(seal_audit_chain(100000) = 0, 'sealing again adds nothing');
SELECT pg_temp.must(NOT EXISTS (
                        SELECT 1 FROM (SELECT seq, previous,
                                              lag(entry_hash) OVER (ORDER BY seq) AS prior,
                                              lag(seq) OVER (ORDER BY seq) AS prior_seq
                                       FROM audit_chain_entry) x
                        WHERE (prior_seq IS NULL AND (seq <> 1 OR previous <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea))
                           OR (prior_seq IS NOT NULL AND (seq <> prior_seq + 1 OR previous <> prior))),
                    'contiguous linked chain from a zero genesis');

-- Append-only, even for a superuser and in replica mode.
SELECT pg_temp.expect_err('UPDATE audit_chain_entry SET sealed_at = now()', '23001');
SELECT pg_temp.expect_err('DELETE FROM audit_chain_entry', '23001');
SELECT pg_temp.expect_err('TRUNCATE audit_chain_entry', '23001');
SET LOCAL session_replication_role = replica;
SELECT pg_temp.expect_err('DELETE FROM audit_chain_entry', '23001');
SET LOCAL session_replication_role = origin;

-- Roles: the sealer seals, the verifier reads, nobody writes the table.
SET LOCAL ROLE trust_audit_sealer;
SELECT seal_audit_chain(1);
SELECT pg_temp.expect_err('SELECT * FROM audit_chain_entries(0, 1)', '42501');
SELECT pg_temp.expect_err('SELECT count(*) FROM audit_chain_entry', '42501');
RESET ROLE;
SET LOCAL ROLE trust_audit_verifier;
SELECT pg_temp.must((SELECT count(*) FROM audit_chain_entries(0, 10)) > 0, 'verifier reads');
SELECT pg_temp.expect_err('SELECT seal_audit_chain(1)', '42501');
SELECT pg_temp.expect_err(
    'INSERT INTO audit_chain_entry (seq, source, source_key, event_sha256, previous, entry_hash)
     VALUES (999999, ''audit_event'', ''x'', ''\x00''::bytea, ''\x00''::bytea, ''\x00''::bytea)', '42501');
RESET ROLE;
DO $svc$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_crl_signer',
                             'trust_crl_operator', 'trust_ca_admin'] LOOP
        EXECUTE format('SET LOCAL ROLE %I', r);
        PERFORM pg_temp.expect_err('SELECT seal_audit_chain(1)', '42501');
        PERFORM pg_temp.expect_err('SELECT * FROM audit_chain_entries(0, 1)', '42501');
        PERFORM pg_temp.expect_err('SELECT unsealed_audit_records(''0'')', '42501');
        RESET ROLE;
    END LOOP;
END $svc$;

ROLLBACK;
