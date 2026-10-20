-- Lab-only: least-privilege write model (migration 0023, ADR-0006 part A).
-- Each service capability role is exercised with SET LOCAL ROLE: no direct
-- DML on any revocation/CRL table, EXECUTE only on its own functions, and a
-- planted temporary table does not shadow the real one. Single transaction,
-- rolled back. Run as a superuser (or a member of the roles).
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

-- Same as expect_err, and the error message must also match.
CREATE FUNCTION pg_temp.expect_err_msg(p_sql TEXT, p_state TEXT, p_msg TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE <> p_state OR SQLERRM <> p_msg THEN
            RAISE EXCEPTION 'expected % "%" but got % "%" for: %',
                p_state, p_msg, SQLSTATE, SQLERRM, p_sql;
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'expected % "%" but statement succeeded: %', p_state, p_msg, p_sql;
END $f$;

-- Runs p_sql as p_role and expects p_state (NULL: must succeed).
CREATE FUNCTION pg_temp.as_role(p_role TEXT, p_sql TEXT, p_state TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    EXECUTE format('SET LOCAL ROLE %I', p_role);
    IF p_state IS NULL THEN
        EXECUTE p_sql;
    ELSE
        PERFORM pg_temp.expect_err(p_sql, p_state);
    END IF;
    RESET ROLE;
EXCEPTION WHEN OTHERS THEN
    RESET ROLE;
    RAISE EXCEPTION '% as %: %', p_sql, p_role, SQLERRM;
END $f$;

-- Fixtures (superuser): one CA, three certificates, grants, issuer.
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000a23', 'Least Privilege Lab CA', 'lab-1');
INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
SELECT ('d1d1d1d1-0000-4000-8000-000000000a2' || n)::uuid, 'c0c0c0c0-0000-4000-8000-000000000a23',
       'idem-lp-' || n, sha256(('csr-lp' || n)::bytea), 'requester', 'lab-1', 'PUBLISHED'
FROM generate_series(1, 3) n;
INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
SELECT 'c0c0c0c0-0000-4000-8000-000000000a23', decode('4' || n, 'hex'),
       ('d1d1d1d1-0000-4000-8000-000000000a2' || n)::uuid
FROM generate_series(1, 3) n;
INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                        certificate_der, signed_at)
SELECT 'c0c0c0c0-0000-4000-8000-000000000a23', decode('4' || n, 'hex'),
       ('d1d1d1d1-0000-4000-8000-000000000a2' || n)::uuid,
       sha256(('der-lp' || n)::bytea), decode('3003020101', 'hex'), now()
FROM generate_series(1, 3) n;
INSERT INTO revocation_officer_grant(issuer, subject, ca_id) VALUES
 ('https://idp.lab.invalid', 'maker',   'c0c0c0c0-0000-4000-8000-000000000a23'),
 ('https://idp.lab.invalid', 'checker', 'c0c0c0c0-0000-4000-8000-000000000a23');
INSERT INTO ca_revocation_policy(ca_id, suspension_allowed)
VALUES ('c0c0c0c0-0000-4000-8000-000000000a23', true);

-- -------------------- every service function keeps its definer settings
-- (CREATE OR REPLACE in a later migration silently resets SECURITY DEFINER
-- and the pinned search_path; 0025 found this.)
DO $t$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO bad
    FROM pg_proc p
    WHERE p.pronamespace = 'public'::regnamespace
      AND p.proname IN ('certificate_status', 'propose_certificate_status_change',
          'approve_certificate_status_change', 'reject_certificate_status_change',
          'withdraw_certificate_status_change', 'reserve_crl', 'crl_snapshot_entries',
          'record_crl_intent', 'mark_crl_uncertain', 'store_verified_crl',
          'store_reconciled_crl', 'quarantine_stale_crl_intents',
          'abandon_stale_crl_reservations', 'crl_due', 'overdue_status_changes',
          'register_ca_issuer', 'propose_ca_admin_change', 'approve_ca_admin_change',
          'reject_ca_admin_change', 'propose_credential_change',
          'approve_credential_change', 'reject_credential_change')
      AND (NOT p.prosecdef
           OR p.proowner <> 'trust_revocation_owner'::regrole
           OR NOT coalesce(p.proconfig, '{}') @> ARRAY['search_path=pg_catalog, public, pg_temp']);
    PERFORM pg_temp.must(bad IS NULL, 'service functions without definer settings: ' || coalesce(bad, ''));
END $t$;

-- Any function explicitly granted to a capability role runs with definer
-- rights and a pinned search_path, whoever owns it (covers new functions).
DO $t$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(DISTINCT p.oid::regprocedure::text, ', ') INTO bad
    FROM pg_proc p, aclexplode(p.proacl) a
    WHERE p.pronamespace = 'public'::regnamespace
      AND a.grantee::regrole::text IN ('trust_revocation_officer_api', 'trust_crl_signer',
          'trust_crl_operator', 'trust_ca_admin', 'trust_audit_sealer', 'trust_audit_verifier')
      AND (NOT p.prosecdef
           OR NOT coalesce(p.proconfig, '{}') @> ARRAY['search_path=pg_catalog, public, pg_temp']);
    PERFORM pg_temp.must(bad IS NULL, 'granted functions without definer settings: ' || coalesce(bad, ''));
END $t$;

-- ------------------------------------------------ no direct DML for anyone
DO $t$
DECLARE
    r TEXT;
    s TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_crl_signer',
                             'trust_crl_operator', 'trust_ca_admin'] LOOP
        FOREACH s IN ARRAY ARRAY[
            -- the four review bypasses
            $$INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at, actor_id)
              VALUES ('c0c0c0c0-0000-4000-8000-000000000a23', '\x43', 1, now(), 'single-actor')$$,
            $$DELETE FROM revocation WHERE reason_code = 6$$,
            $$INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content, revoked_at, reason_code)
              VALUES ('c0c0c0c0-0000-4000-8000-000000000a23', 1, '\x43', now(), 1)$$,
            $$INSERT INTO crl_publication(ca_id, crl_number, this_update, next_update, status,
                operation_ref, actor_id, entries_sha256, tbs_sha256, crl_sha256, crl_der)
              VALUES ('c0c0c0c0-0000-4000-8000-000000000a23', 99, now(), now() + interval '1 day',
                'STORED', 'forged', 'x', sha256('x'::bytea), sha256('t'::bytea),
                sha256('d'::bytea), 'd'::bytea)$$,
            -- and the rest of the protected tables
            $$UPDATE certificate_status_change SET status = 'APPROVED'$$,
            $$INSERT INTO certificate_status_change(change_id, ca_id, serial_der_content, action,
                reason_code, maker_issuer, maker_subject, status, proposed_at)
              VALUES (gen_random_uuid(), 'c0c0c0c0-0000-4000-8000-000000000a23', '\x43', 'REVOKE', 1,
                'i', 'm', 'PROPOSED', now())$$,
            $$UPDATE crl_publication SET status = 'STORED'$$,
            $$INSERT INTO revocation_officer_grant(issuer, subject, ca_id)
              VALUES ('i', 'self', 'c0c0c0c0-0000-4000-8000-000000000a23')$$,
            $$UPDATE ca_revocation_policy SET suspension_allowed = true$$,
            $$INSERT INTO ca_issuer_certificate(ca_id, certificate_der, registered_by)
              VALUES ('c0c0c0c0-0000-4000-8000-000000000a23', 'x'::bytea, 'x')$$,
            $$TRUNCATE revocation$$,
            $$SELECT count(*) FROM revocation$$,
            $$SELECT count(*) FROM certificate_status_change$$] LOOP
            PERFORM pg_temp.as_role(r, s, '42501');
        END LOOP;
    END LOOP;
END $t$;

-- ------------------------- a planted temporary table does not shadow tables
-- (first function call of the session: PL/pgSQL caches plans per session, so
-- a later call could reuse a plan made before the temporary table existed)
DO $t$
DECLARE
    ca CONSTANT TEXT := 'c0c0c0c0-0000-4000-8000-000000000a23';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    c UUID;
BEGIN
    PERFORM pg_temp.as_role('trust_revocation_officer_api', $$
        CREATE TEMP TABLE IF NOT EXISTS revocation (
            ca_id UUID, serial_der_content BYTEA, reason_code SMALLINT,
            revoked_at TIMESTAMPTZ, invalidity_at TIMESTAMPTZ, actor_id TEXT, change_id UUID)$$,
        NULL);
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format(
        $$SELECT set_config('lp.change2', propose_certificate_status_change(%L, '\x42', 'SUSPEND',
            6::smallint, NULL, %L, 'maker')::text, true)$$, ca, iss), NULL);
    c := current_setting('lp.change2')::uuid;
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format(
        $$SELECT approve_certificate_status_change(%L, %L, 'checker', 'SUSPEND', 6::smallint)$$, c, iss),
        NULL);
    PERFORM pg_temp.must((SELECT count(*) FROM public.revocation WHERE serial_der_content = '\x42'
        AND reason_code = 6) = 1, 'the hold went to public.revocation');
    PERFORM pg_temp.must((SELECT count(*) FROM pg_temp.revocation) = 0,
        'the planted temporary table stayed empty');
END $t$;

-- ------------------------------------- each role executes its functions only
DO $t$
DECLARE
    ca CONSTANT TEXT := 'c0c0c0c0-0000-4000-8000-000000000a23';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    fp BYTEA;
    c UUID;
BEGIN
    -- nobody registers the issuer directly
    PERFORM pg_temp.as_role('trust_revocation_officer_api',
        format($$SELECT register_ca_issuer(%L, 'issuer'::bytea, 'x')$$, ca), '42501');
    PERFORM pg_temp.as_role('trust_crl_signer',
        format($$SELECT register_ca_issuer(%L, 'issuer'::bytea, 'x')$$, ca), '42501');
    -- (0024: registration needs two CA admins, see ca_admin_dual_control.sql;
    -- bootstrap here as superuser)
    PERFORM pg_temp.as_role('trust_ca_admin',
        format($$SELECT register_ca_issuer(%L, 'issuer'::bytea, 'ca-admin')$$, ca), '42501');
    PERFORM register_ca_issuer(ca::uuid, 'issuer'::bytea, 'dba-bootstrap');
    fp := sha256('issuer'::bytea);

    -- officer API: full maker-checker through the functions
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format(
        $$SELECT set_config('lp.change', propose_certificate_status_change(%L, '\x41', 'REVOKE',
            1::smallint, NULL, %L, 'maker')::text, true)$$, ca, iss), NULL);
    c := current_setting('lp.change')::uuid;
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format(
        $$SELECT approve_certificate_status_change(%L, %L, 'checker', 'REVOKE', 1::smallint)$$, c, iss),
        NULL);
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format(
        $$SELECT 1 WHERE certificate_status(%L, '\x41') = 'REVOKED'$$, ca), NULL);
    PERFORM pg_temp.must((SELECT count(*) FROM public.revocation WHERE serial_der_content = '\x41'
        AND change_id = c) = 1, 'revocation written by the definer function');
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format(
        $$SELECT suspension_allowed FROM ca_revocation_policy WHERE ca_id = %L$$, ca), NULL);
    -- ... but no CRL or operator function
    PERFORM pg_temp.as_role('trust_revocation_officer_api',
        format($$SELECT reserve_crl(%L, 'x', 'op')$$, ca), '42501');
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format($$SELECT crl_due(%L)$$, ca), '42501');

    -- CRL signer: reserve, intent, store
    PERFORM pg_temp.as_role('trust_crl_signer',
        format($$SELECT reserve_crl(%L, 'crl-worker', 'lp-op-1')$$, ca), NULL);
    PERFORM pg_temp.as_role('trust_crl_signer', format(
        $$SELECT record_crl_intent(%L, 1, 'lp-op-1', sha256('tbs'::bytea),
            (SELECT entries_sha256 FROM crl_publication WHERE ca_id = %L AND crl_number = 1),
            (SELECT floor(extract(epoch FROM this_update))::bigint FROM crl_publication
               WHERE ca_id = %L AND crl_number = 1),
            (SELECT floor(extract(epoch FROM next_update))::bigint FROM crl_publication
               WHERE ca_id = %L AND crl_number = 1),
            NULL, %L)$$, ca, ca, ca, ca, fp), NULL);
    PERFORM pg_temp.as_role('trust_crl_signer', format(
        $$SELECT store_verified_crl(%L, 1, 'lp-op-1', sha256('tbs'::bytea), sha256('crl'::bytea),
            'crl'::bytea)$$, ca), NULL);
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE crl_number = 1
        AND ca_id = ca::uuid) = 'STORED', 'stored by the signer role');
    PERFORM pg_temp.as_role('trust_crl_signer', format(
        $$SELECT approve_certificate_status_change(%L, %L, 'checker', 'REVOKE', 1::smallint)$$, c, iss),
        '42501');
    PERFORM pg_temp.as_role('trust_crl_signer',
        format($$SELECT abandon_stale_crl_reservations(%L, interval '1 hour')$$, ca), '42501');

    -- CRL operator: reports and housekeeping only
    PERFORM pg_temp.as_role('trust_crl_operator', format(
        $$SELECT crl_due(%L), (SELECT count(*) FROM overdue_status_changes(%L)),
                 abandon_stale_crl_reservations(%L, interval '1 hour'),
                 quarantine_stale_crl_intents(%L, interval '1 hour')$$, ca, ca, ca, ca), NULL);
    PERFORM pg_temp.as_role('trust_crl_operator',
        format($$SELECT reserve_crl(%L, 'x', 'op')$$, ca), '42501');
    PERFORM pg_temp.as_role('trust_crl_operator', format(
        $$SELECT propose_certificate_status_change(%L, '\x42', 'REVOKE', 1::smallint, NULL, %L, 'maker')$$,
        ca, iss), '42501');
    PERFORM pg_temp.as_role('trust_ca_admin',
        format($$SELECT certificate_status(%L, '\x41')$$, ca), '42501');
    -- internal helpers are not callable by any service
    PERFORM pg_temp.as_role('trust_crl_operator',
        format($$SELECT crl_change_covered(%L, true)$$, c), '42501');
END $t$;

ROLLBACK;
