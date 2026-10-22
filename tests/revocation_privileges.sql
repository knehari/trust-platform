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
          'approve_credential_change', 'reject_credential_change',
          'issue_precautionary_hold_challenge', 'apply_precautionary_hold',
          'precautionary_holds', 'enroll_ca_admin_credential', 'remove_ca_admin_credential',
          'issue_ca_admin_challenge', 'ca_admin_challenge_claim', 'ca_admin_credential_for',
          'propose_signed_admin_change', 'approve_signed_admin_change', 'ca_admin_signatures',
          'ca_admin_propose_unchecked', 'ca_admin_approve_unchecked',
          'credential_propose_unchecked', 'credential_approve_unchecked',
          'issue_close_challenge', 'close_signed_status_change',
          'status_change_reject_unchecked', 'status_change_withdraw_unchecked',
          'admin_credential_propose_unchecked', 'admin_credential_approve_unchecked',
          'reject_admin_credential_change', 'signed_evidence_index',
          'reject_signed_admin_change', 'ca_admin_reject_unchecked',
          'credential_reject_unchecked', 'admin_credential_reject_unchecked',
          'pending_admin_changes', 'enroll_breakglass_credential',
          'remove_breakglass_credential', 'breakglass_credential_for',
          'issue_breakglass_challenge', 'breakglass_enroll_admin_credential',
          'issue_breakglass_review_challenge', 'review_breakglass_use', 'breakglass_uses',
          'breakglass_evidence', 'admin_change_ca', 'breakglass_use_ca', 'purge_expired_challenges',
          'stale_admin_proposals', 'certificates_without_not_after',
          'record_certificate_not_after', 'evidence_cas',
          'reserve_delta_crl', 'crl_delta_releases', 'published_delta_crl')
      AND (NOT p.prosecdef
           OR p.proowner <> 'trust_revocation_owner'::regrole
           OR NOT coalesce(p.proconfig, '{}') @> ARRAY['search_path=pg_catalog, public, pg_temp']);
    PERFORM pg_temp.must(bad IS NULL, 'service functions without definer settings: ' || coalesce(bad, ''));
END $t$;

-- -------------------- credential registries (0048): on each registry the
-- first BEFORE INSERT row trigger takes the shared registry lock, so the
-- disjointness checks after it see concurrent enrolments.
DO $t$
DECLARE
    t TEXT;
    first_fn TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['officer_credential', 'ca_admin_credential',
                             'ca_breakglass_credential'] LOOP
        SELECT g.tgfoid::regproc::text INTO first_fn
        FROM pg_trigger g
        WHERE g.tgrelid = t::regclass AND NOT g.tgisinternal
          AND g.tgenabled <> 'D' AND (g.tgtype & 7) = 7
        ORDER BY g.tgname
        LIMIT 1;
        PERFORM pg_temp.must(first_fn = 'lock_credential_registries',
            t || ': first insert trigger is ' || coalesce(first_fn, 'none'));
    END LOOP;
END $t$;

-- -------------------- break-glass (0045): the emergency key is enrolled and
-- removed by the DBA only; only CA admins use it; readers only read.
DO $t$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_ca_admin',
                             'trust_crl_operator', 'trust_crl_signer', 'trust_audit_verifier',
                             'trust_issuance_service', 'trust_policy_admin',
                             'trust_reconciliation_operator'] LOOP
        PERFORM pg_temp.must(NOT has_function_privilege(r,
            'enroll_breakglass_credential(uuid,bytea,text,text,bytea)', 'EXECUTE')
            AND NOT has_function_privilege(r, 'remove_breakglass_credential(bytea)', 'EXECUTE')
            AND NOT has_table_privilege(r, 'ca_breakglass_credential', 'SELECT,INSERT,UPDATE')
            AND NOT has_table_privilege(r, 'breakglass_use', 'SELECT,INSERT,UPDATE')
            AND NOT has_table_privilege(r, 'breakglass_review', 'SELECT,INSERT,UPDATE'),
            r || ' reaches the break-glass registry directly');
        PERFORM pg_temp.must(has_function_privilege(r,
            'breakglass_enroll_admin_credential(uuid,bytea,bytea,bytea,bytea,bytea,text,text,text,bytea)',
            'EXECUTE') = (r = 'trust_ca_admin'), r || ': break-glass use is for CA admins only');
        PERFORM pg_temp.must(has_function_privilege(r, 'breakglass_evidence(uuid)', 'EXECUTE')
            = (r IN ('trust_audit_verifier', 'trust_ca_admin')),
            r || ': break-glass evidence is for auditors and reviewing admins (0051)');
    END LOOP;
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
          'trust_crl_operator', 'trust_ca_admin', 'trust_audit_sealer', 'trust_audit_verifier',
          'trust_crl_publisher', 'trust_issuance_service', 'trust_policy_admin',
          'trust_reconciliation_operator')
      AND (NOT p.prosecdef
           OR NOT coalesce(p.proconfig, '{}') @> ARRAY['search_path=pg_catalog, public, pg_temp']);
    PERFORM pg_temp.must(bad IS NULL, 'granted functions without definer settings: ' || coalesce(bad, ''));
END $t$;

-- ------------------------------------- issuance least privilege (0035)
-- The issuance functions run as trust_issuance_owner (definer, pinned
-- search_path), and the service role reaches the issuance tables through
-- them only.
DO $t$
DECLARE
    bad TEXT;
BEGIN
    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO bad
    FROM pg_proc p
    WHERE p.pronamespace = 'public'::regnamespace
      AND (p.proname IN ('create_issuance_request', 'transition_issuance_request',
               'reserve_issuance_serial', 'create_signing_intent', 'mark_signing_uncertain',
               'quarantine_stale_signing_intents')
           OR p.oid = 'store_signed_certificate(uuid,uuid,text,bytea,bytea,bytea,bytea,timestamptz)'::regprocedure)
      AND (NOT p.prosecdef
           OR p.proowner <> 'trust_issuance_owner'::regrole
           OR NOT coalesce(p.proconfig, '{}') @> ARRAY['search_path=pg_catalog, public, pg_temp']);
    PERFORM pg_temp.must(bad IS NULL, 'issuance functions without definer settings: ' || coalesce(bad, ''));

    SELECT string_agg(t, ', ') INTO bad
    FROM unnest(ARRAY['certificate_request', 'serial_reservation', 'signing_intent', 'certificate',
                      'audit_event', 'ca', 'issuance_policy_grant', 'approved_policy_edition']) t
    WHERE has_table_privilege('trust_issuance_service', t, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE');
    PERFORM pg_temp.must(bad IS NULL, 'trust_issuance_service has table rights on: ' || coalesce(bad, ''));
    PERFORM pg_temp.must(NOT has_column_privilege('trust_issuance_owner', 'ca', 'display_name', 'UPDATE'),
                         'trust_issuance_owner may update more of ca than policy_gate_epoch');
    PERFORM pg_temp.must(NOT (SELECT rolcanlogin FROM pg_roles WHERE rolname = 'trust_issuance_owner'),
                         'trust_issuance_owner can log in');
    -- Policy administration, reconciliation and evidence (0043): same
    -- owner and settings; the two capability roles have no table rights.
    SELECT string_agg(p.oid::regprocedure::text, ', ') INTO bad
    FROM pg_proc p
    WHERE p.pronamespace = 'public'::regnamespace
      AND p.proname IN ('register_ca_public_observation', 'register_cp_cps_draft',
               'approve_policy_draft_lab', 'activate_ca_policy_gate_lab',
               'grant_request_approved_policy_lab', 'persist_verified_dual_policy_receipt_lab',
               'require_dual_signature_policy_lab', 'record_signing_reconciliation_observation',
               'propose_reconciliation_review', 'review_reconciliation_proposal',
               'persist_signing_collector_evidence', 'trace_issued_certificate_to_draft')
      AND (NOT p.prosecdef
           OR p.proowner <> 'trust_issuance_owner'::regrole
           OR NOT coalesce(p.proconfig, '{}') @> ARRAY['search_path=pg_catalog, public, pg_temp']);
    PERFORM pg_temp.must(bad IS NULL, 'policy/reconciliation functions without definer settings: '
                                      || coalesce(bad, ''));
    SELECT string_agg(r || ':' || t, ', ') INTO bad
    FROM unnest(ARRAY['trust_policy_admin', 'trust_reconciliation_operator']) r,
         unnest(ARRAY['approved_policy_edition', 'issuance_policy_grant', 'ca_policy_enforcement',
                      'signing_collector_evidence', 'signing_reconciliation_review',
                      'certificate', 'signing_intent', 'certificate_request']) t
    WHERE has_table_privilege(r, t, 'SELECT, INSERT, UPDATE, DELETE, TRUNCATE');
    PERFORM pg_temp.must(bad IS NULL, 'capability roles with table rights: ' || coalesce(bad, ''));
    PERFORM pg_temp.must(NOT has_function_privilege('trust_policy_admin',
                             'create_issuance_request(uuid,text,bytea,text,text)', 'EXECUTE')
                         AND NOT has_function_privilege('trust_reconciliation_operator',
                             'activate_ca_policy_gate_lab(uuid,text)', 'EXECUTE'),
                         'a capability role reaches another role''s functions');

    -- The service role cannot reach the policy administration functions.
    PERFORM pg_temp.must(NOT has_function_privilege('trust_issuance_service',
                             'activate_ca_policy_gate_lab(uuid,text)', 'EXECUTE'),
                         'trust_issuance_service may activate the policy gate');
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
            $$SELECT count(*) FROM certificate_status_change$$,
            -- signed CA administration (0037): registries, evidence and the
            -- unsigned or bootstrap paths
            $$UPDATE ca_admin_credential SET sign_count = 0$$,
            $$SELECT count(*) FROM ca_admin_challenge$$,
            $$SELECT count(*) FROM ca_admin_signature$$,
            $$SELECT enroll_ca_admin_credential(NULL, NULL, NULL, NULL, NULL, NULL)$$,
            $$SELECT ca_admin_approve_unchecked(NULL, NULL, NULL, NULL)$$,
            $$SELECT credential_propose_unchecked(NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                NULL, NULL)$$,
            $$SELECT status_change_reject_unchecked(NULL, NULL, NULL)$$,
            $$SELECT status_change_withdraw_unchecked(NULL, NULL, NULL)$$,
            $$SELECT count(*) FROM ca_admin_credential_change$$,
            $$SELECT admin_credential_approve_unchecked(NULL, NULL, NULL, NULL)$$,
            $$SELECT ca_admin_reject_unchecked(NULL, NULL, NULL)$$] LOOP
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
