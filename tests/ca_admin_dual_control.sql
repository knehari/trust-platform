-- Lab-only: dual control of CA administration (migration 0024): issuer
-- registration and revocation officer grants need two distinct CA admins,
-- the checker approves the exact content digest, nobody grants themselves
-- an officer role, and trust_ca_admin can no longer register directly.
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

INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000a24', 'CA Admin Dual Control Lab CA', 'lab-1');

INSERT INTO ca_admin_grant(issuer, subject, ca_id) VALUES
 ('https://idp.lab.invalid', 'admin-a', 'c0c0c0c0-0000-4000-8000-000000000a24'),
 ('https://idp.lab.invalid', 'admin-b', 'c0c0c0c0-0000-4000-8000-000000000a24');

CREATE FUNCTION pg_temp.grant_digest(p_kind TEXT, p_issuer TEXT, p_subject TEXT) RETURNS BYTEA
LANGUAGE sql AS $f$
    SELECT sha256(int4send(octet_length(convert_to(p_kind, 'UTF8'))) || convert_to(p_kind, 'UTF8')
        || int4send(octet_length(convert_to(p_issuer, 'UTF8'))) || convert_to(p_issuer, 'UTF8')
        || int4send(octet_length(convert_to(p_subject, 'UTF8'))) || convert_to(p_subject, 'UTF8'))
$f$;

DO $t$
DECLARE
    ca CONSTANT TEXT := 'c0c0c0c0-0000-4000-8000-000000000a24';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    c UUID;
BEGIN
    -- a single CA admin cannot register the issuer certificate on its own
    PERFORM pg_temp.as_role('trust_ca_admin',
        format($$SELECT register_ca_issuer(%L, 'issuer'::bytea, 'one-admin')$$, ca), '42501');

    -- issuer registration: propose by A
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT set_config('t.c', propose_ca_admin_change(%L, 'REGISTER_ISSUER', 'issuer'::bytea,
            NULL, NULL, %L, 'admin-a')::text, true)$$, ca, iss), NULL);
    c := current_setting('t.c')::uuid;
    -- A cannot approve its own proposal; a non-admin cannot approve
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-a', sha256('issuer'::bytea))$$, c, iss), '23514');
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'stranger', sha256('issuer'::bytea))$$, c, iss), '42501');
    -- B must approve exactly the content it reviewed
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-b', sha256('other'::bytea))$$, c, iss), '23514');
    PERFORM pg_temp.must((SELECT count(*) FROM ca_issuer_certificate WHERE ca_id = ca::uuid) = 0,
        'nothing registered before a valid approval');
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-b', sha256('issuer'::bytea))$$, c, iss), NULL);
    PERFORM pg_temp.must((SELECT certificate_sha256 FROM ca_issuer_certificate
        WHERE ca_id = ca::uuid) = sha256('issuer'::bytea), 'issuer registered by two admins');
    -- closed: no second approval, no second registration proposal
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-b', sha256('issuer'::bytea))$$, c, iss), '23514');
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT propose_ca_admin_change(%L, 'REGISTER_ISSUER', 'issuer2'::bytea, NULL, NULL,
            %L, 'admin-a')$$, ca, iss), '23514');

    -- officer grant: nobody grants themselves
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT propose_ca_admin_change(%L, 'GRANT_OFFICER', NULL, %L, 'admin-a', %L, 'admin-a')$$,
        ca, iss, iss), '23514');
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT set_config('t.c', propose_ca_admin_change(%L, 'GRANT_OFFICER', NULL, %L, 'admin-b',
            %L, 'admin-a')::text, true)$$, ca, iss, iss), NULL);
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-b', %L)$$,
        current_setting('t.c'), iss, pg_temp.grant_digest('GRANT_OFFICER', iss, 'admin-b')), '23514');
    -- a real officer grant, then its removal, each by two admins
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT set_config('t.c', propose_ca_admin_change(%L, 'GRANT_OFFICER', NULL, %L, 'officer-1',
            %L, 'admin-a')::text, true)$$, ca, iss, iss), NULL);
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-b', %L)$$,
        current_setting('t.c'), iss, pg_temp.grant_digest('GRANT_OFFICER', iss, 'officer-1')), NULL);
    PERFORM pg_temp.must(EXISTS (SELECT 1 FROM revocation_officer_grant
        WHERE ca_id = ca::uuid AND subject = 'officer-1'), 'officer granted');
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT set_config('t.c', propose_ca_admin_change(%L, 'REVOKE_OFFICER', NULL, %L, 'officer-1',
            %L, 'admin-b')::text, true)$$, ca, iss, iss), NULL);
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT reject_ca_admin_change(%L, %L, 'admin-a')$$, current_setting('t.c'), iss), NULL);
    PERFORM pg_temp.must(EXISTS (SELECT 1 FROM revocation_officer_grant
        WHERE ca_id = ca::uuid AND subject = 'officer-1'), 'rejected removal keeps the grant');
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT set_config('t.c', propose_ca_admin_change(%L, 'REVOKE_OFFICER', NULL, %L, 'officer-1',
            %L, 'admin-b')::text, true)$$, ca, iss, iss), NULL);
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-a', %L)$$,
        current_setting('t.c'), iss, pg_temp.grant_digest('REVOKE_OFFICER', iss, 'officer-1')), NULL);
    PERFORM pg_temp.must(NOT EXISTS (SELECT 1 FROM revocation_officer_grant
        WHERE ca_id = ca::uuid AND subject = 'officer-1'), 'officer removed');

    -- audit trail and append-only history
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = ca::uuid
        AND event_type = 'ca.admin.approved') = 3, 'three approvals audited');
    PERFORM pg_temp.expect_err($$UPDATE ca_admin_change SET kind = 'GRANT_OFFICER'$$, '23514');
    PERFORM pg_temp.expect_err($$DELETE FROM ca_admin_change$$, '23514');

    -- no service writes the admin tables directly or calls the functions
    -- of another role
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$INSERT INTO ca_admin_grant VALUES (%L, 'self', %L)$$, iss, ca), '42501');
    PERFORM pg_temp.as_role('trust_ca_admin', $$UPDATE ca_admin_change SET status = 'APPROVED'$$, '42501');
    PERFORM pg_temp.as_role('trust_ca_admin', format(
        $$INSERT INTO revocation_officer_grant VALUES (%L, 'self', %L)$$, iss, ca), '42501');
    PERFORM pg_temp.as_role('trust_revocation_officer_api', format(
        $$SELECT propose_ca_admin_change(%L, 'GRANT_OFFICER', NULL, %L, 'x', %L, 'admin-a')$$,
        ca, iss, iss), '42501');
    PERFORM pg_temp.as_role('trust_crl_signer', format(
        $$SELECT approve_ca_admin_change(%L, %L, 'admin-b', sha256('x'::bytea))$$, c, iss), '42501');
END $t$;

ROLLBACK;
