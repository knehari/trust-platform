-- Migration 0025: CA proposals and issuer certificates. Run as the migration
-- owner after 0025 on a disposable database; every change is rolled back.
-- The database does not parse X.509 (the API does, and the audit tool
-- re-checks); placeholder bytes stand for a verified certificate here.
-- Before 0025 the first statement fails.
BEGIN;

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

INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'Existing CA', 'v1');
INSERT INTO management_platform_grant (issuer, subject, platform_role) VALUES
    ('https://issuer.ca.invalid', 'admin-1', 'ca-administrator'),
    ('https://issuer.ca.invalid', 'admin-2', 'ca-administrator');
SELECT pg_temp.expect_state($q$INSERT INTO management_platform_grant VALUES
    ('https://issuer.ca.invalid', 'x', 'ca-operator')$q$, '23514');

-- Registers a certificate for a proposal with the given facts.
CREATE FUNCTION pg_temp.register(p_subject text, p_ca uuid, p_spki_byte text, p_cn text,
    p_key text DEFAULT 'p256', p_not_after timestamptz DEFAULT clock_timestamp() + interval '1 year',
    p_operation uuid DEFAULT gen_random_uuid())
RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM register_ca_issuer_certificate_lab(%L, %L, %L, %L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.ca.invalid', p_subject, p_ca, decode(repeat('30', 300), 'hex'),
        decode(repeat(p_spki_byte, 32), 'hex'), p_cn, clock_timestamp() - interval '1 hour', p_not_after, p_key,
        p_operation, decode(repeat('ab', 32), 'hex'))
$fn$;

SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM ca_proposal', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM ca_issuer_certificate', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM management_platform_grant', '42501');
SELECT pg_temp.expect_state($q$INSERT INTO ca_proposal (ca_id, display_name, policy_version, suite_id, proposed_event_id)
    VALUES (gen_random_uuid(), 'X', 'v1', 'ecdsa-p256-sha256', gen_random_uuid())$q$, '42501');

-- Proposals: a non-administrator, an identifier of an existing CA, invalid fields.
SELECT pg_temp.expect_state($q$SELECT * FROM propose_ca_lab('https://issuer.ca.invalid', 'reader',
    gen_random_uuid(), 'Lab Root', 'v1', 'ecdsa-p256-sha256', gen_random_uuid(), decode(repeat('01', 32), 'hex'))$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM propose_ca_lab('https://issuer.ca.invalid', 'admin-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'Lab Root', 'v1', 'ecdsa-p256-sha256', gen_random_uuid(),
    decode(repeat('01', 32), 'hex'))$q$, 'TP409');
SELECT pg_temp.expect_state($q$SELECT * FROM propose_ca_lab('https://issuer.ca.invalid', 'admin-1',
    gen_random_uuid(), E'Lab\nRoot', 'v1', 'ecdsa-p256-sha256', gen_random_uuid(), decode(repeat('01', 32), 'hex'))$q$, '23514');
SELECT pg_temp.expect_state($q$SELECT * FROM propose_ca_lab('https://issuer.ca.invalid', 'admin-1',
    gen_random_uuid(), 'Lab Root', 'v1', 'P256-SHA256', gen_random_uuid(), decode(repeat('01', 32), 'hex'))$q$, '23514');

DO $test$
DECLARE
    iss text := 'https://issuer.ca.invalid';
    op uuid := '0f0f0f0f-0000-4000-8000-000000000001';
    req bytea := decode(repeat('11', 32), 'hex');
    r record;
BEGIN
    SELECT * INTO r FROM propose_ca_lab(iss, 'admin-1', 'a0a0a0a0-0000-4000-8000-000000000001', 'Lab Root One', 'v1',
        'ecdsa-p256-sha256', op, req);
    IF r.replayed OR r.ca_id <> 'a0a0a0a0-0000-4000-8000-000000000001' THEN RAISE EXCEPTION 'proposal: %', r; END IF;
    SELECT * INTO r FROM propose_ca_lab(iss, 'admin-1', 'a0a0a0a0-0000-4000-8000-000000000001', 'Lab Root One', 'v1',
        'ecdsa-p256-sha256', op, req);
    IF NOT r.replayed THEN RAISE EXCEPTION 'proposal replay: %', r; END IF;
    BEGIN
        PERFORM propose_ca_lab(iss, 'admin-2', 'a0a0a0a0-0000-4000-8000-000000000009', 'Other', 'v1',
            'ecdsa-p256-sha256', op, req);
        RAISE EXCEPTION 'key reuse by another administrator accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    BEGIN
        PERFORM propose_ca_lab(iss, 'admin-2', 'a0a0a0a0-0000-4000-8000-000000000001', 'Again', 'v1',
            'ecdsa-p256-sha256', gen_random_uuid(), req);
        RAISE EXCEPTION 'duplicate proposal identifier accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    PERFORM propose_ca_lab(iss, 'admin-2', 'a0a0a0a0-0000-4000-8000-000000000002', 'Lab Root Two', 'v1',
        'ecdsa-p256-sha256', gen_random_uuid(), req);
    PERFORM propose_ca_lab(iss, 'admin-2', 'a0a0a0a0-0000-4000-8000-000000000003', 'Lab Root Three', 'v1',
        'ecdsa-p256-sha384', gen_random_uuid(), req);
    -- Without an identifier, the database draws one.
    SELECT * INTO r FROM propose_ca_lab(iss, 'admin-2', NULL, 'Lab Root Four', 'v1', 'ecdsa-p256-sha256',
        gen_random_uuid(), req);
    IF r.ca_id IS NULL OR r.replayed THEN
        RAISE EXCEPTION 'generated identifier: %', r;
    END IF;
END $test$;

-- Certificate registration refusals.
SELECT pg_temp.expect_state(pg_temp.register('reader', 'a0a0a0a0-0000-4000-8000-000000000001', '0a', 'Lab Root One'), '42501');
SELECT pg_temp.expect_state(pg_temp.register('admin-1', 'a0a0a0a0-0000-4000-8000-0000000000ff', '0a', 'Lab Root One'), 'P0002');
SELECT pg_temp.expect_state(pg_temp.register('admin-1', 'a0a0a0a0-0000-4000-8000-000000000001', '0a', 'Lab Root Uno'), 'TP422');
SELECT pg_temp.expect_state(pg_temp.register('admin-1', 'a0a0a0a0-0000-4000-8000-000000000001', '0a', 'Lab Root One', 'p384'), 'TP422');
SELECT pg_temp.expect_state(pg_temp.register('admin-1', 'a0a0a0a0-0000-4000-8000-000000000003', '0a', 'Lab Root Three'), 'TP422');
SELECT pg_temp.expect_state(pg_temp.register('admin-1', 'a0a0a0a0-0000-4000-8000-000000000001', '0a', 'Lab Root One',
    'p256', clock_timestamp() - interval '1 minute'), 'TP422');
SELECT pg_temp.expect_state($q$SELECT * FROM register_ca_issuer_certificate_lab('https://issuer.ca.invalid', 'admin-1',
    'a0a0a0a0-0000-4000-8000-000000000001', decode(repeat('30', 300), 'hex'), decode(repeat('0a', 32), 'hex'),
    'Lab Root One', clock_timestamp() - interval '2 years', clock_timestamp() - interval '1 year', 'p256',
    gen_random_uuid(), decode(repeat('ab', 32), 'hex'))$q$, 'TP422');

DO $test$
DECLARE
    op uuid := '0f0f0f0f-0000-4000-8000-000000000011';
    r record;
BEGIN
    EXECUTE pg_temp.register('admin-1', 'a0a0a0a0-0000-4000-8000-000000000001', '0a', 'Lab Root One', 'p256',
        clock_timestamp() + interval '1 year', op) INTO r;
    IF r.state <> 'KEY_ATTESTED' OR r.replayed OR r.certificate_sha256 <> digest(decode(repeat('30', 300), 'hex'), 'sha256') THEN
        RAISE EXCEPTION 'registration: %', r;
    END IF;
    EXECUTE pg_temp.register('admin-1', 'a0a0a0a0-0000-4000-8000-000000000001', '0a', 'Lab Root One', 'p256',
        clock_timestamp() + interval '1 year', op) INTO r;
    IF NOT r.replayed THEN RAISE EXCEPTION 'registration replay: %', r; END IF;
END $test$;
-- A second certificate for the same proposal, and the same key for another one.
SELECT pg_temp.expect_state(pg_temp.register('admin-2', 'a0a0a0a0-0000-4000-8000-000000000001', '0b', 'Lab Root One'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.register('admin-2', 'a0a0a0a0-0000-4000-8000-000000000002', '0a', 'Lab Root Two'), 'TP409');
RESET ROLE;

-- Administrators see every proposal and its state; anyone else sees none.
-- A proposal is not a CA: management_ca does not list it.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.ca.invalid', 'reader', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.ca.invalid', true),
       set_config('trust.reader_subject', 'admin-1', true);
DO $test$ BEGIN
    IF (SELECT string_agg(display_name || ':' || lifecycle_status || ':' || (certificate_sha256 IS NOT NULL), ',' ORDER BY display_name)
        FROM management_ca_proposal) <> 'Lab Root Four:PROPOSED:false,Lab Root One:KEY_ATTESTED:true,Lab Root Three:PROPOSED:false,Lab Root Two:PROPOSED:false' THEN
        RAISE EXCEPTION 'unexpected administrator view';
    END IF;
    IF management_ca_proposal_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
SELECT set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_ca_proposal) THEN RAISE EXCEPTION 'a non-administrator sees proposals'; END IF;
    IF EXISTS (SELECT 1 FROM management_ca WHERE ca_id LIKE 'a0a0a0a0-%') THEN RAISE EXCEPTION 'a proposal is listed as a CA'; END IF;
END $test$;
RESET ROLE;

-- Events and audit; nothing can be changed.
DO $test$ BEGIN
    IF (SELECT count(*) FROM ca_lifecycle_event e JOIN audit_event a ON a.event_id = e.event_id
        WHERE a.event_type = e.action AND a.actor_id = e.actor_subject AND a.ca_id IS NULL) <> 5 THEN
        RAISE EXCEPTION 'unexpected CA lifecycle events';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$UPDATE ca_proposal SET display_name = 'Forged'$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM ca_issuer_certificate$q$, 'P0001');

-- Interrupted transaction: a failing audit write leaves no certificate.
CREATE FUNCTION pg_temp.fail_ca_audit() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.event_type = 'ca.certificate_registered' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER inject_ca_audit_failure BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_ca_audit();
SELECT pg_temp.expect_state(pg_temp.register('admin-2', 'a0a0a0a0-0000-4000-8000-000000000002', '0c', 'Lab Root Two'), 'P0001');
DROP TRIGGER inject_ca_audit_failure ON audit_event;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM ca_issuer_certificate WHERE ca_id = 'a0a0a0a0-0000-4000-8000-000000000002') THEN
        RAISE EXCEPTION 'an interrupted registration left a certificate';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: CA proposals and issuer certificates are recorded only by CA administrators, once, without key reuse'
