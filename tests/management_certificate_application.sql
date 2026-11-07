-- Migration 0028: certificate applications and their registration decision.
-- Run as the migration owner after 0028 on a disposable database; every
-- change is rolled back. The database does not parse CSRs (the API does);
-- placeholder bytes stand for a verified CSR here. Before 0028 the first
-- statement fails.
BEGIN;

SELECT 1 FROM certificate_application LIMIT 0;

CREATE FUNCTION pg_temp.expect_state(p_sql text, p_state text) RETURNS void
LANGUAGE plpgsql AS $fn$
BEGIN
    EXECUTE p_sql;
    RAISE EXCEPTION 'expected SQLSTATE % from: %', p_state, p_sql;
EXCEPTION WHEN OTHERS THEN
    IF SQLSTATE <> p_state THEN
        RAISE EXCEPTION 'expected SQLSTATE %, got % (%) from: %', p_state, SQLSTATE, SQLERRM, p_sql;
    END IF;
END
$fn$;

-- CA A: activated through 0025-0026; owner CA O without a lifecycle state.
INSERT INTO management_platform_grant (issuer, subject, platform_role) VALUES
    ('https://issuer.app.invalid', 'admin', 'ca-administrator'),
    ('https://issuer.app.invalid', 'approver-1', 'ca-approver'),
    ('https://issuer.app.invalid', 'approver-2', 'ca-approver');
INSERT INTO ca_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('app-approver-1', 'https://issuer.app.invalid', 'approver-1', decode('04' || repeat('71', 64), 'hex')),
    ('app-approver-2', 'https://issuer.app.invalid', 'approver-2', decode('04' || repeat('72', 64), 'hex'));
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    iss text := 'https://issuer.app.invalid';
    a uuid := 'a1a1a1a1-0000-4000-8000-00000000000a';
    req bytea := decode(repeat('11', 32), 'hex');
    sig bytea := decode(repeat('30', 70), 'hex');
BEGIN
    PERFORM propose_ca_lab(iss, 'admin', a, 'Issuing A', 'v1', 'ecdsa-p256-sha256', gen_random_uuid(), req);
    PERFORM register_ca_issuer_certificate_lab(iss, 'admin', a, decode(repeat('a1', 300), 'hex'), digest('ca-a-key', 'sha256'),
        'Issuing A', clock_timestamp() - interval '1 hour', clock_timestamp() + interval '1 year', 'p256',
        gen_random_uuid(), req);
    PERFORM record_ca_decision_lab(iss, 'approver-1', a, 'approve', clock_timestamp(), sig, gen_random_uuid(), req);
    PERFORM record_ca_decision_lab(iss, 'approver-2', a, 'approve', clock_timestamp(), sig, gen_random_uuid(), req);
    PERFORM activate_ca_lab(iss, 'admin', a, digest(decode(repeat('a1', 300), 'hex'), 'sha256'), gen_random_uuid(), req);
END $setup$;
RESET ROLE;
INSERT INTO ca (ca_id, display_name, policy_version) VALUES ('0b0b0b0b-0000-4000-8000-00000000000b', 'Owner CA', 'v1');

-- An active profile revision on each (owner fixture): zones lab.invalid and
-- apps.example.invalid, at most 3 names and 90 days.
CREATE FUNCTION pg_temp.active_profile(p_ca uuid, p_profile text, p_revision integer DEFAULT 1) RETURNS void
LANGUAGE plpgsql AS $fn$
DECLARE e uuid;
BEGIN
    INSERT INTO certificate_profile_draft (ca_id, profile_id, revision, display_name, policy_version, max_validity_days,
        max_dns_sans, proposed_dns_zones, proposed_signature_suites, created_by)
    VALUES (p_ca, p_profile, p_revision, 'Server', 'v1', 90, 3, ARRAY['lab.invalid', 'apps.example.invalid'],
            ARRAY['ecdsa-p256-sha256'], 'fixture');
    INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id, revision,
        snapshot_sha256, policy_version, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'draft.submitted', p_ca, p_profile, p_revision,
            decode(repeat('aa', 32), 'hex'), 'v1', 'owner', 'owner') RETURNING event_id INTO e;
    INSERT INTO certificate_profile_submission (ca_id, profile_id, revision, snapshot_sha256, event_id)
    VALUES (p_ca, p_profile, p_revision, decode(repeat('aa', 32), 'hex'), e);
    INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id, revision,
        snapshot_sha256, policy_version, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'revision.activation', p_ca, p_profile, p_revision,
            decode(repeat('aa', 32), 'hex'), 'v1', 'owner', 'owner') RETURNING event_id INTO e;
    DELETE FROM certificate_profile_active WHERE ca_id = p_ca AND profile_id = p_profile;
    INSERT INTO certificate_profile_active (ca_id, profile_id, revision, activated_event_id)
    VALUES (p_ca, p_profile, p_revision, e);
END $fn$;
SELECT pg_temp.active_profile('a1a1a1a1-0000-4000-8000-00000000000a', 'server');
SELECT pg_temp.active_profile('0b0b0b0b-0000-4000-8000-00000000000b', 'server');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('https://issuer.app.invalid', 'req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', 'certificate-requester'),
    ('https://issuer.app.invalid', 'req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', 'registration-officer'),
    ('https://issuer.app.invalid', 'req-1', '0b0b0b0b-0000-4000-8000-00000000000b', 'certificate-requester'),
    ('https://issuer.app.invalid', 'ra-1', 'a1a1a1a1-0000-4000-8000-00000000000a', 'registration-officer'),
    -- An officer of another CA: an application is decided only under its own CA.
    ('https://issuer.app.invalid', 'ra-1', '0b0b0b0b-0000-4000-8000-00000000000b', 'registration-officer');
SELECT pg_temp.expect_state($q$INSERT INTO management_role_grant VALUES ('https://issuer.app.invalid', 'x',
    'a1a1a1a1-0000-4000-8000-00000000000a', 'certificate-signer')$q$, '23514');

-- Submits as the writer; returns the statement.
CREATE FUNCTION pg_temp.submit(p_subject text, p_ca text, p_names text[], p_cn text DEFAULT NULL,
    p_days integer DEFAULT 30, p_profile text DEFAULT 'server', p_spki bytea DEFAULT NULL,
    p_operation uuid DEFAULT gen_random_uuid()) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM submit_certificate_application_lab(%L, %L, %L, %L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.app.invalid', p_subject, p_ca, p_profile, decode(repeat('30', 200), 'hex'),
        coalesce(p_spki, digest('subject-key', 'sha256')), coalesce(p_cn, p_names[1]), p_names, p_days, p_operation,
        -- Stands for the API's digest of the request body.
        digest(array_to_string(p_names, ',') || p_days, 'sha256'))
$fn$;
CREATE FUNCTION pg_temp.decide(p_subject text, p_ca text, p_application text, p_decision text,
    p_operation uuid DEFAULT gen_random_uuid()) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM decide_certificate_application_lab(%L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.app.invalid', p_subject, p_ca, p_application, p_decision, 'checked: ' || p_decision, p_operation,
        decode(repeat('33', 32), 'hex'))
$fn$;

SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_application', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_application_decision', '42501');
-- Refusals: grant, owner CA, unknown profile, names, CN, validity, CA key.
SELECT pg_temp.expect_state(pg_temp.submit('ra-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['www.lab.invalid']), '42501');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', '0b0b0b0b-0000-4000-8000-00000000000b', ARRAY['www.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['www.lab.invalid'],
    p_profile => 'mail'), 'P0002');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['www.example.com']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['notlab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['Www.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['*.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a',
    ARRAY['a.lab.invalid', 'b.lab.invalid', 'c.lab.invalid', 'd.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a',
    ARRAY['a.lab.invalid', 'a.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['a.lab.invalid'],
    'b.lab.invalid'), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['a.lab.invalid'],
    p_days => 91), 'TP422');
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['a.lab.invalid'],
    p_spki => digest('ca-a-key', 'sha256')), 'TP422');

DO $test$
DECLARE
    a text := 'a1a1a1a1-0000-4000-8000-00000000000a';
    op uuid := '0f0f0f0f-0000-4000-8000-0000000000d1';
    r record;
    first uuid;
    second uuid;
BEGIN
    EXECUTE pg_temp.submit('req-1', a, ARRAY['www.lab.invalid', 'api.apps.example.invalid', 'lab.invalid'],
        'www.lab.invalid', 90, 'server', NULL, op) INTO r;
    IF r.status <> 'SUBMITTED' OR r.revision <> 1 OR r.replayed THEN RAISE EXCEPTION 'submission: %', r; END IF;
    first := r.application_id;
    EXECUTE pg_temp.submit('req-1', a, ARRAY['www.lab.invalid', 'api.apps.example.invalid', 'lab.invalid'],
        'www.lab.invalid', 90, 'server', NULL, op) INTO r;
    IF NOT r.replayed OR r.application_id <> first THEN RAISE EXCEPTION 'submission replay: %', r; END IF;
    BEGIN
        EXECUTE pg_temp.submit('req-1', a, ARRAY['other.lab.invalid'], NULL, 30, 'server', NULL, op);
        RAISE EXCEPTION 'an idempotency key was reused for another application';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    EXECUTE pg_temp.submit('req-1', a, ARRAY['mail.lab.invalid']) INTO r;
    second := r.application_id;

    -- Decisions: grant, requester, unknown or other CA; then approve once.
    BEGIN
        EXECUTE pg_temp.decide('approver-1', a, first::text, 'approve');
        RAISE EXCEPTION 'a decision without the officer grant was accepted';
    EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
    END;
    BEGIN
        EXECUTE pg_temp.decide('req-1', a, first::text, 'approve');
        RAISE EXCEPTION 'the requester decided on their application';
    EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
    END;
    BEGIN
        EXECUTE pg_temp.decide('ra-1', a, gen_random_uuid()::text, 'approve');
        RAISE EXCEPTION 'an unknown application was decided';
    EXCEPTION WHEN SQLSTATE 'P0002' THEN NULL;
    END;
    EXECUTE pg_temp.decide('ra-1', a, first::text, 'approve', '0f0f0f0f-0000-4000-8000-0000000000d2') INTO r;
    IF r.status <> 'APPROVED' OR r.replayed THEN RAISE EXCEPTION 'approval: %', r; END IF;
    EXECUTE pg_temp.decide('ra-1', a, first::text, 'approve', '0f0f0f0f-0000-4000-8000-0000000000d2') INTO r;
    IF NOT r.replayed THEN RAISE EXCEPTION 'approval replay: %', r; END IF;
    BEGIN
        EXECUTE pg_temp.decide('ra-1', a, first::text, 'reject');
        RAISE EXCEPTION 'an application was decided twice';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    PERFORM set_config('test.second', second::text, true);
END $test$;

-- A suspended CA takes no application and cannot have one approved, but a
-- pending application can still be rejected.
SELECT * FROM suspend_ca_lab('https://issuer.app.invalid', 'admin', 'a1a1a1a1-0000-4000-8000-00000000000a', 'test',
    gen_random_uuid(), decode(repeat('44', 32), 'hex'));
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['x.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.decide('ra-1', 'a1a1a1a1-0000-4000-8000-00000000000a',
    current_setting('test.second'), 'approve'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.decide('ra-1', '0b0b0b0b-0000-4000-8000-00000000000b',
    current_setting('test.second'), 'reject'), 'P0002');
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.decide('ra-1', 'a1a1a1a1-0000-4000-8000-00000000000a', current_setting('test.second'), 'reject') INTO r;
    IF r.status <> 'REJECTED' THEN RAISE EXCEPTION 'rejection: %', r; END IF;
END $test$;
RESET ROLE;

-- An application whose revision is no longer active cannot be approved.
UPDATE ca_operational_state SET state = 'ACTIVE' WHERE ca_id = 'a1a1a1a1-0000-4000-8000-00000000000a';
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['old.lab.invalid']) INTO r;
    PERFORM set_config('test.old', r.application_id::text, true);
END $test$;
RESET ROLE;
SELECT pg_temp.active_profile('a1a1a1a1-0000-4000-8000-00000000000a', 'server', 2);
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.decide('ra-1', 'a1a1a1a1-0000-4000-8000-00000000000a',
    current_setting('test.old'), 'approve'), 'TP409');
RESET ROLE;

-- Readers of the CA see the applications, without actor identities.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.app.invalid', 'reader', 'a1a1a1a1-0000-4000-8000-00000000000a');
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.app.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT string_agg(subject_cn || ':' || status || ':' || revision || ':' || cardinality(dns_names), ',' ORDER BY subject_cn)
        FROM management_certificate_application)
       <> 'mail.lab.invalid:REJECTED:1:1,old.lab.invalid:SUBMITTED:1:1,www.lab.invalid:APPROVED:1:3' THEN
        RAISE EXCEPTION 'unexpected reader view';
    END IF;
    IF management_certificate_application_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
SELECT set_config('trust.reader_subject', 'nobody', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_certificate_application) THEN RAISE EXCEPTION 'an ungranted reader sees applications'; END IF;
END $test$;
RESET ROLE;

-- Events and audit; nothing changes afterwards.
DO $test$ BEGIN
    IF (SELECT string_agg(a.event_type || ':' || a.decision, ',' ORDER BY e.recorded_at)
        FROM certificate_application_event e JOIN audit_event a USING (event_id)
        WHERE e.ca_id = 'a1a1a1a1-0000-4000-8000-00000000000a')
       <> 'certificate.application.submitted:allow,certificate.application.submitted:allow,certificate.application.approved:allow,certificate.application.rejected:deny,certificate.application.submitted:allow' THEN
        RAISE EXCEPTION 'unexpected application audit: %', (SELECT string_agg(a.event_type, ',' ORDER BY a.recorded_at)
            FROM certificate_application_event e JOIN audit_event a USING (event_id));
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$UPDATE certificate_application SET dns_names = ARRAY['evil.lab.invalid']$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM certificate_application_decision$q$, 'P0001');

-- Interrupted transaction: a failing audit write leaves no application.
CREATE FUNCTION pg_temp.fail_application_audit() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.event_type = 'certificate.application.submitted' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER inject_application_failure BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_application_audit();
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.submit('req-1', 'a1a1a1a1-0000-4000-8000-00000000000a', ARRAY['lost.lab.invalid']), 'P0001');
RESET ROLE;
DROP TRIGGER inject_application_failure ON audit_event;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM certificate_application WHERE subject_cn = 'lost.lab.invalid') THEN
        RAISE EXCEPTION 'an interrupted submission left an application';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: certificate applications bind the active profile of an ACTIVE CA and need a registration officer other than the requester'
