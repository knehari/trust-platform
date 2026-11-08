-- Migration 0029: issuance of approved applications through the core state
-- machine, and the laboratory signer's view and one claim per intent. Run as
-- the migration owner after 0029 on a disposable database; every change is
-- rolled back. The database parses no X.509: placeholder bytes stand for the
-- TBS and certificate the API builds and verifies. Before 0029 the first
-- statement fails.
BEGIN;

SELECT 1 FROM lab_signer_claim LIMIT 0;

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

-- An ACTIVE CA through 0025-0026, an active profile revision (owner
-- fixture), grants, and applications through 0028.
INSERT INTO management_platform_grant (issuer, subject, platform_role) VALUES
    ('https://issuer.iss.invalid', 'admin', 'ca-administrator'),
    ('https://issuer.iss.invalid', 'approver-1', 'ca-approver'),
    ('https://issuer.iss.invalid', 'approver-2', 'ca-approver');
INSERT INTO ca_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('iss-approver-1', 'https://issuer.iss.invalid', 'approver-1', decode('04' || repeat('81', 64), 'hex')),
    ('iss-approver-2', 'https://issuer.iss.invalid', 'approver-2', decode('04' || repeat('82', 64), 'hex'));
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    iss text := 'https://issuer.iss.invalid';
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    req bytea := decode(repeat('11', 32), 'hex');
    sig bytea := decode(repeat('30', 70), 'hex');
BEGIN
    PERFORM propose_ca_lab(iss, 'admin', c, 'Issuing C', 'v1', 'ecdsa-p256-sha256', gen_random_uuid(), req);
    PERFORM register_ca_issuer_certificate_lab(iss, 'admin', c, decode(repeat('c5', 300), 'hex'), digest('ca-c-key', 'sha256'),
        'Issuing C', clock_timestamp() - interval '1 hour', clock_timestamp() + interval '1 year', 'p256',
        gen_random_uuid(), req);
    PERFORM record_ca_decision_lab(iss, 'approver-1', c, 'approve', clock_timestamp(), sig, gen_random_uuid(), req);
    PERFORM record_ca_decision_lab(iss, 'approver-2', c, 'approve', clock_timestamp(), sig, gen_random_uuid(), req);
    PERFORM activate_ca_lab(iss, 'admin', c, digest(decode(repeat('c5', 300), 'hex'), 'sha256'), gen_random_uuid(), req);
END $setup$;
RESET ROLE;
DO $setup$
DECLARE
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    e uuid;
BEGIN
    INSERT INTO certificate_profile_draft (ca_id, profile_id, revision, display_name, policy_version, max_validity_days,
        max_dns_sans, proposed_dns_zones, proposed_signature_suites, created_by)
    VALUES (c, 'server', 1, 'Server', 'v1', 90, 3, ARRAY['lab.invalid'], ARRAY['ecdsa-p256-sha256'], 'fixture');
    INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id, revision,
        snapshot_sha256, policy_version, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'draft.submitted', c, 'server', 1,
            decode(repeat('aa', 32), 'hex'), 'v1', 'owner', 'owner') RETURNING event_id INTO e;
    INSERT INTO certificate_profile_submission (ca_id, profile_id, revision, snapshot_sha256, event_id)
    VALUES (c, 'server', 1, decode(repeat('aa', 32), 'hex'), e);
    INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id, revision,
        snapshot_sha256, policy_version, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'revision.activation', c, 'server', 1,
            decode(repeat('aa', 32), 'hex'), 'v1', 'owner', 'owner') RETURNING event_id INTO e;
    INSERT INTO certificate_profile_active (ca_id, profile_id, revision, activated_event_id) VALUES (c, 'server', 1, e);
END $setup$;
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('https://issuer.iss.invalid', 'req-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester'),
    ('https://issuer.iss.invalid', 'req-2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester'),
    ('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer');

-- Seven applications by req-1: A approved (issued), B approved (left
-- uncertain), C submitted, D rejected, E and F approved (blocked by a
-- suspension), G approved (its requester loses the grant).
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    iss text := 'https://issuer.iss.invalid';
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    names text[] := ARRAY['a', 'b', 'c', 'd', 'e', 'f', 'g'];
    r record;
BEGIN
    FOR i IN 1..7 LOOP
        SELECT * INTO r FROM submit_certificate_application_lab(iss, 'req-1', c, 'server', decode(repeat('3' || i, 200), 'hex'),
            digest('key-' || i, 'sha256'), names[i] || '.lab.invalid', ARRAY[names[i] || '.lab.invalid', 'www.' || names[i] || '.lab.invalid'],
            30, gen_random_uuid(), digest(names[i], 'sha256'));
        PERFORM set_config('test.app_' || names[i], r.application_id::text, true);
        IF names[i] <> 'c' THEN
            PERFORM decide_certificate_application_lab(iss, 'ra-1', c, r.application_id,
                CASE names[i] WHEN 'd' THEN 'reject' ELSE 'approve' END, 'checked', gen_random_uuid(), digest(names[i], 'sha256'));
        END IF;
    END LOOP;
END $setup$;

-- Helpers.
CREATE FUNCTION pg_temp.begin_issuance(p_subject text, p_app text, p_operation uuid DEFAULT gen_random_uuid()) RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM begin_application_issuance_lab(%L, %L, %L, %L, %L, %L)', 'https://issuer.iss.invalid',
        p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_app, p_operation, decode(repeat('55', 32), 'hex'))
$fn$;
CREATE FUNCTION pg_temp.intent(p_subject text, p_app text, p_tbs text) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM record_application_signing_intent_lab(%L, %L, %L, %L, %L, %L)', 'https://issuer.iss.invalid',
        p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_app, 'lab-signer:c5c5c5c5', digest(p_tbs, 'sha256'))
$fn$;
CREATE FUNCTION pg_temp.store(p_subject text, p_app text, p_tbs text, p_cn text, p_names text[]) RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT store_application_certificate_lab(%L, %L, %L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.iss.invalid', p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_app, digest(p_tbs, 'sha256'),
        decode(repeat('d0', 400), 'hex'), p_cn, '2026-11-07T00:00:00Z', '2026-12-07T00:00:00Z', p_names)
$fn$;

SELECT pg_temp.expect_state('SELECT 1 FROM certificate_application_issuance', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM lab_signer_intent', '42501');
SELECT pg_temp.expect_state(format('SELECT claim_lab_signing_intent(%L, %L)', gen_random_uuid(), decode(repeat('00', 32), 'hex')), '42501');
-- Begin: only an officer or the application's requester; only APPROVED.
SELECT pg_temp.expect_state(pg_temp.begin_issuance('approver-1', current_setting('test.app_a')), '42501');
SELECT pg_temp.expect_state(pg_temp.begin_issuance('req-2', current_setting('test.app_a')), '42501');
SELECT pg_temp.expect_state(pg_temp.begin_issuance('ra-1', current_setting('test.app_c')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.begin_issuance('ra-1', current_setting('test.app_d')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.begin_issuance('ra-1', gen_random_uuid()::text), 'P0002');
SELECT pg_temp.expect_state(pg_temp.intent('ra-1', current_setting('test.app_a'), 'tbs-a'), 'P0002');

DO $test$
DECLARE
    a text := current_setting('test.app_a');
    r record;
    first record;
BEGIN
    EXECUTE pg_temp.begin_issuance('req-1', a) INTO first;
    IF first.replayed OR first.request_state <> 'SERIAL_RESERVED' OR octet_length(first.serial) <> 16
       OR first.subject_cn <> 'a.lab.invalid' OR first.dns_names <> ARRAY['a.lab.invalid', 'www.a.lab.invalid']
       OR first.validity_days <> 30 OR first.issuer_certificate_der <> decode(repeat('c5', 300), 'hex')
       OR first.policy_version <> 'v1' OR first.csr_der <> decode(repeat('31', 200), 'hex') THEN
        RAISE EXCEPTION 'begin: %', first;
    END IF;
    EXECUTE pg_temp.begin_issuance('ra-1', a) INTO r;
    IF NOT r.replayed OR r.request_id <> first.request_id OR r.serial <> first.serial THEN
        RAISE EXCEPTION 'begin replay: %', r;
    END IF;
    -- The intent is durable before any signature; a second call is a replay.
    EXECUTE pg_temp.intent('ra-1', a, 'tbs-a') INTO r;
    IF r.replayed THEN RAISE EXCEPTION 'intent: %', r; END IF;
    PERFORM set_config('test.intent_a', r.intent_id::text, true);
    EXECUTE pg_temp.intent('ra-1', a, 'tbs-a') INTO r;
    IF NOT r.replayed OR r.intent_id::text <> current_setting('test.intent_a') THEN RAISE EXCEPTION 'intent replay: %', r; END IF;
    BEGIN
        EXECUTE pg_temp.intent('ra-1', a, 'other-tbs') INTO r;
        IF NOT r.replayed THEN RAISE EXCEPTION 'a second TBS got a new intent'; END IF;
    END;
END $test$;
RESET ROLE;

-- The signer sees what it needs, claims once, and nothing else.
SET LOCAL ROLE trust_lab_signer;
SELECT pg_temp.expect_state('SELECT 1 FROM signing_intent', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_application', '42501');
SELECT pg_temp.expect_state(format('SELECT * FROM begin_application_issuance_lab(%L, %L, %L, %L, %L, %L)',
    'https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_e'),
    gen_random_uuid(), decode(repeat('55', 32), 'hex')), '42501');
DO $test$
DECLARE r record;
BEGIN
    SELECT * INTO r FROM lab_signer_intent WHERE intent_id = current_setting('test.intent_a');
    IF NOT r.signable OR r.claimed OR r.tbs_sha256 <> digest('tbs-a', 'sha256') OR r.subject_cn <> 'a.lab.invalid'
       OR r.spki_sha256 <> digest('key-1', 'sha256') OR r.issuer_spki_sha256 <> digest('ca-c-key', 'sha256')
       OR octet_length(r.serial) <> 16 THEN
        RAISE EXCEPTION 'signer view: %', r;
    END IF;
END $test$;
SELECT pg_temp.expect_state(format('SELECT claim_lab_signing_intent(%L, %L)', current_setting('test.intent_a'),
    digest('other-tbs', 'sha256')), 'TP409');
SELECT pg_temp.expect_state(format('SELECT claim_lab_signing_intent(%L, %L)', gen_random_uuid(),
    digest('tbs-a', 'sha256')), 'P0002');
SELECT claim_lab_signing_intent(current_setting('test.intent_a')::uuid, digest('tbs-a', 'sha256'));
SELECT pg_temp.expect_state(format('SELECT claim_lab_signing_intent(%L, %L)', current_setting('test.intent_a'),
    digest('tbs-a', 'sha256')), 'TP409');
DO $test$ BEGIN
    IF NOT (SELECT claimed FROM lab_signer_intent WHERE intent_id = current_setting('test.intent_a')) THEN
        RAISE EXCEPTION 'the claim is not visible';
    END IF;
END $test$;
RESET ROLE;

-- Store: the names must be the application's; the core checks the TBS.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.store('ra-1', current_setting('test.app_a'), 'tbs-a', 'a.lab.invalid',
    ARRAY['a.lab.invalid', 'evil.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.store('ra-1', current_setting('test.app_a'), 'tbs-a', 'www.a.lab.invalid',
    ARRAY['a.lab.invalid', 'www.a.lab.invalid']), 'TP422');
SELECT pg_temp.expect_state(pg_temp.store('ra-1', current_setting('test.app_a'), 'other-tbs', 'a.lab.invalid',
    ARRAY['a.lab.invalid', 'www.a.lab.invalid']), '23514');
SELECT pg_temp.expect_state(pg_temp.store('req-2', current_setting('test.app_a'), 'tbs-a', 'a.lab.invalid',
    ARRAY['a.lab.invalid', 'www.a.lab.invalid']), '42501');
DO $test$
DECLARE v text;
BEGIN
    EXECUTE pg_temp.store('req-1', current_setting('test.app_a'), 'tbs-a', 'a.lab.invalid',
        ARRAY['a.lab.invalid', 'www.a.lab.invalid']) INTO v;
    IF v <> 'SIGNED' THEN RAISE EXCEPTION 'store: %', v; END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.store('ra-1', current_setting('test.app_a'), 'tbs-a', 'a.lab.invalid',
    ARRAY['a.lab.invalid', 'www.a.lab.invalid']), '23514');

-- B: an ambiguous signer outcome becomes RECONCILIATION_REQUIRED, never a
-- second signature, and nothing can be stored afterwards.
DO $test$
DECLARE
    b text := current_setting('test.app_b');
    r record;
    v text;
BEGIN
    EXECUTE pg_temp.begin_issuance('ra-1', b);
    EXECUTE pg_temp.intent('ra-1', b, 'tbs-b') INTO r;
    PERFORM set_config('test.intent_b', r.intent_id::text, true);
    v := mark_application_signing_uncertain_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', b::uuid);
    IF v <> 'RECONCILIATION_REQUIRED' THEN RAISE EXCEPTION 'uncertain: %', v; END IF;
    EXECUTE pg_temp.intent('ra-1', b, 'tbs-b') INTO r;
    IF NOT r.replayed THEN RAISE EXCEPTION 'an uncertain intent was recreated'; END IF;
    BEGIN
        EXECUTE pg_temp.store('ra-1', b, 'tbs-b', 'b.lab.invalid', ARRAY['b.lab.invalid', 'www.b.lab.invalid']);
        RAISE EXCEPTION 'a certificate was stored after an uncertain outcome';
    EXCEPTION WHEN SQLSTATE '23514' THEN NULL;
    END;
END $test$;
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
SELECT pg_temp.expect_state(format('SELECT claim_lab_signing_intent(%L, %L)', current_setting('test.intent_b'),
    digest('tbs-b', 'sha256')), 'TP409');
RESET ROLE;

-- G: a requester whose grant was withdrawn cannot run issuance.
RESET ROLE;
DELETE FROM management_role_grant WHERE subject = 'req-1' AND lifecycle_role = 'certificate-requester';
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.begin_issuance('req-1', current_setting('test.app_g')), '42501');

-- E and F: started, then the CA is suspended: nothing can be signed,
-- recorded or started.
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.begin_issuance('ra-1', current_setting('test.app_e'));
    EXECUTE pg_temp.intent('ra-1', current_setting('test.app_e'), 'tbs-e') INTO r;
    PERFORM set_config('test.intent_e', r.intent_id::text, true);
    EXECUTE pg_temp.begin_issuance('ra-1', current_setting('test.app_f'));
END $test$;
SELECT * FROM suspend_ca_lab('https://issuer.iss.invalid', 'admin', 'c5c5c5c5-0000-4000-8000-00000000000c', 'test',
    gen_random_uuid(), decode(repeat('66', 32), 'hex'));
SELECT pg_temp.expect_state(pg_temp.intent('ra-1', current_setting('test.app_f'), 'tbs-f'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.begin_issuance('ra-1', current_setting('test.app_g')), 'TP409');
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF (SELECT signable FROM lab_signer_intent WHERE intent_id = current_setting('test.intent_e')) THEN
        RAISE EXCEPTION 'an intent of a suspended CA is signable';
    END IF;
END $test$;
SELECT pg_temp.expect_state(format('SELECT claim_lab_signing_intent(%L, %L)', current_setting('test.intent_e'),
    digest('tbs-e', 'sha256')), 'TP409');
RESET ROLE;

-- Readers of the CA see the issuance state and the certificate.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.iss.invalid', 'reader', 'c5c5c5c5-0000-4000-8000-00000000000c');
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.iss.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT string_agg(subject_cn || ':' || status || ':' || (certificate_sha256 IS NOT NULL)
                          || ':' || coalesce(length(certificate_serial_hex), 0), ',' ORDER BY subject_cn)
        FROM management_certificate_application)
       <> 'a.lab.invalid:ISSUED:true:32,b.lab.invalid:RECONCILIATION_REQUIRED:false:0,c.lab.invalid:SUBMITTED:false:0,d.lab.invalid:REJECTED:false:0,e.lab.invalid:ISSUING:false:0,f.lab.invalid:ISSUING:false:0,g.lab.invalid:APPROVED:false:0' THEN
        RAISE EXCEPTION 'unexpected reader view: %', (SELECT string_agg(subject_cn || ':' || status, ',') FROM management_certificate_application);
    END IF;
    IF management_application_issuance_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
SELECT set_config('trust.reader_subject', 'nobody', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_certificate_application) THEN RAISE EXCEPTION 'an ungranted reader sees applications'; END IF;
END $test$;
RESET ROLE;

-- The core request and its audit trail; nothing changes afterwards.
DO $test$ BEGIN
    IF (SELECT r.state || ':' || r.requester_id FROM certificate_request r JOIN certificate_application_issuance i USING (ca_id, request_id)
        WHERE i.application_id = current_setting('test.app_a')::uuid) <> 'SIGNED:req-1' THEN
        RAISE EXCEPTION 'unexpected core request';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM audit_event WHERE event_type = 'certificate.application.issuance_started')
       OR NOT EXISTS (SELECT 1 FROM audit_event WHERE event_type = 'signing.result') THEN
        RAISE EXCEPTION 'missing issuance audit events';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$DELETE FROM certificate_application_issuance$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM lab_signer_claim$q$, 'P0001');

ROLLBACK;
\echo 'PASS: approved applications go through the core state machine with a durable intent before one signer claim, and ambiguity is never re-signed'
