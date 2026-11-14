-- Migration 0041: authorization proofs for the laboratory signer (ADR-0028).
-- Run as the migration owner after 0041 on a disposable database; every
-- change is rolled back. Signatures are placeholders: PostgreSQL verifies no
-- ECDSA (the API, the signer and lab_verify_issued_certificates do). Before
-- 0041 the first statement fails.
BEGIN;

SELECT management_authorization_proofs_version();

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

-- The RA version 2 bytes equal the Rust vector (trust_pki_core::ra_request).
DO $test$ BEGIN
    IF encode(sha256(ra_issuance_message_v2('lab-ra', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 'server',
            '11111111-1111-1111-1111-111111111111', decode(repeat('ab', 32), 'hex'),
            ARRAY['api.lab.invalid', 'www.lab.invalid'], 30, 1794225600, 'www.lab.invalid', ARRAY['client-auth'])), 'hex')
       <> 'e4d2d2c2083d1db9337224804003a0b5626b31fa3531c953ef10cc7ce88602dc' THEN
        RAISE EXCEPTION 'the RA v2 message differs from the Rust vector';
    END IF;
END $test$;

-- An ACTIVE CA through 0026-0027, an active profile revision (owner
-- fixture), grants, and applications through 0029.
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
    ('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer'),
    ('https://issuer.iss.invalid', 'ra-2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer'),
    ('https://issuer.iss.invalid', 'req-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer');

-- Officer keys: one per officer, never an approver's or an RA's key.
INSERT INTO registration_officer_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('officer-1', 'https://issuer.iss.invalid', 'ra-1', decode('04' || repeat('c1', 64), 'hex')),
    ('requester-officer', 'https://issuer.iss.invalid', 'req-1', decode('04' || repeat('c3', 64), 'hex'));
SELECT pg_temp.expect_state($$INSERT INTO registration_officer_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('copy', 'https://issuer.iss.invalid', 'ra-2', decode('04' || repeat('81', 64), 'hex'))$$, 'P0001');
SELECT pg_temp.expect_state($$INSERT INTO registration_officer_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('second', 'https://issuer.iss.invalid', 'ra-1', decode('04' || repeat('c9', 64), 'hex'))$$, '23505');
SELECT pg_temp.expect_state($$DELETE FROM registration_officer_key$$, 'P0001');

-- Two applications by req-1, and an RA allowed one optional extension.
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    r record;
BEGIN
    FOR i IN 1..3 LOOP
        SELECT * INTO r FROM submit_certificate_application_lab('https://issuer.iss.invalid', 'req-1',
            'c5c5c5c5-0000-4000-8000-00000000000c', 'server', decode(repeat('5' || i, 200), 'hex'),
            digest('key-' || i, 'sha256'), 'app' || i || '.lab.invalid', ARRAY['app' || i || '.lab.invalid'],
            30, gen_random_uuid(), digest('app' || i, 'sha256'));
        PERFORM set_config('test.app_' || i, r.application_id::text, true);
    END LOOP;
END $setup$;
RESET ROLE;
INSERT INTO ra_system (ra_id, display_name, public_key_sec1) VALUES
    ('ra-v2', 'RA v2', decode('04' || repeat('d1', 64), 'hex'));
INSERT INTO ra_profile_grant (ra_id, ca_id, profile_id) VALUES ('ra-v2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'server');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('urn:trust-platform:ra', 'ra-v2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester');
SELECT pg_temp.expect_state($$INSERT INTO registration_officer_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('ra-copy', 'https://issuer.iss.invalid', 'ra-2', decode('04' || repeat('d1', 64), 'hex'))$$, 'P0001');

SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM certificate_application_authorization$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_authorization$$, '42501');
SELECT pg_temp.expect_state(format('SELECT * FROM prepare_certificate_decision_lab(%L, %L, %L, %L, %L)',
    'https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_1'), 'approve'),
    '42501');
RESET ROLE;

SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM certificate_application_authorization$$, '42501');
DO $test$
DECLARE
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    app1 uuid := current_setting('test.app_1')::uuid;
    app2 uuid := current_setting('test.app_2')::uuid;
    p record;
    r record;
    replay record;
    op uuid := gen_random_uuid();
BEGIN
    -- An officer without a registered key cannot even get a claim.
    PERFORM pg_temp.expect_state(format('SELECT * FROM prepare_certificate_decision_lab(%L, %L, %L, %L, %L)',
        'https://issuer.iss.invalid', 'ra-2', c, app1, 'approve'), '42501');
    -- The claim the officer signs: every fact the signer will check.
    SELECT * INTO p FROM prepare_certificate_decision_lab('https://issuer.iss.invalid', 'ra-1', c, app1, 'approve');
    IF p.key_id <> 'officer-1' OR p.claim <> 'trust-platform/issuance-authorization/v1;decision=approve;ca=' || c
        || ';application=' || app1 || ';profile=server;revision=1;csr_sha256=' || encode(sha256(decode(repeat('51', 200), 'hex')), 'hex')
        || ';subject_cn=app1.lab.invalid;dns_names=app1.lab.invalid;validity_days=30;extensions=;key=officer-1;issued_at='
        || p.issued_at THEN
        RAISE EXCEPTION 'unexpected claim %', p.claim;
    END IF;
    -- Stale or future claims are refused.
    PERFORM pg_temp.expect_state(format('SELECT * FROM record_signed_certificate_decision_lab(%L, %L, %L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.iss.invalid', 'ra-1', c, app1, 'approve', 'checked', clock_timestamp() - interval '11 minutes',
        decode(repeat('30', 70), 'hex'), gen_random_uuid(), digest('d', 'sha256')), 'TP409');
    -- The requester never decides, even holding an officer key.
    PERFORM pg_temp.expect_state(format('SELECT * FROM record_signed_certificate_decision_lab(%L, %L, %L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.iss.invalid', 'req-1', c, app1, 'approve', 'checked', clock_timestamp(),
        decode(repeat('30', 70), 'hex'), gen_random_uuid(), digest('d', 'sha256')), '42501');
    -- Recorded with its claim and key; a replay returns the same.
    SELECT * INTO r FROM record_signed_certificate_decision_lab('https://issuer.iss.invalid', 'ra-1', c, app1, 'approve',
        'checked', p.issued_at::timestamptz, decode(repeat('30', 70), 'hex'), op, digest('d1', 'sha256'));
    IF r.replayed OR r.status <> 'APPROVED' OR r.claim <> p.claim
       OR r.public_key_sec1 <> decode('04' || repeat('c1', 64), 'hex') THEN
        RAISE EXCEPTION 'unexpected signed decision %', r;
    END IF;
    SELECT * INTO replay FROM record_signed_certificate_decision_lab('https://issuer.iss.invalid', 'ra-1', c, app1, 'approve',
        'checked', p.issued_at::timestamptz, decode(repeat('30', 70), 'hex'), op, digest('d1', 'sha256'));
    IF NOT replay.replayed OR replay.claim <> p.claim THEN RAISE EXCEPTION 'replay differs'; END IF;
    PERFORM pg_temp.expect_state(format('SELECT * FROM record_signed_certificate_decision_lab(%L, %L, %L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.iss.invalid', 'ra-1', c, app1, 'approve', 'again', clock_timestamp(),
        decode(repeat('30', 70), 'hex'), gen_random_uuid(), digest('d2', 'sha256')), 'TP409');
    -- A signed approval is a proof; an unsigned one (migration 0029) is not.
    PERFORM decide_certificate_application_lab('https://issuer.iss.invalid', 'ra-1', c, app2, 'approve', 'unsigned',
        gen_random_uuid(), digest('u', 'sha256'));
    IF NOT application_authorization_present_lab(c, app1) OR application_authorization_present_lab(c, app2) THEN
        RAISE EXCEPTION 'proof detection is wrong';
    END IF;
    -- A signed rejection is recorded and proves nothing to issue.
    SELECT * INTO p FROM prepare_certificate_decision_lab('https://issuer.iss.invalid', 'ra-1', c,
        current_setting('test.app_3')::uuid, 'reject');
    SELECT * INTO r FROM record_signed_certificate_decision_lab('https://issuer.iss.invalid', 'ra-1', c,
        current_setting('test.app_3')::uuid, 'reject', 'refused', p.issued_at::timestamptz,
        decode(repeat('30', 70), 'hex'), gen_random_uuid(), digest('d3', 'sha256'));
    IF r.status <> 'REJECTED' OR application_authorization_present_lab(c, current_setting('test.app_3')::uuid) THEN
        RAISE EXCEPTION 'a rejection must not be a proof';
    END IF;
END $test$;

-- RA version 2: the RA sets the subject among the names and asks for an
-- extension the profile allows; nothing else.
CREATE FUNCTION pg_temp.v2(p_request uuid, p_cn text, p_names text[], p_extensions text[]) RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM submit_ra_issuance_v2_lab(%L, %L, %L, %L, %L, %L, %L, %L, 30, %s, %L, %L)',
        'ra-v2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'server', p_request, decode(repeat('61', 200), 'hex'),
        digest('ra-key-' || p_request::text, 'sha256'), p_cn, p_names, extract(epoch FROM clock_timestamp())::bigint,
        p_extensions, decode(repeat('30', 70), 'hex'))
$fn$;
GRANT EXECUTE ON FUNCTION pg_temp.v2(uuid, text, text[], text[]) TO PUBLIC;
DO $test$
DECLARE
    r record;
BEGIN
    PERFORM pg_temp.expect_state(pg_temp.v2(gen_random_uuid(), 'b.lab.invalid', ARRAY['a.lab.invalid', 'b.lab.invalid'],
        ARRAY['client-auth']), 'TP422');
    PERFORM pg_temp.expect_state(pg_temp.v2(gen_random_uuid(), 'b.lab.invalid', ARRAY['a.lab.invalid', 'b.lab.invalid'],
        ARRAY['ocsp-must-staple']), '22023');
    PERFORM pg_temp.expect_state(pg_temp.v2(gen_random_uuid(), 'other.lab.invalid', ARRAY['a.lab.invalid'], '{}'), 'TP422');
END $test$;
RESET ROLE;
INSERT INTO profile_optional_extension (ca_id, profile_id, extension)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'server', 'client-auth');
SELECT pg_temp.expect_state($$INSERT INTO profile_optional_extension (ca_id, profile_id, extension)
    VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'server', 'anything')$$, '23514');
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    req uuid := 'e1e1e1e1-0000-4000-8000-000000000001';
    r record;
    b record;
BEGIN
    -- The subject is the second name: the RA corrected the CSR's.
    EXECUTE pg_temp.v2(req, 'b.lab.invalid', ARRAY['a.lab.invalid', 'b.lab.invalid'], ARRAY['client-auth']) INTO r;
    IF r.replayed OR NOT application_authorization_present_lab('c5c5c5c5-0000-4000-8000-00000000000c', r.application_id)
       OR application_extensions_lab('c5c5c5c5-0000-4000-8000-00000000000c', r.application_id) <> ARRAY['client-auth'] THEN
        RAISE EXCEPTION 'unexpected v2 submission %', r;
    END IF;
    PERFORM set_config('test.ra_app', r.application_id::text, true);
    -- Issuance as the RA, up to the journaled intent the signer will read.
    SELECT * INTO b FROM begin_application_issuance_lab('urn:trust-platform:ra', 'ra-v2',
        'c5c5c5c5-0000-4000-8000-00000000000c', r.application_id, gen_random_uuid(), digest('i', 'sha256'));
    PERFORM record_application_signing_intent_lab('urn:trust-platform:ra', 'ra-v2', 'c5c5c5c5-0000-4000-8000-00000000000c',
        r.application_id, 'lab-signer:c5', digest('tbs-ra', 'sha256'));
    -- An officer-signed application, issued as well.
    SELECT * INTO b FROM begin_application_issuance_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_1')::uuid, gen_random_uuid(), digest('j', 'sha256'));
    PERFORM record_application_signing_intent_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
        current_setting('test.app_1')::uuid, 'lab-signer:c5', digest('tbs-officer', 'sha256'));
END $test$;
RESET ROLE;

-- The signer's view carries each proof with its registered key.
SET LOCAL ROLE trust_lab_signer;
SELECT pg_temp.expect_state($$SELECT * FROM certificate_application_authorization$$, '42501');
DO $test$
DECLARE
    v record;
BEGIN
    SELECT * INTO v FROM lab_signer_authorization WHERE application_id = current_setting('test.ra_app');
    IF v.ra_id <> 'ra-v2' OR v.ra_message_version <> 2 OR NOT v.ra_enabled
       OR v.ra_public_key <> decode('04' || repeat('d1', 64), 'hex') OR v.optional_extensions <> ARRAY['client-auth']
       OR v.officer_key_id IS NOT NULL THEN
        RAISE EXCEPTION 'unexpected RA proof row %', v;
    END IF;
    SELECT * INTO v FROM lab_signer_authorization WHERE application_id = current_setting('test.app_1');
    IF v.officer_key_id <> 'officer-1' OR v.officer_decision <> 'approve' OR NOT v.officer_key_active
       OR v.officer_public_key <> decode('04' || repeat('c1', 64), 'hex') OR v.ra_id IS NOT NULL
       OR v.optional_extensions <> '{}' OR v.officer_issued_at !~ '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$' THEN
        RAISE EXCEPTION 'unexpected officer proof row %', v;
    END IF;
END $test$;
RESET ROLE;

-- A revoked officer key no longer counts for the signer.
UPDATE registration_officer_key SET revoked_at = clock_timestamp() WHERE key_id = 'officer-1';
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF (SELECT officer_key_active FROM lab_signer_authorization WHERE application_id = current_setting('test.app_1')) THEN
        RAISE EXCEPTION 'a revoked key still counts';
    END IF;
END $test$;
RESET ROLE;
SELECT pg_temp.expect_state($$UPDATE certificate_application_authorization SET decision = 'reject'$$, 'P0001');
SELECT pg_temp.expect_state($$DELETE FROM certificate_application_option$$, 'P0001');

ROLLBACK;
\echo 'PASS: authorization proofs for the signer (0041)'
