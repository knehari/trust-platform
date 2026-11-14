-- Migration 0038: the RA issuance channel (ADR-0025). Run as the migration
-- owner after 0038 on a disposable database; every change is rolled back. The
-- signature bytes are placeholders: PostgreSQL does not verify ECDSA (the API
-- and lab_verify_issued_certificates do). Before 0038 the first statement fails.
BEGIN;

SELECT management_ra_channel_version();

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

-- The signed bytes equal the Rust vector (trust_pki_core::ra_request).
DO $test$ BEGIN
    IF encode(sha256(ra_issuance_message('lab-ra', 'dddddddd-dddd-dddd-dddd-dddddddddddd', 'server',
            '11111111-1111-1111-1111-111111111111', decode(repeat('ab', 32), 'hex'),
            ARRAY['api.lab.invalid', 'www.lab.invalid'], 30, 1794225600)), 'hex')
       <> 'bacfd3cabe918a56fe404ac14fc5372bb151ec7cc3fdcd64484f5511f292454e' THEN
        RAISE EXCEPTION 'the RA message differs from the Rust vector';
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
-- Two RA systems: one granted the server profile, one not; one disabled.
INSERT INTO ra_system (ra_id, display_name, public_key_sec1) VALUES
    ('ra-good', 'Granted RA', decode('04' || repeat('a1', 64), 'hex')),
    ('ra-other', 'Ungranted RA', decode('04' || repeat('a2', 64), 'hex'));
INSERT INTO ra_system (ra_id, display_name, public_key_sec1, enabled) VALUES
    ('ra-off', 'Disabled RA', decode('04' || repeat('a3', 64), 'hex'), false);
INSERT INTO ra_profile_grant (ra_id, ca_id, profile_id) VALUES
    ('ra-good', 'c5c5c5c5-0000-4000-8000-00000000000c', 'server'),
    ('ra-off', 'c5c5c5c5-0000-4000-8000-00000000000c', 'server');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('urn:trust-platform:ra', 'ra-good', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester'),
    ('urn:trust-platform:ra', 'ra-off', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester');
SELECT pg_temp.expect_state($$INSERT INTO ra_system (ra_id, display_name, public_key_sec1)
    VALUES ('Bad_ID', 'x', decode('04' || repeat('a4', 64), 'hex'))$$, '23514');
SELECT pg_temp.expect_state($$INSERT INTO ra_system (ra_id, display_name, public_key_sec1)
    VALUES ('ra-short', 'x', decode('02' || repeat('a4', 32), 'hex'))$$, '23514');

-- submit(ra, request, names, signed_at): the call as SQL text.
CREATE FUNCTION pg_temp.submit(p_ra text, p_request uuid, p_names text[], p_signed_at bigint,
                               p_profile text DEFAULT 'server', p_validity int DEFAULT 30) RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM submit_ra_issuance_lab(%L, %L, %L, %L, %L, %L, %L, %L, %s, %s, %L)',
        p_ra, 'c5c5c5c5-0000-4000-8000-00000000000c', p_profile, p_request,
        decode(repeat('30', 200), 'hex'), digest('ra-subject-key-' || p_request::text, 'sha256'),
        p_names[1], p_names, p_validity, p_signed_at, decode(repeat('30', 70), 'hex'))
$fn$;
GRANT EXECUTE ON FUNCTION pg_temp.submit(text, uuid, text[], bigint, text, int) TO PUBLIC;

-- Readers cannot reach the channel; the writer (the API) can.
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT ra_system_key_lab('ra-good')$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM ra_system$$, '42501');
RESET ROLE;

SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM ra_issuance_request$$, '42501');
DO $test$
DECLARE
    now_unix bigint := extract(epoch FROM clock_timestamp())::bigint;
    req uuid := 'a1a1a1a1-0000-4000-8000-000000000001';
    r record;
    replay record;
BEGIN
    IF ra_system_key_lab('ra-good') <> decode('04' || repeat('a1', 64), 'hex')
       OR ra_system_key_lab('ra-off') IS NOT NULL OR ra_system_key_lab('nobody') IS NOT NULL THEN
        RAISE EXCEPTION 'the key lookup must return enabled RAs only';
    END IF;
    -- Unknown, disabled or ungranted RAs, and a profile not granted.
    PERFORM pg_temp.expect_state(pg_temp.submit('nobody', gen_random_uuid(), ARRAY['a.lab.invalid'], now_unix), '42501');
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-off', gen_random_uuid(), ARRAY['a.lab.invalid'], now_unix), '42501');
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-other', gen_random_uuid(), ARRAY['a.lab.invalid'], now_unix), '42501');
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['a.lab.invalid'], now_unix,
                                                'client'), '42501');
    -- Stale or future requests.
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['a.lab.invalid'], now_unix - 400), 'TP422');
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['a.lab.invalid'], now_unix + 400), 'TP422');
    -- The profile still applies to a trusted RA: zones and validity.
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['a.example.com'], now_unix), 'TP422');
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['a.lab.invalid'], now_unix,
                                                'server', 91), 'TP422');

    -- Accepted: submitted and approved by the RA, in one transaction.
    EXECUTE pg_temp.submit('ra-good', req, ARRAY['api.lab.invalid', 'www.lab.invalid'], now_unix) INTO r;
    IF r.replayed THEN
        RAISE EXCEPTION 'a first request reported as replayed';
    END IF;
    -- The same signed bytes replay; other bytes under the same id conflict.
    EXECUTE pg_temp.submit('ra-good', req, ARRAY['api.lab.invalid', 'www.lab.invalid'], now_unix) INTO replay;
    IF NOT replay.replayed OR replay.application_id <> r.application_id THEN
        RAISE EXCEPTION 'the replay did not return the same application';
    END IF;
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', req, ARRAY['api.lab.invalid'], now_unix), 'TP409');
    PERFORM set_config('test.application', r.application_id::text, true);
    -- Nothing was issued yet.
    IF ra_issued_certificate_lab('ra-good', req) IS NOT NULL THEN
        RAISE EXCEPTION 'a certificate before issuance';
    END IF;
END $test$;
RESET ROLE;

-- The stored request is what the RA signed, attributed to the RA.
DO $test$
DECLARE
    app uuid := current_setting('test.application')::uuid;
    stored ra_issuance_request%ROWTYPE;
BEGIN
    IF certificate_application_status(app) <> 'APPROVED' THEN
        RAISE EXCEPTION 'the RA request was not approved';
    END IF;
    -- The RA, as requester of record, may start the issuance.
    IF NOT certificate_issuance_permitted('urn:trust-platform:ra', 'ra-good', 'c5c5c5c5-0000-4000-8000-00000000000c', app) THEN
        RAISE EXCEPTION 'the RA cannot start its issuance';
    END IF;
    SELECT * INTO stored FROM ra_issuance_request WHERE application_id = app;
    IF stored.message <> ra_issuance_message('ra-good', 'c5c5c5c5-0000-4000-8000-00000000000c', 'server',
            'a1a1a1a1-0000-4000-8000-000000000001', sha256(decode(repeat('30', 200), 'hex')),
            ARRAY['api.lab.invalid', 'www.lab.invalid'], 30, extract(epoch FROM stored.signed_at)::bigint) THEN
        RAISE EXCEPTION 'the stored message is not the signed bytes';
    END IF;
    IF (SELECT array_agg(e.action || ':' || e.actor_issuer || ':' || e.actor_subject ORDER BY e.recorded_at)
        FROM certificate_application_event e WHERE e.application_id = app)
       <> ARRAY['application.submitted:urn:trust-platform:ra:ra-good',
                'application.approved:urn:trust-platform:ra:ra-good'] THEN
        RAISE EXCEPTION 'the application events are not attributed to the RA';
    END IF;
    IF (SELECT count(*) FROM audit_event a JOIN certificate_application_event e ON e.event_id = a.event_id
        WHERE e.application_id = app AND a.actor_id = 'ra-good') <> 2 THEN
        RAISE EXCEPTION 'the audit trail does not name the RA';
    END IF;
END $test$;
SELECT pg_temp.expect_state($$UPDATE ra_issuance_request SET signature = '\x00'$$, 'P0001');
SELECT pg_temp.expect_state($$DELETE FROM ra_issuance_request$$, 'P0001');

DO $test$ BEGIN
    IF management_ra_channel_version() <> 1 THEN RAISE EXCEPTION 'unexpected RA channel version'; END IF;
END $test$;

ROLLBACK;
\echo 'PASS: RA issuance channel (0038)'
