-- Migration 0039: revocation through the RA channel (ADR-0026). Run as the
-- migration owner after 0039 on a disposable database; every change is rolled
-- back. Signatures and certificates are placeholders: PostgreSQL verifies
-- neither (the API and lab_verify_issued_certificates do). Before 0039 the
-- first statement fails.
BEGIN;

SELECT management_ra_revocation_version();

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
    IF encode(sha256(ra_revocation_message('lab-ra', 'dddddddd-dddd-dddd-dddd-dddddddddddd',
            '22222222-2222-2222-2222-222222222222', '\x4cc48aa1'::bytea, 1::smallint,
            'key compromise reported by the subscriber', 1794225600)), 'hex')
       <> 'c4d4cb0110b9acd644e22bd56a57a5d809d33b85dcd70dd7a334d4bf1974a5f3' THEN
        RAISE EXCEPTION 'the RA revocation message differs from the Rust vector';
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
-- Two RA systems, each with one certificate obtained through the channel.
INSERT INTO ra_system (ra_id, display_name, public_key_sec1) VALUES
    ('ra-one', 'RA one', decode('04' || repeat('b1', 64), 'hex')),
    ('ra-two', 'RA two', decode('04' || repeat('b2', 64), 'hex'));
INSERT INTO ra_profile_grant (ra_id, ca_id, profile_id) VALUES
    ('ra-one', 'c5c5c5c5-0000-4000-8000-00000000000c', 'server'),
    ('ra-two', 'c5c5c5c5-0000-4000-8000-00000000000c', 'server');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('urn:trust-platform:ra', 'ra-one', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester'),
    ('urn:trust-platform:ra', 'ra-two', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester');

SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    now_unix bigint := extract(epoch FROM clock_timestamp())::bigint;
    ras text[] := ARRAY['ra-one', 'ra-two'];
    r record;
    b record;
BEGIN
    FOR i IN 1..2 LOOP
        SELECT * INTO r FROM submit_ra_issuance_lab(ras[i], c, 'server', gen_random_uuid(),
            decode(repeat('4' || i, 200), 'hex'), digest('ra-key-' || i, 'sha256'), ras[i] || '.lab.invalid',
            ARRAY[ras[i] || '.lab.invalid'], 30, now_unix, decode(repeat('30', 70), 'hex'));
        SELECT * INTO b FROM begin_application_issuance_lab('urn:trust-platform:ra', ras[i], c, r.application_id,
            gen_random_uuid(), digest(ras[i], 'sha256'));
        PERFORM set_config('test.serial_' || i, encode(b.serial, 'hex'), true);
        PERFORM record_application_signing_intent_lab('urn:trust-platform:ra', ras[i], c, r.application_id,
            'lab-signer:c5', digest('tbs-' || ras[i], 'sha256'));
        PERFORM store_application_certificate_lab('urn:trust-platform:ra', ras[i], c, r.application_id,
            digest('tbs-' || ras[i], 'sha256'), decode(repeat('e' || i, 400), 'hex'), ras[i] || '.lab.invalid',
            '2026-11-07T00:00:00Z', '2026-12-07T00:00:00Z', ARRAY[ras[i] || '.lab.invalid']);
    END LOOP;
END $setup$;

-- revoke(ra, request, serial hex, code, signed_at): the call as SQL text.
CREATE FUNCTION pg_temp.revoke(p_ra text, p_request uuid, p_serial text, p_code int, p_signed_at bigint,
                               p_reason text DEFAULT 'key compromise reported') RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM submit_ra_revocation_lab(%L, %L, %L, %L, %s::smallint, %L, %s, %L)',
        p_ra, 'c5c5c5c5-0000-4000-8000-00000000000c', p_request, decode(p_serial, 'hex'), p_code, p_reason,
        p_signed_at, decode(repeat('30', 70), 'hex'))
$fn$;
GRANT EXECUTE ON FUNCTION pg_temp.revoke(text, uuid, text, int, bigint, text) TO PUBLIC;
RESET ROLE;

SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state(pg_temp.revoke('ra-one', gen_random_uuid(), current_setting('test.serial_1'), 1,
    extract(epoch FROM clock_timestamp())::bigint), '42501');
RESET ROLE;

SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM ra_revocation_request$$, '42501');
DO $test$
DECLARE
    now_unix bigint := extract(epoch FROM clock_timestamp())::bigint;
    one text := current_setting('test.serial_1');
    two text := current_setting('test.serial_2');
    req uuid := 'b1b1b1b1-0000-4000-8000-000000000001';
    r record;
    replay record;
BEGIN
    -- Unknown RA; another RA's certificate; an unknown serial.
    PERFORM pg_temp.expect_state(pg_temp.revoke('nobody', gen_random_uuid(), one, 1, now_unix), '42501');
    PERFORM pg_temp.expect_state(pg_temp.revoke('ra-one', gen_random_uuid(), two, 1, now_unix), 'P0002');
    PERFORM pg_temp.expect_state(pg_temp.revoke('ra-one', gen_random_uuid(), 'ffff', 1, now_unix), 'P0002');
    -- Reason codes outside the closed list; stale requests.
    PERFORM pg_temp.expect_state(pg_temp.revoke('ra-one', gen_random_uuid(), one, 2, now_unix), '22023');
    PERFORM pg_temp.expect_state(pg_temp.revoke('ra-one', gen_random_uuid(), one, 6, now_unix), '22023');
    PERFORM pg_temp.expect_state(pg_temp.revoke('ra-one', gen_random_uuid(), one, 1, now_unix - 400), 'TP422');

    -- Revoked at once, by the RA.
    EXECUTE pg_temp.revoke('ra-one', req, one, 1, now_unix) INTO r;
    IF r.replayed OR r.revoked_at IS NULL THEN
        RAISE EXCEPTION 'the RA revocation did not revoke: %', r;
    END IF;
    PERFORM set_config('test.revocation', r.revocation_id::text, true);
    -- The same signed bytes replay; other bytes under the same id conflict;
    -- a new request for the same certificate finds it revoked.
    EXECUTE pg_temp.revoke('ra-one', req, one, 1, now_unix) INTO replay;
    IF NOT replay.replayed OR replay.revocation_id <> r.revocation_id OR replay.revoked_at <> r.revoked_at THEN
        RAISE EXCEPTION 'the replay did not return the same revocation';
    END IF;
    PERFORM pg_temp.expect_state(pg_temp.revoke('ra-one', req, one, 4, now_unix), 'TP409');
    PERFORM pg_temp.expect_state(pg_temp.revoke('ra-one', gen_random_uuid(), one, 1, now_unix), 'TP409');
END $test$;
RESET ROLE;

-- The core revocation, the events and the stored bytes name the RA.
DO $test$
DECLARE
    rev uuid := current_setting('test.revocation')::uuid;
    stored ra_revocation_request%ROWTYPE;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM revocation x WHERE x.ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c'
                   AND x.serial_der_content = decode(current_setting('test.serial_1'), 'hex')
                   AND x.reason_code = 1 AND x.actor_id = 'ra-one') THEN
        RAISE EXCEPTION 'no core revocation by the RA';
    END IF;
    IF EXISTS (SELECT 1 FROM revocation x WHERE x.serial_der_content = decode(current_setting('test.serial_2'), 'hex')) THEN
        RAISE EXCEPTION 'the other RA''s certificate was revoked';
    END IF;
    IF (SELECT array_agg(e.action || ':' || e.actor_issuer || ':' || e.actor_subject ORDER BY e.recorded_at)
        FROM certificate_application_event e
        WHERE e.event_id IN ((SELECT q.requested_event_id FROM certificate_revocation_request q WHERE q.revocation_id = rev),
                             (SELECT d.decided_event_id FROM certificate_revocation_decision d WHERE d.revocation_id = rev)))
       <> ARRAY['revocation.requested:urn:trust-platform:ra:ra-one', 'revocation.approved:urn:trust-platform:ra:ra-one'] THEN
        RAISE EXCEPTION 'the revocation events are not attributed to the RA';
    END IF;
    SELECT * INTO stored FROM ra_revocation_request WHERE revocation_id = rev;
    IF stored.message <> ra_revocation_message('ra-one', 'c5c5c5c5-0000-4000-8000-00000000000c',
            'b1b1b1b1-0000-4000-8000-000000000001', decode(current_setting('test.serial_1'), 'hex'), 1::smallint,
            'key compromise reported', extract(epoch FROM stored.signed_at)::bigint) THEN
        RAISE EXCEPTION 'the stored message is not the signed bytes';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM audit_event a WHERE a.event_type = 'certificate.revoked' AND a.actor_id = 'ra-one') THEN
        RAISE EXCEPTION 'the audit trail does not name the RA';
    END IF;
END $test$;
-- A disabled RA cannot revoke.
UPDATE ra_system SET enabled = false WHERE ra_id = 'ra-two';
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.revoke('ra-two', gen_random_uuid(), current_setting('test.serial_2'), 1,
    extract(epoch FROM clock_timestamp())::bigint), '42501');
RESET ROLE;
SELECT pg_temp.expect_state($$UPDATE ra_revocation_request SET signature = '\x00'$$, 'P0001');
SELECT pg_temp.expect_state($$DELETE FROM ra_revocation_request$$, 'P0001');

ROLLBACK;
\echo 'PASS: RA revocation channel (0039)'
