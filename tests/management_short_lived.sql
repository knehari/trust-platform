-- Migration 0048: short-lived certificates without revocation (ADR-0042).
-- Run as the migration owner after 0048 on a disposable database; every
-- change is rolled back. The fixture is that of management_ra_channel.sql
-- (migration 0038). The certificate itself (noRevAvail, no distribution
-- point) and the refused revocations through the API are checked by the API
-- HTTP test. Before 0048 the first statement fails.
BEGIN;

SELECT management_short_lived_version();

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


-- The policy is the owner's; the API's roles neither read nor change it,
-- nor the snapshots.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM profile_short_lived_policy$$, '42501');
SELECT pg_temp.expect_state($$INSERT INTO profile_short_lived_policy (ca_id, profile_id, max_validity_days)
    VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'server', 7)$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM certificate_application_short_lived$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM profile_short_lived_policy$$, '42501');
SELECT pg_temp.expect_state($$SELECT application_short_lived_lab('x', 'y',
    'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid())$$, '42501');
RESET ROLE;
-- At most seven days; at least one.
SELECT pg_temp.expect_state($$INSERT INTO profile_short_lived_policy (ca_id, profile_id, max_validity_days)
    VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'server', 8)$$, '23514');
SELECT pg_temp.expect_state($$INSERT INTO profile_short_lived_policy (ca_id, profile_id, max_validity_days)
    VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'server', 0)$$, '23514');

-- An ordinary application first, then the profile becomes short-lived.
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.submit('ra-good', 'c1c1c1c1-0000-4000-8000-000000000001', ARRAY['ordinary.lab.invalid'],
        extract(epoch FROM clock_timestamp())::bigint, 'server', 30) INTO r;
    PERFORM set_config('test.ordinary', r.application_id::text, true);
END $test$;
RESET ROLE;
INSERT INTO profile_short_lived_policy (ca_id, profile_id, max_validity_days)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'server', 5);
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE r record;
BEGIN
    -- Longer than the short-lived bound, though within the profile: refused.
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['long.lab.invalid'],
        extract(epoch FROM clock_timestamp())::bigint, 'server', 6), 'TP422');
    EXECUTE pg_temp.submit('ra-good', 'c1c1c1c1-0000-4000-8000-000000000002', ARRAY['short.lab.invalid'],
        extract(epoch FROM clock_timestamp())::bigint, 'server', 5) INTO r;
    PERFORM set_config('test.short', r.application_id::text, true);
    -- Whether an application is short-lived: for its requester or an officer.
    IF NOT application_short_lived_lab('urn:trust-platform:ra', 'ra-good', 'c5c5c5c5-0000-4000-8000-00000000000c',
                                       current_setting('test.short')::uuid)
       OR application_short_lived_lab('urn:trust-platform:ra', 'ra-good', 'c5c5c5c5-0000-4000-8000-00000000000c',
                                      current_setting('test.ordinary')::uuid) THEN
        RAISE EXCEPTION 'unexpected short-lived answers';
    END IF;
    PERFORM pg_temp.expect_state(format($$SELECT application_short_lived_lab('urn:trust-platform:ra', 'ra-other',
        'c5c5c5c5-0000-4000-8000-00000000000c', %L)$$, current_setting('test.short')), '42501');
END $test$;
RESET ROLE;

-- The snapshot: only the short-lived application, with its bound; it stays
-- when the owner lifts the policy, and it is immutable.
DO $test$ BEGIN
    IF (SELECT array_agg(row(application_id::text, max_validity_days)::text) FROM certificate_application_short_lived)
       <> ARRAY[format('(%s,5)', current_setting('test.short'))] THEN
        RAISE EXCEPTION 'unexpected short-lived snapshots';
    END IF;
END $test$;
DELETE FROM profile_short_lived_policy;
DO $test$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM certificate_application_short_lived
                   WHERE application_id = current_setting('test.short')::uuid) THEN
        RAISE EXCEPTION 'lifting the policy changed a submitted application';
    END IF;
END $test$;
SELECT pg_temp.expect_state(format($$DELETE FROM certificate_application_short_lived WHERE application_id = %L$$,
    current_setting('test.short')), 'P0001');
SELECT pg_temp.expect_state(format($$UPDATE certificate_application_short_lived SET max_validity_days = 7
    WHERE application_id = %L$$, current_setting('test.short')), 'P0001');

-- No distribution point for the short-lived application, the CA's for the
-- ordinary one.
INSERT INTO ca_crl_distribution_point (ca_id, base_url)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'http://crl.lab.invalid');
SET LOCAL ROLE trust_profile_writer;
DO $test$ BEGIN
    IF application_crl_distribution_point_lab('urn:trust-platform:ra', 'ra-good',
           'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.short')::uuid) IS NOT NULL
       OR application_crl_distribution_point_lab('urn:trust-platform:ra', 'ra-good',
           'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.ordinary')::uuid) IS NULL THEN
        RAISE EXCEPTION 'unexpected distribution points';
    END IF;
END $test$;
RESET ROLE;

-- A revocation request for the short-lived application is refused before
-- anything else is checked (TP409); for the ordinary one the trigger lets
-- it through to the constraints (here, a missing issuance: 23503).
SELECT pg_temp.expect_state(format($$INSERT INTO certificate_revocation_request
    (application_id, ca_id, serial_der_content, reason_code, reason, requested_event_id)
    VALUES (%L, 'c5c5c5c5-0000-4000-8000-00000000000c', '\x01', 1, 'test', gen_random_uuid())$$,
    current_setting('test.short')), 'TP409');
SELECT pg_temp.expect_state(format($$INSERT INTO certificate_revocation_request
    (application_id, ca_id, serial_der_content, reason_code, reason, requested_event_id)
    VALUES (%L, 'c5c5c5c5-0000-4000-8000-00000000000c', '\x01', 1, 'test', gen_random_uuid())$$,
    current_setting('test.ordinary')), '23503');

-- The signer reads the flag.
DO $test$ BEGIN
    IF (SELECT format_type(atttypid, atttypmod) FROM pg_attribute
        WHERE attrelid = 'lab_signer_intent'::regclass AND attname = 'no_rev_avail') <> 'boolean'
       OR NOT has_table_privilege('trust_lab_signer', 'lab_signer_intent', 'SELECT') THEN
        RAISE EXCEPTION 'the signer view lacks no_rev_avail';
    END IF;
    IF management_short_lived_version() <> 1 THEN RAISE EXCEPTION 'unexpected version'; END IF;
END $test$;

ROLLBACK;
\echo 'PASS: short-lived certificates (0048)'
