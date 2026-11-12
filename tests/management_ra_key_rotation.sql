-- Migration 0047: RA key rotation (ADR-0040). Run as the migration owner
-- after 0047 on a disposable database; every change is rolled back. The
-- fixture is that of management_ra_channel.sql (migration 0038). The views'
-- key sets are checked end to end by the API HTTP test, with real
-- signatures. Before 0047 the first statement fails.
BEGIN;

SELECT management_ra_key_rotation_version();

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


CREATE FUNCTION pg_temp.k(p_byte text) RETURNS bytea LANGUAGE sql AS $fn$
    SELECT decode('04' || repeat(p_byte, 64), 'hex')
$fn$;

-- Registering an RA registered its first key, as key 1.
DO $test$ BEGIN
    IF (SELECT array_agg(row(ra_id, key_id, public_key_sec1 = pg_temp.k(CASE ra_id
            WHEN 'ra-good' THEN 'a1' WHEN 'ra-other' THEN 'a2' ELSE 'a3' END), retired_at IS NULL)::text
            ORDER BY ra_id) FROM ra_system_key)
       <> ARRAY['(ra-good,1,t,t)', '(ra-off,1,t,t)', '(ra-other,1,t,t)'] THEN
        RAISE EXCEPTION 'unexpected first keys: %', (SELECT array_agg(row(k.*)::text) FROM ra_system_key k);
    END IF;
END $test$;

-- The API's roles cannot read or change the keys.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM ra_system_key$$, '42501');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1)
    VALUES ('ra-good', 2, decode('04' || repeat('b1', 64), 'hex'))$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM ra_system_key$$, '42501');
SELECT pg_temp.expect_state($$SELECT ra_system_keys_lab('ra-good')$$, '42501');
RESET ROLE;

-- The first key can no longer be changed in ra_system.
SELECT pg_temp.expect_state($$UPDATE ra_system SET public_key_sec1 = decode('04' || repeat('b1', 64), 'hex')
    WHERE ra_id = 'ra-good'$$, '55000');
UPDATE ra_system SET display_name = 'Granted RA (renamed)' WHERE ra_id = 'ra-good';

-- A second key: numbered and dated by the database, whatever was asked.
INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1, activated_at)
VALUES ('ra-good', 99, pg_temp.k('b1'), '2000-01-01');
DO $test$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM ra_system_key WHERE ra_id = 'ra-good' AND key_id = 2
                   AND public_key_sec1 = pg_temp.k('b1') AND activated_at > clock_timestamp() - interval '1 minute') THEN
        RAISE EXCEPTION 'the second key was not numbered 2 and dated now';
    END IF;
END $test$;
-- A third unretired key, a key born retired, or a key anyone else uses.
SELECT pg_temp.expect_state($$INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1)
    VALUES ('ra-good', 3, decode('04' || repeat('b2', 64), 'hex'))$$, '55000');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1, retired_at)
    VALUES ('ra-other', 2, decode('04' || repeat('b3', 64), 'hex'), clock_timestamp())$$, '22023');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1)
    VALUES ('ra-other', 2, decode('04' || repeat('81', 64), 'hex'))$$, '23505');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1)
    VALUES ('ra-other', 2, decode('04' || repeat('a1', 64), 'hex'))$$, '23505');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1)
    VALUES ('ra-other', 2, decode('04' || repeat('b1', 64), 'hex'))$$, '23505');
SELECT pg_temp.expect_state($$INSERT INTO ra_system (ra_id, display_name, public_key_sec1)
    VALUES ('ra-copy', 'Copy', decode('04' || repeat('b1', 64), 'hex'))$$, '23505');
-- An officer key may not be an RA's rotated key either.
SELECT pg_temp.expect_state($$INSERT INTO registration_officer_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('officer-x', 'https://issuer.iss.invalid', 'officer-x', decode('04' || repeat('b1', 64), 'hex'))$$, 'P0001');

-- During the overlap, both keys sign new requests, oldest first; the
-- single-key lookup answers the newest.
SET LOCAL ROLE trust_profile_writer;
DO $test$ BEGIN
    IF ra_system_keys_lab('ra-good') <> ARRAY[pg_temp.k('a1'), pg_temp.k('b1')]
       OR ra_system_key_lab('ra-good') <> pg_temp.k('b1')
       OR ra_system_keys_lab('ra-off') IS NOT NULL OR ra_system_keys_lab('nobody') IS NOT NULL THEN
        RAISE EXCEPTION 'unexpected usable keys during the overlap';
    END IF;
END $test$;
RESET ROLE;

-- Retirement: once, dated by the database; nothing else changes and nothing
-- is deleted.
UPDATE ra_system_key SET retired_at = '2000-01-01' WHERE ra_id = 'ra-good' AND key_id = 1;
DO $test$ BEGIN
    IF (SELECT retired_at FROM ra_system_key WHERE ra_id = 'ra-good' AND key_id = 1)
       < clock_timestamp() - interval '1 minute' THEN
        RAISE EXCEPTION 'retirement was backdated';
    END IF;
END $test$;
SELECT pg_temp.expect_state($$UPDATE ra_system_key SET retired_at = clock_timestamp()
    WHERE ra_id = 'ra-good' AND key_id = 1$$, '55000');
SELECT pg_temp.expect_state($$UPDATE ra_system_key SET public_key_sec1 = decode('04' || repeat('b4', 64), 'hex')
    WHERE ra_id = 'ra-good' AND key_id = 2$$, '55000');
SELECT pg_temp.expect_state($$UPDATE ra_system_key SET activated_at = '2000-01-01'
    WHERE ra_id = 'ra-good' AND key_id = 2$$, '55000');
SELECT pg_temp.expect_state($$DELETE FROM ra_system_key WHERE ra_id = 'ra-good' AND key_id = 1$$, '55000');
SET LOCAL ROLE trust_profile_writer;
DO $test$ BEGIN
    IF ra_system_keys_lab('ra-good') <> ARRAY[pg_temp.k('b1')] THEN
        RAISE EXCEPTION 'a retired key is still usable';
    END IF;
END $test$;
RESET ROLE;
-- A third key is allowed once one is retired; its number follows.
INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1) VALUES ('ra-good', 0, pg_temp.k('b5'));
DO $test$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM ra_system_key WHERE ra_id = 'ra-good' AND key_id = 3
                   AND public_key_sec1 = pg_temp.k('b5')) THEN
        RAISE EXCEPTION 'the third key was not numbered 3';
    END IF;
END $test$;
-- Retiring every key leaves the RA without a usable key.
UPDATE ra_system_key SET retired_at = clock_timestamp() WHERE ra_id = 'ra-good' AND retired_at IS NULL;
SET LOCAL ROLE trust_profile_writer;
DO $test$ BEGIN
    IF ra_system_keys_lab('ra-good') IS NOT NULL OR ra_system_key_lab('ra-good') IS NOT NULL THEN
        RAISE EXCEPTION 'an RA with only retired keys still has a usable key';
    END IF;
END $test$;
RESET ROLE;

-- The signer's views expose key sets; the signer reads them.
DO $test$ BEGIN
    IF (SELECT array_agg(attname::text || ':' || format_type(atttypid, atttypmod) ORDER BY attname)
        FROM pg_attribute WHERE attrelid IN ('lab_signer_authorization'::regclass, 'lab_signer_crl_entry_proof'::regclass)
          AND attname LIKE 'ra_public_key%' AND NOT attisdropped)
       <> ARRAY['ra_public_keys:bytea[]', 'ra_public_keys:bytea[]'] THEN
        RAISE EXCEPTION 'the signer views do not expose RA key sets';
    END IF;
    IF NOT has_table_privilege('trust_lab_signer', 'lab_signer_authorization', 'SELECT')
       OR NOT has_table_privilege('trust_lab_signer', 'lab_signer_crl_entry_proof', 'SELECT')
       OR has_table_privilege('trust_profile_writer', 'lab_signer_authorization', 'SELECT') THEN
        RAISE EXCEPTION 'unexpected privileges on the signer views';
    END IF;
END $test$;

DO $test$ BEGIN
    IF management_ra_key_rotation_version() <> 1 THEN RAISE EXCEPTION 'unexpected version'; END IF;
END $test$;

ROLLBACK;
\echo 'PASS: RA key rotation (0047)'
