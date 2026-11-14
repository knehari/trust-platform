-- Migration 0049: readers see the RA channel's policies (ADR-0044). Run as
-- the migration owner after 0049 on a disposable database; every change is
-- rolled back. The fixture is that of management_ra_channel.sql (migration
-- 0038). Before 0049 the first statement fails.
BEGIN;

SELECT management_ra_policy_views_version();

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


-- A reader of the CA, and one of no CA.
INSERT INTO management_reader_grant (issuer, subject, ca_id)
VALUES ('https://reader.iss.invalid', 'reader', 'c5c5c5c5-0000-4000-8000-00000000000c');
INSERT INTO ra_system_policy (ra_id, max_issuance_per_hour, max_revocation_per_hour, allowed_dns_zones)
VALUES ('ra-off', 7, 3, ARRAY['team.lab.invalid']);
INSERT INTO ra_system_key (ra_id, key_id, public_key_sec1) VALUES ('ra-good', 0, decode('04' || repeat('b1', 64), 'hex'));
UPDATE ra_system_key SET retired_at = clock_timestamp() WHERE ra_id = 'ra-good' AND key_id = 1;
INSERT INTO profile_short_lived_policy (ca_id, profile_id, max_validity_days)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'server', 3);
SET LOCAL ROLE trust_profile_writer;
DO $test$ DECLARE r record; BEGIN
    EXECUTE pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['a.lab.invalid'],
        extract(epoch FROM clock_timestamp())::bigint, 'server', 3) INTO r;
END $test$;
RESET ROLE;

-- The API's reader sees nothing of the raw tables, only the views.
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM ra_system_key$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM ra_system_policy$$, '42501');
SELECT set_config('trust.reader_issuer', 'https://reader.iss.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$
DECLARE
    good record;
    off record;
BEGIN
    -- Only the RAs granted a profile of this CA (not ra-other).
    IF (SELECT array_agg(ra_id ORDER BY ra_id) FROM management_ra_system) <> ARRAY['ra-good', 'ra-off'] THEN
        RAISE EXCEPTION 'unexpected RAs: %', (SELECT array_agg(ra_id) FROM management_ra_system);
    END IF;
    SELECT * INTO good FROM management_ra_system WHERE ra_id = 'ra-good';
    SELECT * INTO off FROM management_ra_system WHERE ra_id = 'ra-off';
    -- Defaults without a policy row; the owner's values with one.
    IF row(good.enabled, good.profile_ids, good.max_issuance_per_hour, good.max_revocation_per_hour,
           good.allowed_dns_zones, good.issuance_last_hour, good.revocation_last_hour)::text
       <> '(t,{server},100,20,,1,0)' THEN
        RAISE EXCEPTION 'unexpected ra-good row: %', good;
    END IF;
    IF row(off.enabled, off.max_issuance_per_hour, off.max_revocation_per_hour, off.allowed_dns_zones,
           off.issuance_last_hour)::text <> '(f,7,3,{team.lab.invalid},0)' THEN
        RAISE EXCEPTION 'unexpected ra-off row: %', off;
    END IF;
    -- Keys: fingerprints and dates only, oldest first; the retired one dated.
    IF jsonb_array_length(good.keys_json::jsonb) <> 2
       OR good.keys_json::jsonb -> 0 ->> 'sha256' <> encode(digest(decode('04' || repeat('a1', 64), 'hex'), 'sha256'), 'hex')
       OR good.keys_json::jsonb -> 0 ->> 'retired_at' IS NULL
       OR good.keys_json::jsonb -> 1 ->> 'retired_at' IS NOT NULL
       OR (good.keys_json::jsonb -> 1 ->> 'key_id')::int <> 2
       OR good.keys_json LIKE '%' || encode(decode('04' || repeat('b1', 64), 'hex'), 'hex') || '%' THEN
        RAISE EXCEPTION 'unexpected keys: %', good.keys_json;
    END IF;
    IF (SELECT array_agg(row(profile_id, max_validity_days)::text) FROM management_short_lived_profile)
       <> ARRAY['(server,3)'] THEN
        RAISE EXCEPTION 'unexpected short-lived profiles';
    END IF;
END $test$;
-- Another principal, or none, sees nothing.
SELECT set_config('trust.reader_subject', 'someone-else', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_ra_system) OR EXISTS (SELECT 1 FROM management_short_lived_profile) THEN
        RAISE EXCEPTION 'a principal without a grant sees RA policies';
    END IF;
END $test$;
SELECT set_config('trust.reader_issuer', '', true), set_config('trust.reader_subject', '', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_ra_system) OR EXISTS (SELECT 1 FROM management_short_lived_profile) THEN
        RAISE EXCEPTION 'no principal, yet RA policies are visible';
    END IF;
END $test$;
RESET ROLE;
-- The writer and the signer have no access to the views.
DO $test$ BEGIN
    IF has_table_privilege('trust_profile_writer', 'management_ra_system', 'SELECT')
       OR has_table_privilege('trust_lab_signer', 'management_short_lived_profile', 'SELECT') THEN
        RAISE EXCEPTION 'unexpected privileges on the RA policy views';
    END IF;
    IF management_ra_policy_views_version() <> 1 THEN RAISE EXCEPTION 'unexpected version'; END IF;
END $test$;

ROLLBACK;
\echo 'PASS: RA policy views for readers (0049)'
