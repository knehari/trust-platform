-- Migration 0046: RA channel hardening (ADR-0039). Run as the migration owner
-- after 0046 on a disposable database; every change is rolled back. The
-- fixture is that of management_ra_channel.sql (migration 0038); signature
-- bytes are placeholders, as there. Before 0046 the first statement fails.
BEGIN;

SELECT management_ra_hardening_version();

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


-- The policy is the owner's: the API's roles neither read nor change it.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM ra_system_policy$$, '42501');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_policy VALUES ('ra-good', 1000, 1000, NULL)$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM ra_system_policy$$, '42501');
RESET ROLE;
-- Zones must be DNS names; quotas must be bounded; the RA must exist.
SELECT pg_temp.expect_state($$INSERT INTO ra_system_policy VALUES ('ra-good', 5, 5, ARRAY['bad zone'])$$, '22023');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_policy VALUES ('ra-good', 5, 5, ARRAY['*.lab.invalid'])$$, '22023');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_policy VALUES ('ra-good', -1, 5, NULL)$$, '23514');
SELECT pg_temp.expect_state($$INSERT INTO ra_system_policy VALUES ('nobody', 5, 5, NULL)$$, '23503');

-- Without a row, the defaults: 100 issuances, 20 revocations, the profile's
-- zones.
DO $test$ BEGIN
    IF (SELECT row(max_issuance_per_hour, max_revocation_per_hour, allowed_dns_zones)::text
        FROM ra_effective_policy('ra-good')) <> '(100,20,)' THEN
        RAISE EXCEPTION 'unexpected default policy';
    END IF;
END $test$;

-- ra-good may ask only for names under team.lab.invalid, twice an hour.
INSERT INTO ra_system_policy (ra_id, max_issuance_per_hour, max_revocation_per_hour, allowed_dns_zones)
VALUES ('ra-good', 2, 1, ARRAY['team.lab.invalid']);

SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    now_unix bigint := extract(epoch FROM clock_timestamp())::bigint;
    first uuid := 'b2b2b2b2-0000-4000-8000-000000000001';
    r record;
BEGIN
    -- Outside the RA's zones, though inside the profile's: refused, and
    -- nothing is recorded.
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['other.lab.invalid'], now_unix), '42501');
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(),
        ARRAY['a.team.lab.invalid', 'b.lab.invalid'], now_unix), '42501');
    -- A label boundary: "xteam.lab.invalid" is not under "team.lab.invalid".
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['xteam.lab.invalid'], now_unix), '42501');
    -- Dated more than 30 seconds ahead: refused, though inside the old
    -- five-minute window.
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['a.team.lab.invalid'], now_unix + 120), 'TP422');
    -- Within the zones: accepted twice; replaying the first costs nothing.
    EXECUTE pg_temp.submit('ra-good', first, ARRAY['a.team.lab.invalid'], now_unix + 10) INTO r;
    IF r.replayed THEN RAISE EXCEPTION 'first request reported as replay'; END IF;
    EXECUTE pg_temp.submit('ra-good', first, ARRAY['a.team.lab.invalid'], now_unix + 10) INTO r;
    IF NOT r.replayed THEN RAISE EXCEPTION 'replay not recognized'; END IF;
    EXECUTE pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['team.lab.invalid'], now_unix) INTO r;
    -- The third within the hour: the quota is exhausted, nothing recorded.
    PERFORM pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['c.team.lab.invalid'], now_unix), 'TP429');
    -- A replay still answers, without counting.
    EXECUTE pg_temp.submit('ra-good', first, ARRAY['a.team.lab.invalid'], now_unix + 10) INTO r;
    IF NOT r.replayed THEN RAISE EXCEPTION 'replay refused once the quota is exhausted'; END IF;
END $test$;
RESET ROLE;
DO $test$ BEGIN
    IF (SELECT count(*) FROM ra_issuance_request WHERE ra_id = 'ra-good') <> 2 THEN
        RAISE EXCEPTION 'refused requests were recorded';
    END IF;
END $test$;
-- Requests older than an hour no longer count (the owner ages them here).
ALTER TABLE ra_issuance_request DISABLE TRIGGER immutable_ra_issuance_request;
UPDATE ra_issuance_request SET recorded_at = recorded_at - interval '61 minutes' WHERE ra_id = 'ra-good';
ALTER TABLE ra_issuance_request ENABLE TRIGGER immutable_ra_issuance_request;
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    r record;
BEGIN
    EXECUTE pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['d.team.lab.invalid'],
                           extract(epoch FROM clock_timestamp())::bigint) INTO r;
    IF r.replayed THEN RAISE EXCEPTION 'a fresh request after the hour was refused'; END IF;
END $test$;
RESET ROLE;

-- A zero quota stops the RA at once; the owner's change applies to the next
-- request.
UPDATE ra_system_policy SET max_issuance_per_hour = 0 WHERE ra_id = 'ra-good';
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.submit('ra-good', gen_random_uuid(), ARRAY['e.team.lab.invalid'],
    extract(epoch FROM clock_timestamp())::bigint), 'TP429');
RESET ROLE;

DO $test$ BEGIN
    IF management_ra_hardening_version() <> 1 THEN RAISE EXCEPTION 'unexpected version'; END IF;
END $test$;

ROLLBACK;
\echo 'PASS: RA channel hardening (0046)'
