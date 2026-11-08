-- Migration 0024: activation and retirement of approved profile revisions.
-- Run as the migration owner after 0024 on a disposable database; every
-- change is rolled back. Decisions are recorded with placeholder signatures
-- (the database does not verify ECDSA; the API and the audit tool do).
-- Before 0024 the first statement fails.
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
CREATE FUNCTION pg_temp.point(p_byte text) RETURNS bytea LANGUAGE sql AS
$fn$ SELECT '\x04'::bytea || decode(repeat(p_byte, 64), 'hex') $fn$;

-- Creates, submits and (optionally) approves the next revision of a profile.
CREATE FUNCTION pg_temp.revision(p_profile text, p_policy text, p_suites text[], p_approve boolean)
RETURNS integer LANGUAGE plpgsql AS $fn$
DECLARE
    x uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    iss text := 'https://issuer.activation.invalid';
    r integer;
BEGIN
    SELECT c.revision INTO r FROM create_profile_draft_lab(iss, 'author', x, p_profile, 'Profile', p_policy, 90, 5,
        ARRAY['lab.invalid'], p_suites, gen_random_uuid(), decode(repeat('01', 32), 'hex')) c;
    PERFORM submit_profile_draft_lab(iss, 'author', x, p_profile, r,
        profile_draft_snapshot_sha256(x, p_profile, r), gen_random_uuid(), decode(repeat('02', 32), 'hex'));
    IF p_approve THEN
        PERFORM record_profile_decision_lab(iss, a, x, p_profile, r, 'approve', date_trunc('milliseconds', clock_timestamp()),
            decode(repeat('30', 70), 'hex'), gen_random_uuid(), decode(repeat('03', 32), 'hex'))
        FROM unnest(ARRAY['approver-1', 'approver-2']) AS a;
    END IF;
    RETURN r;
END
$fn$;

INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'Activation CA', 'v1');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role)
SELECT 'https://issuer.activation.invalid', s, 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', r
FROM (VALUES ('author', 'profile-editor'), ('approver-1', 'policy-approver'), ('approver-2', 'policy-approver'),
             ('approver-1', 'ca-operator'), ('operator', 'ca-operator')) AS v(s, r);
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.activation.invalid', 'reader', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
INSERT INTO profile_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('a1', 'https://issuer.activation.invalid', 'approver-1', pg_temp.point('01')),
    ('a2', 'https://issuer.activation.invalid', 'approver-2', pg_temp.point('02'));
INSERT INTO ca_signing_capability (ca_id, suite_id) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'ecdsa-p256-sha256'),
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'ecdsa-p384-sha384');

-- Capabilities: catalogue-style identifiers, append-only, one revocation.
SELECT pg_temp.expect_state($q$INSERT INTO ca_signing_capability (ca_id, suite_id)
    VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'P256-SHA256')$q$, '23514');
SELECT pg_temp.expect_state($q$DELETE FROM ca_signing_capability$q$, 'P0001');
SELECT pg_temp.expect_state($q$UPDATE ca_signing_capability SET declared_at = now()$q$, 'P0001');

-- server-lab: revisions 1 and 2 approved (v1), 3 approved with v2.
-- suite-lab: approved with an undeclared suite. pending-lab: submitted only.
-- p384-lab: approved with the suite that is revoked below.
SELECT pg_temp.revision('server-lab', 'v1', ARRAY['ecdsa-p256-sha256'], true);
SELECT pg_temp.revision('server-lab', 'v1', ARRAY['ecdsa-p256-sha256'], true);
SELECT pg_temp.revision('server-lab', 'v2', ARRAY['ecdsa-p256-sha256'], true);
SELECT pg_temp.revision('suite-lab', 'v1', ARRAY['ecdsa-p256-sha256', 'rsa-pss-2048-sha256'], true);
SELECT pg_temp.revision('pending-lab', 'v1', ARRAY['ecdsa-p256-sha256'], false);
SELECT pg_temp.revision('p384-lab', 'v1', ARRAY['ecdsa-p384-sha384'], true);

CREATE FUNCTION pg_temp.activate(p_subject text, p_profile text, p_revision integer, p_digest bytea DEFAULT NULL)
RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM activate_profile_revision_lab(%L, %L, %L, %L, %s, %L, gen_random_uuid(), %L)',
        'https://issuer.activation.invalid', p_subject, 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', p_profile, p_revision,
        coalesce(p_digest, profile_draft_snapshot_sha256('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', p_profile, p_revision)),
        decode(repeat('aa', 32), 'hex'))
$fn$;
CREATE FUNCTION pg_temp.retire(p_subject text, p_profile text, p_revision integer)
RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM retire_profile_revision_lab(%L, %L, %L, %L, %s, gen_random_uuid(), %L)',
        'https://issuer.activation.invalid', p_subject, 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', p_profile, p_revision,
        decode(repeat('bb', 32), 'hex'))
$fn$;

-- Refusals: no ca-operator grant (author, reader), an approver who also
-- holds the operator grant, an unapproved revision, an altered digest, a
-- policy-version mismatch, an undeclared suite, an unknown revision.
SELECT pg_temp.expect_state(pg_temp.activate('author', 'server-lab', 1), '42501');
SELECT pg_temp.expect_state(pg_temp.activate('reader', 'server-lab', 1), '42501');
SELECT pg_temp.expect_state(pg_temp.activate('approver-1', 'server-lab', 1), '42501');
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'pending-lab', 1), 'TP409');
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'server-lab', 1, decode(repeat('00', 32), 'hex')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'server-lab', 3), 'TP422');
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'suite-lab', 1), 'TP422');
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'server-lab', 9, decode(repeat('00', 32), 'hex')), 'P0002');

-- The writer role reads none of the new tables and writes only through the functions.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_profile_active', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM ca_signing_capability', '42501');
SELECT pg_temp.expect_state($q$INSERT INTO certificate_profile_active (ca_id, profile_id, revision, activated_event_id)
    VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 1, gen_random_uuid())$q$, '42501');
DO $test$
DECLARE
    x uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    iss text := 'https://issuer.activation.invalid';
    op uuid := '0e0e0e0e-0000-4000-8000-000000000001';
    req bytea := decode(repeat('11', 32), 'hex');
    digest1 bytea;
    digest2 bytea;
    r record;
BEGIN
    RESET ROLE;
    digest1 := profile_draft_snapshot_sha256(x, 'server-lab', 1);
    digest2 := profile_draft_snapshot_sha256(x, 'server-lab', 2);
    SET LOCAL ROLE trust_profile_writer;
    SELECT * INTO r FROM activate_profile_revision_lab(iss, 'operator', x, 'server-lab', 1, digest1, op, req);
    IF r.status <> 'ACTIVE' OR r.superseded_revision IS NOT NULL OR r.replayed
       OR r.proposed_signature_suites <> ARRAY['ecdsa-p256-sha256'] THEN
        RAISE EXCEPTION 'first activation: %', r;
    END IF;
    SELECT * INTO r FROM activate_profile_revision_lab(iss, 'operator', x, 'server-lab', 1, digest1, op, req);
    IF NOT r.replayed OR r.status <> 'ACTIVE' THEN RAISE EXCEPTION 'activation replay: %', r; END IF;
    BEGIN
        PERFORM activate_profile_revision_lab(iss, 'operator', x, 'server-lab', 1, digest1, op, decode(repeat('12', 32), 'hex'));
        RAISE EXCEPTION 'key reuse accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    BEGIN
        PERFORM activate_profile_revision_lab(iss, 'operator', x, 'server-lab', 1, digest1, gen_random_uuid(), req);
        RAISE EXCEPTION 'second activation of an active revision accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    -- Revision 2 supersedes revision 1: one active revision per profile.
    SELECT * INTO r FROM activate_profile_revision_lab(iss, 'operator', x, 'server-lab', 2, digest2,
        '0e0e0e0e-0000-4000-8000-000000000002', req);
    IF r.status <> 'ACTIVE' OR r.superseded_revision <> 1 THEN RAISE EXCEPTION 'supersession: %', r; END IF;
    -- A superseded revision is never activated again.
    BEGIN
        PERFORM activate_profile_revision_lab(iss, 'operator', x, 'server-lab', 1, digest1, gen_random_uuid(), req);
        RAISE EXCEPTION 'superseded revision re-activated';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
END $test$;
RESET ROLE;

-- Retirement: only the active revision, once; a retired revision stays retired.
SELECT pg_temp.expect_state(pg_temp.retire('operator', 'server-lab', 1), 'TP409');
SELECT pg_temp.expect_state(pg_temp.retire('author', 'server-lab', 2), '42501');
DO $test$
DECLARE r record;
BEGIN
    SELECT * INTO r FROM retire_profile_revision_lab('https://issuer.activation.invalid', 'operator',
        'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 2, '0e0e0e0e-0000-4000-8000-000000000003',
        decode(repeat('13', 32), 'hex'));
    IF r.status <> 'RETIRED' OR r.replayed THEN RAISE EXCEPTION 'retirement: %', r; END IF;
    SELECT * INTO r FROM retire_profile_revision_lab('https://issuer.activation.invalid', 'operator',
        'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 2, '0e0e0e0e-0000-4000-8000-000000000003',
        decode(repeat('13', 32), 'hex'));
    IF NOT r.replayed THEN RAISE EXCEPTION 'retirement replay: %', r; END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.retire('operator', 'server-lab', 2), 'TP409');
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'server-lab', 2), 'TP409');

-- A revoked capability blocks activation.
UPDATE ca_signing_capability SET revoked_at = clock_timestamp() WHERE suite_id = 'ecdsa-p384-sha384';
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'p384-lab', 1), 'TP422');

-- Readers see every state and its times.
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.activation.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT string_agg(profile_id || '/' || revision || ':' || lifecycle_status || ':'
                          || (activated_at IS NOT NULL) || ':' || (ended_at IS NOT NULL), ',' ORDER BY profile_id, revision)
        FROM management_profile_draft)
       <> 'p384-lab/1:APPROVED:false:false,pending-lab/1:SUBMITTED:false:false,server-lab/1:SUPERSEDED:true:true,'
          'server-lab/2:RETIRED:true:true,server-lab/3:APPROVED:false:false,suite-lab/1:APPROVED:false:false' THEN
        RAISE EXCEPTION 'unexpected reader states: %', (SELECT string_agg(profile_id || '/' || revision || ':' || lifecycle_status, ','
                                                                          ORDER BY profile_id, revision) FROM management_profile_draft);
    END IF;
    IF management_profile_activation_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
RESET ROLE;

-- History and events: three activations or retirements, each with its
-- lifecycle and audit event; revision 1's supersession shares revision 2's
-- activation event.
DO $test$ BEGIN
    IF (SELECT string_agg(h.revision || ':' || h.action || ':' || e.action || ':' || a.event_type, ',' ORDER BY h.revision, h.action)
        FROM certificate_profile_activation h
        JOIN profile_lifecycle_event e ON e.event_id = h.event_id
        JOIN audit_event a ON a.event_id = h.event_id
        WHERE h.profile_id = 'server-lab')
       <> '1:activate:revision.activation:profile.revision.activation,'
          '1:supersede:revision.activation:profile.revision.activation,'
          '2:activate:revision.activation:profile.revision.activation,'
          '2:retire:revision.retirement:profile.revision.retirement' THEN
        RAISE EXCEPTION 'unexpected activation history: %', (SELECT string_agg(h.revision || ':' || h.action, ',' ORDER BY h.recorded_at)
                                                             FROM certificate_profile_activation h);
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$DELETE FROM certificate_profile_activation$q$, 'P0001');

-- Interrupted transaction: a failing audit write leaves no pointer or history.
CREATE FUNCTION pg_temp.fail_activation_audit() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.event_type = 'profile.revision.activation' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER inject_activation_audit_failure BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_activation_audit();
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'server-lab', 3), 'TP422');
UPDATE ca SET policy_version = 'v2' WHERE ca_id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
SELECT pg_temp.expect_state(pg_temp.activate('operator', 'server-lab', 3), 'P0001');
DROP TRIGGER inject_activation_audit_failure ON audit_event;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM certificate_profile_active)
       OR EXISTS (SELECT 1 FROM certificate_profile_activation WHERE revision = 3) THEN
        RAISE EXCEPTION 'an interrupted activation left rows behind';
    END IF;
END $test$;
-- With the CA on v2, revision 3 now activates.
DO $test$ BEGIN
    IF (SELECT status FROM activate_profile_revision_lab('https://issuer.activation.invalid', 'operator',
            'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 3,
            profile_draft_snapshot_sha256('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 3),
            gen_random_uuid(), decode(repeat('14', 32), 'hex'))) <> 'ACTIVE' THEN
        RAISE EXCEPTION 'activation after the CA policy change failed';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: approved revisions are activated one at a time by an independent operator, for compatible CAs only, and retired once'
