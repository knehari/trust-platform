-- Migration 0022: profile draft authoring and submission. Run as the
-- migration owner after 0022 on a disposable database; every change is
-- rolled back. Before 0022 the first statement fails (no such function).
BEGIN;

-- Expects a statement to fail with one SQLSTATE.
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

INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'Lifecycle CA X', 'v1'),
    ('7b7b7b7b-0000-4000-8000-0000000000b2', 'Lifecycle CA Y', 'v1');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('https://issuer.lifecycle.invalid', 'editor-1', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'profile-editor'),
    ('https://issuer.lifecycle.invalid', 'editor-2', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'profile-editor'),
    ('https://issuer.lifecycle.invalid', 'approver-1', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'policy-approver');
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.lifecycle.invalid', 'editor-1', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');

-- The writer role holds no table or view privilege; the reader role cannot
-- execute the write functions.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_profile_draft', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM management_role_grant', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM management_profile_draft', '42501');
SELECT pg_temp.expect_state($q$INSERT INTO management_role_grant VALUES
    ('https://issuer.lifecycle.invalid','forged','eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','profile-editor')$q$, '42501');
SELECT pg_temp.expect_state($q$INSERT INTO certificate_profile_draft
    (ca_id,profile_id,revision,display_name,policy_version,max_validity_days,max_dns_sans,
     proposed_dns_zones,proposed_signature_suites,created_by)
    VALUES ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','forged',1,'F','v1',1,1,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],'x')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT profile_draft_snapshot_sha256('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','x',1)$q$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($q$SELECT * FROM create_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab','S','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, '42501');
RESET ROLE;

SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    x uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    iss text := 'https://issuer.lifecycle.invalid';
    op1 uuid := '0c0c0c0c-0000-4000-8000-000000000001';
    op2 uuid := '0c0c0c0c-0000-4000-8000-000000000002';
    req1 bytea := decode(repeat('11', 32), 'hex');
    r record;
BEGIN
    -- Revision 1, then an identical replay, then reuse of its key.
    SELECT * INTO r FROM create_profile_draft_lab(iss, 'editor-1', x, 'server-lab', 'Server proposal', 'v1', 90, 5,
        ARRAY['lab.invalid'], ARRAY['P256-SHA256'], op1, req1);
    IF r.revision <> 1 OR r.replayed THEN RAISE EXCEPTION 'first draft: %', r; END IF;
    SELECT * INTO r FROM create_profile_draft_lab(iss, 'editor-1', x, 'server-lab', 'Server proposal', 'v1', 90, 5,
        ARRAY['lab.invalid'], ARRAY['P256-SHA256'], op1, req1);
    IF r.revision <> 1 OR NOT r.replayed THEN RAISE EXCEPTION 'replay: %', r; END IF;
    BEGIN
        PERFORM create_profile_draft_lab(iss, 'editor-1', x, 'server-lab', 'Other', 'v1', 90, 5,
            ARRAY['lab.invalid'], ARRAY['P256-SHA256'], op1, decode(repeat('12', 32), 'hex'));
        RAISE EXCEPTION 'key reuse accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    -- Another editor's replay of the same key is not a replay.
    BEGIN
        PERFORM create_profile_draft_lab(iss, 'editor-2', x, 'server-lab', 'Server proposal', 'v1', 90, 5,
            ARRAY['lab.invalid'], ARRAY['P256-SHA256'], op1, req1);
        RAISE EXCEPTION 'key reuse by another editor accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;

    -- Revision 2 by a second editor, with UTF-8 text and two-element lists.
    SELECT * INTO r FROM create_profile_draft_lab(iss, 'editor-2', x, 'server-lab', 'Serveur été', 'v1', 90, 5,
        ARRAY['a.lab.invalid', 'b.lab.invalid'], ARRAY['P256-SHA256', 'RSA-PSS-SHA256'], op2,
        decode(repeat('22', 32), 'hex'));
    IF r.revision <> 2 THEN RAISE EXCEPTION 'second draft: %', r; END IF;
END $test$;
RESET ROLE;

-- The database's digest equals the API's pinned vectors
-- (profile_proposal.rs, snapshot_digest_matches_pinned_database_vectors).
DO $test$ BEGIN
    IF encode(profile_draft_snapshot_sha256('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 1), 'hex')
         <> '5e74e6260bf6f56f899c323e3525cfac09a2fd1c9b01653e2c47247d08f72330'
       OR encode(profile_draft_snapshot_sha256('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 2), 'hex')
         <> '2bee232acffcc1e3d29e99e4d03f6fa5b3641e87f7d997acab73007999f1a80f' THEN
        RAISE EXCEPTION 'database digest differs from the API digest';
    END IF;
END $test$;

-- Denials: no grant for the CA, another issuer, an approver, invalid input.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($q$SELECT * FROM create_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    '7b7b7b7b-0000-4000-8000-0000000000b2','server-lab','S','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM create_profile_draft_lab('https://other.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab','S','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM create_profile_draft_lab('https://issuer.lifecycle.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab','S','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM create_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab','S','v1',0,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, '23514');
SELECT pg_temp.expect_state($q$SELECT * FROM create_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab','S','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],
    gen_random_uuid(),decode('aa','hex'))$q$, '22023');

-- Submission: stale revision, altered digest, unknown revision, no grant.
SELECT pg_temp.expect_state($q$SELECT * FROM submit_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,
    decode('5e74e6260bf6f56f899c323e3525cfac09a2fd1c9b01653e2c47247d08f72330','hex'),
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, 'TP409');
SELECT pg_temp.expect_state($q$SELECT * FROM submit_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',2,
    decode('5e74e6260bf6f56f899c323e3525cfac09a2fd1c9b01653e2c47247d08f72330','hex'),
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, 'TP409');
SELECT pg_temp.expect_state($q$SELECT * FROM submit_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',3,
    decode('2bee232acffcc1e3d29e99e4d03f6fa5b3641e87f7d997acab73007999f1a80f','hex'),
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, 'P0002');
SELECT pg_temp.expect_state($q$SELECT * FROM submit_profile_draft_lab('https://issuer.lifecycle.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',2,
    decode('2bee232acffcc1e3d29e99e4d03f6fa5b3641e87f7d997acab73007999f1a80f','hex'),
    gen_random_uuid(),decode(repeat('aa',32),'hex'))$q$, '42501');

DO $test$
DECLARE
    x uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    iss text := 'https://issuer.lifecycle.invalid';
    digest2 bytea := decode('2bee232acffcc1e3d29e99e4d03f6fa5b3641e87f7d997acab73007999f1a80f', 'hex');
    op3 uuid := '0c0c0c0c-0000-4000-8000-000000000003';
    req3 bytea := decode(repeat('33', 32), 'hex');
    r record;
BEGIN
    SELECT * INTO r FROM submit_profile_draft_lab(iss, 'editor-1', x, 'server-lab', 2, digest2, op3, req3);
    IF r.replayed OR r.submitted_at IS NULL OR r.display_name <> 'Serveur été' THEN
        RAISE EXCEPTION 'submission: %', r;
    END IF;
    SELECT * INTO r FROM submit_profile_draft_lab(iss, 'editor-1', x, 'server-lab', 2, digest2, op3, req3);
    IF NOT r.replayed THEN RAISE EXCEPTION 'submission replay: %', r; END IF;
    BEGIN
        PERFORM submit_profile_draft_lab(iss, 'editor-2', x, 'server-lab', 2, digest2,
            '0c0c0c0c-0000-4000-8000-000000000004', req3);
        RAISE EXCEPTION 'second submission accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    -- After submission, a change is a new revision, which is a DRAFT again.
    SELECT * INTO r FROM create_profile_draft_lab(iss, 'editor-1', x, 'server-lab', 'Server proposal 3', 'v2', 60, 3,
        ARRAY['lab.invalid'], ARRAY['P256-SHA256'], '0c0c0c0c-0000-4000-8000-000000000005',
        decode(repeat('55', 32), 'hex'));
    IF r.revision <> 3 THEN RAISE EXCEPTION 'post-submission draft: %', r; END IF;
END $test$;
RESET ROLE;

-- A reader sees each revision's state through the isolated view.
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.lifecycle.invalid', true),
       set_config('trust.reader_subject', 'editor-1', true);
DO $test$ BEGIN
    IF (SELECT string_agg(revision || ':' || lifecycle_status || ':' || (submitted_at IS NOT NULL), ',' ORDER BY revision)
        FROM management_profile_draft WHERE profile_id = 'server-lab')
       <> '1:DRAFT:false,2:SUBMITTED:true,3:DRAFT:false' THEN
        RAISE EXCEPTION 'unexpected lifecycle states in the reader view';
    END IF;
    IF management_profile_lifecycle_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
RESET ROLE;

-- Every operation left one lifecycle event and one audit event with the
-- same id, actor and digest; neither can be changed.
DO $test$ BEGIN
    IF (SELECT string_agg(e.action || '@' || e.revision || '/' || e.actor_subject, ',' ORDER BY e.recorded_at)
        FROM profile_lifecycle_event e JOIN audit_event a ON a.event_id = e.event_id
             AND a.actor_id = e.actor_subject AND a.event_type = 'profile.' || e.action AND a.decision = 'allow'
        WHERE e.profile_id = 'server-lab')
       <> 'draft.created@1/editor-1,draft.created@2/editor-2,draft.submitted@2/editor-1,draft.created@3/editor-1' THEN
        RAISE EXCEPTION 'unexpected lifecycle or audit events';
    END IF;
    IF EXISTS (SELECT 1 FROM profile_lifecycle_event e
               WHERE e.snapshot_sha256 IS DISTINCT FROM profile_draft_snapshot_sha256(e.ca_id, e.profile_id, e.revision)) THEN
        RAISE EXCEPTION 'an event digest differs from its revision';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$UPDATE profile_lifecycle_event SET actor_subject = 'forged'$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM certificate_profile_submission$q$, 'P0001');

-- Interrupted transaction: when the audit write fails, nothing of the
-- operation remains (no revision, no lifecycle event, no submission).
CREATE FUNCTION pg_temp.fail_profile_audit() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.event_type LIKE 'profile.%' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER inject_profile_audit_failure BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_profile_audit();
SELECT pg_temp.expect_state($q$SELECT * FROM create_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab','S4','v1',90,5,ARRAY['lab.invalid'],ARRAY['P256-SHA256'],
    '0c0c0c0c-0000-4000-8000-000000000006',decode(repeat('66',32),'hex'))$q$, 'P0001');
SELECT pg_temp.expect_state($q$SELECT * FROM submit_profile_draft_lab('https://issuer.lifecycle.invalid','editor-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',3,
    profile_draft_snapshot_sha256('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',3),
    '0c0c0c0c-0000-4000-8000-000000000007',decode(repeat('77',32),'hex'))$q$, 'P0001');
DROP TRIGGER inject_profile_audit_failure ON audit_event;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM certificate_profile_draft WHERE profile_id = 'server-lab' AND revision = 4)
       OR EXISTS (SELECT 1 FROM profile_lifecycle_event
                  WHERE operation_id IN ('0c0c0c0c-0000-4000-8000-000000000006', '0c0c0c0c-0000-4000-8000-000000000007'))
       OR EXISTS (SELECT 1 FROM certificate_profile_submission WHERE profile_id = 'server-lab' AND revision = 3) THEN
        RAISE EXCEPTION 'an interrupted operation left rows behind';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: profile drafts are created and submitted only through granted, idempotent, audited functions'
