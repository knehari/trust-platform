-- Migration 0023: signed decisions on submitted profile revisions. Run as
-- the migration owner after 0023 on a disposable database; every change is
-- rolled back. The database stores signatures but does not verify ECDSA
-- (the API does, before commit); these checks cover the rules the database
-- enforces itself. Before 0023 the first statement fails.
BEGIN;

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
-- A structurally valid uncompressed point (0x04 || 64 bytes); the database
-- checks the encoding only.
CREATE FUNCTION pg_temp.point(p_byte text) RETURNS bytea LANGUAGE sql AS
$fn$ SELECT '\x04'::bytea || decode(repeat(p_byte, 64), 'hex') $fn$;

INSERT INTO ca (ca_id, display_name, policy_version) VALUES
    ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'Decision CA', 'v1');
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('https://issuer.decision.invalid', 'author', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'profile-editor'),
    ('https://issuer.decision.invalid', 'author', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'policy-approver'),
    ('https://issuer.decision.invalid', 'submitter', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'profile-editor'),
    ('https://issuer.decision.invalid', 'submitter', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'policy-approver'),
    ('https://issuer.decision.invalid', 'approver-1', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'policy-approver'),
    ('https://issuer.decision.invalid', 'approver-2', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'policy-approver'),
    ('https://issuer.decision.invalid', 'keyless', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'policy-approver');
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.decision.invalid', 'reader', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee');
INSERT INTO profile_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('author-key', 'https://issuer.decision.invalid', 'author', pg_temp.point('0a')),
    ('submitter-key', 'https://issuer.decision.invalid', 'submitter', pg_temp.point('0b')),
    ('approver-1-key', 'https://issuer.decision.invalid', 'approver-1', pg_temp.point('01')),
    ('approver-2-key', 'https://issuer.decision.invalid', 'approver-2', pg_temp.point('02'));

-- Key registration: one point per key, uncompressed only, append-only.
SELECT pg_temp.expect_state($q$INSERT INTO profile_approver_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('copy-of-1', 'https://issuer.decision.invalid', 'keyless', pg_temp.point('01'))$q$, '23505');
SELECT pg_temp.expect_state($q$INSERT INTO profile_approver_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('compressed', 'https://issuer.decision.invalid', 'keyless', '\x02'::bytea || decode(repeat('01', 32), 'hex'))$q$, '23514');
SELECT pg_temp.expect_state($q$INSERT INTO profile_approver_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('second-active', 'https://issuer.decision.invalid', 'approver-1', pg_temp.point('03'))$q$, '23505');
SELECT pg_temp.expect_state($q$UPDATE profile_approver_key SET public_key_sec1 = pg_temp.point('04') WHERE key_id = 'approver-1-key'$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM profile_approver_key WHERE key_id = 'approver-1-key'$q$, 'P0001');

-- Revision 1 of "server-lab" by "author", submitted by "submitter";
-- "other-lab" stays a draft.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM profile_approver_key', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_profile_decision', '42501');
RESET ROLE;
DO $test$
DECLARE
    x uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    iss text := 'https://issuer.decision.invalid';
BEGIN
    PERFORM create_profile_draft_lab(iss, 'author', x, 'server-lab', 'Server', 'v1', 90, 5,
        ARRAY['lab.invalid'], ARRAY['P256-SHA256'], '0d0d0d0d-0000-4000-8000-000000000001', decode(repeat('01', 32), 'hex'));
    PERFORM submit_profile_draft_lab(iss, 'submitter', x, 'server-lab', 1,
        profile_draft_snapshot_sha256(x, 'server-lab', 1), '0d0d0d0d-0000-4000-8000-000000000002', decode(repeat('02', 32), 'hex'));
    PERFORM create_profile_draft_lab(iss, 'author', x, 'other-lab', 'Other', 'v1', 90, 5,
        ARRAY['lab.invalid'], ARRAY['P256-SHA256'], '0d0d0d0d-0000-4000-8000-000000000003', decode(repeat('03', 32), 'hex'));
    PERFORM create_profile_draft_lab(iss, 'author', x, 'reject-lab', 'Reject', 'v1', 90, 5,
        ARRAY['lab.invalid'], ARRAY['P256-SHA256'], '0d0d0d0d-0000-4000-8000-000000000004', decode(repeat('04', 32), 'hex'));
    PERFORM submit_profile_draft_lab(iss, 'author', x, 'reject-lab', 1,
        profile_draft_snapshot_sha256(x, 'reject-lab', 1), '0d0d0d0d-0000-4000-8000-000000000005', decode(repeat('05', 32), 'hex'));
END $test$;

SET LOCAL ROLE trust_profile_writer;
-- The claim names every bound value in a fixed order, on one line.
DO $test$
DECLARE
    r record;
    expected text;
BEGIN
    SELECT * INTO r FROM prepare_profile_decision_lab('https://issuer.decision.invalid', 'approver-1',
        'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'server-lab', 1, 'approve');
    expected := 'trust-platform/profile-decision/v1;decision=approve;ca_id=eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee'
        || ';profile_id=server-lab;revision=1;snapshot_sha256=' || '%;submission_event_id=%'
        || ';approver_issuer=https://issuer.decision.invalid;approver_subject=approver-1;key_id=approver-1-key;issued_at='
        || r.issued_at;
    IF r.key_id <> 'approver-1-key' OR r.claim NOT LIKE expected OR r.claim ~ '[[:cntrl:]]'
       OR r.claim !~ ';snapshot_sha256=[0-9a-f]{64};submission_event_id=[0-9a-f-]{36};' THEN
        RAISE EXCEPTION 'unexpected claim: %', r.claim;
    END IF;
END $test$;

-- Refusals before any decision: not an approver, author, submitter, no
-- key, unsubmitted revision, unknown revision, issuer with a separator.
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','reader',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'approve')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','author',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'approve')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','submitter',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'approve')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','keyless',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'approve')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','other-lab',1,'approve')$q$, 'TP409');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',9,'approve')$q$, 'P0002');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid;x','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'approve')$q$, '22023');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'activate')$q$, '22023');
-- An expired claim, and one issued in the future.
SELECT pg_temp.expect_state($q$SELECT * FROM record_profile_decision_lab('https://issuer.decision.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'approve', clock_timestamp() - interval '11 minutes',
    decode(repeat('30',70),'hex'), gen_random_uuid(), decode(repeat('aa',32),'hex'))$q$, 'TP409');
SELECT pg_temp.expect_state($q$SELECT * FROM record_profile_decision_lab('https://issuer.decision.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'approve', clock_timestamp() + interval '1 minute',
    decode(repeat('30',70),'hex'), gen_random_uuid(), decode(repeat('aa',32),'hex'))$q$, 'TP409');

DO $test$
DECLARE
    x uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    iss text := 'https://issuer.decision.invalid';
    issued timestamptz := date_trunc('milliseconds', clock_timestamp());
    sig bytea := decode(repeat('30', 70), 'hex');
    op1 uuid := '0d0d0d0d-0000-4000-8000-000000000011';
    req1 bytea := decode(repeat('11', 32), 'hex');
    r record;
BEGIN
    SELECT * INTO r FROM record_profile_decision_lab(iss, 'approver-1', x, 'server-lab', 1, 'approve', issued, sig, op1, req1);
    IF r.replayed OR r.lifecycle_status <> 'SUBMITTED' OR r.approval_count <> 1 OR r.signature_der <> sig
       OR r.public_key_sec1 <> pg_temp.point('01') OR r.claim NOT LIKE '%;approver_subject=approver-1;%' THEN
        RAISE EXCEPTION 'first approval: %', r;
    END IF;
    SELECT * INTO r FROM record_profile_decision_lab(iss, 'approver-1', x, 'server-lab', 1, 'approve', issued, sig, op1, req1);
    IF NOT r.replayed OR r.approval_count <> 1 THEN RAISE EXCEPTION 'replay: %', r; END IF;
END $test$;
RESET ROLE;

-- After one approval, readers still see SUBMITTED.
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.decision.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT lifecycle_status || ':' || approval_count || ':' || (decided_at IS NULL)
        FROM management_profile_draft WHERE profile_id = 'server-lab') <> 'SUBMITTED:1:true' THEN
        RAISE EXCEPTION 'one approval changed the reader state';
    END IF;
END $test$;
RESET ROLE;

SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    x uuid := 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    iss text := 'https://issuer.decision.invalid';
    issued timestamptz := date_trunc('milliseconds', clock_timestamp());
    sig bytea := decode(repeat('30', 70), 'hex');
    op1 uuid := '0d0d0d0d-0000-4000-8000-000000000011';
    req1 bytea := decode(repeat('11', 32), 'hex');
    r record;
BEGIN
    BEGIN
        PERFORM record_profile_decision_lab(iss, 'approver-1', x, 'server-lab', 1, 'approve', issued, sig, op1,
            decode(repeat('12', 32), 'hex'));
        RAISE EXCEPTION 'key reuse accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    BEGIN
        PERFORM record_profile_decision_lab(iss, 'approver-1', x, 'server-lab', 1, 'approve', issued, sig,
            gen_random_uuid(), req1);
        RAISE EXCEPTION 'second decision by one approver accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    SELECT * INTO r FROM record_profile_decision_lab(iss, 'approver-2', x, 'server-lab', 1, 'approve', issued, sig,
        '0d0d0d0d-0000-4000-8000-000000000012', decode(repeat('13', 32), 'hex'));
    IF r.lifecycle_status <> 'APPROVED' OR r.approval_count <> 2 THEN RAISE EXCEPTION 'second approval: %', r; END IF;

    -- One rejection ends a revision; nothing is decided after it.
    SELECT * INTO r FROM record_profile_decision_lab(iss, 'approver-1', x, 'reject-lab', 1, 'reject', issued, sig,
        '0d0d0d0d-0000-4000-8000-000000000013', decode(repeat('14', 32), 'hex'));
    IF r.lifecycle_status <> 'REJECTED' OR r.approval_count <> 0 THEN RAISE EXCEPTION 'rejection: %', r; END IF;
END $test$;
SELECT pg_temp.expect_state($q$SELECT * FROM record_profile_decision_lab('https://issuer.decision.invalid','approver-2',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','reject-lab',1,'approve', date_trunc('milliseconds', clock_timestamp()),
    decode(repeat('30',70),'hex'), gen_random_uuid(), decode(repeat('aa',32),'hex'))$q$, 'TP409');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','approver-2',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','server-lab',1,'reject')$q$, 'TP409');
RESET ROLE;

-- A revoked key can no longer decide.
UPDATE profile_approver_key SET revoked_at = clock_timestamp() WHERE key_id = 'approver-2-key';
SELECT pg_temp.expect_state($q$UPDATE profile_approver_key SET revoked_at = clock_timestamp() WHERE key_id = 'approver-2-key'$q$, 'P0001');
DO $test$ BEGIN
    PERFORM submit_profile_draft_lab('https://issuer.decision.invalid', 'author', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
        'other-lab', 1, profile_draft_snapshot_sha256('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'other-lab', 1),
        '0d0d0d0d-0000-4000-8000-000000000021', decode(repeat('21', 32), 'hex'));
END $test$;
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_profile_decision_lab('https://issuer.decision.invalid','approver-2',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','other-lab',1,'approve')$q$, '42501');

-- Readers see APPROVED with two approvals, REJECTED, and SUBMITTED.
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.decision.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT string_agg(profile_id || ':' || lifecycle_status || ':' || approval_count || ':' || (decided_at IS NOT NULL),
                          ',' ORDER BY profile_id)
        FROM management_profile_draft)
       <> 'other-lab:SUBMITTED:0:false,reject-lab:REJECTED:0:true,server-lab:APPROVED:2:true' THEN
        RAISE EXCEPTION 'unexpected reader states: %', (SELECT string_agg(profile_id || ':' || lifecycle_status, ',')
                                                         FROM management_profile_draft);
    END IF;
    IF management_profile_decision_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
RESET ROLE;

-- Every decision has its lifecycle and audit events; decisions are immutable.
DO $test$ BEGIN
    IF (SELECT count(*) FROM certificate_profile_decision x
        JOIN profile_lifecycle_event e ON e.event_id = x.event_id
        JOIN audit_event a ON a.event_id = x.event_id
        WHERE e.actor_subject = x.approver_subject AND a.actor_id = x.approver_subject
          AND e.snapshot_sha256 = profile_draft_snapshot_sha256(x.ca_id, x.profile_id, x.revision)
          AND a.event_type = 'profile.draft.' || CASE x.decision WHEN 'approve' THEN 'approval' ELSE 'rejection' END
          AND x.claim = profile_decision_claim(x.decision, x.ca_id, x.profile_id, x.revision, e.snapshot_sha256,
                (SELECT s.event_id FROM certificate_profile_submission s
                 WHERE (s.ca_id, s.profile_id, s.revision) = (x.ca_id, x.profile_id, x.revision)),
                x.approver_issuer, x.approver_subject, x.key_id, x.claim_issued_at)) <> 3 THEN
        RAISE EXCEPTION 'decision events or claims do not match';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$UPDATE certificate_profile_decision SET decision = 'reject'$q$, 'P0001');

-- Interrupted transaction: a failing audit write leaves no decision behind.
CREATE FUNCTION pg_temp.fail_decision_audit() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.event_type LIKE 'profile.draft.approval' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER inject_decision_audit_failure BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_decision_audit();
SELECT pg_temp.expect_state($q$SELECT * FROM record_profile_decision_lab('https://issuer.decision.invalid','approver-1',
    'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','other-lab',1,'approve', date_trunc('milliseconds', clock_timestamp()),
    decode(repeat('30',70),'hex'), '0d0d0d0d-0000-4000-8000-000000000031', decode(repeat('31',32),'hex'))$q$, 'P0001');
DROP TRIGGER inject_decision_audit_failure ON audit_event;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM certificate_profile_decision WHERE profile_id = 'other-lab')
       OR EXISTS (SELECT 1 FROM profile_lifecycle_event WHERE operation_id = '0d0d0d0d-0000-4000-8000-000000000031') THEN
        RAISE EXCEPTION 'an interrupted decision left rows behind';
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: profile decisions need two distinct granted approvers with distinct registered keys, and one rejection ends a revision'
