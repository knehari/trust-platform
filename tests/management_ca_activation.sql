-- Migration 0027: signed approval and activation of CA proposals. Run as the
-- migration owner after 0027 on a disposable database; every change is
-- rolled back. PostgreSQL does not verify ECDSA (the API does, and
-- lab_verify_ca_lifecycle re-checks); placeholder bytes stand for keys and
-- signatures here. Before 0027 the first statement fails.
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

CREATE FUNCTION pg_temp.point(p_byte text) RETURNS bytea LANGUAGE sql AS $fn$
    SELECT decode('04' || repeat(p_byte, 64), 'hex')
$fn$;

INSERT INTO ca_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('probe', 'https://issuer.ca.invalid', 'probe', pg_temp.point('99'));
INSERT INTO management_platform_grant (issuer, subject, platform_role) VALUES
    ('https://issuer.ca.invalid', 'admin-1', 'ca-administrator'),
    ('https://issuer.ca.invalid', 'admin-2', 'ca-administrator'),
    ('https://issuer.ca.invalid', 'admin-1', 'ca-approver'),
    ('https://issuer.ca.invalid', 'approver-1', 'ca-approver'),
    ('https://issuer.ca.invalid', 'approver-2', 'ca-approver'),
    ('https://issuer.ca.invalid', 'approver-2', 'ca-administrator'),
    ('https://issuer.ca.invalid', 'approver-3', 'ca-approver'),
    ('https://issuer.ca.invalid', 'keyless', 'ca-approver');
SELECT pg_temp.expect_state($q$INSERT INTO management_platform_grant VALUES
    ('https://issuer.ca.invalid', 'x', 'policy-approver')$q$, '23514');

-- Keys: one power per point, append-only.
INSERT INTO profile_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('profile-approver', 'https://issuer.ca.invalid', 'profile-approver', pg_temp.point('aa'));
INSERT INTO ca_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('admin-1-ca', 'https://issuer.ca.invalid', 'admin-1', pg_temp.point('01')),
    ('approver-1-ca', 'https://issuer.ca.invalid', 'approver-1', pg_temp.point('02')),
    ('approver-2-ca', 'https://issuer.ca.invalid', 'approver-2', pg_temp.point('03')),
    ('approver-3-ca', 'https://issuer.ca.invalid', 'approver-3', pg_temp.point('04')),
    -- A key without the approver grant: the grant check alone refuses it.
    ('admin-2-ca', 'https://issuer.ca.invalid', 'admin-2', pg_temp.point('06'));
SELECT pg_temp.expect_state($q$INSERT INTO ca_approver_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('reused', 'https://issuer.ca.invalid', 'other', pg_temp.point('aa'))$q$, '23505');
SELECT pg_temp.expect_state($q$INSERT INTO profile_approver_key (key_id, issuer, subject, public_key_sec1)
    VALUES ('reused', 'https://issuer.ca.invalid', 'other', pg_temp.point('02'))$q$, '23505');
SELECT pg_temp.expect_state($q$UPDATE ca_approver_key SET public_key_sec1 = pg_temp.point('05')
    WHERE key_id = 'approver-3-ca'$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM ca_approver_key WHERE key_id = 'approver-3-ca'$q$, 'P0001');

-- Proposals: A and C key-attested, B only proposed, E with an expired
-- certificate recorded by the owner (the registration route refuses those).
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM ca_decision', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM ca_activation', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM ca_approver_key', '42501');
DO $setup$
DECLARE
    iss text := 'https://issuer.ca.invalid';
    req bytea := decode(repeat('11', 32), 'hex');
    ca uuid;
    names text[] := ARRAY['Root A', 'Root B', 'Root C', 'Root E', 'Root D'];
    ids uuid[] := ARRAY['c0c0c0c0-0000-4000-8000-00000000000a', 'c0c0c0c0-0000-4000-8000-00000000000b',
                        'c0c0c0c0-0000-4000-8000-00000000000c', 'c0c0c0c0-0000-4000-8000-00000000000e',
                        'c0c0c0c0-0000-4000-8000-00000000000d']::uuid[];
BEGIN
    FOR i IN 1..5 LOOP
        PERFORM propose_ca_lab(iss, 'admin-1', ids[i], names[i], 'v1', 'ecdsa-p256-sha256', gen_random_uuid(), req);
    END LOOP;
    FOREACH ca IN ARRAY ARRAY[ids[1], ids[3], ids[5]] LOOP
        PERFORM register_ca_issuer_certificate_lab(iss, 'admin-1', ca, decode(repeat(substr(ca::text, 36, 1) || '0', 300), 'hex'),
            digest(ca::text, 'sha256'), (SELECT names[i] FROM generate_subscripts(ids, 1) i WHERE ids[i] = ca),
            clock_timestamp() - interval '1 hour', clock_timestamp() + interval '1 year', 'p256',
            gen_random_uuid(), req);
    END LOOP;
END $setup$;
RESET ROLE;
INSERT INTO ca_lifecycle_event (event_id, operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
VALUES ('e0e0e0e0-0000-4000-8000-00000000000e', gen_random_uuid(), decode(repeat('11', 32), 'hex'),
        'ca.certificate_registered', 'c0c0c0c0-0000-4000-8000-00000000000e', 'https://issuer.ca.invalid', 'owner');
INSERT INTO ca_issuer_certificate (ca_id, certificate_der, spki_sha256, subject_cn, not_before, not_after, key_parameter,
                                   custody, registered_event_id)
VALUES ('c0c0c0c0-0000-4000-8000-00000000000e', decode(repeat('e0', 300), 'hex'), digest('e', 'sha256'), 'Root E',
        clock_timestamp() - interval '2 years', clock_timestamp() - interval '1 day', 'p256', 'lab-software-file',
        'e0e0e0e0-0000-4000-8000-00000000000e');

SET LOCAL ROLE trust_profile_writer;
-- Preparing: grant, key, state, separation of duties, expiry.
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'admin-2',
    'c0c0c0c0-0000-4000-8000-00000000000a', 'approve')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'keyless',
    'c0c0c0c0-0000-4000-8000-00000000000a', 'approve')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'admin-1',
    'c0c0c0c0-0000-4000-8000-00000000000a', 'approve')$q$, '42501');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'approver-1',
    'c0c0c0c0-0000-4000-8000-0000000000ff', 'approve')$q$, 'P0002');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'approver-1',
    'c0c0c0c0-0000-4000-8000-00000000000b', 'approve')$q$, 'TP409');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'approver-1',
    'c0c0c0c0-0000-4000-8000-00000000000e', 'approve')$q$, 'TP422');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'approver-1',
    'c0c0c0c0-0000-4000-8000-00000000000a', 'endorse')$q$, '22023');
SELECT pg_temp.expect_state($q$SELECT * FROM prepare_ca_decision_lab('https://issuer.ca.invalid', 'approver;1',
    'c0c0c0c0-0000-4000-8000-00000000000a', 'approve')$q$, '22023');

DO $test$
DECLARE
    iss text := 'https://issuer.ca.invalid';
    a uuid := 'c0c0c0c0-0000-4000-8000-00000000000a';
    c uuid := 'c0c0c0c0-0000-4000-8000-00000000000c';
    sig bytea := decode(repeat('30', 70), 'hex');
    req bytea := decode(repeat('22', 32), 'hex');
    op uuid := '0f0f0f0f-0000-4000-8000-0000000000a1';
    claim record;
    r record;
BEGIN
    SELECT * INTO claim FROM prepare_ca_decision_lab(iss, 'approver-1', a, 'approve');
    IF claim.claim !~ ('^trust-platform/ca-decision/v1;decision=approve;ca_id=' || a::text
        || ';certificate_sha256=[0-9a-f]{64};spki_sha256=[0-9a-f]{64};registration_event_id=[0-9a-f-]{36}'
        || ';approver_issuer=https://issuer\.ca\.invalid;approver_subject=approver-1;key_id=approver-1-ca'
        || ';issued_at=' || claim.issued_at || '$') THEN
        RAISE EXCEPTION 'unexpected claim: %', claim.claim;
    END IF;
    SELECT * INTO r FROM record_ca_decision_lab(iss, 'approver-1', a, 'approve', claim.issued_at::timestamptz, sig, op, req);
    IF r.claim <> claim.claim OR r.public_key_sec1 <> pg_temp.point('02') OR r.lifecycle_status <> 'KEY_ATTESTED'
       OR r.approval_count <> 1 OR r.replayed THEN
        RAISE EXCEPTION 'first approval: %', r;
    END IF;
    SELECT * INTO r FROM record_ca_decision_lab(iss, 'approver-1', a, 'approve', claim.issued_at::timestamptz, sig, op, req);
    IF NOT r.replayed THEN RAISE EXCEPTION 'replay: %', r; END IF;
    BEGIN
        PERFORM record_ca_decision_lab(iss, 'approver-1', a, 'reject', clock_timestamp(), sig, gen_random_uuid(), req);
        RAISE EXCEPTION 'a second decision by the same approver was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    BEGIN
        PERFORM record_ca_decision_lab(iss, 'approver-2', a, 'approve', clock_timestamp() - interval '11 minutes',
            sig, gen_random_uuid(), req);
        RAISE EXCEPTION 'a stale claim was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    BEGIN
        PERFORM record_ca_decision_lab(iss, 'approver-2', a, 'approve', clock_timestamp() + interval '1 minute',
            sig, gen_random_uuid(), req);
        RAISE EXCEPTION 'a future claim was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    SELECT * INTO r FROM record_ca_decision_lab(iss, 'approver-2', a, 'approve', clock_timestamp(), sig,
        gen_random_uuid(), req);
    IF r.lifecycle_status <> 'APPROVED' OR r.approval_count <> 2 THEN RAISE EXCEPTION 'second approval: %', r; END IF;
    BEGIN
        PERFORM prepare_ca_decision_lab(iss, 'approver-3', a, 'reject');
        RAISE EXCEPTION 'a decision on an approved proposal was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    -- Proposal D keeps a single approval.
    PERFORM record_ca_decision_lab(iss, 'approver-1', 'c0c0c0c0-0000-4000-8000-00000000000d', 'approve',
        clock_timestamp(), sig, gen_random_uuid(), req);
    -- One rejection ends proposal C.
    SELECT * INTO r FROM record_ca_decision_lab(iss, 'approver-3', c, 'reject', clock_timestamp(), sig,
        gen_random_uuid(), req);
    IF r.lifecycle_status <> 'REJECTED' OR r.approval_count <> 0 THEN RAISE EXCEPTION 'rejection: %', r; END IF;
    BEGIN
        PERFORM record_ca_decision_lab(iss, 'approver-1', c, 'approve', clock_timestamp(), sig, gen_random_uuid(), req);
        RAISE EXCEPTION 'a decision on a rejected proposal was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
END $test$;

-- Activation refusals: no administrator grant, an approver of the CA, an
-- unapproved or rejected proposal, another digest, an unknown proposal.
CREATE FUNCTION pg_temp.activate(p_subject text, p_ca text, p_digest bytea DEFAULT NULL,
    p_operation uuid DEFAULT gen_random_uuid()) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM activate_ca_lab(%L, %L, %L, %L, %L, %L)', 'https://issuer.ca.invalid', p_subject,
        p_ca, coalesce(p_digest, (SELECT digest(decode(repeat('a0', 300), 'hex'), 'sha256'))), p_operation,
        decode(repeat('33', 32), 'hex'))
$fn$;
SELECT pg_temp.expect_state(pg_temp.activate('approver-3', 'c0c0c0c0-0000-4000-8000-00000000000a'), '42501');
SELECT pg_temp.expect_state(pg_temp.activate('approver-2', 'c0c0c0c0-0000-4000-8000-00000000000a'), '42501');
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000b'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000c',
    digest(decode(repeat('c0', 300), 'hex'), 'sha256')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000d',
    digest(decode(repeat('d0', 300), 'hex'), 'sha256')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000a',
    decode(repeat('00', 32), 'hex')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-0000000000ff'), 'P0002');

-- Interrupted transaction: a failing audit write leaves no CA.
RESET ROLE;
CREATE FUNCTION pg_temp.fail_ca_activation_audit() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.event_type = 'ca.activation' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER inject_ca_activation_failure BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_ca_activation_audit();
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000a'), 'P0001');
RESET ROLE;
DROP TRIGGER inject_ca_activation_failure ON audit_event;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM ca WHERE ca_id = 'c0c0c0c0-0000-4000-8000-00000000000a')
       OR EXISTS (SELECT 1 FROM ca_activation) THEN
        RAISE EXCEPTION 'an interrupted activation left a CA';
    END IF;
END $test$;

-- An approved proposal whose certificate expired is not activated (owner
-- fixture: decisions cannot be recorded on an expired certificate).
DO $setup$
DECLARE v_event uuid;
BEGIN
    FOR n IN 1..2 LOOP
        INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
        VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'ca.approval',
                'c0c0c0c0-0000-4000-8000-00000000000e', 'https://issuer.ca.invalid', 'approver-' || n)
        RETURNING event_id INTO v_event;
        INSERT INTO ca_decision (ca_id, approver_issuer, approver_subject, decision, key_id, public_key_sec1, claim,
                                 signature_der, claim_issued_at, event_id)
        VALUES ('c0c0c0c0-0000-4000-8000-00000000000e', 'https://issuer.ca.invalid', 'approver-' || n, 'approve',
                'approver-' || n || '-ca', pg_temp.point('0' || (n + 1)), 'owner fixture',
                decode(repeat('30', 70), 'hex'), clock_timestamp(), v_event);
    END LOOP;
END $setup$;
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000e',
    digest(decode(repeat('e0', 300), 'hex'), 'sha256')), 'TP422');

DO $test$
DECLARE
    op uuid := '0f0f0f0f-0000-4000-8000-0000000000b1';
    r record;
BEGIN
    EXECUTE pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000a', NULL, op) INTO r;
    IF r.lifecycle_status <> 'ACTIVE' OR r.suite_id <> 'ecdsa-p256-sha256' OR r.replayed
       OR r.certificate_der <> decode(repeat('a0', 300), 'hex') THEN
        RAISE EXCEPTION 'activation: %', r;
    END IF;
    EXECUTE pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000a', NULL, op) INTO r;
    IF NOT r.replayed THEN RAISE EXCEPTION 'activation replay: %', r; END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.activate('admin-2', 'c0c0c0c0-0000-4000-8000-00000000000a'), 'TP409');
RESET ROLE;

-- The CA exists, with its attested suite as its only possible capability.
DO $test$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM ca WHERE ca_id = 'c0c0c0c0-0000-4000-8000-00000000000a'
                   AND display_name = 'Root A' AND policy_version = 'v1') THEN
        RAISE EXCEPTION 'activation did not create the CA';
    END IF;
    IF (SELECT array_agg(suite_id) FROM ca_signing_capability
        WHERE ca_id = 'c0c0c0c0-0000-4000-8000-00000000000a') <> ARRAY['ecdsa-p256-sha256'] THEN
        RAISE EXCEPTION 'unexpected capabilities of the activated CA';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$INSERT INTO ca_signing_capability (ca_id, suite_id)
    VALUES ('c0c0c0c0-0000-4000-8000-00000000000a', 'ecdsa-p384-sha384')$q$, '23514');
-- A CA that was not activated keeps owner-declared capabilities (0024).
INSERT INTO ca (ca_id, display_name, policy_version) VALUES ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'Owner CA', 'v1');
INSERT INTO ca_signing_capability (ca_id, suite_id) VALUES ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'ecdsa-p384-sha384');

-- Views: administrators and approvers see the states; others see none.
-- A granted reader sees the new CA like any other.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.ca.invalid', 'reader', 'c0c0c0c0-0000-4000-8000-00000000000a');
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.ca.invalid', true),
       set_config('trust.reader_subject', 'approver-3', true);
DO $test$ BEGIN
    IF (SELECT string_agg(display_name || ':' || lifecycle_status || ':' || approval_count
                          || ':' || (decided_at IS NOT NULL) || ':' || (activated_at IS NOT NULL), ',' ORDER BY display_name)
        FROM management_ca_proposal)
       <> 'Root A:ACTIVE:2:true:true,Root B:PROPOSED:0:false:false,Root C:REJECTED:0:true:false,Root D:KEY_ATTESTED:1:false:false,Root E:APPROVED:2:true:false' THEN
        RAISE EXCEPTION 'unexpected approver view: %', (SELECT string_agg(display_name || ':' || lifecycle_status, ',') FROM management_ca_proposal);
    END IF;
    IF management_ca_activation_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
SELECT set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_ca_proposal) THEN RAISE EXCEPTION 'a reader sees proposals'; END IF;
    IF NOT EXISTS (SELECT 1 FROM management_ca WHERE ca_id = 'c0c0c0c0-0000-4000-8000-00000000000a') THEN
        RAISE EXCEPTION 'a granted reader does not see the activated CA';
    END IF;
END $test$;
RESET ROLE;

-- Events and audit: decisions without a CA, activation with it; immutable.
DO $test$ BEGIN
    IF (SELECT string_agg(e.action || ':' || coalesce(a.ca_id::text, '-'), ',' ORDER BY e.recorded_at)
        FROM ca_lifecycle_event e JOIN audit_event a ON a.event_id = e.event_id
        WHERE e.ca_id = 'c0c0c0c0-0000-4000-8000-00000000000a' AND e.action IN ('ca.approval', 'ca.activation'))
       <> 'ca.approval:-,ca.approval:-,ca.activation:c0c0c0c0-0000-4000-8000-00000000000a' THEN
        RAISE EXCEPTION 'unexpected decision and activation events';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$UPDATE ca_decision SET decision = 'reject'$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM ca_activation$q$, 'P0001');

ROLLBACK;
\echo 'PASS: CA proposals are activated only after two distinct signed approvals, by a non-approver, with their attested suite'
