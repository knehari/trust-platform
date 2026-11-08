-- Migration 0028: suspension, reactivation and retirement of activated CAs.
-- Run as the migration owner after 0028 on a disposable database; every
-- change is rolled back. Placeholder bytes stand for keys and signatures:
-- the API verifies signatures, lab_verify_ca_lifecycle re-checks them.
-- Before 0028 the first statement fails.
BEGIN;

SELECT 1 FROM ca_operational_state LIMIT 0;

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

INSERT INTO management_platform_grant (issuer, subject, platform_role) VALUES
    ('https://issuer.ca.invalid', 'admin-1', 'ca-administrator'),
    ('https://issuer.ca.invalid', 'admin-1', 'ca-approver'),
    ('https://issuer.ca.invalid', 'admin-3', 'ca-administrator'),
    ('https://issuer.ca.invalid', 'approver-1', 'ca-approver'),
    ('https://issuer.ca.invalid', 'approver-2', 'ca-approver'),
    ('https://issuer.ca.invalid', 'approver-2', 'ca-administrator'),
    ('https://issuer.ca.invalid', 'approver-3', 'ca-approver');
INSERT INTO ca_approver_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('admin-1-ca', 'https://issuer.ca.invalid', 'admin-1', pg_temp.point('01')),
    ('approver-1-ca', 'https://issuer.ca.invalid', 'approver-1', pg_temp.point('02')),
    ('approver-2-ca', 'https://issuer.ca.invalid', 'approver-2', pg_temp.point('03')),
    ('approver-3-ca', 'https://issuer.ca.invalid', 'approver-3', pg_temp.point('04')),
    -- A key without the approver grant: the grant check alone refuses it.
    ('admin-3-ca', 'https://issuer.ca.invalid', 'admin-3', pg_temp.point('05'));

-- Activated CAs S and T through 0026–0027 (proposed by admin-3, approved by
-- approver-1 and approver-3, activated by admin-3); an owner-created CA O;
-- CA X activated by the owner with an expired certificate.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state('SELECT 1 FROM ca_operational_state', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM ca_change_request', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM ca_state_change', '42501');
DO $setup$
DECLARE
    iss text := 'https://issuer.ca.invalid';
    req bytea := decode(repeat('11', 32), 'hex');
    sig bytea := decode(repeat('30', 70), 'hex');
    ids uuid[] := ARRAY['5a5a5a5a-0000-4000-8000-000000000005', '5a5a5a5a-0000-4000-8000-000000000007']::uuid[];
    names text[] := ARRAY['Root S', 'Root T'];
BEGIN
    FOR i IN 1..2 LOOP
        PERFORM propose_ca_lab(iss, 'admin-3', ids[i], names[i], 'v1', 'ecdsa-p256-sha256', gen_random_uuid(), req);
        PERFORM register_ca_issuer_certificate_lab(iss, 'admin-3', ids[i], decode(repeat('5' || i, 300), 'hex'),
            digest(names[i], 'sha256'), names[i], clock_timestamp() - interval '1 hour',
            clock_timestamp() + interval '1 year', 'p256', gen_random_uuid(), req);
        PERFORM record_ca_decision_lab(iss, 'approver-1', ids[i], 'approve', clock_timestamp(), sig, gen_random_uuid(), req);
        PERFORM record_ca_decision_lab(iss, 'approver-3', ids[i], 'approve', clock_timestamp(), sig, gen_random_uuid(), req);
        PERFORM activate_ca_lab(iss, 'admin-3', ids[i], digest(decode(repeat('5' || i, 300), 'hex'), 'sha256'),
            gen_random_uuid(), req);
    END LOOP;
END $setup$;
RESET ROLE;
INSERT INTO ca (ca_id, display_name, policy_version) VALUES ('0a0a0a0a-0000-4000-8000-00000000000a', 'Owner CA', 'v1');
DO $setup$
DECLARE
    x uuid := '5a5a5a5a-0000-4000-8000-0000000000ff';
    e uuid;
BEGIN
    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'ca.proposed', x, 'owner', 'owner') RETURNING event_id INTO e;
    INSERT INTO ca_proposal (ca_id, display_name, policy_version, suite_id, proposed_event_id)
    VALUES (x, 'Root X', 'v1', 'ecdsa-p256-sha256', e);
    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'ca.certificate_registered', x, 'owner', 'owner')
    RETURNING event_id INTO e;
    INSERT INTO ca_issuer_certificate (ca_id, certificate_der, spki_sha256, subject_cn, not_before, not_after,
                                       key_parameter, custody, registered_event_id)
    VALUES (x, decode(repeat('5f', 300), 'hex'), digest('x', 'sha256'), 'Root X', clock_timestamp() - interval '2 years',
            clock_timestamp() - interval '1 day', 'p256', 'lab-software-file', e);
    INSERT INTO ca (ca_id, display_name, policy_version) VALUES (x, 'Root X', 'v1');
    INSERT INTO ca_lifecycle_event (operation_id, request_sha256, action, ca_id, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'ca.activation', x, 'owner', 'owner') RETURNING event_id INTO e;
    INSERT INTO ca_activation (ca_id, event_id) VALUES (x, e);
END $setup$;

-- An active profile revision on T and on the owner CA (owner fixture).
CREATE FUNCTION pg_temp.active_profile(p_ca uuid, p_profile text) RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE e uuid;
BEGIN
    INSERT INTO certificate_profile_draft (ca_id, profile_id, revision, display_name, policy_version, max_validity_days,
        max_dns_sans, proposed_dns_zones, proposed_signature_suites, created_by)
    VALUES (p_ca, p_profile, 1, 'Fixture', 'v1', 90, 5, ARRAY['lab.invalid'], ARRAY['ecdsa-p256-sha256'], 'fixture');
    INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id, revision,
        snapshot_sha256, policy_version, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'draft.submitted', p_ca, p_profile, 1,
            decode(repeat('aa', 32), 'hex'), 'v1', 'owner', 'owner') RETURNING event_id INTO e;
    INSERT INTO certificate_profile_submission (ca_id, profile_id, revision, snapshot_sha256, event_id)
    VALUES (p_ca, p_profile, 1, decode(repeat('aa', 32), 'hex'), e);
    INSERT INTO profile_lifecycle_event (operation_id, request_sha256, action, ca_id, profile_id, revision,
        snapshot_sha256, policy_version, actor_issuer, actor_subject)
    VALUES (gen_random_uuid(), decode(repeat('11', 32), 'hex'), 'revision.activation', p_ca, p_profile, 1,
            decode(repeat('aa', 32), 'hex'), 'v1', 'owner', 'owner') RETURNING event_id INTO e;
    INSERT INTO certificate_profile_active (ca_id, profile_id, revision, activated_event_id) VALUES (p_ca, p_profile, 1, e);
    INSERT INTO certificate_profile_activation (event_id, ca_id, profile_id, revision, action)
    VALUES (e, p_ca, p_profile, 1, 'activate');
END $fn$;
SELECT pg_temp.active_profile('5a5a5a5a-0000-4000-8000-000000000007', 'server-t');
SELECT pg_temp.active_profile('0a0a0a0a-0000-4000-8000-00000000000a', 'server-o');

DO $test$ BEGIN
    IF (SELECT string_agg(ca_id::text || ':' || state, ',' ORDER BY ca_id) FROM ca_operational_state)
       <> '5a5a5a5a-0000-4000-8000-000000000005:ACTIVE,5a5a5a5a-0000-4000-8000-000000000007:ACTIVE,5a5a5a5a-0000-4000-8000-0000000000ff:ACTIVE' THEN
        RAISE EXCEPTION 'activated CAs do not start ACTIVE';
    END IF;
END $test$;

-- Helpers, run as the writer.
CREATE FUNCTION pg_temp.suspend(p_subject text, p_ca text, p_operation uuid DEFAULT gen_random_uuid()) RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM suspend_ca_lab(%L, %L, %L, %L, %L, %L)', 'https://issuer.ca.invalid', p_subject, p_ca,
        'suspected key exposure', p_operation, decode(repeat('22', 32), 'hex'))
$fn$;
CREATE FUNCTION pg_temp.request(p_subject text, p_ca text, p_action text, p_operation uuid DEFAULT gen_random_uuid())
RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM request_ca_change_lab(%L, %L, %L, %L, %L, %L, %L)', 'https://issuer.ca.invalid',
        p_subject, p_ca, p_action, 'change: ' || p_action, p_operation, decode(repeat('33', 32), 'hex'))
$fn$;
CREATE FUNCTION pg_temp.decide(p_subject text, p_ca uuid, p_request uuid, p_decision text,
    p_issued_at timestamptz DEFAULT clock_timestamp()) RETURNS record LANGUAGE sql AS $fn$
    SELECT (r.request_status, r.approval_count)::record FROM record_ca_change_decision_lab('https://issuer.ca.invalid',
        p_subject, p_ca, p_request, p_decision, p_issued_at, decode(repeat('30', 70), 'hex'), gen_random_uuid(),
        decode(repeat('44', 32), 'hex')) r
$fn$;
CREATE FUNCTION pg_temp.apply(p_subject text, p_ca text, p_request text, p_operation uuid DEFAULT gen_random_uuid())
RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM apply_ca_change_lab(%L, %L, %L, %L, %L, %L)', 'https://issuer.ca.invalid', p_subject,
        p_ca, p_request, p_operation, decode(repeat('55', 32), 'hex'))
$fn$;

SET LOCAL ROLE trust_profile_writer;
-- Suspension: grant, unknown or owner CA, replay, only from ACTIVE.
SELECT pg_temp.expect_state(pg_temp.suspend('approver-1', '5a5a5a5a-0000-4000-8000-000000000005'), '42501');
SELECT pg_temp.expect_state(pg_temp.suspend('admin-1', '0a0a0a0a-0000-4000-8000-00000000000a'), 'P0002');
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.suspend('admin-1', '5a5a5a5a-0000-4000-8000-000000000005', '0f0f0f0f-0000-4000-8000-0000000000c1') INTO r;
    IF r.operational_state <> 'SUSPENDED' OR r.replayed THEN RAISE EXCEPTION 'suspension: %', r; END IF;
    EXECUTE pg_temp.suspend('admin-1', '5a5a5a5a-0000-4000-8000-000000000005', '0f0f0f0f-0000-4000-8000-0000000000c1') INTO r;
    IF NOT r.replayed THEN RAISE EXCEPTION 'suspension replay: %', r; END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.suspend('admin-1', '5a5a5a5a-0000-4000-8000-000000000005'), 'TP409');

-- Change requests: grant, action and state, one open request per CA.
SELECT pg_temp.expect_state(pg_temp.request('approver-1', '5a5a5a5a-0000-4000-8000-000000000005', 'reactivate'), '42501');
SELECT pg_temp.expect_state(pg_temp.request('admin-1', '5a5a5a5a-0000-4000-8000-000000000007', 'reactivate'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.request('admin-1', '5a5a5a5a-0000-4000-8000-000000000005', 'suspend'), '22023');
SELECT pg_temp.expect_state(pg_temp.request('admin-1', '0a0a0a0a-0000-4000-8000-00000000000a', 'retire'), 'P0002');

DO $test$
DECLARE
    iss text := 'https://issuer.ca.invalid';
    s uuid := '5a5a5a5a-0000-4000-8000-000000000005';
    r record;
    claim record;
    req uuid;
    st text; n integer;
BEGIN
    EXECUTE pg_temp.request('admin-1', s::text, 'reactivate', '0f0f0f0f-0000-4000-8000-0000000000c2') INTO r;
    IF r.from_state <> 'SUSPENDED' OR r.replayed THEN RAISE EXCEPTION 'request: %', r; END IF;
    req := r.request_id;
    EXECUTE pg_temp.request('admin-1', s::text, 'reactivate', '0f0f0f0f-0000-4000-8000-0000000000c2') INTO r;
    IF NOT r.replayed OR r.request_id <> req THEN RAISE EXCEPTION 'request replay: %', r; END IF;
    BEGIN
        EXECUTE pg_temp.request('admin-3', s::text, 'retire');
        RAISE EXCEPTION 'a second open request was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;

    -- Decisions: the requester cannot decide; the claim; two approvals.
    BEGIN
        PERFORM prepare_ca_change_decision_lab(iss, 'admin-1', s, req, 'approve');
        RAISE EXCEPTION 'the requester was allowed to decide';
    EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
    END;
    BEGIN
        PERFORM prepare_ca_change_decision_lab(iss, 'admin-3', s, req, 'approve');
        RAISE EXCEPTION 'an administrator without the approver grant was allowed to decide';
    EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
    END;
    BEGIN
        PERFORM prepare_ca_change_decision_lab(iss, 'approver-1', '5a5a5a5a-0000-4000-8000-000000000007', req, 'approve');
        RAISE EXCEPTION 'a request was decided under another CA';
    EXCEPTION WHEN SQLSTATE 'P0002' THEN NULL;
    END;
    SELECT * INTO claim FROM prepare_ca_change_decision_lab(iss, 'approver-1', s, req, 'approve');
    IF claim.claim !~ ('^trust-platform/ca-change-decision/v1;decision=approve;action=reactivate;request_id=' || req::text
        || ';ca_id=' || s::text || ';from_state=SUSPENDED;reason_sha256=' || encode(digest('change: reactivate', 'sha256'), 'hex')
        || ';certificate_sha256=' || encode(digest(decode(repeat('51', 300), 'hex'), 'sha256'), 'hex')
        || ';approver_issuer=https://issuer\.ca\.invalid;approver_subject=approver-1;key_id=approver-1-ca;issued_at='
        || claim.issued_at || '$') THEN
        RAISE EXCEPTION 'unexpected change claim: %', claim.claim;
    END IF;
    SELECT * INTO st, n FROM pg_temp.decide('approver-1', s, req, 'approve', claim.issued_at::timestamptz) AS (st text, n integer);
    IF st <> 'OPEN' OR n <> 1 THEN RAISE EXCEPTION 'first change approval: % %', st, n; END IF;
    BEGIN
        PERFORM pg_temp.decide('approver-1', s, req, 'reject');
        RAISE EXCEPTION 'a repeated decision was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    BEGIN
        PERFORM pg_temp.decide('approver-2', s, req, 'approve', clock_timestamp() - interval '11 minutes');
        RAISE EXCEPTION 'a stale change claim was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    SELECT * INTO st, n FROM pg_temp.decide('approver-2', s, req, 'approve') AS (st text, n integer);
    IF st <> 'APPROVED' OR n <> 2 THEN RAISE EXCEPTION 'second change approval: % %', st, n; END IF;
    BEGIN
        PERFORM prepare_ca_change_decision_lab(iss, 'approver-3', s, req, 'reject');
        RAISE EXCEPTION 'a decision on an approved request was accepted';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;

    -- Application: grant, an approver of the request; then reactivation.
    BEGIN
        EXECUTE pg_temp.apply('approver-3', s::text, req::text);
        RAISE EXCEPTION 'an approver without the administrator grant applied the change';
    EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
    END;
    BEGIN
        EXECUTE pg_temp.apply('approver-2', s::text, req::text);
        RAISE EXCEPTION 'an approver of the request applied it';
    EXCEPTION WHEN SQLSTATE '42501' THEN NULL;
    END;
    EXECUTE pg_temp.apply('admin-1', s::text, req::text, '0f0f0f0f-0000-4000-8000-0000000000c3') INTO r;
    IF r.operational_state <> 'ACTIVE' OR r.retired_revisions <> 0 OR r.replayed THEN RAISE EXCEPTION 'reactivation: %', r; END IF;
    EXECUTE pg_temp.apply('admin-1', s::text, req::text, '0f0f0f0f-0000-4000-8000-0000000000c3') INTO r;
    IF NOT r.replayed OR r.operational_state <> 'ACTIVE' THEN RAISE EXCEPTION 'reactivation replay: %', r; END IF;
    BEGIN
        EXECUTE pg_temp.apply('admin-1', s::text, req::text);
        RAISE EXCEPTION 'a change was applied twice';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;

    -- A rejection ends a request; a new one is then possible.
    EXECUTE pg_temp.request('admin-1', s::text, 'retire') INTO r;
    SELECT * INTO st, n FROM pg_temp.decide('approver-3', s, r.request_id, 'reject') AS (st text, n integer);
    IF st <> 'REJECTED' THEN RAISE EXCEPTION 'change rejection: %', st; END IF;
    BEGIN
        EXECUTE pg_temp.apply('admin-3', s::text, r.request_id::text);
        RAISE EXCEPTION 'a rejected change was applied';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    EXECUTE pg_temp.request('admin-3', s::text, 'retire') INTO r;
END $test$;

-- While a CA is suspended, no profile revision is activated for it; an
-- owner-created CA is unaffected.
DO $test$
DECLARE
    iss text := 'https://issuer.ca.invalid';
    t uuid := '5a5a5a5a-0000-4000-8000-000000000007';
    r record;
    stale uuid;
    st text; n integer;
BEGIN
    -- A retirement approved while ACTIVE goes stale when the CA is suspended.
    EXECUTE pg_temp.request('admin-1', t::text, 'retire') INTO r;
    stale := r.request_id;
    PERFORM pg_temp.decide('approver-1', t, stale, 'approve');
    PERFORM pg_temp.decide('approver-2', t, stale, 'approve');
    EXECUTE pg_temp.suspend('admin-1', t::text);
    BEGIN
        EXECUTE pg_temp.apply('admin-3', t::text, stale::text);
        RAISE EXCEPTION 'a stale change was applied';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL;
    END;
    EXECUTE pg_temp.request('admin-1', t::text, 'retire') INTO r;
    IF r.from_state <> 'SUSPENDED' THEN RAISE EXCEPTION 'retirement request: %', r; END IF;
    PERFORM pg_temp.decide('approver-1', t, r.request_id, 'approve');
    PERFORM pg_temp.decide('approver-3', t, r.request_id, 'approve');
    PERFORM set_config('test.retire_request', r.request_id::text, true);
END $test$;
RESET ROLE;
SELECT pg_temp.expect_state($q$SELECT pg_temp.active_profile('5a5a5a5a-0000-4000-8000-000000000007', 'server-t2')$q$, 'TP409');
SELECT pg_temp.active_profile('0a0a0a0a-0000-4000-8000-00000000000a', 'server-o2');

-- Interrupted transaction: a failing audit write leaves the CA and its
-- profiles as they were.
CREATE FUNCTION pg_temp.fail_retirement_audit() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
    IF NEW.event_type = 'profile.revision.retirement' THEN RAISE EXCEPTION 'injected audit failure'; END IF;
    RETURN NEW;
END $fn$;
CREATE TRIGGER inject_retirement_failure BEFORE INSERT ON audit_event
    FOR EACH ROW EXECUTE FUNCTION pg_temp.fail_retirement_audit();
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.apply('admin-3', '5a5a5a5a-0000-4000-8000-000000000007',
    current_setting('test.retire_request')), 'P0001');
RESET ROLE;
DROP TRIGGER inject_retirement_failure ON audit_event;
DO $test$ BEGIN
    IF (SELECT state FROM ca_operational_state WHERE ca_id = '5a5a5a5a-0000-4000-8000-000000000007') <> 'SUSPENDED'
       OR NOT EXISTS (SELECT 1 FROM certificate_profile_active WHERE ca_id = '5a5a5a5a-0000-4000-8000-000000000007') THEN
        RAISE EXCEPTION 'an interrupted retirement changed the CA or its profiles';
    END IF;
END $test$;

-- Retirement: the CA and its active profile revision, once and for good.
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.apply('admin-3', '5a5a5a5a-0000-4000-8000-000000000007', current_setting('test.retire_request')) INTO r;
    IF r.operational_state <> 'RETIRED' OR r.retired_revisions <> 1 THEN RAISE EXCEPTION 'retirement: %', r; END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.suspend('admin-1', '5a5a5a5a-0000-4000-8000-000000000007'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.request('admin-1', '5a5a5a5a-0000-4000-8000-000000000007', 'retire'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.request('admin-1', '5a5a5a5a-0000-4000-8000-000000000007', 'reactivate'), 'TP409');

-- Reactivation needs a current certificate.
DO $test$
DECLARE
    x uuid := '5a5a5a5a-0000-4000-8000-0000000000ff';
    r record;
BEGIN
    EXECUTE pg_temp.suspend('admin-1', x::text);
    EXECUTE pg_temp.request('admin-1', x::text, 'reactivate') INTO r;
    PERFORM pg_temp.decide('approver-1', x, r.request_id, 'approve');
    PERFORM pg_temp.decide('approver-3', x, r.request_id, 'approve');
    BEGIN
        EXECUTE pg_temp.apply('admin-3', x::text, r.request_id::text);
        RAISE EXCEPTION 'a CA with an expired certificate was reactivated';
    EXCEPTION WHEN SQLSTATE 'TP422' THEN NULL;
    END;
END $test$;
RESET ROLE;

DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM certificate_profile_active WHERE ca_id = '5a5a5a5a-0000-4000-8000-000000000007')
       OR NOT EXISTS (SELECT 1 FROM certificate_profile_activation
                      WHERE ca_id = '5a5a5a5a-0000-4000-8000-000000000007' AND profile_id = 'server-t' AND action = 'retire')
       OR NOT EXISTS (SELECT 1 FROM profile_lifecycle_event e JOIN audit_event a USING (event_id)
                      WHERE e.ca_id = '5a5a5a5a-0000-4000-8000-000000000007' AND e.action = 'revision.retirement'
                        AND a.event_type = 'profile.revision.retirement') THEN
        RAISE EXCEPTION 'retiring the CA did not retire its profile revision';
    END IF;
    IF (SELECT count(*) FROM certificate_profile_active WHERE ca_id = '0a0a0a0a-0000-4000-8000-00000000000a') <> 2 THEN
        RAISE EXCEPTION 'the owner CA was affected';
    END IF;
    IF (SELECT string_agg(action || ':' || from_state || '>' || to_state, ',' ORDER BY recorded_at) FROM ca_state_change
        WHERE ca_id = '5a5a5a5a-0000-4000-8000-000000000007') <> 'suspend:ACTIVE>SUSPENDED,retire:SUSPENDED>RETIRED' THEN
        RAISE EXCEPTION 'unexpected state history';
    END IF;
END $test$;

-- Views: readers of a CA see its state; administrators and approvers see
-- states and the open request.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.ca.invalid', 'reader', '5a5a5a5a-0000-4000-8000-000000000007'),
    ('https://issuer.ca.invalid', 'reader', '0a0a0a0a-0000-4000-8000-00000000000a');
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.ca.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT string_agg(display_name || ':' || coalesce(operational_state, '-'), ',' ORDER BY display_name) FROM management_ca)
       <> 'Owner CA:-,Root T:RETIRED' THEN
        RAISE EXCEPTION 'unexpected reader CA view';
    END IF;
    IF management_ca_operation_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_ca_proposal) THEN RAISE EXCEPTION 'a reader sees CA proposals'; END IF;
END $test$;
SELECT set_config('trust.reader_subject', 'approver-3', true);
DO $test$ BEGIN
    IF (SELECT string_agg(display_name || ':' || lifecycle_status || ':' || coalesce(change_action || '/' || change_status
                          || '/' || change_approval_count, '-'), ',' ORDER BY display_name) FROM management_ca_proposal)
       <> 'Root S:ACTIVE:retire/OPEN/0,Root T:RETIRED:-,Root X:SUSPENDED:reactivate/APPROVED/2' THEN
        RAISE EXCEPTION 'unexpected approver view: %', (SELECT string_agg(display_name || ':' || lifecycle_status || ':'
            || coalesce(change_action || '/' || change_status, '-'), ',') FROM management_ca_proposal);
    END IF;
END $test$;
RESET ROLE;

-- Records cannot change.
SELECT pg_temp.expect_state($q$UPDATE ca_state_change SET reason = 'x'$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM ca_change_request$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM ca_change_decision$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM ca_change_application$q$, 'P0001');

ROLLBACK;
\echo 'PASS: activated CAs are suspended at once, reactivated or retired only after two signed approvals, with their profiles'
