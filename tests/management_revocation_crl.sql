-- Migration 0031: revocation of certificates issued for applications, with
-- a registration officer's decision, and CRLs signed once by the laboratory
-- signer. Run as the migration owner after 0031 on a disposable database;
-- every change is rolled back. The database parses no X.509: placeholder
-- bytes stand for the TBS and CRL the API builds and verifies. Before 0031
-- the first statement fails.
BEGIN;

SELECT 1 FROM crl_signing_intent LIMIT 0;

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
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('https://issuer.iss.invalid', 'req-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester'),
    ('https://issuer.iss.invalid', 'req-2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'certificate-requester'),
    ('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer'),
    ('https://issuer.iss.invalid', 'ra-2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer');


-- Five approved applications by req-1; A to D are issued (placeholder
-- bytes stand for the TBS and certificate the API builds and verifies), E
-- is only approved.
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    iss text := 'https://issuer.iss.invalid';
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    names text[] := ARRAY['a', 'b', 'c', 'd', 'e'];
    r record;
    b record;
BEGIN
    FOR i IN 1..5 LOOP
        SELECT * INTO r FROM submit_certificate_application_lab(iss, 'req-1', c, 'server', decode(repeat('3' || i, 200), 'hex'),
            digest('key-' || i, 'sha256'), names[i] || '.lab.invalid', ARRAY[names[i] || '.lab.invalid'],
            30, gen_random_uuid(), digest(names[i], 'sha256'));
        PERFORM set_config('test.app_' || names[i], r.application_id::text, true);
        PERFORM decide_certificate_application_lab(iss, 'ra-1', c, r.application_id, 'approve', 'checked',
            gen_random_uuid(), digest(names[i], 'sha256'));
        IF names[i] <> 'e' THEN
            SELECT * INTO b FROM begin_application_issuance_lab(iss, 'ra-1', c, r.application_id, gen_random_uuid(),
                digest(names[i], 'sha256'));
            PERFORM set_config('test.serial_' || names[i], encode(b.serial, 'hex'), true);
            PERFORM record_application_signing_intent_lab(iss, 'ra-1', c, r.application_id, 'lab-signer:c5',
                digest('tbs-' || names[i], 'sha256'));
            PERFORM store_application_certificate_lab(iss, 'ra-1', c, r.application_id, digest('tbs-' || names[i], 'sha256'),
                decode(repeat('d' || i, 400), 'hex'), names[i] || '.lab.invalid', '2026-11-07T00:00:00Z',
                '2026-12-07T00:00:00Z', ARRAY[names[i] || '.lab.invalid']);
        END IF;
    END LOOP;
END $setup$;

CREATE FUNCTION pg_temp.request(p_subject text, p_app text, p_code int, p_reason text DEFAULT 'compromised',
    p_operation uuid DEFAULT gen_random_uuid(), p_sha text DEFAULT 'r') RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM request_certificate_revocation_lab(%L, %L, %L, %L, %s::smallint, %L, %L, %L)',
        'https://issuer.iss.invalid', p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_app, p_code, p_reason,
        p_operation, digest(p_sha, 'sha256'))
$fn$;
CREATE FUNCTION pg_temp.decide(p_subject text, p_app text, p_revocation text, p_decision text,
    p_operation uuid DEFAULT gen_random_uuid(), p_sha text DEFAULT 'd') RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM decide_certificate_revocation_lab(%L, %L, %L, %L, %L, %L, %L, %L, %L)',
        'https://issuer.iss.invalid', p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_app, p_revocation,
        p_decision, 'reviewed', p_operation, digest(p_sha, 'sha256'))
$fn$;
CREATE FUNCTION pg_temp.begin_crl(p_subject text, p_operation uuid DEFAULT gen_random_uuid(), p_sha text DEFAULT 'c')
RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM begin_crl_publication_lab(%L, %L, %L, %L, %L)', 'https://issuer.iss.invalid',
        p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_operation, digest(p_sha, 'sha256'))
$fn$;
CREATE FUNCTION pg_temp.record_crl(p_intent text, p_tbs text) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT record_crl_signing_intent_lab(%L, %L, %L, %L, %L)', 'https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', p_intent, digest(p_tbs, 'sha256'))
$fn$;
CREATE FUNCTION pg_temp.store_crl(p_intent text) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT store_crl_lab(%L, %L, %L, %L, %L)', 'https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', p_intent, decode(repeat('e1', 200), 'hex'))
$fn$;
CREATE FUNCTION pg_temp.claim_crl(p_intent text, p_tbs text) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT claim_lab_crl_intent(%L, %L)', p_intent, digest(p_tbs, 'sha256'))
$fn$;

-- The writer reads no table; the signer cannot claim as the writer.
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_revocation_request', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM crl_signing_intent', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM lab_signer_crl_intent', '42501');
SELECT pg_temp.expect_state(pg_temp.claim_crl(gen_random_uuid()::text, 'x'), '42501');

-- Requests: an issued certificate, the requester or an officer, a reason
-- from the closed list.
SELECT pg_temp.expect_state(pg_temp.request('ra-1', current_setting('test.app_e'), 1), 'P0002');
SELECT pg_temp.expect_state(pg_temp.request('req-2', current_setting('test.app_a'), 1), '42501');
SELECT pg_temp.expect_state(pg_temp.request('approver-1', current_setting('test.app_a'), 1), '42501');
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_a'), 2), '22023');
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_a'), 6), '22023');
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_a'), 7), '22023');
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_a'), 1, ''), '22023');
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_a'), 1, e'line\nbreak'), '22023');

DO $test$
DECLARE
    op uuid := gen_random_uuid();
    first record;
    r record;
BEGIN
    EXECUTE pg_temp.request('req-1', current_setting('test.app_a'), 1, 'compromised', op) INTO first;
    IF first.replayed THEN RAISE EXCEPTION 'first request replayed'; END IF;
    EXECUTE pg_temp.request('req-1', current_setting('test.app_a'), 1, 'compromised', op) INTO r;
    IF NOT r.replayed OR r.revocation_id <> first.revocation_id THEN RAISE EXCEPTION 'request replay: %', r; END IF;
    PERFORM set_config('test.rev_a1', first.revocation_id::text, true);
    PERFORM set_config('test.op_a1', op::text, true);
END $test$;
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_a'), 1, 'compromised',
    current_setting('test.op_a1')::uuid, 'other'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.request('ra-1', current_setting('test.app_a'), 4), 'TP409');

-- Decisions: an officer who did not request it, once.
SELECT pg_temp.expect_state(pg_temp.decide('req-1', current_setting('test.app_a'), current_setting('test.rev_a1'), 'approve'), '42501');
SELECT pg_temp.expect_state(pg_temp.decide('ra-1', current_setting('test.app_b'), current_setting('test.rev_a1'), 'approve'), 'P0002');
SELECT pg_temp.expect_state(pg_temp.decide('ra-1', current_setting('test.app_a'), gen_random_uuid()::text, 'approve'), 'P0002');
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.decide('ra-1', current_setting('test.app_a'), current_setting('test.rev_a1'), 'reject') INTO r;
    IF r.status <> 'REJECTED' OR r.revoked_at IS NOT NULL OR r.replayed THEN RAISE EXCEPTION 'reject: %', r; END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.decide('ra-2', current_setting('test.app_a'), current_setting('test.rev_a1'), 'approve'), 'TP409');
-- A rejected request leaves the certificate valid; a new one may follow.
DO $test$
DECLARE
    r record;
    d record;
    op uuid := gen_random_uuid();
BEGIN
    EXECUTE pg_temp.request('req-1', current_setting('test.app_a'), 1, 'key leaked') INTO r;
    EXECUTE pg_temp.decide('ra-1', current_setting('test.app_a'), r.revocation_id::text, 'approve', op) INTO d;
    IF d.status <> 'REVOKED' OR d.revoked_at IS NULL OR d.replayed THEN RAISE EXCEPTION 'approve: %', d; END IF;
    EXECUTE pg_temp.decide('ra-1', current_setting('test.app_a'), r.revocation_id::text, 'approve', op) INTO d;
    IF d.status <> 'REVOKED' OR d.revoked_at IS NULL OR NOT d.replayed THEN RAISE EXCEPTION 'approve replay: %', d; END IF;
    -- An officer who requested cannot decide; another officer can.
    EXECUTE pg_temp.request('ra-1', current_setting('test.app_b'), 4) INTO r;
    PERFORM set_config('test.rev_b', r.revocation_id::text, true);
END $test$;
SELECT pg_temp.expect_state(pg_temp.decide('ra-1', current_setting('test.app_b'), current_setting('test.rev_b'), 'approve'), '42501');
SELECT * FROM decide_certificate_revocation_lab('https://issuer.iss.invalid', 'ra-2', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.app_b')::uuid, current_setting('test.rev_b')::uuid, 'approve', 'reviewed', gen_random_uuid(),
    digest('b', 'sha256')) \gset ignored_
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_a'), 1), 'TP409');
RESET ROLE;
DO $test$ BEGIN
    IF (SELECT string_agg(encode(r.serial_der_content, 'hex') || ':' || r.reason_code || ':' || r.actor_id, ','
                          ORDER BY r.reason_code)
        FROM revocation r) <> current_setting('test.serial_a') || ':1:ra-1,' || current_setting('test.serial_b') || ':4:ra-2' THEN
        RAISE EXCEPTION 'unexpected core revocations: %', (SELECT string_agg(r.actor_id, ',') FROM revocation r);
    END IF;
    IF (SELECT count(*) FROM audit_event WHERE event_type = 'certificate.revoked') <> 2
       OR (SELECT count(*) FROM audit_event WHERE event_type = 'certificate.revocation.rejected') <> 1 THEN
        RAISE EXCEPTION 'missing revocation audit events';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$UPDATE revocation SET reason_code = 0$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM revocation$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM certificate_revocation_decision$q$, 'P0001');

-- CRLs: officers only; the number and the listed revocations are fixed at
-- the start.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.begin_crl('req-1'), '42501');
DO $test$
DECLARE
    op uuid := gen_random_uuid();
    first record;
    r record;
    n int;
BEGIN
    EXECUTE pg_temp.begin_crl('ra-1', op) INTO first;
    IF first.replayed OR first.crl_number <> 1 OR first.outcome <> 'PREPARED'
       OR first.issuer_certificate_der <> decode(repeat('c5', 300), 'hex')
       OR (first.next_update::timestamptz - first.this_update::timestamptz) <> interval '7 days' THEN
        RAISE EXCEPTION 'begin CRL: %', first;
    END IF;
    -- (Rolled back with this block: the exception handler discards it.)
    EXECUTE pg_temp.begin_crl('ra-2', op) INTO r;
    RAISE EXCEPTION 'another officer replayed a CRL key';
EXCEPTION WHEN SQLSTATE 'TP409' THEN
    NULL;
END $test$;
DO $test$
DECLARE
    op uuid := gen_random_uuid();
    first record;
    r record;
BEGIN
    EXECUTE pg_temp.begin_crl('ra-1', op) INTO first;
    IF first.crl_number <> 1 THEN RAISE EXCEPTION 'first number %', first.crl_number; END IF;
    EXECUTE pg_temp.begin_crl('ra-1', op) INTO r;
    IF NOT r.replayed OR r.intent_id <> first.intent_id OR r.crl_number <> first.crl_number THEN
        RAISE EXCEPTION 'CRL replay: %', r;
    END IF;
    PERFORM set_config('test.crl_1', first.intent_id::text, true);
    PERFORM set_config('test.crl_1_op', op::text, true);
END $test$;
SELECT pg_temp.expect_state(pg_temp.begin_crl('ra-1', current_setting('test.crl_1_op')::uuid, 'other'), 'TP409');
DO $test$ BEGIN
    IF (SELECT string_agg(encode(serial, 'hex') || ':' || reason_code, ',' ORDER BY serial)
        FROM crl_publication_entries_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
                                         current_setting('test.crl_1')::uuid))
       <> (SELECT string_agg(s, ',' ORDER BY s) FROM unnest(ARRAY[current_setting('test.serial_a') || ':1',
                                                                current_setting('test.serial_b') || ':4']) s) THEN
        RAISE EXCEPTION 'unexpected CRL entries';
    END IF;
END $test$;
-- A revocation after the CRL started is not in it.
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.request('req-1', current_setting('test.app_c'), 5) INTO r;
    EXECUTE pg_temp.decide('ra-1', current_setting('test.app_c'), r.revocation_id::text, 'approve');
    IF (SELECT count(*) FROM crl_publication_entries_lab('https://issuer.iss.invalid', 'ra-1',
            'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.crl_1')::uuid)) <> 2 THEN
        RAISE EXCEPTION 'a later revocation entered an earlier CRL';
    END IF;
END $test$;
SELECT pg_temp.expect_state(format('SELECT * FROM crl_publication_entries_lab(%L, %L, %L, %L)', 'https://issuer.iss.invalid',
    'req-1', 'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.crl_1')), '42501');

-- Before the digest is journaled, the signer cannot claim.
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF (SELECT signable FROM lab_signer_crl_intent WHERE intent_id = current_setting('test.crl_1')) THEN
        RAISE EXCEPTION 'a prepared CRL is signable';
    END IF;
    IF (SELECT count(*) FROM lab_signer_crl_entry WHERE intent_id = current_setting('test.crl_1')) <> 2 THEN
        RAISE EXCEPTION 'the signer sees other entries';
    END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.claim_crl(current_setting('test.crl_1'), 'crl-tbs-1'), 'TP409');
SELECT pg_temp.expect_state('SELECT 1 FROM crl_signing_intent', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM revocation', '42501');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
DO $test$ BEGIN
    IF (SELECT record_crl_signing_intent_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
            current_setting('test.crl_1')::uuid, digest('crl-tbs-1', 'sha256'))) THEN
        RAISE EXCEPTION 'first journal replayed';
    END IF;
    IF NOT (SELECT record_crl_signing_intent_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
            current_setting('test.crl_1')::uuid, digest('crl-tbs-other', 'sha256'))) THEN
        RAISE EXCEPTION 'a second journal was accepted';
    END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.store_crl(current_setting('test.crl_1')), 'TP409');
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF NOT (SELECT signable FROM lab_signer_crl_intent WHERE intent_id = current_setting('test.crl_1')) THEN
        RAISE EXCEPTION 'a journaled CRL is not signable';
    END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.claim_crl(current_setting('test.crl_1'), 'crl-tbs-other'), 'TP409');
SELECT claim_lab_crl_intent(current_setting('test.crl_1')::uuid, digest('crl-tbs-1', 'sha256'));
SELECT pg_temp.expect_state(pg_temp.claim_crl(current_setting('test.crl_1'), 'crl-tbs-1'), 'TP409');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT store_crl_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.crl_1')::uuid, decode(repeat('e1', 200), 'hex'));
SELECT pg_temp.expect_state(pg_temp.store_crl(current_setting('test.crl_1')), 'TP409');

-- Only the latest intent can be journaled or signed: a newer one supersedes
-- an older one, and an ambiguous one is never signed.
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.begin_crl('ra-1') INTO r;
    PERFORM set_config('test.crl_3', r.intent_id::text, true);
    IF r.crl_number <> 2 THEN RAISE EXCEPTION 'number %', r.crl_number; END IF;
    IF (SELECT count(*) FROM crl_publication_entries_lab('https://issuer.iss.invalid', 'ra-1',
            'c5c5c5c5-0000-4000-8000-00000000000c', r.intent_id)) <> 3 THEN
        RAISE EXCEPTION 'the new CRL misses a revocation';
    END IF;
    EXECUTE pg_temp.begin_crl('ra-2') INTO r;
    PERFORM set_config('test.crl_4', r.intent_id::text, true);
END $test$;
SELECT pg_temp.expect_state(pg_temp.record_crl(current_setting('test.crl_3'), 'crl-tbs-3'), 'TP409');
SELECT record_crl_signing_intent_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.crl_4')::uuid, digest('crl-tbs-4', 'sha256'));
SELECT mark_crl_signing_uncertain_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.crl_4')::uuid);
SELECT pg_temp.expect_state(format('SELECT mark_crl_signing_uncertain_lab(%L, %L, %L, %L)', 'https://issuer.iss.invalid',
    'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.crl_4')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.store_crl(current_setting('test.crl_4')), 'TP409');
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF (SELECT bool_or(signable) FROM lab_signer_crl_intent
        WHERE intent_id IN (current_setting('test.crl_3'), current_setting('test.crl_4'))) THEN
        RAISE EXCEPTION 'a superseded or ambiguous CRL is signable';
    END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.claim_crl(current_setting('test.crl_4'), 'crl-tbs-4'), 'TP409');
RESET ROLE;

-- A suspended CA still revokes and publishes; a retired one does neither,
-- and a journaled intent of a retired CA cannot be claimed.
SET LOCAL ROLE trust_profile_writer;
SELECT * FROM suspend_ca_lab('https://issuer.iss.invalid', 'admin', 'c5c5c5c5-0000-4000-8000-00000000000c', 'test',
    gen_random_uuid(), decode(repeat('66', 32), 'hex'));
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.request('req-1', current_setting('test.app_d'), 3) INTO r;
    PERFORM set_config('test.rev_d', r.revocation_id::text, true);
    EXECUTE pg_temp.begin_crl('ra-1') INTO r;
    PERFORM set_config('test.crl_5', r.intent_id::text, true);
    PERFORM record_crl_signing_intent_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
        r.intent_id, digest('crl-tbs-5', 'sha256'));
END $test$;
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF NOT (SELECT signable FROM lab_signer_crl_intent WHERE intent_id = current_setting('test.crl_5')) THEN
        RAISE EXCEPTION 'a CRL of a suspended CA is not signable';
    END IF;
END $test$;
RESET ROLE;
-- A newer intent supersedes a journaled one before the signer claims it.
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE r record;
BEGIN
    EXECUTE pg_temp.begin_crl('ra-2') INTO r;
    PERFORM set_config('test.crl_6', r.intent_id::text, true);
END $test$;
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF (SELECT signable FROM lab_signer_crl_intent WHERE intent_id = current_setting('test.crl_5')) THEN
        RAISE EXCEPTION 'a superseded journaled CRL is signable';
    END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.claim_crl(current_setting('test.crl_5'), 'crl-tbs-5'), 'TP409');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT record_crl_signing_intent_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.crl_6')::uuid, digest('crl-tbs-6', 'sha256'));
RESET ROLE;
UPDATE ca_operational_state SET state = 'RETIRED' WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c';
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(pg_temp.begin_crl('ra-1'), 'TP409');
SELECT pg_temp.expect_state(pg_temp.request('req-1', current_setting('test.app_e'), 1), 'P0002');
SELECT pg_temp.expect_state(pg_temp.decide('ra-1', current_setting('test.app_d'), current_setting('test.rev_d'), 'approve'), 'TP409');
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF (SELECT signable FROM lab_signer_crl_intent WHERE intent_id = current_setting('test.crl_6')) THEN
        RAISE EXCEPTION 'a CRL of a retired CA is signable';
    END IF;
END $test$;
SELECT pg_temp.expect_state(pg_temp.claim_crl(current_setting('test.crl_6'), 'crl-tbs-6'), 'TP409');
RESET ROLE;
UPDATE ca_operational_state SET state = 'ACTIVE' WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c';
SET LOCAL ROLE trust_profile_writer;
-- D's request is still open: another one is refused.
SELECT pg_temp.expect_state(pg_temp.request('ra-2', current_setting('test.app_d'), 1), 'TP409');
RESET ROLE;

-- Intents only move forward; documents and claims are final.
SELECT pg_temp.expect_state(format($q$UPDATE crl_signing_intent SET crl_number = 99 WHERE intent_id = %L$q$,
    current_setting('test.crl_1')), 'P0001');
SELECT pg_temp.expect_state(format($q$UPDATE crl_signing_intent SET outcome = 'UNCONFIRMED' WHERE intent_id = %L$q$,
    current_setting('test.crl_4')), 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM crl_signing_intent$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM crl_document$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM lab_signer_crl_claim$q$, 'P0001');
DO $test$ BEGIN
    IF (SELECT count(*) FROM crl_publication WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c' AND crl_number = 1
            AND published_at IS NOT NULL AND crl_sha256 = digest(decode(repeat('e1', 200), 'hex'), 'sha256')) <> 1
       OR (SELECT count(*) FROM audit_event WHERE event_type = 'crl.published') <> 1
       OR (SELECT count(*) FROM audit_event WHERE event_type = 'crl.reconciliation_required') <> 1 THEN
        RAISE EXCEPTION 'unexpected CRL records';
    END IF;
END $test$;

-- Readers of the CA see revocation states and the published CRL; others
-- see nothing.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.iss.invalid', 'reader', 'c5c5c5c5-0000-4000-8000-00000000000c');
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.iss.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT string_agg(subject_cn || ':' || status || ':' || coalesce(revocation_reason_code::text, '-') || ':'
                          || coalesce(open_revocation_reason_code::text, '-') || ':' || (revoked_at IS NOT NULL),
                          ',' ORDER BY subject_cn)
        FROM management_certificate_application)
       <> 'a.lab.invalid:REVOKED:1:-:true,b.lab.invalid:REVOKED:4:-:true,c.lab.invalid:REVOKED:5:-:true,d.lab.invalid:REVOCATION_REQUESTED:-:3:false,e.lab.invalid:APPROVED:-:-:false' THEN
        RAISE EXCEPTION 'unexpected reader view: %', (SELECT string_agg(subject_cn || ':' || status, ',') FROM management_certificate_application);
    END IF;
    IF (SELECT string_agg(crl_number || ':' || entry_count || ':' || length(crl_sha256) || ':' || octet_length(crl_der), ',')
        FROM management_certificate_crl) <> '1:2:64:200' THEN
        RAISE EXCEPTION 'unexpected CRL view';
    END IF;
    IF management_revocation_crl_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
SELECT set_config('trust.reader_subject', 'nobody', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_certificate_crl) OR EXISTS (SELECT 1 FROM management_certificate_application) THEN
        RAISE EXCEPTION 'an ungranted reader sees revocations or CRLs';
    END IF;
END $test$;
RESET ROLE;

ROLLBACK;
\echo 'PASS: revocations need a requester and a different officer, and CRLs list a fixed instant, take increasing numbers and are signed once by the signer'
