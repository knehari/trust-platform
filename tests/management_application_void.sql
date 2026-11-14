-- Migration 0034: an ambiguous application issuance is voided under dual
-- control, its serial is listed on later CRLs, and the application becomes
-- VOIDED. Run as the migration owner after 0034 on a disposable database;
-- every change is rolled back. Placeholder bytes stand for the TBS and
-- certificates the API builds and verifies. Before 0034 the first statement
-- fails.
BEGIN;

SELECT 1 FROM certificate_application_void LIMIT 0;

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
    ('https://issuer.iss.invalid', 'req-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer'),
    ('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer'),
    ('https://issuer.iss.invalid', 'ra-2', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer');

-- Four applications by req-1, approved by ra-1: A uncertain before any
-- signer claim, B uncertain after a claim, C issued, D approved, not started.
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    iss text := 'https://issuer.iss.invalid';
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    names text[] := ARRAY['a', 'b', 'c', 'd'];
    r record;
    i record;
BEGIN
    FOR n IN 1..4 LOOP
        SELECT * INTO r FROM submit_certificate_application_lab(iss, 'req-1', c, 'server', decode(repeat('4' || n, 200), 'hex'),
            digest('void-key-' || n, 'sha256'), names[n] || '.lab.invalid', ARRAY[names[n] || '.lab.invalid'],
            30, gen_random_uuid(), digest(names[n], 'sha256'));
        PERFORM set_config('test.app_' || names[n], r.application_id::text, true);
        PERFORM decide_certificate_application_lab(iss, 'ra-1', c, r.application_id, 'approve', 'checked',
            gen_random_uuid(), digest(names[n], 'sha256'));
        IF names[n] <> 'd' THEN
            PERFORM begin_application_issuance_lab(iss, 'ra-1', c, r.application_id, gen_random_uuid(), digest(names[n], 'sha256'));
            SELECT * INTO i FROM record_application_signing_intent_lab(iss, 'ra-1', c, r.application_id, 'lab-signer:c5',
                digest('tbs-' || names[n], 'sha256'));
            PERFORM set_config('test.intent_' || names[n], i.intent_id::text, true);
        END IF;
    END LOOP;
END $setup$;
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
SELECT claim_lab_signing_intent(current_setting('test.intent_b')::uuid, digest('tbs-b', 'sha256'));
SELECT claim_lab_signing_intent(current_setting('test.intent_c')::uuid, digest('tbs-c', 'sha256'));
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    iss text := 'https://issuer.iss.invalid';
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
BEGIN
    PERFORM mark_application_signing_uncertain_lab(iss, 'ra-1', c, current_setting('test.app_a')::uuid);
    PERFORM mark_application_signing_uncertain_lab(iss, 'ra-1', c, current_setting('test.app_b')::uuid);
    PERFORM store_application_certificate_lab(iss, 'ra-1', c, current_setting('test.app_c')::uuid, digest('tbs-c', 'sha256'),
        decode(repeat('d0', 400), 'hex'), 'c.lab.invalid', '2026-11-07T00:00:00Z', '2026-12-07T00:00:00Z',
        ARRAY['c.lab.invalid']);
END $setup$;

CREATE FUNCTION pg_temp.propose(p_subject text, p_app text, p_operation uuid DEFAULT gen_random_uuid(),
                                p_request bytea DEFAULT decode(repeat('66', 32), 'hex')) RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM propose_application_void_lab(%L, %L, %L, %L, %L, %L, %L)', 'https://issuer.iss.invalid',
        p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_app, 'signer timed out', p_operation, p_request)
$fn$;
CREATE FUNCTION pg_temp.confirm(p_subject text, p_app text, p_operation uuid DEFAULT gen_random_uuid(),
                                p_request bytea DEFAULT decode(repeat('77', 32), 'hex')) RETURNS text
LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM confirm_application_void_lab(%L, %L, %L, %L, %L, %L, %L)', 'https://issuer.iss.invalid',
        p_subject, 'c5c5c5c5-0000-4000-8000-00000000000c', p_app, 'confirmed with the signer log', p_operation, p_request)
$fn$;

-- Writers cannot touch the table directly.
SELECT pg_temp.expect_state('SELECT 1 FROM certificate_application_void', '42501');
-- Refusals: no officer grant, the requester (even with an officer grant),
-- an issuance that is not ambiguous, nothing started, an unknown application,
-- invalid input, and a confirmation without a proposal.
SELECT pg_temp.expect_state(pg_temp.propose('req-2', current_setting('test.app_a')), '42501');
SELECT pg_temp.expect_state(pg_temp.propose('req-1', current_setting('test.app_a')), '42501');
SELECT pg_temp.expect_state(pg_temp.propose('ra-1', current_setting('test.app_c')), 'TP409');
SELECT pg_temp.expect_state(pg_temp.propose('ra-1', current_setting('test.app_d')), 'P0002');
SELECT pg_temp.expect_state(pg_temp.propose('ra-1', gen_random_uuid()::text), 'P0002');
SELECT pg_temp.expect_state(format('SELECT * FROM propose_application_void_lab(%L, %L, %L, %L, %L, %L, %L)',
    'https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_a'), '',
    gen_random_uuid(), decode(repeat('66', 32), 'hex')), '22023');
SELECT pg_temp.expect_state(pg_temp.confirm('ra-2', current_setting('test.app_a')), 'P0002');

-- A CRL intent fixed before any void lists nothing.
DO $test$
DECLARE
    v record;
    w record;
    op uuid := gen_random_uuid();
    entries int;
BEGIN
    SELECT * INTO v FROM begin_crl_publication_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('88', 32), 'hex'));
    PERFORM set_config('test.crl_before', v.intent_id::text, true);

    -- Proposals record whether the signer had claimed the intent.
    SELECT * INTO v FROM propose_application_void_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_a')::uuid, 'signer unreachable', op,
        decode(repeat('66', 32), 'hex'));
    IF (v.status, v.signer_claimed, v.replayed) IS DISTINCT FROM ('RECONCILIATION_REQUIRED', false, false) THEN
        RAISE EXCEPTION 'proposal of A returned %', v;
    END IF;
    -- The same request replays; the key reused for another request is refused.
    SELECT * INTO w FROM propose_application_void_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_a')::uuid, 'signer unreachable', op,
        decode(repeat('66', 32), 'hex'));
    IF NOT w.replayed THEN RAISE EXCEPTION 'proposal replay not recognised'; END IF;
    PERFORM pg_temp.expect_state(pg_temp.propose('ra-1', current_setting('test.app_b'), op), 'TP409');
    -- One proposal per issuance.
    PERFORM pg_temp.expect_state(pg_temp.propose('ra-2', current_setting('test.app_a')), 'TP409');

    SELECT * INTO v FROM propose_application_void_lab('https://issuer.iss.invalid', 'ra-2',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_b')::uuid, 'signer crashed after claim',
        gen_random_uuid(), decode(repeat('66', 32), 'hex'));
    IF v.signer_claimed IS NOT TRUE THEN RAISE EXCEPTION 'B should record a signer claim'; END IF;

    -- The proposer cannot confirm; the requester cannot either.
    PERFORM pg_temp.expect_state(pg_temp.confirm('ra-1', current_setting('test.app_a')), '42501');
    PERFORM pg_temp.expect_state(pg_temp.confirm('req-1', current_setting('test.app_a')), '42501');

    -- A different officer confirms A; a replay returns the same instant.
    op := gen_random_uuid();
    SELECT * INTO v FROM confirm_application_void_lab('https://issuer.iss.invalid', 'ra-2',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_a')::uuid, 'no claim, no signature', op,
        decode(repeat('77', 32), 'hex'));
    IF v.status <> 'VOIDED' OR v.replayed OR v.voided_at IS NULL THEN RAISE EXCEPTION 'confirmation returned %', v; END IF;
    SELECT * INTO w FROM confirm_application_void_lab('https://issuer.iss.invalid', 'ra-2',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_a')::uuid, 'no claim, no signature', op,
        decode(repeat('77', 32), 'hex'));
    IF NOT w.replayed OR w.voided_at <> v.voided_at THEN RAISE EXCEPTION 'confirmation replay returned %', w; END IF;
    PERFORM pg_temp.expect_state(pg_temp.confirm('ra-2', current_setting('test.app_a')), 'TP409');
    PERFORM set_config('test.serial_a', encode(v.serial, 'hex'), true);

    -- A voided issuance cannot be voided again.
    PERFORM pg_temp.expect_state(pg_temp.propose('ra-1', current_setting('test.app_a')), 'TP409');
END $test$;
RESET ROLE;
DO $test$ BEGIN
    IF certificate_application_issuance_status(current_setting('test.app_a')::uuid) <> 'VOIDED'
       OR certificate_application_issuance_status(current_setting('test.app_b')::uuid) <> 'RECONCILIATION_REQUIRED' THEN
        RAISE EXCEPTION 'unexpected issuance statuses';
    END IF;
    -- The core request keeps its state: history is not rewritten.
    IF (SELECT r.state FROM certificate_request r JOIN certificate_application_issuance i
          ON i.ca_id = r.ca_id AND i.request_id = r.request_id
        WHERE i.application_id = current_setting('test.app_a')::uuid) <> 'RECONCILIATION_REQUIRED' THEN
        RAISE EXCEPTION 'the core request state changed';
    END IF;
END $test$;
SELECT set_config('test.serial_b', encode(s.serial_der_content, 'hex'), true)
FROM serial_reservation s JOIN certificate_application_issuance i ON i.ca_id = s.ca_id AND i.request_id = s.request_id
WHERE i.application_id = current_setting('test.app_b')::uuid;

-- The table is append-only apart from the single confirmation.
SELECT pg_temp.expect_state(format('UPDATE certificate_application_void SET signer_claimed = true WHERE application_id = %L',
    current_setting('test.app_a')), 'P0001');
SELECT pg_temp.expect_state(format('DELETE FROM certificate_application_void WHERE application_id = %L',
    current_setting('test.app_b')), 'P0001');

-- CRL entries: the intent fixed before the void lists nothing; one fixed
-- after lists A's serial without reason, and not B's unconfirmed one. The
-- API's function, the signer's view and the readers' count agree.
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    v record;
BEGIN
    SELECT * INTO v FROM begin_crl_publication_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('99', 32), 'hex'));
    PERFORM set_config('test.crl_after', v.intent_id::text, true);
END $test$;
RESET ROLE;
DO $test$
DECLARE
    seen text;
BEGIN
    IF EXISTS (SELECT 1 FROM crl_intent_entries(current_setting('test.crl_before')::uuid)) THEN
        RAISE EXCEPTION 'a CRL fixed before the void lists it';
    END IF;
    SELECT string_agg(encode(serial, 'hex') || '/' || reason_code, ',') INTO seen
      FROM crl_intent_entries(current_setting('test.crl_after')::uuid);
    IF seen IS DISTINCT FROM current_setting('test.serial_a') || '/0' THEN
        RAISE EXCEPTION 'CRL entries after the void: %', seen;
    END IF;
    SELECT string_agg(encode(serial, 'hex') || '/' || reason_code, ',') INTO seen
      FROM lab_signer_crl_entry WHERE intent_id = current_setting('test.crl_after');
    IF seen IS DISTINCT FROM current_setting('test.serial_a') || '/0' THEN
        RAISE EXCEPTION 'signer CRL entries after the void: %', seen;
    END IF;
END $test$;

-- Readers of the CA see the void state; others see nothing.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c');
SET LOCAL ROLE trust_api_reader;
DO $test$
DECLARE
    seen text;
BEGIN
    IF management_application_void_version() <> 1 THEN RAISE EXCEPTION 'unexpected void version'; END IF;
    IF EXISTS (SELECT 1 FROM management_certificate_application WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c') THEN
        RAISE EXCEPTION 'applications visible without a declared principal';
    END IF;
    PERFORM set_config('trust.reader_issuer', 'https://issuer.iss.invalid', true),
            set_config('trust.reader_subject', 'ra-1', true);
    SELECT string_agg(subject_cn || '=' || status || '/' || coalesce(void_status, '-') || '/'
                      || coalesce(void_signer_claimed::text, '-') || '/' || coalesce(void_proposed_by_reader::text, '-')
                      || '/' || coalesce(void_serial_hex, '-') || '/' || (voided_at IS NOT NULL)::text, ' ' ORDER BY subject_cn)
      INTO seen FROM management_certificate_application WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c';
    IF seen IS DISTINCT FROM format('a.lab.invalid=VOIDED/VOIDED/false/true/%s/true b.lab.invalid=RECONCILIATION_REQUIRED/PROPOSED/true/false/%s/false c.lab.invalid=ISSUED/-/-/-/-/false d.lab.invalid=APPROVED/-/-/-/-/false',
        current_setting('test.serial_a'), current_setting('test.serial_b')) THEN
        RAISE EXCEPTION 'reader sees %', seen;
    END IF;
END $test$;

ROLLBACK;
\echo 'PASS: dual-control void of ambiguous application issuance (0034)'
