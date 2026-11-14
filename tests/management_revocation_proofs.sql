-- Migration 0042: signed proofs for CRL entries (ADR-0029). Run as the
-- migration owner after 0042 on a disposable database; every change is rolled
-- back. Signatures are placeholders: PostgreSQL verifies no ECDSA (the API, the
-- signer and lab_verify_issued_certificates do). Before 0042 the first
-- statement fails.
BEGIN;

SELECT management_revocation_proofs_version();


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

RESET ROLE;

-- Officer keys for ra-1 and ra-2; req-1 holds an officer grant and a key too.
INSERT INTO registration_officer_key (key_id, issuer, subject, public_key_sec1) VALUES
    ('officer-1', 'https://issuer.iss.invalid', 'ra-1', decode('04' || repeat('c1', 64), 'hex')),
    ('officer-2', 'https://issuer.iss.invalid', 'ra-2', decode('04' || repeat('c2', 64), 'hex')),
    ('requester-officer', 'https://issuer.iss.invalid', 'req-1', decode('04' || repeat('c3', 64), 'hex'));

-- The claim texts have the layout of trust_pki_core::authorization.
DO $test$ BEGIN
    IF lab_claim_instant('2026-11-11T09:00:00Z') <> '2026-11-11T09:00:00.000Z' THEN
        RAISE EXCEPTION 'claim instant format';
    END IF;
END $test$;

-- req-1 asks to revoke C; the requester cannot decide, even signed.
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    r record;
BEGIN
    SELECT * INTO r FROM request_certificate_revocation_lab('https://issuer.iss.invalid', 'req-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_c')::uuid, 1::smallint, 'key leaked',
        gen_random_uuid(), digest('revoke-c', 'sha256'));
    PERFORM set_config('test.revocation', r.revocation_id::text, true);
END $test$;
RESET ROLE;
-- The serials, read as the owner: the writer cannot read the tables.
SELECT set_config('test.serial_c', encode(q.serial_der_content, 'hex'), true)
FROM certificate_revocation_request q WHERE q.revocation_id = current_setting('test.revocation')::uuid;
SELECT set_config('test.serial_a', encode(s.serial_der_content, 'hex'), true)
FROM certificate_application_issuance i
JOIN serial_reservation s ON s.ca_id = i.ca_id AND s.request_id = i.request_id
WHERE i.application_id = current_setting('test.app_a')::uuid;
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM certificate_revocation_authorization$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_crl_entry_proof$$, '42501');
SELECT pg_temp.expect_state(format('SELECT * FROM prepare_revocation_decision_lab(%L, %L, %L, %L, %L, %L)',
    'https://issuer.iss.invalid', 'ra-2', 'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_c'),
    current_setting('test.revocation'), 'approve'), '42501');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM certificate_revocation_authorization$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_crl_entry_proof$$, '42501');
DO $test$
DECLARE
    iss text := 'https://issuer.iss.invalid';
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    app uuid := current_setting('test.app_c')::uuid;
    rev uuid := current_setting('test.revocation')::uuid;
    p record;
    d record;
    op uuid := gen_random_uuid();
    sig bytea := decode(repeat('30', 70), 'hex');
    expected text;
BEGIN
    -- Without a key, a grant, or for another decision: refused.
    BEGIN
        PERFORM * FROM prepare_revocation_decision_lab(iss, 'req-2', c, app, rev, 'approve');
        RAISE EXCEPTION 'a requester without an officer grant prepared a claim';
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
    BEGIN
        PERFORM * FROM prepare_revocation_decision_lab(iss, 'ra-2', c, app, rev, 'revoke');
        RAISE EXCEPTION 'an unknown decision was prepared';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;
    BEGIN
        PERFORM * FROM prepare_revocation_decision_lab(iss, 'ra-2', c, app, gen_random_uuid(), 'approve');
        RAISE EXCEPTION 'a claim for an unknown revocation';
    EXCEPTION WHEN no_data_found THEN NULL; END;

    SELECT * INTO p FROM prepare_revocation_decision_lab(iss, 'ra-2', c, app, rev, 'approve');
    expected := format('trust-platform/revocation-authorization/v1;decision=approve;ca=%s;application=%s;revocation=%s;serial=%s;reason_code=1;key=officer-2;issued_at=%s',
        c, app, rev, current_setting('test.serial_c'), p.issued_at);
    IF p.claim IS DISTINCT FROM expected OR p.key_id <> 'officer-2' THEN
        RAISE EXCEPTION 'revocation claim %', p.claim;
    END IF;

    -- The requester holds a key and a grant, and still cannot decide.
    BEGIN
        PERFORM * FROM record_signed_revocation_decision_lab(iss, 'req-1', c, app, rev, 'approve', 'self',
            clock_timestamp(), sig, gen_random_uuid(), digest('self', 'sha256'));
        RAISE EXCEPTION 'the requester decided';
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
    -- A stale claim: nothing recorded.
    BEGIN
        PERFORM * FROM record_signed_revocation_decision_lab(iss, 'ra-2', c, app, rev, 'approve', 'stale',
            clock_timestamp() - interval '11 minutes', sig, gen_random_uuid(), digest('stale', 'sha256'));
        RAISE EXCEPTION 'a stale claim was recorded';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL; END;

    SELECT * INTO d FROM record_signed_revocation_decision_lab(iss, 'ra-2', c, app, rev, 'approve', 'confirmed',
        p.issued_at::timestamptz, sig, op, digest('approve-c', 'sha256'));
    IF d.status <> 'REVOKED' OR d.replayed OR d.claim <> p.claim OR d.public_key_sec1 <> decode('04' || repeat('c2', 64), 'hex')
       OR d.revoked_at IS NULL THEN
        RAISE EXCEPTION 'signed revocation %', row_to_json(d);
    END IF;
    SELECT * INTO d FROM record_signed_revocation_decision_lab(iss, 'ra-2', c, app, rev, 'approve', 'confirmed',
        p.issued_at::timestamptz, sig, op, digest('approve-c', 'sha256'));
    IF NOT d.replayed OR d.claim <> p.claim THEN
        RAISE EXCEPTION 'replay %', row_to_json(d);
    END IF;
    BEGIN
        PERFORM * FROM record_signed_revocation_decision_lab(iss, 'ra-2', c, app, rev, 'reject', 'again',
            clock_timestamp(), sig, gen_random_uuid(), digest('again', 'sha256'));
        RAISE EXCEPTION 'decided twice';
    EXCEPTION WHEN SQLSTATE 'TP409' THEN NULL; END;
END $test$;

-- ra-1 proposes to void A; ra-1 cannot confirm; ra-2 confirms with a signature.
DO $test$
DECLARE
    iss text := 'https://issuer.iss.invalid';
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    app uuid := current_setting('test.app_a')::uuid;
    p record;
    d record;
    sig bytea := decode(repeat('30', 70), 'hex');
BEGIN
    BEGIN
        PERFORM * FROM prepare_void_confirmation_lab(iss, 'ra-2', c, app);
        RAISE EXCEPTION 'a claim without a proposed void';
    EXCEPTION WHEN no_data_found THEN NULL; END;
    PERFORM propose_application_void_lab(iss, 'ra-1', c, app, 'signer timed out', gen_random_uuid(), digest('pa', 'sha256'));
    SELECT * INTO p FROM prepare_void_confirmation_lab(iss, 'ra-2', c, app);
    IF p.claim IS DISTINCT FROM format('trust-platform/void-authorization/v1;ca=%s;application=%s;serial=%s;signer_claimed=false;key=officer-2;issued_at=%s',
        c, app, current_setting('test.serial_a'), p.issued_at) THEN
        RAISE EXCEPTION 'void claim %', p.claim;
    END IF;
    BEGIN
        PERFORM * FROM record_signed_void_confirmation_lab(iss, 'ra-1', c, app, 'own', clock_timestamp(), sig,
            gen_random_uuid(), digest('own', 'sha256'));
        RAISE EXCEPTION 'the proposer confirmed';
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
    SELECT * INTO d FROM record_signed_void_confirmation_lab(iss, 'ra-2', c, app, 'no claim recorded',
        p.issued_at::timestamptz, sig, gen_random_uuid(), digest('confirm-a', 'sha256'));
    IF d.status <> 'VOIDED' OR d.claim <> p.claim OR d.replayed THEN
        RAISE EXCEPTION 'signed void %', row_to_json(d);
    END IF;
    IF encode(d.serial, 'hex') <> current_setting('test.serial_a') THEN
        RAISE EXCEPTION 'voided serial %', encode(d.serial, 'hex');
    END IF;
END $test$;
RESET ROLE;

-- A revocation recorded before the proof requirement (owner fixture, an older
-- instant): listed, marked legacy, without a proof.
INSERT INTO certificate_request (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
VALUES ('7e7e7e7e-0000-4000-8000-000000000001', 'c5c5c5c5-0000-4000-8000-00000000000c', 'legacy',
        decode(repeat('7e', 32), 'hex'), 'legacy-fixture', 'v1', 'SIGNED');
INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', decode('7e01', 'hex'), '7e7e7e7e-0000-4000-8000-000000000001');
INSERT INTO certificate (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at, subject_cn)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', decode('7e01', 'hex'), '7e7e7e7e-0000-4000-8000-000000000001',
        decode(repeat('7f', 32), 'hex'), decode('3000', 'hex'), '2026-10-01T12:00:00Z', 'legacy.lab.invalid');
INSERT INTO revocation (ca_id, serial_der_content, reason_code, revoked_at, actor_id)
SELECT 'c5c5c5c5-0000-4000-8000-00000000000c', decode('7e01', 'hex'), 4,
       p.required_since - interval '1 day', 'legacy-fixture'
FROM crl_entry_proof_policy p;

-- The signer's view: every entry with its proof and key.
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    v record;
BEGIN
    SELECT * INTO v FROM begin_crl_publication_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('98', 32), 'hex'));
    PERFORM set_config('test.crl', v.intent_id::text, true);
END $test$;
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
SELECT pg_temp.expect_state($$SELECT * FROM certificate_revocation_authorization$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM certificate_void_authorization$$, '42501');
DO $test$
DECLARE
    seen text;
BEGIN
    IF management_revocation_proofs_version() <> 1 THEN RAISE EXCEPTION 'version'; END IF;
    SELECT string_agg(kind || '/' || encode(serial, 'hex') || '/' || reason_code || '/' || legacy || '/'
                      || coalesce(officer_decision, '-') || '/' || coalesce(officer_key_id, '-') || '/'
                      || coalesce(officer_key_valid::text, '-') || '/' || coalesce(void_signer_claimed::text, '-') || '/'
                      || (officer_signature IS NOT NULL) || '/' || coalesce(ra_id, '-'), ' ' ORDER BY legacy, kind)
      INTO seen FROM lab_signer_crl_entry_proof WHERE intent_id = current_setting('test.crl');
    IF seen IS DISTINCT FROM format('revocation/%s/1/false/approve/officer-2/true/-/true/- void/%s/0/false/approve/officer-2/true/false/true/- revocation/7e01/4/true/-/-/false/-/false/-',
        current_setting('test.serial_c'), current_setting('test.serial_a')) THEN
        RAISE EXCEPTION 'signer sees %', seen;
    END IF;
END $test$;
RESET ROLE;

-- A key revoked after its claim still counts for what it signed; one revoked
-- before would not.
UPDATE registration_officer_key SET revoked_at = clock_timestamp() + interval '1 second' WHERE key_id = 'officer-2';
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM lab_signer_crl_entry_proof WHERE intent_id = current_setting('test.crl')
               AND officer_key_id = 'officer-2' AND NOT officer_key_valid) THEN
        RAISE EXCEPTION 'a key revoked after its claim unlisted an entry';
    END IF;
END $test$;
RESET ROLE;

-- Proofs are immutable, and so is the requirement.
SELECT pg_temp.expect_state($$UPDATE certificate_revocation_authorization SET decision = 'reject'$$, 'P0001');
SELECT pg_temp.expect_state($$DELETE FROM certificate_void_authorization$$, 'P0001');
SELECT pg_temp.expect_state($$UPDATE crl_entry_proof_policy SET required_since = clock_timestamp()$$, 'P0001');
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$INSERT INTO certificate_revocation_authorization VALUES (gen_random_uuid())$$, '42501');
RESET ROLE;

ROLLBACK;
\echo 'PASS: signed proofs for CRL entries (0042)'
