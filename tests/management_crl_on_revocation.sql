-- Migration 0040: publish a CRL as soon as a revocation is recorded, per CA
-- (ADR-0027). Run as the migration owner after 0040 on a disposable database;
-- every change is rolled back. CRL bytes are placeholders. Before 0040 the
-- first statement fails.
BEGIN;

SELECT management_crl_on_revocation_version();

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
RESET ROLE;

-- Publishes the next CRL as officer ra-1, through the journaled path.
CREATE FUNCTION pg_temp.publish(p_tag text, p_issuer text DEFAULT 'https://issuer.iss.invalid',
                                p_subject text DEFAULT 'ra-1') RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    r record;
BEGIN
    SELECT * INTO r FROM begin_crl_publication_lab(p_issuer, p_subject, c, gen_random_uuid(), digest(p_tag, 'sha256'));
    PERFORM record_crl_signing_intent_lab(p_issuer, p_subject, c, r.intent_id, digest('tbs-' || p_tag, 'sha256'));
    PERFORM claim_lab_crl_intent(r.intent_id, digest('tbs-' || p_tag, 'sha256'));
    PERFORM store_crl_lab(p_issuer, p_subject, c, r.intent_id, decode(repeat('e1', 200), 'hex'));
END
$fn$;
-- Revokes application `p_name` (requested by req-1, approved by ra-2).
CREATE FUNCTION pg_temp.revoke(p_name text) RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
    app uuid := current_setting('test.app_' || p_name)::uuid;
    r record;
BEGIN
    SELECT * INTO r FROM request_certificate_revocation_lab('https://issuer.iss.invalid', 'req-1', c, app,
        1::smallint, 'compromised', gen_random_uuid(), digest('rq-' || p_name, 'sha256'));
    PERFORM decide_certificate_revocation_lab('https://issuer.iss.invalid', 'ra-2', c, app, r.revocation_id,
        'approve', 'checked', gen_random_uuid(), digest('dc-' || p_name, 'sha256'));
END
$fn$;
INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('urn:trust-platform:system', 'crl-renewer', 'c5c5c5c5-0000-4000-8000-00000000000c', 'crl-publisher');
INSERT INTO management_reader_grant (issuer, subject, ca_id)
VALUES ('https://issuer.iss.invalid', 'reader', 'c5c5c5c5-0000-4000-8000-00000000000c');

DO $test$
DECLARE
    c uuid := 'c5c5c5c5-0000-4000-8000-00000000000c';
BEGIN
    -- No CRL yet: due by time, whatever the setting.
    IF NOT crl_renewal_due(c) THEN RAISE EXCEPTION 'a CA without CRL must be due'; END IF;
    PERFORM pg_temp.publish('first');
    IF crl_renewal_due(c) OR crl_unpublished_entries(c) <> 0 THEN
        RAISE EXCEPTION 'a fresh CRL with nothing new must not be due';
    END IF;
    -- Off (the default): a revocation waits for the time-based renewal.
    PERFORM pg_temp.revoke('a');
    IF crl_unpublished_entries(c) <> 1 OR crl_renewal_due(c) THEN
        RAISE EXCEPTION 'without the setting, a revocation must not make the CRL due';
    END IF;
    IF EXISTS (SELECT 1 FROM crl_renewal_candidates_lab('urn:trust-platform:system', 'crl-renewer')) THEN
        RAISE EXCEPTION 'the renewer must have nothing to do';
    END IF;
    -- On: the pending revocation makes the CRL due, for the renewer too.
    INSERT INTO ca_crl_policy (ca_id, publish_on_revocation) VALUES (c, true);
    IF NOT crl_renewal_due(c) OR (SELECT array_agg(ca_id) FROM crl_renewal_candidates_lab(
            'urn:trust-platform:system', 'crl-renewer')) IS DISTINCT FROM ARRAY[c] THEN
        RAISE EXCEPTION 'with the setting, a pending revocation must make the CRL due';
    END IF;
    -- The renewer publishes it through the journaled path; the new CRL lists
    -- the revocation, and nothing is pending any more.
    PERFORM pg_temp.publish('renewed', 'urn:trust-platform:system', 'crl-renewer');
    IF crl_unpublished_entries(c) <> 0 OR crl_renewal_due(c) THEN
        RAISE EXCEPTION 'after publication nothing must be pending';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM crl_document d JOIN crl_signing_intent i ON i.intent_id = d.intent_id
                   JOIN LATERAL crl_intent_entries(i.intent_id) e ON true
                   WHERE d.ca_id = c AND d.crl_number = 2
                     AND e.serial = decode(current_setting('test.serial_a'), 'hex')) THEN
        RAISE EXCEPTION 'the renewed CRL does not list the revocation';
    END IF;
    -- Without anything pending the renewer is refused again.
    PERFORM pg_temp.expect_state(format('SELECT * FROM begin_crl_publication_lab(%L, %L, %L, %L, %L)',
        'urn:trust-platform:system', 'crl-renewer', c, gen_random_uuid(), digest('again', 'sha256')), 'TP409');
    -- A second revocation is pending again.
    PERFORM pg_temp.revoke('b');
    IF crl_unpublished_entries(c) <> 1 OR NOT crl_renewal_due(c) THEN
        RAISE EXCEPTION 'a new revocation must make the CRL due again';
    END IF;
    -- Turned off, it waits for the time-based renewal.
    UPDATE ca_crl_policy SET publish_on_revocation = false, updated_at = clock_timestamp() WHERE ca_id = c;
    IF crl_renewal_due(c) THEN RAISE EXCEPTION 'the setting no longer applies'; END IF;
    UPDATE ca_crl_policy SET publish_on_revocation = true, updated_at = clock_timestamp() WHERE ca_id = c;
END $test$;

-- Readers see the setting and the pending count of their CA only.
SET LOCAL ROLE trust_api_reader;
SET LOCAL trust.reader_issuer = 'https://issuer.iss.invalid';
SET LOCAL trust.reader_subject = 'reader';
DO $test$
DECLARE
    s record;
BEGIN
    SELECT * INTO s FROM management_crl_status WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c';
    IF NOT s.publish_on_revocation OR s.unpublished_entries <> 1 OR s.latest_crl_number <> 2 OR NOT s.auto_renewal THEN
        RAISE EXCEPTION 'unexpected CRL status %', s;
    END IF;
    IF (SELECT count(*) FROM management_crl_status) <> 1 THEN
        RAISE EXCEPTION 'readers see other CAs';
    END IF;
    IF management_crl_on_revocation_version() <> 1 THEN RAISE EXCEPTION 'unexpected version'; END IF;
END $test$;
RESET ROLE;
-- The writer cannot change the setting; only the owner can.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$UPDATE ca_crl_policy SET publish_on_revocation = false$$, '42501');
RESET ROLE;

ROLLBACK;
\echo 'PASS: CRL publication on revocation (0040)'
