-- Migration 0035: the crl-publisher role of the automatic CRL renewer. Run
-- as the migration owner after 0044 on a disposable database; every change
-- is rolled back. Since 0044 (ADR-0037) the renewer acts only from a worker
-- login (a direct member of trust_worker): the test uses one through
-- SET SESSION AUTHORIZATION. Placeholder bytes stand for the TBS and CRLs the API builds
-- and verifies. Before 0035 the first statement fails.
BEGIN;

SELECT crl_renewal_due('00000000-0000-4000-8000-000000000000');
CREATE ROLE trust_test_renewal_worker LOGIN;
GRANT trust_worker TO trust_test_renewal_worker;

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
    ('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c', 'registration-officer');

INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role) VALUES
    ('urn:trust-platform:system', 'crl-renewer', 'c5c5c5c5-0000-4000-8000-00000000000c', 'crl-publisher');

CREATE FUNCTION pg_temp.begin_as(p_issuer text, p_subject text) RETURNS text LANGUAGE sql AS $fn$
    SELECT format('SELECT * FROM begin_crl_publication_lab(%L, %L, %L, %L, %L)', p_issuer, p_subject,
        'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('44', 32), 'hex'))
$fn$;

-- The API's writer role can neither list candidates nor act as the renewer
-- (0044): the system principal needs a worker login.
SET LOCAL ROLE trust_profile_writer;
DO $test$ BEGIN
    PERFORM pg_temp.expect_state($$SELECT * FROM crl_renewal_candidates_lab('urn:trust-platform:system', 'crl-renewer')$$, '42501');
    PERFORM pg_temp.expect_state(pg_temp.begin_as('urn:trust-platform:system', 'crl-renewer'), '42501');
END $test$;
RESET ROLE;

SET LOCAL SESSION AUTHORIZATION trust_test_renewal_worker;

DO $test$
DECLARE
    r record;
BEGIN
    -- No CRL yet: the CA is due, and the renewer sees it as a candidate.
    IF (SELECT array_agg(ca_id) FROM crl_renewal_candidates_lab('urn:trust-platform:system', 'crl-renewer'))
       IS DISTINCT FROM ARRAY['c5c5c5c5-0000-4000-8000-00000000000c'::uuid] THEN
        RAISE EXCEPTION 'the CA is not a renewal candidate';
    END IF;
    -- Nobody else sees candidates, and an ungranted principal cannot publish.
    IF EXISTS (SELECT 1 FROM crl_renewal_candidates_lab('urn:trust-platform:system', 'someone-else')) THEN
        RAISE EXCEPTION 'candidates leaked to another principal';
    END IF;
    PERFORM pg_temp.expect_state(pg_temp.begin_as('urn:trust-platform:system', 'someone-else'), '42501');
    -- The renewer can neither issue nor decide.
    PERFORM pg_temp.expect_state(format('SELECT * FROM begin_application_issuance_lab(%L, %L, %L, %L, %L, %L)',
        'urn:trust-platform:system', 'crl-renewer', 'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid(),
        gen_random_uuid(), decode(repeat('55', 32), 'hex')), '42501');
    -- A worker login cannot publish as an officer (0044).
    PERFORM pg_temp.expect_state(pg_temp.begin_as('https://issuer.iss.invalid', 'ra-1'), '42501');

    -- It publishes the due CRL through the unchanged path.
    EXECUTE pg_temp.begin_as('urn:trust-platform:system', 'crl-renewer') INTO r;
    PERFORM set_config('test.intent', r.intent_id::text, true);
    PERFORM 1 FROM crl_publication_entries_lab('urn:trust-platform:system', 'crl-renewer',
        'c5c5c5c5-0000-4000-8000-00000000000c', r.intent_id);
    IF record_crl_signing_intent_lab('urn:trust-platform:system', 'crl-renewer', 'c5c5c5c5-0000-4000-8000-00000000000c',
        r.intent_id, digest('renewed-tbs', 'sha256')) THEN
        RAISE EXCEPTION 'first journal replayed';
    END IF;
END $test$;
RESET SESSION AUTHORIZATION;
SET LOCAL ROLE trust_lab_signer;
SELECT claim_lab_crl_intent(current_setting('test.intent')::uuid, digest('renewed-tbs', 'sha256'));
RESET ROLE;
SET LOCAL SESSION AUTHORIZATION trust_test_renewal_worker;
SELECT store_crl_lab('urn:trust-platform:system', 'crl-renewer', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.intent')::uuid, decode(repeat('e2', 200), 'hex'));

DO $test$ BEGIN
    -- Published with seven days ahead: no longer due. The renewer may not
    -- publish again; a registration officer still may.
    IF EXISTS (SELECT 1 FROM crl_renewal_candidates_lab('urn:trust-platform:system', 'crl-renewer')) THEN
        RAISE EXCEPTION 'a fresh CRL is still a renewal candidate';
    END IF;
    PERFORM pg_temp.expect_state(pg_temp.begin_as('urn:trust-platform:system', 'crl-renewer'), 'TP409');
END $test$;
RESET SESSION AUTHORIZATION;
SET LOCAL ROLE trust_profile_writer;
DO $test$ BEGIN
    PERFORM 1 FROM begin_crl_publication_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid(), decode(repeat('66', 32), 'hex'));
END $test$;
RESET ROLE;

-- Readers of the CA see that its CRL is renewed automatically.
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c');
SET LOCAL ROLE trust_api_reader;
DO $test$ BEGIN
    PERFORM set_config('trust.reader_issuer', 'https://issuer.iss.invalid', true),
            set_config('trust.reader_subject', 'ra-1', true);
    IF (SELECT auto_renewal FROM management_crl_status WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c') IS NOT TRUE THEN
        RAISE EXCEPTION 'auto_renewal is not reported';
    END IF;
END $test$;
RESET ROLE;

-- The renewal is attributed to the renewer in the audit trail.
DO $test$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM audit_event WHERE ca_id = 'c5c5c5c5-0000-4000-8000-00000000000c'
                   AND event_type = 'crl.published' AND actor_id = 'crl-renewer') THEN
        RAISE EXCEPTION 'the renewal is not attributed to the renewer';
    END IF;
    IF management_crl_renewal_version() <> 1 THEN RAISE EXCEPTION 'unexpected renewal version'; END IF;
END $test$;

ROLLBACK;
\echo 'PASS: automatic CRL renewal role (0035)'
