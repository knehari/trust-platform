-- Migration 0032: public CRL publication. Run as the migration owner after
-- 0032 on a disposable database; every change is rolled back. Placeholder
-- bytes stand for the TBS and CRLs the API builds and verifies. Before 0032
-- the first statement fails.
BEGIN;

SELECT 1 FROM ca_crl_distribution_point LIMIT 0;

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



-- Three approved applications by req-1.
SET LOCAL ROLE trust_profile_writer;
DO $setup$
DECLARE
    r record;
    names text[] := ARRAY['a', 'b', 'c'];
BEGIN
    FOR i IN 1..3 LOOP
        SELECT * INTO r FROM submit_certificate_application_lab('https://issuer.iss.invalid', 'req-1',
            'c5c5c5c5-0000-4000-8000-00000000000c', 'server', decode(repeat('3' || i, 200), 'hex'),
            digest('key-' || i, 'sha256'), names[i] || '.lab.invalid', ARRAY[names[i] || '.lab.invalid'], 30,
            gen_random_uuid(), digest(names[i], 'sha256'));
        PERFORM set_config('test.app_' || names[i], r.application_id::text, true);
        PERFORM decide_certificate_application_lab('https://issuer.iss.invalid', 'ra-1',
            'c5c5c5c5-0000-4000-8000-00000000000c', r.application_id, 'approve', 'checked', gen_random_uuid(),
            digest(names[i], 'sha256'));
    END LOOP;
END $setup$;

CREATE FUNCTION pg_temp.journal(p_app text) RETURNS uuid LANGUAGE plpgsql AS $fn$
DECLARE r record;
BEGIN
    PERFORM begin_application_issuance_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
        p_app::uuid, gen_random_uuid(), digest(p_app, 'sha256'));
    SELECT * INTO r FROM record_application_signing_intent_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', p_app::uuid, 'lab-signer:c5', digest('tbs-' || p_app, 'sha256'));
    RETURN r.intent_id;
END
$fn$;
CREATE FUNCTION pg_temp.publish_crl(p_tbs text) RETURNS void LANGUAGE plpgsql AS $fn$
DECLARE r record;
BEGIN
    SELECT * INTO r FROM begin_crl_publication_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', gen_random_uuid(), digest(p_tbs, 'sha256'));
    PERFORM record_crl_signing_intent_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
        r.intent_id, digest(p_tbs, 'sha256'));
    PERFORM set_config('test.crl_intent', r.intent_id::text, true);
END
$fn$;

-- Readers of the CA: no CRL yet means renewal is due, nothing expired.
RESET ROLE;
INSERT INTO management_reader_grant (issuer, subject, ca_id) VALUES
    ('https://issuer.iss.invalid', 'reader', 'c5c5c5c5-0000-4000-8000-00000000000c');
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.iss.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT coalesce(distribution_point, '-') || ':' || coalesce(latest_crl_number::text, '-') || ':' || renewal_due
               || ':' || expired FROM management_crl_status) <> '-:-:true:false' THEN
        RAISE EXCEPTION 'unexpected initial CRL status';
    END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;

-- The writer and the reader read no new table; the writer cannot record a
-- distribution point.
SELECT pg_temp.expect_state('SELECT 1 FROM ca_crl_distribution_point', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM signing_intent_crl_distribution_point', '42501');
SELECT pg_temp.expect_state($q$INSERT INTO ca_crl_distribution_point (ca_id, base_url)
    VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'http://crl.lab.invalid')$q$, '42501');

-- Before publication: no distribution point in intents, nothing public.
DO $test$ BEGIN
    PERFORM set_config('test.intent_a', pg_temp.journal(current_setting('test.app_a'))::text, true);
    IF application_crl_distribution_point_lab('https://issuer.iss.invalid', 'req-1',
           'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_a')::uuid) IS NOT NULL THEN
        RAISE EXCEPTION 'a distribution point without publication';
    END IF;
END $test$;
SELECT pg_temp.publish_crl('crl-1');
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
SELECT claim_lab_crl_intent(current_setting('test.crl_intent')::uuid, digest('crl-1', 'sha256'));
DO $test$ BEGIN
    IF (SELECT crl_distribution_point FROM lab_signer_intent WHERE intent_id = current_setting('test.intent_a')) IS NOT NULL THEN
        RAISE EXCEPTION 'the signer sees a distribution point that was never recorded';
    END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT store_crl_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.crl_intent')::uuid, decode(repeat('e1', 200), 'hex'));
RESET ROLE;
-- The public view is read as the owner: since migration 0043 only the
-- separate publisher reads CRLs for publication (crl_publisher_feed).
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM public_crl_latest) THEN RAISE EXCEPTION 'an unpublished CA has a public CRL'; END IF;
END $test$;
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state('SELECT 1 FROM ca_crl_distribution_point', '42501');
SELECT pg_temp.expect_state('SELECT 1 FROM crl_document', '42501');
RESET ROLE;

-- Only http(s) base URLs with a lowercase host and an optional port.
SELECT pg_temp.expect_state(format($q$INSERT INTO ca_crl_distribution_point (ca_id, base_url) VALUES (%L, %L)$q$,
    'c5c5c5c5-0000-4000-8000-00000000000c', u), '23514')
FROM unnest(ARRAY['ftp://crl.lab.invalid', 'http://user:pw@crl.lab.invalid', 'http://crl.lab.invalid/path',
    'http://crl.lab.invalid?x=1', 'http://CRL.lab.invalid', 'http://crl.lab.invalid:', 'https://crl.lab.invalid/',
    'http://-crl.lab.invalid', 'http://crl.lab.invalid#f', 'http://' || repeat('a', 200) || '.invalid', 'crl.lab.invalid']) u;
INSERT INTO ca_crl_distribution_point (ca_id, base_url)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'http://crl.lab.invalid:8081');
SELECT pg_temp.expect_state($q$INSERT INTO ca_crl_distribution_point (ca_id, base_url)
    VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 'https://other.lab.invalid')$q$, '23505');
SELECT pg_temp.expect_state($q$UPDATE ca_crl_distribution_point SET base_url = 'https://other.lab.invalid'$q$, 'P0001');
SELECT pg_temp.expect_state($q$DELETE FROM ca_crl_distribution_point$q$, 'P0001');

-- After: the issuance callers read the URL; intents snapshot it once.
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state(format('SELECT application_crl_distribution_point_lab(%L, %L, %L, %L)',
    'https://issuer.iss.invalid', 'req-2', 'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_b')), '42501');
DO $test$
DECLARE
    url text := 'http://crl.lab.invalid:8081/v1/public/crls/c5c5c5c5-0000-4000-8000-00000000000c/latest.crl';
    r record;
BEGIN
    IF application_crl_distribution_point_lab('https://issuer.iss.invalid', 'req-1',
           'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_b')::uuid) IS DISTINCT FROM url THEN
        RAISE EXCEPTION 'unexpected distribution point';
    END IF;
    PERFORM set_config('test.intent_b', pg_temp.journal(current_setting('test.app_b'))::text, true);
    -- A replayed journal records nothing more.
    SELECT * INTO r FROM record_application_signing_intent_lab('https://issuer.iss.invalid', 'ra-1',
        'c5c5c5c5-0000-4000-8000-00000000000c', current_setting('test.app_b')::uuid, 'lab-signer:c5',
        digest('tbs-other', 'sha256'));
    IF NOT r.replayed OR r.intent_id::text <> current_setting('test.intent_b') THEN
        RAISE EXCEPTION 'replayed journal: %', r;
    END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
DO $test$ BEGIN
    IF (SELECT crl_distribution_point FROM lab_signer_intent WHERE intent_id = current_setting('test.intent_b'))
       IS DISTINCT FROM 'http://crl.lab.invalid:8081/v1/public/crls/c5c5c5c5-0000-4000-8000-00000000000c/latest.crl'
       OR (SELECT crl_distribution_point FROM lab_signer_intent WHERE intent_id = current_setting('test.intent_a')) IS NOT NULL THEN
        RAISE EXCEPTION 'unexpected snapshots in the signer view';
    END IF;
    IF NOT (SELECT signable FROM lab_signer_intent WHERE intent_id = current_setting('test.intent_b')) THEN
        RAISE EXCEPTION 'the journaled intent is no longer signable';
    END IF;
END $test$;
RESET ROLE;
DO $test$ BEGIN
    IF (SELECT count(*) FROM signing_intent_crl_distribution_point) <> 1 THEN
        RAISE EXCEPTION 'unexpected number of snapshots';
    END IF;
END $test$;
SELECT pg_temp.expect_state($q$UPDATE signing_intent_crl_distribution_point SET url = 'http://evil.invalid'$q$, 'P0001');

-- Public: the latest CRL of a published CA only, without a principal.
DO $test$ BEGIN
    IF (SELECT string_agg(ca_id || ':' || crl_number || ':' || octet_length(crl_der), ',') FROM public_crl_latest)
       <> 'c5c5c5c5-0000-4000-8000-00000000000c:1:200' THEN
        RAISE EXCEPTION 'unexpected public CRL';
    END IF;
END $test$;
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.publish_crl('crl-2');
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
SELECT claim_lab_crl_intent(current_setting('test.crl_intent')::uuid, digest('crl-2', 'sha256'));
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT store_crl_lab('https://issuer.iss.invalid', 'ra-1', 'c5c5c5c5-0000-4000-8000-00000000000c',
    current_setting('test.crl_intent')::uuid, decode(repeat('e2', 201), 'hex'));
-- A later, unpublished intent does not change what is public.
SELECT pg_temp.publish_crl('crl-3');
RESET ROLE;
DO $test$ BEGIN
    IF (SELECT string_agg(crl_number || ':' || octet_length(crl_der), ',') FROM public_crl_latest) <> '2:201' THEN
        RAISE EXCEPTION 'the public CRL is not the latest published one';
    END IF;
END $test$;
SET LOCAL ROLE trust_api_reader;

-- Readers of the CA see the distribution point and the renewal state;
-- others see nothing.
RESET ROLE;
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_issuer', 'https://issuer.iss.invalid', true),
       set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT distribution_point || ':' || latest_crl_number || ':' || renewal_due || ':' || expired
               || ':' || (next_update::timestamptz > now() + interval '6 days')
        FROM management_crl_status) <> 'http://crl.lab.invalid:8081/v1/public/crls/c5c5c5c5-0000-4000-8000-00000000000c/latest.crl:2:false:false:true' THEN
        RAISE EXCEPTION 'unexpected CRL status: %', (SELECT row_to_json(s) FROM management_crl_status s);
    END IF;
    IF management_crl_publication_version() <> 1 THEN RAISE EXCEPTION 'marker'; END IF;
END $test$;
SELECT set_config('trust.reader_subject', 'nobody', true);
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_crl_status) THEN RAISE EXCEPTION 'an ungranted reader sees CRL status'; END IF;
END $test$;
RESET ROLE;

-- A latest CRL close to, or past, its nextUpdate is due (owner fixtures
-- standing for CRLs published earlier): first one due tomorrow.
INSERT INTO crl_signing_intent (ca_id, crl_number, entries_until, this_update, next_update, tbs_sha256, outcome,
    operation_id, request_sha256, actor_issuer, actor_subject)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 9, now() - interval '6 days', date_trunc('second', now() - interval '6 days'),
    date_trunc('second', now() + interval '1 day'), digest('due', 'sha256'), 'PUBLISHED', gen_random_uuid(),
    digest('due', 'sha256'), 'owner', 'owner');
INSERT INTO crl_publication (ca_id, crl_number, this_update, next_update, crl_sha256, published_at)
SELECT ca_id, crl_number, this_update, next_update, digest('due', 'sha256'), now() FROM crl_signing_intent WHERE crl_number = 9;
INSERT INTO crl_document (ca_id, crl_number, intent_id, crl_der)
SELECT ca_id, crl_number, intent_id, decode(repeat('e4', 202), 'hex') FROM crl_signing_intent WHERE crl_number = 9;
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT latest_crl_number || ':' || renewal_due || ':' || expired FROM management_crl_status) <> '9:true:false' THEN
        RAISE EXCEPTION 'a CRL due tomorrow is not reported as due';
    END IF;
END $test$;
RESET ROLE;
INSERT INTO crl_signing_intent (ca_id, crl_number, entries_until, this_update, next_update, tbs_sha256, outcome,
    operation_id, request_sha256, actor_issuer, actor_subject)
VALUES ('c5c5c5c5-0000-4000-8000-00000000000c', 10, now() - interval '8 days', date_trunc('second', now() - interval '8 days'),
    date_trunc('second', now() - interval '1 day'), digest('old', 'sha256'), 'PUBLISHED', gen_random_uuid(),
    digest('old', 'sha256'), 'owner', 'owner');
INSERT INTO crl_publication (ca_id, crl_number, this_update, next_update, crl_sha256, published_at)
SELECT ca_id, crl_number, this_update, next_update, digest('old', 'sha256'), now() FROM crl_signing_intent WHERE crl_number = 10;
INSERT INTO crl_document (ca_id, crl_number, intent_id, crl_der)
SELECT ca_id, crl_number, intent_id, decode(repeat('e3', 202), 'hex') FROM crl_signing_intent WHERE crl_number = 10;
SET LOCAL ROLE trust_api_reader;
SELECT set_config('trust.reader_subject', 'reader', true);
DO $test$ BEGIN
    IF (SELECT latest_crl_number || ':' || renewal_due || ':' || expired FROM management_crl_status) <> '10:true:true' THEN
        RAISE EXCEPTION 'an expired CRL is not reported';
    END IF;
END $test$;
RESET ROLE;

ROLLBACK;
\echo 'PASS: owner-set distribution points are snapshotted with intents, the latest published CRL is public, and renewal is reported'
