-- Lab-only: officer credential registry (migration 0028, ADR-0007 step 1).
-- Enrolment and removal need two distinct CA admins approving the exact
-- content digest; one key never serves two credentials, one person never
-- holds two officer identities on a CA, admins never change their own
-- credentials, and the registry is append-only. Keys are canonicalised and
-- curve-checked by the Rust core (tests in revocation_crl_postgres.rs);
-- here they are opaque 33-byte compressed points.
-- Single transaction, rolled back. Run as a superuser.
\set ON_ERROR_STOP 1
BEGIN;

CREATE FUNCTION pg_temp.expect_err(p_sql TEXT, p_state TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE <> p_state THEN
            RAISE EXCEPTION 'expected SQLSTATE % but got % (%) for: %',
                p_state, SQLSTATE, SQLERRM, p_sql;
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'expected SQLSTATE % but statement succeeded: %', p_state, p_sql;
END $f$;

CREATE FUNCTION pg_temp.must(p_ok BOOLEAN, p_what TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    IF p_ok IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'assertion failed: %', p_what;
    END IF;
END $f$;

CREATE TEMP TABLE t (k TEXT PRIMARY KEY, v TEXT);
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('5eedc0de-0000-4000-8000-000000000028', 'Credential CA', 'v1');
INSERT INTO ca_admin_grant(issuer, subject, ca_id) VALUES
    ('https://idp.lab.invalid', 'admin-a', '5eedc0de-0000-4000-8000-000000000028'),
    ('https://idp.lab.invalid', 'admin-b', '5eedc0de-0000-4000-8000-000000000028');
INSERT INTO revocation_officer_grant(issuer, subject, ca_id) VALUES
    ('https://idp.lab.invalid', 'maker', '5eedc0de-0000-4000-8000-000000000028'),
    ('https://idp.lab.invalid', 'checker', '5eedc0de-0000-4000-8000-000000000028'),
    ('https://idp.lab.invalid', 'admin-b', '5eedc0de-0000-4000-8000-000000000028');

-- propose(kind, credential byte, officer, person, key byte) as admin-a.
CREATE FUNCTION pg_temp.propose(p_kind TEXT, p_cred INT, p_officer TEXT, p_person TEXT,
                                p_key INT, p_maker TEXT DEFAULT 'admin-a') RETURNS UUID
LANGUAGE sql AS $f$
    SELECT propose_credential_change('5eedc0de-0000-4000-8000-000000000028', p_kind,
        decode(repeat(lpad(to_hex(p_cred), 2, '0'), 16), 'hex'),
        'https://idp.lab.invalid', p_officer, p_person,
        CASE WHEN p_key IS NULL THEN NULL
             ELSE '\x02'::bytea || decode(repeat(lpad(to_hex(p_key), 2, '0'), 32), 'hex') END,
        'https://idp.lab.invalid', p_maker)
$f$;
CREATE FUNCTION pg_temp.approve(p_change UUID, p_checker TEXT DEFAULT 'admin-b') RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT approve_credential_change(p_change, 'https://idp.lab.invalid', p_checker,
        (SELECT content_sha256 FROM officer_credential_change WHERE change_id = p_change))
$f$;

-- Input validation (fail closed).
SELECT pg_temp.expect_err($$SELECT propose_credential_change('5eedc0de-0000-4000-8000-000000000028',
    'ENROLL_CREDENTIAL', '\x01'::bytea, 'https://idp.lab.invalid', 'maker', 'p1',
    '\x02'::bytea || decode(repeat('11', 32), 'hex'), 'https://idp.lab.invalid', 'admin-a')$$, '22023');
SELECT pg_temp.expect_err($$SELECT propose_credential_change('5eedc0de-0000-4000-8000-000000000028',
    'ENROLL_CREDENTIAL', decode(repeat('01', 16), 'hex'), 'https://idp.lab.invalid', 'maker', 'p1',
    '\x04'::bytea || decode(repeat('11', 64), 'hex'), 'https://idp.lab.invalid', 'admin-a')$$, '22023');
SELECT pg_temp.expect_err($$SELECT pg_temp.propose('REMOVE_CREDENTIAL', 1, 'maker', 'p1', 17)$$, '22023');
SELECT pg_temp.expect_err($$SELECT pg_temp.propose('ENROLL_CREDENTIAL', 1, 'maker', 'p1', 17, 'maker')$$, '42501');

-- Enrol maker's first credential: the digest is the length-prefixed content.
INSERT INTO t VALUES ('c1', pg_temp.propose('ENROLL_CREDENTIAL', 1, 'maker', 'person-1', 17));
SELECT pg_temp.must((SELECT content_sha256 FROM officer_credential_change
                     WHERE change_id = (SELECT v::uuid FROM t WHERE k = 'c1'))
    = sha256('\x00000011'::bytea || convert_to('ENROLL_CREDENTIAL', 'UTF8')
             || '\x00000010'::bytea || uuid_send('5eedc0de-0000-4000-8000-000000000028')
             || '\x00000010'::bytea || decode(repeat('01', 16), 'hex')
             || '\x00000017'::bytea || convert_to('https://idp.lab.invalid', 'UTF8')
             || '\x00000005'::bytea || convert_to('maker', 'UTF8')
             || '\x00000008'::bytea || convert_to('person-1', 'UTF8')
             || '\x00000021'::bytea || '\x02'::bytea || decode(repeat('11', 32), 'hex')),
    'content digest is the length-prefixed content');
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L, %L)',
    (SELECT v FROM t WHERE k = 'c1'), 'admin-a'), '23514');            -- maker approves
SELECT pg_temp.expect_err(format('SELECT approve_credential_change(%L, %L, %L, %L)',
    (SELECT v FROM t WHERE k = 'c1'), 'https://idp.lab.invalid', 'admin-b',
    sha256('other')), '23514');                                        -- other content
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L, %L)',
    (SELECT v FROM t WHERE k = 'c1'), 'maker'), '42501');              -- not an admin
SELECT pg_temp.approve((SELECT v::uuid FROM t WHERE k = 'c1'));
SELECT pg_temp.must((SELECT status = 'ACTIVE' AND person_id = 'person-1' AND sign_count = 0
                     FROM officer_credential WHERE credential_id = decode(repeat('01', 16), 'hex')),
                    'credential enrolled');
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)', (SELECT v FROM t WHERE k = 'c1')),
                          '23514');                                    -- closed

-- The same key under another credential id and officer is refused.
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)',
    pg_temp.propose('ENROLL_CREDENTIAL', 2, 'checker', 'person-2', 17)), '23514');
-- The same credential id again is refused.
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)',
    pg_temp.propose('ENROLL_CREDENTIAL', 1, 'checker', 'person-2', 34)), '23514');
-- One person cannot hold a second officer identity on the CA ...
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)',
    pg_temp.propose('ENROLL_CREDENTIAL', 3, 'checker', 'person-1', 51)), '23514');
-- ... and an identity's credentials belong to one person.
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)',
    pg_temp.propose('ENROLL_CREDENTIAL', 4, 'maker', 'person-2', 68)), '23514');
-- A second authenticator of the same person and identity is fine.
SELECT pg_temp.approve(pg_temp.propose('ENROLL_CREDENTIAL', 5, 'maker', 'person-1', 85));
SELECT pg_temp.approve(pg_temp.propose('ENROLL_CREDENTIAL', 6, 'checker', 'person-2', 102));
-- No officer grant, no enrolment.
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)',
    pg_temp.propose('ENROLL_CREDENTIAL', 7, 'stranger', 'person-3', 119)), '23514');
-- No CA admin changes their own credentials, as maker or as checker.
SELECT pg_temp.expect_err($$SELECT pg_temp.propose('ENROLL_CREDENTIAL', 8, 'admin-a', 'person-4', 136)$$,
                          '23514');
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)',
    pg_temp.propose('ENROLL_CREDENTIAL', 9, 'admin-b', 'person-5', 153)), '23514');

-- Removal: the stored person and key are part of what the checker reviews.
INSERT INTO t VALUES ('r1', pg_temp.propose('REMOVE_CREDENTIAL', 1, 'maker', NULL, NULL));
SELECT pg_temp.must((SELECT person_id = 'person-1'
                            AND public_key_sec1 = '\x02'::bytea || decode(repeat('11', 32), 'hex')
                     FROM officer_credential_change
                     WHERE change_id = (SELECT v::uuid FROM t WHERE k = 'r1')),
                    'removal carries the stored person and key');
SELECT pg_temp.approve((SELECT v::uuid FROM t WHERE k = 'r1'));
SELECT pg_temp.must((SELECT status = 'REMOVED' FROM officer_credential
                     WHERE credential_id = decode(repeat('01', 16), 'hex')), 'credential removed');
SELECT pg_temp.expect_err($$SELECT pg_temp.propose('REMOVE_CREDENTIAL', 1, 'maker', NULL, NULL)$$,
                          '23514');                                    -- already removed
-- A removed key is never enrolled again.
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)',
    pg_temp.propose('ENROLL_CREDENTIAL', 10, 'maker', 'person-1', 17)), '23514');
-- Rejection closes a change.
INSERT INTO t VALUES ('x1', pg_temp.propose('ENROLL_CREDENTIAL', 11, 'maker', 'person-1', 170));
SELECT reject_credential_change((SELECT v::uuid FROM t WHERE k = 'x1'),
                                'https://idp.lab.invalid', 'admin-b');
SELECT pg_temp.expect_err(format('SELECT pg_temp.approve(%L)', (SELECT v FROM t WHERE k = 'x1')),
                          '23514');

-- Append-only registry and history, even for a superuser.
SELECT pg_temp.expect_err($$UPDATE officer_credential SET person_id = 'x'$$, '23514');
SELECT pg_temp.expect_err($$UPDATE officer_credential SET public_key_sec1 = public_key_sec1$$ ||
                          $$ || '\x00'::bytea$$, '23514');
SELECT pg_temp.expect_err($$UPDATE officer_credential SET status = 'ACTIVE', removed_change = NULL
                            WHERE status = 'REMOVED'$$, '23514');
UPDATE officer_credential SET sign_count = 5 WHERE credential_id = decode(repeat('05', 16), 'hex');
SELECT pg_temp.expect_err($$UPDATE officer_credential SET sign_count = 4
                            WHERE credential_id = decode(repeat('05', 16), 'hex')$$, '23514');
SELECT pg_temp.expect_err($$DELETE FROM officer_credential$$, '23514');
-- Refused by the guard, or earlier by the foreign key of 0029's signatures.
DO $tr$
BEGIN
    TRUNCATE officer_credential;
    RAISE EXCEPTION 'TRUNCATE officer_credential succeeded';
EXCEPTION WHEN SQLSTATE '23514' OR SQLSTATE '0A000' THEN
    NULL;
END $tr$;
SELECT pg_temp.expect_err($$UPDATE officer_credential_change SET person_id = 'x'$$, '23514');
SELECT pg_temp.expect_err($$DELETE FROM officer_credential_change$$, '23514');

-- Privileges: CA admins call the functions only; no other service may.
SET LOCAL ROLE trust_ca_admin;
SELECT pg_temp.propose('ENROLL_CREDENTIAL', 12, 'checker', 'person-2', 187);
SELECT pg_temp.expect_err('SELECT count(*) FROM officer_credential', '42501');
SELECT pg_temp.expect_err('SELECT count(*) FROM officer_credential_change', '42501');
RESET ROLE;
DO $svc$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_crl_signer',
                             'trust_crl_operator', 'trust_audit_sealer', 'trust_audit_verifier'] LOOP
        EXECUTE format('SET LOCAL ROLE %I', r);
        PERFORM pg_temp.expect_err(
            $$SELECT pg_temp.propose('ENROLL_CREDENTIAL', 13, 'checker', 'person-2', 204)$$, '42501');
        PERFORM pg_temp.expect_err(
            $$SELECT reject_credential_change(gen_random_uuid(), 'i', 's')$$, '42501');
        PERFORM pg_temp.expect_err('SELECT count(*) FROM officer_credential', '42501');
        RESET ROLE;
    END LOOP;
END $svc$;

ROLLBACK;
