-- Lab-only: signed status-change approvals (migration 0029, ADR-0007
-- step 2): catalog, privileges, guards and the database-side checks. The
-- signed flow itself (real ES256 assertions) is in
-- crates/pki-core/tests/signed_status_change_postgres.rs.
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

-- The original bodies are reachable only through the wrappers.
SELECT pg_temp.must(NOT has_function_privilege('trust_revocation_officer_api',
    'status_change_approve_unchecked(uuid,text,text,text,smallint)', 'EXECUTE'),
    'unchecked approve not granted');
SELECT pg_temp.must(NOT has_function_privilege('trust_revocation_officer_api',
    'status_change_propose_unchecked(uuid,uuid,bytea,text,smallint,timestamp with time zone,text,text)',
    'EXECUTE'), 'unchecked propose not granted');
SELECT pg_temp.must(has_function_privilege('trust_revocation_officer_api',
    'approve_certificate_status_change(uuid,text,text,text,smallint)', 'EXECUTE'),
    'approve wrapper granted');
SELECT pg_temp.must((SELECT bool_and(p.prosecdef
                              AND p.proconfig @> ARRAY['search_path=pg_catalog, public, pg_temp'])
                     FROM pg_proc p
                     WHERE p.proname IN ('status_change_approve_unchecked',
                                         'status_change_propose_unchecked')),
                    'unchecked bodies keep definer settings');

-- Claim digest: domain tag, then 0x00 / 0x01 + length + bytes per field.
SELECT pg_temp.must(status_change_claim_digest(
        '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002',
        decode(repeat('03', 32), 'hex'), '\x0102', 'REVOKE', 1::smallint, NULL, 'v1',
        decode(repeat('04', 32), 'hex'), to_timestamp(1792533719))
    = sha256(convert_to('trust-platform/status-change/v1', 'UTF8') || '\x00'::bytea
             || '\x0100000010'::bytea || uuid_send('00000000-0000-0000-0000-000000000001')
             || '\x0100000010'::bytea || uuid_send('00000000-0000-0000-0000-000000000002')
             || '\x0100000020'::bytea || decode(repeat('03', 32), 'hex')
             || '\x01000000020102'::bytea
             || '\x0100000006'::bytea || convert_to('REVOKE', 'UTF8')
             || '\x010000000101'::bytea
             || '\x00'::bytea
             || '\x01000000027631'::bytea
             || '\x0100000020'::bytea || decode(repeat('04', 32), 'hex')
             || '\x0100000008'::bytea || int8send(1792533719000000)),
    'claim digest encoding');

-- Database-side assertion checks.
SELECT pg_temp.must(webauthn_precheck(decode(repeat('aa', 32) || '05' || '00000007', 'hex'),
    convert_to('{"type":"webauthn.get","challenge":"'
               || rtrim(translate(encode(sha256('c'), 'base64'), '+/', '-_'), '=')
               || '","origin":"https://officer.lab.invalid"}', 'UTF8'), sha256('c')) = 7,
    'precheck returns the counter');
SELECT pg_temp.expect_err($$SELECT webauthn_precheck(decode(repeat('aa', 32) || '01' || '00000007', 'hex'),
    convert_to('{}', 'UTF8'), sha256('c'))$$, '23514');                -- no UV
SELECT pg_temp.expect_err($$SELECT webauthn_precheck(decode(repeat('aa', 32) || '45' || '00000007', 'hex'),
    convert_to('{}', 'UTF8'), sha256('c'))$$, '23514');                -- attested data
SELECT pg_temp.expect_err($$SELECT webauthn_precheck(decode(repeat('aa', 32) || '05' || '00000007', 'hex'),
    convert_to('not json', 'UTF8'), sha256('c'))$$, '23514');
SELECT pg_temp.expect_err($$SELECT webauthn_precheck(decode(repeat('aa', 32) || '05' || '00000007', 'hex'),
    convert_to('{"type":"webauthn.create","challenge":"'
               || rtrim(translate(encode(sha256('c'), 'base64'), '+/', '-_'), '=') || '"}', 'UTF8'),
    sha256('c'))$$, '23514');
SELECT pg_temp.expect_err($$SELECT webauthn_precheck(decode(repeat('aa', 32) || '05' || '00000007', 'hex'),
    convert_to('{"type":"webauthn.get","challenge":"'
               || rtrim(translate(encode(sha256('c'), 'base64'), '+/', '-_'), '=')
               || '","crossOrigin":true}', 'UTF8'), sha256('c'))$$, '23514');
SELECT pg_temp.expect_err($$SELECT webauthn_precheck(decode(repeat('aa', 32) || '05' || '00000007', 'hex'),
    convert_to('{"type":"webauthn.get","challenge":"other"}', 'UTF8'), sha256('c'))$$, '23514');

-- Challenges: TTL bounded, actor must hold a grant, issuer must be registered.
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('5eedc0de-0000-4000-8000-000000000029', 'Signed CA', 'v1');
INSERT INTO revocation_officer_grant(issuer, subject, ca_id)
VALUES ('https://idp.lab.invalid', 'maker', '5eedc0de-0000-4000-8000-000000000029');
SELECT pg_temp.expect_err($$SELECT issue_status_change_challenge('PROPOSE',
    '5eedc0de-0000-4000-8000-000000000029', NULL, '\x01', 'REVOKE', 1::smallint, NULL,
    'https://idp.lab.invalid', 'maker', 601)$$, '22023');
SELECT pg_temp.expect_err($$SELECT issue_status_change_challenge('PROPOSE',
    '5eedc0de-0000-4000-8000-000000000029', NULL, '\x01', 'REVOKE', 1::smallint, NULL,
    'https://idp.lab.invalid', 'stranger', 60)$$, '42501');
SELECT pg_temp.expect_err($$SELECT issue_status_change_challenge('PROPOSE',
    '5eedc0de-0000-4000-8000-000000000029', NULL, '\x01', 'REVOKE', 1::smallint, NULL,
    'https://idp.lab.invalid', 'maker', 60)$$, '42704');
INSERT INTO ca_issuer_certificate(ca_id, certificate_der, registered_by)
VALUES ('5eedc0de-0000-4000-8000-000000000029', '\x3000', 'test');
CREATE TEMP TABLE t AS SELECT issue_status_change_challenge('PROPOSE',
    '5eedc0de-0000-4000-8000-000000000029', NULL, '\x01', 'REVOKE', 1::smallint, NULL,
    'https://idp.lab.invalid', 'maker', 60) AS challenge;
SELECT pg_temp.must((SELECT expires_at - issued_at <= interval '60 seconds'
                            AND octet_length(challenge_sha256) = 32 AND consumed_at IS NULL
                     FROM status_change_challenge WHERE challenge_id = (SELECT challenge FROM t)),
                    'challenge stored with expiry, digest only');
-- Consumed once, never changed, never deleted.
SELECT pg_temp.expect_err($$UPDATE status_change_challenge SET expires_at = expires_at + interval '1 day'$$, '23514');
UPDATE status_change_challenge SET consumed_at = clock_timestamp()
WHERE challenge_id = (SELECT challenge FROM t);
SELECT pg_temp.expect_err($$UPDATE status_change_challenge SET consumed_at = clock_timestamp()$$, '23514');
SELECT pg_temp.expect_err($$DELETE FROM status_change_challenge$$, '23514');
-- (refused by the signatures' foreign key before the guard fires)
SELECT pg_temp.expect_err($$TRUNCATE status_change_challenge$$, '0A000');
-- No signature rows exist here (the signed flow is in the Rust test), so
-- check the row guard is installed for UPDATE and DELETE.
SELECT pg_temp.must((SELECT tgenabled = 'O' AND (tgtype & 24) = 24
                     FROM pg_trigger WHERE tgname = 'status_change_signature_append_only'),
                    'signature rows guarded against UPDATE and DELETE');
SELECT pg_temp.expect_err($$TRUNCATE status_change_signature$$, '23514');

-- One-way requirement.
INSERT INTO ca_revocation_policy(ca_id, signed_approvals_required)
VALUES ('5eedc0de-0000-4000-8000-000000000029', true);
SELECT pg_temp.expect_err($$UPDATE ca_revocation_policy SET signed_approvals_required = false
                            WHERE ca_id = '5eedc0de-0000-4000-8000-000000000029'$$, '23514');

-- No direct table access for any service.
DO $svc$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_crl_signer',
                             'trust_crl_operator', 'trust_ca_admin'] LOOP
        EXECUTE format('SET LOCAL ROLE %I', r);
        PERFORM pg_temp.expect_err('SELECT count(*) FROM status_change_challenge', '42501');
        PERFORM pg_temp.expect_err('SELECT count(*) FROM status_change_signature', '42501');
        PERFORM pg_temp.expect_err(
            'SELECT status_change_approve_unchecked(gen_random_uuid(), ''i'', ''s'', ''REVOKE'', 1::smallint)',
            '42501');
        RESET ROLE;
    END LOOP;
END $svc$;

ROLLBACK;
