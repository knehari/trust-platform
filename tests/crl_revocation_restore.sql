-- Lab-only: re-applying revocations from the last published CRL after a
-- database is restored from an older backup (migration 0060). The Rust tool
-- verifies the CRL signature first; this tests what the database does with
-- the entries. Single transaction, rolled back. Run as a superuser.
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

-- Same as expect_err, and the error message must also match.
CREATE FUNCTION pg_temp.expect_err_msg(p_sql TEXT, p_state TEXT, p_msg TEXT) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    BEGIN
        EXECUTE p_sql;
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE <> p_state OR SQLERRM <> p_msg THEN
            RAISE EXCEPTION 'expected % "%" but got % "%" for: %',
                p_state, p_msg, SQLSTATE, SQLERRM, p_sql;
        END IF;
        RETURN;
    END;
    RAISE EXCEPTION 'expected % "%" but statement succeeded: %', p_state, p_msg, p_sql;
END $f$;

-- What an honest CA core passes to record_crl_intent: the digest of the
-- entries it signs (here: the snapshot) and the reservation's number and times.
CREATE FUNCTION pg_temp.snapshot_digest(p_ca UUID, p_n BIGINT) RETURNS BYTEA
LANGUAGE sql AS $f$
    SELECT sha256(COALESCE(string_agg(
               crl_entry_encoding(e.serial_der_content, e.revoked_at, e.reason_code, e.invalidity_at),
               '\x'::bytea ORDER BY e.serial_der_content), '\x'::bytea))
    FROM crl_snapshot_entries(p_ca, p_n) e
$f$;

-- The CA's registered issuer fingerprint (0022). Test CAs get a placeholder
-- issuer registered on first use; the binding itself is tested separately.
CREATE FUNCTION pg_temp.issuer(p_ca UUID) RETURNS BYTEA
LANGUAGE sql AS $f$
    SELECT register_ca_issuer(p_ca, convert_to('test issuer of ' || p_ca, 'UTF8'), 'test-admin')
$f$;

CREATE FUNCTION pg_temp.intent(p_ca UUID, p_n BIGINT, p_op TEXT, p_tbs BYTEA) RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT record_crl_intent(p_ca, p_n, p_op, p_tbs, pg_temp.snapshot_digest(p_ca, p_n),
               floor(extract(epoch FROM cp.this_update))::bigint,
               floor(extract(epoch FROM cp.next_update))::bigint,
               floor(extract(epoch FROM cp.expired_certs_on_crl_since))::bigint,
               pg_temp.issuer(p_ca))
    FROM crl_publication cp WHERE cp.ca_id = p_ca AND cp.crl_number = p_n
$f$;

CREATE FUNCTION pg_temp.ca(p_ca UUID, p_keep BOOLEAN) RETURNS VOID
LANGUAGE plpgsql AS $f$
BEGIN
    INSERT INTO ca(ca_id, display_name, policy_version) VALUES (p_ca, 'Restore CA', 'v1');
    INSERT INTO ca_revocation_policy(ca_id, keep_expired_on_crl, suspension_allowed,
                                     suspension_cps_ref)
    VALUES (p_ca, p_keep, true, 'lab-cps-restore');
    INSERT INTO revocation_officer_grant(issuer, subject, ca_id)
    VALUES ('https://idp.lab.invalid', 'maker', p_ca), ('https://idp.lab.invalid', 'checker', p_ca);
END $f$;

-- A revoked certificate with the given validity end (NULL: unknown).
CREATE FUNCTION pg_temp.revoked(p_ca UUID, p_serial BYTEA, p_not_after TIMESTAMPTZ) RETURNS VOID
LANGUAGE plpgsql AS $f$
DECLARE
    v_request UUID := gen_random_uuid();
    v_change UUID;
BEGIN
    INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                    requester_id, policy_version, state)
    VALUES (v_request, p_ca, encode(p_serial, 'hex'), sha256(p_serial), 'requester', 'v1',
            'PUBLISHED');
    INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
    VALUES (p_ca, p_serial, v_request);
    INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                            certificate_der, signed_at, not_after)
    VALUES (p_ca, p_serial, v_request, sha256(p_serial), '\x3003020101',
            now() - interval '30 days', p_not_after);
    v_change := propose_certificate_status_change(p_ca, p_serial, 'REVOKE', 1::smallint, NULL,
                                                  'https://idp.lab.invalid', 'maker');
    PERFORM approve_certificate_status_change(v_change, 'https://idp.lab.invalid', 'checker',
                                              'REVOKE', 1::smallint);
END $f$;

-- Reserve, journal and store CRL n as an honest CA core would (no real
-- signature: storage trusts the Rust verifier, tested elsewhere).
CREATE FUNCTION pg_temp.crl(p_ca UUID) RETURNS BIGINT
LANGUAGE plpgsql AS $f$
DECLARE
    n BIGINT;
BEGIN
    SELECT crl_number INTO n FROM reserve_crl(p_ca, 'crl-worker', 'prune-op-' || clock_timestamp());
    PERFORM pg_temp.intent(p_ca, n, (SELECT operation_ref FROM crl_publication
                                    WHERE ca_id = p_ca AND crl_number = n),
                           sha256(('tbs-' || n)::bytea));
    PERFORM store_verified_crl(p_ca, n, (SELECT operation_ref FROM crl_publication
                                         WHERE ca_id = p_ca AND crl_number = n),
                               sha256(('tbs-' || n)::bytea), sha256(('der-' || n)::bytea),
                               ('der-' || n)::bytea);
    RETURN n;
END $f$;

CREATE FUNCTION pg_temp.cert(p_ca UUID, p_serial BYTEA) RETURNS VOID
LANGUAGE plpgsql AS $f$
DECLARE
    v_request UUID := gen_random_uuid();
BEGIN
    INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                    requester_id, policy_version, state)
    VALUES (v_request, p_ca, encode(p_serial, 'hex'), sha256(p_serial), 'requester', 'v1',
            'PUBLISHED');
    INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
    VALUES (p_ca, p_serial, v_request);
    INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                            certificate_der, signed_at, not_after)
    VALUES (p_ca, p_serial, v_request, sha256(p_serial), '\x3003020101',
            now() - interval '30 days', now() + interval '30 days');
END $f$;

CREATE FUNCTION pg_temp.status(p_ca UUID, p_serial BYTEA, p_action TEXT, p_reason SMALLINT)
RETURNS VOID
LANGUAGE plpgsql AS $f$
DECLARE
    v_change UUID;
BEGIN
    v_change := propose_certificate_status_change(p_ca, p_serial, p_action, p_reason, NULL,
                                                  'https://idp.lab.invalid', 'maker');
    PERFORM approve_certificate_status_change(v_change, 'https://idp.lab.invalid', 'checker',
                                              p_action, p_reason);
END $f$;


-- Restores what a CRL lists, as the Rust tool passes it after verifying
-- the CRL signature: one array per field, times in epoch seconds.
CREATE FUNCTION pg_temp.restore(p_ca UUID, p_n BIGINT, p_der BYTEA, p_serials BYTEA[],
                                p_reasons SMALLINT[], p_at BIGINT[]) RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT string_agg(encode(serial_der_content, 'hex') || ':' || outcome, ','
                      ORDER BY serial_der_content)
    FROM restore_revocations_from_crl(p_ca, p_n, p_der, p_serials, p_reasons, p_at,
             array_fill(NULL::bigint, ARRAY[cardinality(p_serials)]), 'restore drill')
$f$;

CREATE FUNCTION pg_temp.state(p_ca UUID, p_serial BYTEA) RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT coalesce((SELECT reason_code::text || '@' || floor(extract(epoch FROM revoked_at))::bigint
                     FROM revocation WHERE ca_id = p_ca AND serial_der_content = p_serial), 'none')
$f$;

-- Restored database: 01 valid, 02 on hold, 03 revoked (superseded),
-- 04 on hold, 05 valid. The lost CRL 7 (published after the backup) lists
-- 01 keyCompromise, 02 keyCompromise, 03 keyCompromise, 06 (a certificate
-- issued after the backup, unknown here) and not 04 (released since).
SELECT pg_temp.ca('2e570000-0000-4000-8000-000000000001', true);
SELECT pg_temp.cert('2e570000-0000-4000-8000-000000000001', s)
FROM unnest(ARRAY['\x01','\x02','\x03','\x04','\x05']::bytea[]) s;
SELECT pg_temp.status('2e570000-0000-4000-8000-000000000001', '\x02', 'SUSPEND', 6::smallint);
SELECT pg_temp.status('2e570000-0000-4000-8000-000000000001', '\x03', 'REVOKE', 4::smallint);
SELECT pg_temp.status('2e570000-0000-4000-8000-000000000001', '\x04', 'SUSPEND', 6::smallint);
SELECT pg_temp.crl('2e570000-0000-4000-8000-000000000001');

-- Input is refused before anything is written.
SELECT pg_temp.expect_err($$SELECT * FROM restore_revocations_from_crl(
    '2e570000-0000-4000-8000-000000000001', 7, '\x30', ARRAY['\x01']::bytea[],
    ARRAY[1,1]::smallint[], ARRAY[1]::bigint[], ARRAY[NULL]::bigint[], 'x')$$, '22023');
SELECT pg_temp.expect_err($$SELECT * FROM restore_revocations_from_crl(
    '2e570000-0000-4000-8000-000000000001', 7, '\x30', ARRAY['\x01']::bytea[],
    ARRAY[8]::smallint[], ARRAY[1]::bigint[], ARRAY[NULL]::bigint[], 'x')$$, '22023');
SELECT pg_temp.expect_err($$SELECT * FROM restore_revocations_from_crl(
    '2e570000-0000-4000-8000-000000000001', 7, '\x30', ARRAY['\x01','\x01']::bytea[],
    ARRAY[1,1]::smallint[], ARRAY[1,1]::bigint[], ARRAY[NULL,NULL]::bigint[], 'x')$$, '22023');
-- A CRL number this database already stored with other content is not a
-- lost CRL: refused.
SELECT pg_temp.expect_err($$SELECT * FROM restore_revocations_from_crl(
    '2e570000-0000-4000-8000-000000000001', 1, '\x3001', ARRAY['\x01']::bytea[],
    ARRAY[1]::smallint[], ARRAY[1]::bigint[], ARRAY[NULL]::bigint[], 'x')$$, '23514');

SELECT pg_temp.must(pg_temp.restore('2e570000-0000-4000-8000-000000000001', 7, '\x30070201',
    ARRAY['\x01','\x02','\x03','\x06']::bytea[], ARRAY[1,1,1,1]::smallint[],
    ARRAY[1800000000,1800000001,1800000002,1800000003]::bigint[])
    = '01:RESTORED,02:UPGRADED,03:CONFLICT,04:HOLD_NOT_ON_CRL,06:UNKNOWN_CERTIFICATE',
    'outcomes');
SELECT pg_temp.must(pg_temp.state('2e570000-0000-4000-8000-000000000001', '\x01') = '1@1800000000',
    'missing revocation restored with the CRL date');
SELECT pg_temp.must(pg_temp.state('2e570000-0000-4000-8000-000000000001', '\x02') LIKE '1@%'
    AND pg_temp.state('2e570000-0000-4000-8000-000000000001', '\x02') <> '1@1800000001',
    'hold made definitive, original revocation date kept');
SELECT pg_temp.must(pg_temp.state('2e570000-0000-4000-8000-000000000001', '\x03') LIKE '4@%',
    'a definitive revocation is never changed');
SELECT pg_temp.must(pg_temp.state('2e570000-0000-4000-8000-000000000001', '\x04') LIKE '6@%',
    'a hold missing from the CRL is reported, not released');
SELECT pg_temp.must(pg_temp.state('2e570000-0000-4000-8000-000000000001', '\x05') = 'none',
    'others untouched');
SELECT pg_temp.must(certificate_status('2e570000-0000-4000-8000-000000000001', '\x01') = 'REVOKED',
    'status is revoked again');
-- Evidence, audit and the number floor.
SELECT pg_temp.must((SELECT count(*) FROM crl_restore WHERE ca_id = '2e570000-0000-4000-8000-000000000001'
    AND crl_number = 7 AND crl_sha256 = sha256('\x30070201') AND restored_by = session_user) = 1,
    'the CRL is kept as evidence');
SELECT pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = '2e570000-0000-4000-8000-000000000001'
    AND event_type = 'revocation.restored_from_crl'
    AND decision = 'CRL:7:restored=1:upgraded=1:conflict=1:hold_not_on_crl=1:unknown=1') = 1,
    'audited with counts');
SELECT pg_temp.must((SELECT max(floor) FROM crl_number_floor
    WHERE ca_id = '2e570000-0000-4000-8000-000000000001') = 7, 'floor raised to the CRL number');
SELECT pg_temp.must((SELECT crl_number FROM reserve_crl('2e570000-0000-4000-8000-000000000001',
    'w', 'after-restore')) = 8, 'next CRL numbered above the restored one');
SELECT pg_temp.must((SELECT string_agg(encode(serial_der_content, 'hex'), ',' ORDER BY serial_der_content)
    FROM crl_entry_snapshot WHERE ca_id = '2e570000-0000-4000-8000-000000000001' AND crl_number = 8)
    = '01,02,03,04', 'the next CRL lists the restored revocation');
-- Running it again changes nothing and keeps the floor.
SELECT pg_temp.must(pg_temp.restore('2e570000-0000-4000-8000-000000000001', 7, '\x30070201',
    ARRAY['\x01','\x02']::bytea[], ARRAY[1,1]::smallint[], ARRAY[1800000000,1800000001]::bigint[])
    = '01:PRESENT,02:PRESENT,04:HOLD_NOT_ON_CRL', 'idempotent');
-- Restored rows stay immutable like any definitive revocation.
SELECT pg_temp.expect_err($$DELETE FROM revocation WHERE ca_id = '2e570000-0000-4000-8000-000000000001'
    AND serial_der_content = '\x01'$$, '23514');
SELECT pg_temp.expect_err($$DELETE FROM crl_restore$$, '23514');
SELECT pg_temp.expect_err($$UPDATE crl_restore SET reason = 'x'$$, '23514');

-- No service role may call it: restoring revocations is a superuser act.
DO $t$
DECLARE r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_crl_signer', 'trust_crl_operator', 'trust_ca_admin',
                             'trust_revocation_officer_api', 'trust_crl_publisher',
                             'trust_audit_verifier', 'trust_revocation_owner', 'public'] LOOP
        PERFORM pg_temp.must(NOT has_function_privilege(r,
            'restore_revocations_from_crl(uuid,bigint,bytea,bytea[],smallint[],bigint[],bigint[],text)',
            'EXECUTE'), r || ' cannot restore revocations');
        -- The owner role owns the table; no login is a member of it.
        PERFORM pg_temp.must(r = 'trust_revocation_owner'
            OR NOT has_table_privilege(r, 'crl_restore', 'INSERT'), r || ' cannot write evidence');
    END LOOP;
END $t$;

ROLLBACK;
