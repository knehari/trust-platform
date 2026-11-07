-- Lab-only: pruning expired entries from CRLs (migration 0031, RFC 5280
-- 3.3). With keep_expired_on_crl false, a revoked certificate's entry leaves
-- the CRL only once a stored CRL issued after the certificate expired has
-- listed it; unknown expiry is never pruned; ETSI EN 319 411-2 CAs keep
-- expired entries; not_after is set once; coverage accepts the pruning.
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
    INSERT INTO ca(ca_id, display_name, policy_version) VALUES (p_ca, 'Pruning CA', 'v1');
    INSERT INTO ca_revocation_policy(ca_id, keep_expired_on_crl) VALUES (p_ca, p_keep);
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

CREATE FUNCTION pg_temp.listed(p_ca UUID, p_n BIGINT) RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT coalesce(string_agg(encode(serial_der_content, 'hex'), ',' ORDER BY serial_der_content), '')
    FROM crl_entry_snapshot WHERE ca_id = p_ca AND crl_number = p_n
$f$;

-- ETSI EN 319 411-2 CAs keep expired entries.
SELECT pg_temp.expect_err($$INSERT INTO ca_revocation_policy(ca_id, conformance_target,
    keep_expired_on_crl) VALUES (gen_random_uuid(), 'ETSI_EN_319_411_2', false)$$, '23514');

-- Pruning CA: 01 expired yesterday, 02 valid, 03 expiry unknown.
SELECT pg_temp.ca('5eedc0de-0000-4000-8000-000000000031', false);
SELECT pg_temp.revoked('5eedc0de-0000-4000-8000-000000000031', '\x01', now() - interval '1 day');
SELECT pg_temp.revoked('5eedc0de-0000-4000-8000-000000000031', '\x02', now() + interval '30 days');
SELECT pg_temp.revoked('5eedc0de-0000-4000-8000-000000000031', '\x03', NULL);
-- Keeping CA: same certificates.
SELECT pg_temp.ca('5eedc0de-0000-4000-8000-00000000003a', true);
SELECT pg_temp.revoked('5eedc0de-0000-4000-8000-00000000003a', '\x01', now() - interval '1 day');

-- CRL 1: the expired entry has not yet appeared on a CRL issued after its
-- expiry, so it is still listed.
SELECT pg_temp.must(pg_temp.crl('5eedc0de-0000-4000-8000-000000000031') = 1, 'CRL 1');
SELECT pg_temp.must(pg_temp.listed('5eedc0de-0000-4000-8000-000000000031', 1) = '01,02,03',
                    'expired entry kept until listed after expiry');
-- CRL 2: it was, so it leaves; unknown expiry stays.
SELECT pg_temp.must(pg_temp.crl('5eedc0de-0000-4000-8000-000000000031') = 2, 'CRL 2');
SELECT pg_temp.must(pg_temp.listed('5eedc0de-0000-4000-8000-000000000031', 2) = '02,03',
                    'expired entry pruned; unknown expiry kept');
-- The revocation itself is untouched.
SELECT pg_temp.must(certificate_status('5eedc0de-0000-4000-8000-000000000031', '\x01') = 'REVOKED',
                    'certificate stays revoked');
-- Coverage accepts the pruning: nothing due, nothing overdue.
SELECT pg_temp.must(NOT crl_due('5eedc0de-0000-4000-8000-000000000031'), 'not due after pruning');
SELECT pg_temp.must((SELECT count(*) FROM overdue_status_changes('5eedc0de-0000-4000-8000-000000000031')) = 0,
                    'nothing overdue after pruning');

-- The keeping CA lists it on every CRL.
SELECT pg_temp.crl('5eedc0de-0000-4000-8000-00000000003a');
SELECT pg_temp.crl('5eedc0de-0000-4000-8000-00000000003a');
SELECT pg_temp.must(pg_temp.listed('5eedc0de-0000-4000-8000-00000000003a', 2) = '01',
                    'keep_expired_on_crl keeps the entry');

-- not_after is set once.
SELECT pg_temp.expect_err($$UPDATE certificate SET not_after = now() - interval '9 days'
    WHERE ca_id = '5eedc0de-0000-4000-8000-000000000031' AND serial_der_content = '\x02'$$, '23514');
SELECT pg_temp.expect_err($$UPDATE certificate SET not_after = now() - interval '9 days'
    WHERE ca_id = '5eedc0de-0000-4000-8000-000000000031' AND serial_der_content = '\x03'$$, '23514');
-- ... and never before signing.
SELECT pg_temp.expect_err($$INSERT INTO certificate(ca_id, serial_der_content, request_id,
    fingerprint_sha256, certificate_der, signed_at, not_after)
    VALUES ('5eedc0de-0000-4000-8000-000000000031', '\x09', gen_random_uuid(), sha256('x'),
            '\x30', now(), now() - interval '1 day')$$, '23514');

-- The 8-argument issuance refuses a missing or past expiry before anything else.
SELECT pg_temp.expect_err($$SELECT store_signed_certificate(gen_random_uuid(), gen_random_uuid(),
    'actor', '\x01', sha256('t'), sha256('\x30'::bytea), '\x30'::bytea, now() - interval '1 second')$$,
    '22023');
SELECT pg_temp.expect_err($$SELECT store_signed_certificate(gen_random_uuid(), gen_random_uuid(),
    'actor', '\x01', sha256('t'), sha256('\x30'::bytea), '\x30'::bytea, NULL)$$, '22023');

ROLLBACK;
