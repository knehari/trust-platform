-- Lab-only: delta CRLs (migration 0059, RFC 5280 5.2.4). A delta lists the
-- revocations and holds added since its base complete CRL and the entries
-- removed since it (removeFromCRL); it shares the CRL numbering, is never
-- served or counted as a complete CRL, and needs a base that advertises it.
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
    INSERT INTO ca(ca_id, display_name, policy_version) VALUES (p_ca, 'Delta CA', 'v1');
    INSERT INTO ca_revocation_policy(ca_id, keep_expired_on_crl, suspension_allowed,
                                     suspension_cps_ref)
    VALUES (p_ca, p_keep, true, 'lab-cps-delta');
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

-- The digest an honest CA core computes for a delta: entries and releases
-- (reason 8, at thisUpdate) in serial order.
CREATE FUNCTION pg_temp.delta_digest(p_ca UUID, p_n BIGINT) RETURNS BYTEA
LANGUAGE sql AS $f$
    SELECT sha256(COALESCE(string_agg(x.encoded, '\x'::bytea ORDER BY x.serial), '\x'::bytea))
    FROM (SELECT e.serial_der_content AS serial,
                 crl_entry_encoding(e.serial_der_content, e.revoked_at, e.reason_code,
                                    e.invalidity_at) AS encoded
          FROM crl_snapshot_entries(p_ca, p_n) e
          UNION ALL
          SELECT d.serial_der_content,
                 crl_entry_encoding(d.serial_der_content, d.released_at, 8::smallint, NULL)
          FROM crl_delta_releases(p_ca, p_n) d) x
$f$;

CREATE FUNCTION pg_temp.delta(p_ca UUID) RETURNS BIGINT
LANGUAGE plpgsql AS $f$
DECLARE
    n BIGINT;
    op TEXT := 'delta-op-' || clock_timestamp();
BEGIN
    SELECT crl_number INTO n FROM reserve_delta_crl(p_ca, 'crl-worker', op);
    PERFORM record_crl_intent(p_ca, n, op, sha256(('tbs-' || n)::bytea),
               pg_temp.delta_digest(p_ca, n),
               floor(extract(epoch FROM cp.this_update))::bigint,
               floor(extract(epoch FROM cp.next_update))::bigint, NULL, pg_temp.issuer(p_ca))
    FROM crl_publication cp WHERE cp.ca_id = p_ca AND cp.crl_number = n;
    PERFORM store_verified_crl(p_ca, n, op, sha256(('tbs-' || n)::bytea),
                               sha256(('der-' || n)::bytea), ('der-' || n)::bytea);
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

CREATE FUNCTION pg_temp.entries(p_ca UUID, p_n BIGINT) RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT coalesce(string_agg(encode(serial_der_content, 'hex') || ':' || reason_code, ','
                               ORDER BY serial_der_content), '')
    FROM crl_entry_snapshot WHERE ca_id = p_ca AND crl_number = p_n
$f$;

CREATE FUNCTION pg_temp.releases(p_ca UUID, p_n BIGINT) RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT coalesce(string_agg(encode(serial_der_content, 'hex'), ',' ORDER BY serial_der_content), '')
    FROM crl_delta_release WHERE ca_id = p_ca AND crl_number = p_n
$f$;

-- ------------------------------------------------------------- disabled
SELECT pg_temp.ca('de17a000-0000-4000-8000-000000000001', true);
SELECT pg_temp.cert('de17a000-0000-4000-8000-000000000001', '\x01');
SELECT pg_temp.status('de17a000-0000-4000-8000-000000000001', '\x01', 'REVOKE', 1::smallint);
SELECT pg_temp.crl('de17a000-0000-4000-8000-000000000001');
SELECT pg_temp.expect_err_msg($$SELECT * FROM reserve_delta_crl('de17a000-0000-4000-8000-000000000001', 'w', 'op')$$,
    '55000', 'delta CRLs are not enabled for this CA');
-- Enabled now, but the stored complete CRL does not advertise deltas.
UPDATE ca_revocation_policy SET delta_crl_url = 'http://crl.lab.invalid/delta/a.crl'
WHERE ca_id = 'de17a000-0000-4000-8000-000000000001';
SELECT pg_temp.must((SELECT freshest_crl_url FROM crl_publication
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND crl_number = 1) IS NULL,
    'a CRL reserved before keeps no freshest URL');
SELECT pg_temp.expect_err_msg($$SELECT * FROM reserve_delta_crl('de17a000-0000-4000-8000-000000000001', 'w', 'op')$$,
    '55000', 'no stored complete CRL advertising delta CRLs; issue one first');
-- The URL follows the CDP rules.
SELECT pg_temp.expect_err($$UPDATE ca_revocation_policy SET delta_crl_url = 'https://x/d.crl'
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001'$$, '23514');
SELECT pg_temp.expect_err($$UPDATE ca_revocation_policy SET delta_crl_url = 'http://u@x/d.crl'
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001'$$, '23514');
SELECT pg_temp.expect_err($$UPDATE ca_revocation_policy SET delta_crl_url = 'http:///d.crl'
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001'$$, '23514');

-- ------------------------------------------------------------- the delta
-- Base CRL 2: 01 keyCompromise, 02 on hold, 03 on hold.
SELECT pg_temp.cert('de17a000-0000-4000-8000-000000000001', '\x02');
SELECT pg_temp.cert('de17a000-0000-4000-8000-000000000001', '\x03');
SELECT pg_temp.cert('de17a000-0000-4000-8000-000000000001', '\x04');
SELECT pg_temp.status('de17a000-0000-4000-8000-000000000001', '\x02', 'SUSPEND', 6::smallint);
SELECT pg_temp.status('de17a000-0000-4000-8000-000000000001', '\x03', 'SUSPEND', 6::smallint);
SELECT pg_sleep(1.1);
SELECT pg_temp.must(pg_temp.crl('de17a000-0000-4000-8000-000000000001') = 2, 'base CRL 2');
SELECT pg_temp.must((SELECT freshest_crl_url FROM crl_publication
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND crl_number = 2)
    = 'http://crl.lab.invalid/delta/a.crl', 'complete CRL advertises deltas');
SELECT pg_temp.must(pg_temp.entries('de17a000-0000-4000-8000-000000000001', 2) = '01:1,02:6,03:6', 'base');
-- Since: 02 released, 03 hold made definitive, 04 revoked.
SELECT pg_temp.status('de17a000-0000-4000-8000-000000000001', '\x02', 'RELEASE', NULL);
SELECT pg_temp.status('de17a000-0000-4000-8000-000000000001', '\x03', 'REVOKE', 1::smallint);
SELECT pg_temp.status('de17a000-0000-4000-8000-000000000001', '\x04', 'REVOKE', 4::smallint);
SELECT pg_sleep(1.1);
SELECT pg_temp.must(pg_temp.delta('de17a000-0000-4000-8000-000000000001') = 3, 'delta shares the numbering');
SELECT pg_temp.must((SELECT base_crl_number FROM crl_publication
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND crl_number = 3) = 2, 'base is CRL 2');
SELECT pg_temp.must(pg_temp.entries('de17a000-0000-4000-8000-000000000001', 3) = '03:1,04:4',
    'delta lists changed and new entries only');
SELECT pg_temp.must(pg_temp.releases('de17a000-0000-4000-8000-000000000001', 3) = '02',
    'delta lists the released hold');
SELECT pg_temp.must((SELECT freshest_crl_url IS NULL AND expired_certs_on_crl_since IS NULL
    AND next_update <= (SELECT next_update FROM crl_publication
                        WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND crl_number = 2)
    FROM crl_publication WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND crl_number = 3),
    'delta: no freshest URL, no ExpiredCertsOnCRL, not valid beyond its base');
SELECT pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = 'de17a000-0000-4000-8000-000000000001'
    AND event_type = 'crl.delta_reserved' AND decision = 'RESERVED:3:base=2') = 1, 'audited');
-- A wrong digest (releases left out) is refused at the intent.
SELECT pg_temp.must((SELECT crl_number FROM reserve_delta_crl('de17a000-0000-4000-8000-000000000001',
    'w', 'delta-bad-digest')) = 4, 'delta 4 reserved');
SELECT pg_temp.expect_err($$SELECT record_crl_intent('de17a000-0000-4000-8000-000000000001', 4,
    'delta-bad-digest', sha256('t'), pg_temp.snapshot_digest('de17a000-0000-4000-8000-000000000001', 4),
    floor(extract(epoch FROM cp.this_update))::bigint, floor(extract(epoch FROM cp.next_update))::bigint,
    NULL, pg_temp.issuer('de17a000-0000-4000-8000-000000000001'))
    FROM crl_publication cp WHERE cp.ca_id = 'de17a000-0000-4000-8000-000000000001' AND cp.crl_number = 4$$,
    '23514');

-- ------------------------------------------------ complete CRLs only
-- The distribution point serves the complete CRL 2 and the delta 3.
SELECT pg_temp.must((SELECT crl_number FROM published_crl('de17a000-0000-4000-8000-000000000001')) = 2,
    'published_crl never returns a delta');
SELECT pg_temp.must((SELECT crl_number FROM published_delta_crl('de17a000-0000-4000-8000-000000000001')) = 3,
    'published_delta_crl returns the delta');
-- A delta does not make a CRL less due, nor cover a status change.
SELECT pg_temp.must(crl_due('de17a000-0000-4000-8000-000000000001'),
    'changes published only in a delta keep the complete CRL due');
SELECT pg_temp.must(NOT crl_change_covered((SELECT change_id FROM certificate_status_change
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND serial_der_content = '\x04'), false),
    'a change listed in a delta only is not covered');
-- The omission check has nothing to explain for a delta.
SELECT pg_temp.must((SELECT count(*) FROM crl_pruned_entries('de17a000-0000-4000-8000-000000000001', 3)) = 0,
    'delta has no omissions to explain');
-- The next complete CRL lists the current state and covers the changes.
SELECT pg_sleep(1.1);
SELECT pg_temp.must(pg_temp.crl('de17a000-0000-4000-8000-000000000001') = 5, 'complete CRL 5 after the deltas');
SELECT pg_temp.must(pg_temp.entries('de17a000-0000-4000-8000-000000000001', 5) = '01:1,03:1,04:4',
    'complete CRL 5');
SELECT pg_temp.must(crl_change_covered((SELECT change_id FROM certificate_status_change
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND serial_der_content = '\x04'), true),
    'covered by the complete CRL');
SELECT pg_temp.must(NOT crl_due('de17a000-0000-4000-8000-000000000001'), 'not due after complete CRL 5');

-- ------------------------------------------------------- immutability
SELECT pg_temp.expect_err($$UPDATE crl_publication SET base_crl_number = 1
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND crl_number = 3$$, '23514');
SELECT pg_temp.expect_err($$UPDATE crl_publication SET freshest_crl_url = NULL
    WHERE ca_id = 'de17a000-0000-4000-8000-000000000001' AND crl_number = 5$$, '23514');
SELECT pg_temp.expect_err($$DELETE FROM crl_delta_release$$, '23514');
SELECT pg_temp.expect_err($$UPDATE crl_delta_release SET released_at = now()$$, '23514');
SELECT pg_temp.expect_err($$TRUNCATE crl_delta_release$$, '23514');
-- A delta's base precedes it.
SELECT pg_temp.expect_err($$INSERT INTO crl_publication(ca_id, crl_number, this_update, next_update,
    operation_ref, actor_id, entries_sha256, base_crl_number)
    VALUES ('de17a000-0000-4000-8000-000000000001', 50, now(), now() + interval '1 day', 'x', 'x',
            sha256('x'), 50)$$, '23514');

-- ------------------------------------------------------------ privileges
DO $t$
DECLARE r TEXT;
BEGIN
    PERFORM pg_temp.must(has_function_privilege('trust_crl_signer', 'reserve_delta_crl(uuid,text,text)', 'EXECUTE'), 'signer reserves deltas');
    PERFORM pg_temp.must(has_function_privilege('trust_crl_signer', 'crl_delta_releases(uuid,bigint)', 'EXECUTE'), 'signer reads releases');
    PERFORM pg_temp.must(has_function_privilege('trust_crl_publisher', 'published_delta_crl(uuid)', 'EXECUTE'), 'publisher reads deltas');
    FOREACH r IN ARRAY ARRAY['trust_crl_operator', 'trust_ca_admin', 'trust_revocation_officer_api',
                             'trust_crl_publisher', 'trust_audit_verifier'] LOOP
        PERFORM pg_temp.must(NOT has_function_privilege(r, 'reserve_delta_crl(uuid,text,text)', 'EXECUTE'), r || ' cannot reserve deltas');
        PERFORM pg_temp.must(NOT has_table_privilege(r, 'crl_delta_release', 'INSERT'), r || ' cannot write releases');
    END LOOP;
    PERFORM pg_temp.must(NOT has_function_privilege('public', 'reserve_delta_crl(uuid,text,text)', 'EXECUTE'), 'not PUBLIC');
    PERFORM pg_temp.must(NOT has_function_privilege('public', 'published_delta_crl(uuid)', 'EXECUTE'), 'not PUBLIC');
END $t$;

ROLLBACK;
