-- Lab-only: CRL pipeline robustness (migration 0016). Single transaction,
-- rolled back. Rows that only time can produce (old reservations, a clock
-- behind the latest CRL) are inserted directly as table owner.
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

CREATE FUNCTION pg_temp.intent(p_ca UUID, p_n BIGINT, p_op TEXT, p_tbs BYTEA) RETURNS TEXT
LANGUAGE sql AS $f$
    SELECT record_crl_intent(p_ca, p_n, p_op, p_tbs, pg_temp.snapshot_digest(p_ca, p_n),
               floor(extract(epoch FROM cp.this_update))::bigint,
               floor(extract(epoch FROM cp.next_update))::bigint,
               floor(extract(epoch FROM cp.expired_certs_on_crl_since))::bigint)
    FROM crl_publication cp WHERE cp.ca_id = p_ca AND cp.crl_number = p_n
$f$;

INSERT INTO ca(ca_id, display_name, policy_version) VALUES
    ('c0c0c0c0-0000-4000-8000-000000000016', 'CRL Robustness Lab CA', 'lab-1');

-- Reservation n made p_age ago, in the 0015 row shape.
CREATE FUNCTION pg_temp.old_reservation(p_n BIGINT, p_age INTERVAL, p_op TEXT) RETURNS VOID
LANGUAGE sql AS $f$
    INSERT INTO crl_publication(ca_id, crl_number, this_update, next_update, status,
                                operation_ref, actor_id, entries_sha256)
    VALUES ('c0c0c0c0-0000-4000-8000-000000000016', p_n,
            date_trunc('second', clock_timestamp() - p_age),
            date_trunc('second', clock_timestamp() - p_age) + INTERVAL '7 days',
            'RESERVED', p_op, 'crl-worker', sha256('\x'::bytea))
$f$;

-- -------------------------------------- intent time and abandoned reservations
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000016';
    v_before TIMESTAMPTZ;
BEGIN
    PERFORM pg_temp.old_reservation(1, INTERVAL '3 days', 'stale-op');
    PERFORM pg_temp.old_reservation(2, INTERVAL '3 hours', 'old-intent-op');
    PERFORM pg_temp.old_reservation(3, INTERVAL '0 seconds', 'fresh-op');

    -- the intent time is the moment of the intent, not the reservation
    v_before := clock_timestamp();
    PERFORM pg_temp.intent(ca, 2, 'old-intent-op', sha256('tbs-2'::bytea));
    PERFORM pg_temp.must((SELECT intent_recorded_at >= v_before FROM crl_publication
        WHERE ca_id = ca AND crl_number = 2), 'intent_recorded_at stamped at the intent');

    -- an intent recorded just now is not stale although its reservation is
    PERFORM pg_temp.must(quarantine_stale_crl_intents(ca, INTERVAL '1 hour') = 0,
        'fresh intent on an old reservation is not quarantined');
    PERFORM pg_temp.must((SELECT status FROM crl_publication
        WHERE ca_id = ca AND crl_number = 2) = 'INTENT_RECORDED', 'number 2 still INTENT_RECORDED');

    -- only RESERVED rows older than the threshold are abandoned
    PERFORM pg_temp.must(abandon_stale_crl_reservations(ca, INTERVAL '1 hour') = 1,
        'one stale reservation abandoned');
    PERFORM pg_temp.must((SELECT array_agg(status ORDER BY crl_number) FROM crl_publication
        WHERE ca_id = ca) = ARRAY['ABANDONED','INTENT_RECORDED','RESERVED'],
        'statuses after abandon');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = ca
        AND event_type = 'crl.abandoned' AND decision = 'ABANDONED:1'
        AND actor_id = 'crl-worker') = 1, 'audit crl.abandoned');
    PERFORM pg_temp.must(abandon_stale_crl_reservations(ca, INTERVAL '1 hour') = 0,
        'abandon is idempotent');

    -- an abandoned reservation can never be signed, quarantined or reopened
    PERFORM pg_temp.expect_err($$SELECT pg_temp.intent('c0c0c0c0-0000-4000-8000-000000000016',
        1, 'stale-op', sha256('tbs-1'::bytea))$$, '23514');
    PERFORM pg_temp.expect_err($$SELECT mark_crl_uncertain('c0c0c0c0-0000-4000-8000-000000000016',
        1, 'stale-op')$$, '23514');
    PERFORM pg_temp.expect_err($$UPDATE crl_publication SET status = 'RESERVED'
        WHERE ca_id = 'c0c0c0c0-0000-4000-8000-000000000016' AND crl_number = 1$$, '23514');
    PERFORM pg_temp.expect_err($$DELETE FROM crl_publication
        WHERE ca_id = 'c0c0c0c0-0000-4000-8000-000000000016' AND crl_number = 1$$, '23514');

    -- intent_recorded_at is set once, only by the intent transition
    PERFORM pg_temp.expect_err($$UPDATE crl_publication SET intent_recorded_at = now()
        WHERE ca_id = 'c0c0c0c0-0000-4000-8000-000000000016' AND crl_number = 2$$, '23514');
    PERFORM pg_temp.expect_err($$UPDATE crl_publication
        SET status = 'INTENT_RECORDED', tbs_sha256 = sha256('x'::bytea)
        WHERE ca_id = 'c0c0c0c0-0000-4000-8000-000000000016' AND crl_number = 3$$, '23514');

    -- numbering continues above abandoned numbers (never reused)
    PERFORM pg_temp.must((SELECT crl_number FROM reserve_crl(ca, 'crl-worker', 'next-op')) = 4,
        'next number after an abandoned one');

    PERFORM pg_temp.expect_err($$SELECT abandon_stale_crl_reservations(
        'c0c0c0c0-0000-4000-8000-000000000016', INTERVAL '-1 second')$$, '22023');
    PERFORM pg_temp.expect_err($$SELECT abandon_stale_crl_reservations(NULL, INTERVAL '1 hour')$$, '22023');
END $t$;

-- ------------------------------------------ thisUpdate never moves backwards
INSERT INTO ca(ca_id, display_name, policy_version) VALUES
    ('c0c0c0c0-0000-4000-8000-000000000017', 'CRL Clock Lab CA', 'lab-1');
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000017';
    r RECORD;
BEGIN
    -- Equal thisUpdate (two reservations in one second) stays allowed.
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'clock-op-1');
    PERFORM pg_temp.must((SELECT crl_number FROM reserve_crl(ca, 'crl-worker', 'clock-op-2')) = 2,
        'same-second reservations are allowed');

    -- A CRL already reserved one hour ahead: the database clock is now behind
    -- it (clock stepped back), so the next reservation fails closed.
    INSERT INTO crl_publication(ca_id, crl_number, this_update, next_update, status,
                                operation_ref, actor_id, entries_sha256)
    VALUES (ca, 3, date_trunc('second', clock_timestamp()) + INTERVAL '1 hour',
            date_trunc('second', clock_timestamp()) + INTERVAL '1 hour 7 days',
            'ABANDONED', 'clock-op-3', 'crl-worker', sha256('\x'::bytea));
    PERFORM pg_temp.expect_err_msg(
        $$SELECT * FROM reserve_crl('c0c0c0c0-0000-4000-8000-000000000017', 'crl-worker', 'clock-op-4')$$,
        '23514', 'clock is behind the latest CRL thisUpdate of this CA');
    PERFORM pg_temp.must((SELECT count(*) FROM crl_publication WHERE ca_id = ca) = 3,
        'nothing reserved while the clock is behind');
END $t$;

-- --------------------------------------------------- revoked_at stays encodable
-- Direct (legacy-style) rows, bypassing the lifecycle functions: a revocation
-- date the CRL builder cannot encode would break every later CRL of the CA.
INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
VALUES ('d1d1d1d1-0000-4000-8000-000000000016', 'c0c0c0c0-0000-4000-8000-000000000017',
        'idem-range', sha256('csr-range'::bytea), 'requester', 'lab-1', 'PUBLISHED');
INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
VALUES ('c0c0c0c0-0000-4000-8000-000000000017', '\x16', 'd1d1d1d1-0000-4000-8000-000000000016');
INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                        certificate_der, signed_at)
VALUES ('c0c0c0c0-0000-4000-8000-000000000017', '\x16', 'd1d1d1d1-0000-4000-8000-000000000016',
        sha256('der-range'::bytea), decode('3003020101', 'hex'), now());
DO $t$ BEGIN
    PERFORM pg_temp.expect_err($$INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at, actor_id)
        VALUES ('c0c0c0c0-0000-4000-8000-000000000017', '\x16', 1, '1969-12-31 23:59:59+00', 'legacy')$$, '23514');
    PERFORM pg_temp.expect_err($$INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at, actor_id)
        VALUES ('c0c0c0c0-0000-4000-8000-000000000017', '\x16', 1, '10000-01-01 00:00:00+00', 'legacy')$$, '23514');
    PERFORM pg_temp.expect_err($$INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at, actor_id)
        VALUES ('c0c0c0c0-0000-4000-8000-000000000017', '\x16', 1, 'infinity', 'legacy')$$, '23514');
    -- both bounds are encodable and accepted
    INSERT INTO revocation(ca_id, serial_der_content, reason_code, revoked_at, actor_id)
    VALUES ('c0c0c0c0-0000-4000-8000-000000000017', '\x16', 6, '1970-01-01 00:00:00+00', 'legacy');
    UPDATE revocation SET reason_code = 1, revoked_at = '1970-01-01 00:00:00+00'
    WHERE ca_id = 'c0c0c0c0-0000-4000-8000-000000000017' AND serial_der_content = '\x16';
END $t$;

-- ------------------------------- intent ordering and staleness (migration 0017)
INSERT INTO ca(ca_id, display_name, policy_version) VALUES
    ('c0c0c0c0-0000-4000-8000-000000000018', 'CRL Order Lab CA', 'lab-1');
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000018';
BEGIN
    -- two workers reserve 1 and 2; 2 is signed and stored first
    PERFORM reserve_crl(ca, 'crl-worker', 'order-op-1');
    PERFORM reserve_crl(ca, 'crl-worker', 'order-op-2');
    PERFORM pg_temp.intent(ca, 2, 'order-op-2', sha256('tbs-2'::bytea));
    PERFORM store_verified_crl(ca, 2, 'order-op-2', sha256('tbs-2'::bytea),
                               sha256('der-2'::bytea), 'der-2'::bytea);
    -- CRL 1 would now be older than a stored CRL: never signed
    PERFORM pg_temp.expect_err_msg($$SELECT pg_temp.intent('c0c0c0c0-0000-4000-8000-000000000018',
        1, 'order-op-1', sha256('tbs-1'::bytea))$$, '23514',
        'CRL intent refused: a higher CRL number is already stored');
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE ca_id = ca AND crl_number = 1)
        = 'RESERVED', 'refused intent leaves the reservation untouched');

    -- a reservation older than the issue interval (default 24 h) is stale:
    -- a newer CRL is already due, so it is never signed
    INSERT INTO crl_publication(ca_id, crl_number, this_update, next_update, status,
                                operation_ref, actor_id, entries_sha256)
    VALUES (ca, 3, date_trunc('second', clock_timestamp() - INTERVAL '25 hours'),
            date_trunc('second', clock_timestamp() - INTERVAL '25 hours') + INTERVAL '7 days',
            'RESERVED', 'order-op-3', 'crl-worker', sha256('\x'::bytea));
    PERFORM pg_temp.expect_err_msg($$SELECT pg_temp.intent('c0c0c0c0-0000-4000-8000-000000000018',
        3, 'order-op-3', sha256('tbs-3'::bytea))$$, '23514',
        'CRL intent refused: reservation older than the CRL issue interval');
    -- the per-CA interval applies
    INSERT INTO ca_revocation_policy(ca_id, crl_issue_interval, crl_validity)
    VALUES (ca, INTERVAL '2 days', INTERVAL '7 days');
    PERFORM pg_temp.must(pg_temp.intent(ca, 3, 'order-op-3', sha256('tbs-3'::bytea))
        = 'INTENT_RECORDED', 'within a 2-day interval the intent is accepted');
END $t$;

-- ----------------------------- suspension CPS reference is meaningful (0018)
INSERT INTO ca(ca_id, display_name, policy_version) VALUES
    ('c0c0c0c0-0000-4000-8000-000000000019', 'CPS Ref Lab CA', 'lab-1');
DO $t$ BEGIN
    -- an ETSI target with suspension needs a CPS reference; blanks are not one
    PERFORM pg_temp.expect_err($$INSERT INTO ca_revocation_policy(ca_id, conformance_target,
        suspension_allowed, suspension_cps_ref)
        VALUES ('c0c0c0c0-0000-4000-8000-000000000019', 'ETSI_EN_319_411_1', true, '   ')$$, '23514');
    PERFORM pg_temp.expect_err($$INSERT INTO ca_revocation_policy(ca_id, suspension_cps_ref)
        VALUES ('c0c0c0c0-0000-4000-8000-000000000019', E'\t\n')$$, '23514');
    INSERT INTO ca_revocation_policy(ca_id, conformance_target, suspension_allowed, suspension_cps_ref)
    VALUES ('c0c0c0c0-0000-4000-8000-000000000019', 'ETSI_EN_319_411_1', true, 'CPS 4.9.13');
END $t$;

-- --------------------------- lifecycle audit names the change and reason (0018)
INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
SELECT ('d1d1d1d1-0000-4000-8000-00000000002' || n)::uuid, 'c0c0c0c0-0000-4000-8000-000000000019',
       'idem-audit-' || n, sha256(('csr-audit' || n)::bytea), 'requester', 'lab-1', 'PUBLISHED'
FROM generate_series(1, 3) n;
INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
SELECT 'c0c0c0c0-0000-4000-8000-000000000019', decode('2' || n, 'hex'),
       ('d1d1d1d1-0000-4000-8000-00000000002' || n)::uuid
FROM generate_series(1, 3) n;
INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                        certificate_der, signed_at)
SELECT 'c0c0c0c0-0000-4000-8000-000000000019', decode('2' || n, 'hex'),
       ('d1d1d1d1-0000-4000-8000-00000000002' || n)::uuid,
       sha256(('der-audit' || n)::bytea), decode('3003020101', 'hex'), now()
FROM generate_series(1, 3) n;
INSERT INTO revocation_officer_grant(issuer, subject, ca_id) VALUES
 ('https://idp.lab.invalid', 'maker',   'c0c0c0c0-0000-4000-8000-000000000019'),
 ('https://idp.lab.invalid', 'checker', 'c0c0c0c0-0000-4000-8000-000000000019');
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000019';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    c1 UUID; c2 UUID; c3 UUID;
BEGIN
    c1 := propose_certificate_status_change(ca, '\x21', 'REVOKE', 4::smallint, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c1, iss, 'checker', 'REVOKE', 4::smallint);
    c2 := propose_certificate_status_change(ca, '\x22', 'REVOKE', 1::smallint, NULL, iss, 'maker');
    PERFORM reject_certificate_status_change(c2, iss, 'checker');
    c3 := propose_certificate_status_change(ca, '\x23', 'SUSPEND', 6::smallint, NULL, iss, 'maker');
    PERFORM withdraw_certificate_status_change(c3, iss, 'maker');
    -- one transaction: recorded_at is identical, so compare as sorted sets
    PERFORM pg_temp.must((SELECT array_agg(event_type || '=' || decision ORDER BY event_type || '=' || decision)
        FROM audit_event WHERE ca_id = ca AND event_type LIKE 'certificate.status.%')
        = (SELECT array_agg(x ORDER BY x) FROM unnest(ARRAY[
            'certificate.status.proposed=REVOKE:pending_approval:change=' || c1 || ':reason=4',
            'certificate.status.approved=REVOKE:applied:change=' || c1 || ':reason=4',
            'certificate.status.proposed=REVOKE:pending_approval:change=' || c2 || ':reason=1',
            'certificate.status.rejected=REVOKE:rejected:change=' || c2 || ':reason=1',
            'certificate.status.proposed=SUSPEND:pending_approval:change=' || c3 || ':reason=6',
            'certificate.status.withdrawn=SUSPEND:withdrawn:change=' || c3 || ':reason=6']) x),
        'lifecycle audit decisions carry change id and reason');
END $t$;

ROLLBACK;
