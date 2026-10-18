-- Lab-only: durable CRL numbering, signing intents, entry snapshots and
-- deadline queries (migration 0015). Single transaction, rolled back.
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

-- Fixtures (inserted as table owner): one CA, two issued certificates.
INSERT INTO ca(ca_id, display_name, policy_version, created_at)
VALUES ('c0c0c0c0-0000-4000-8000-000000000002', 'CRL Pipeline Lab CA', 'lab-1',
        '2026-01-01 00:00:00+00');

INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
SELECT ('d1d1d1d1-0000-4000-8000-00000000000' || n)::uuid,
       'c0c0c0c0-0000-4000-8000-000000000002', 'idem-' || n,
       sha256(('csr' || n)::bytea), 'requester', 'lab-1', 'PUBLISHED'
FROM generate_series(1, 2) n;

INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
SELECT 'c0c0c0c0-0000-4000-8000-000000000002', decode('0' || n, 'hex'),
       ('d1d1d1d1-0000-4000-8000-00000000000' || n)::uuid
FROM generate_series(1, 2) n;

INSERT INTO certificate(ca_id, serial_der_content, request_id,
                        fingerprint_sha256, certificate_der, signed_at)
SELECT 'c0c0c0c0-0000-4000-8000-000000000002', decode('0' || n, 'hex'),
       ('d1d1d1d1-0000-4000-8000-00000000000' || n)::uuid,
       sha256(('der' || n)::bytea), decode('3003020101', 'hex'), now()
FROM generate_series(1, 2) n;

INSERT INTO revocation_officer_grant(issuer, subject, ca_id) VALUES
 ('https://idp.lab.invalid', 'maker',   'c0c0c0c0-0000-4000-8000-000000000002'),
 ('https://idp.lab.invalid', 'checker', 'c0c0c0c0-0000-4000-8000-000000000002');

-- ---------------------------------------------------- numbering and snapshot
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000002';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    r RECORD;
    c UUID;
BEGIN
    -- first CRL: number 1, empty snapshot, second precision, default validity
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-1');
    PERFORM pg_temp.must(r.crl_number = 1, 'first number is 1');
    PERFORM pg_temp.must(r.next_update - r.this_update = INTERVAL '7 days', 'default validity 7 days');
    PERFORM pg_temp.must(r.this_update = date_trunc('second', r.this_update), 'this_update whole seconds');
    PERFORM pg_temp.must(r.expired_certs_on_crl_since IS NULL, 'RFC5280 has no ExpiredCertsOnCRL date');
    PERFORM pg_temp.must((SELECT count(*) FROM crl_snapshot_entries(ca, 1)) = 0, 'empty first snapshot');
    PERFORM pg_temp.must((SELECT count(*) FROM crl_entry_snapshot WHERE ca_id = ca AND crl_number = 1) = 0, 'no snapshot rows stored');
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE ca_id = ca AND crl_number = 1) = 'RESERVED', 'status RESERVED');
    PERFORM pg_temp.must((SELECT entries_sha256 FROM crl_publication WHERE ca_id = ca AND crl_number = 1) = sha256('\x'::bytea), 'empty digest');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE event_type = 'crl.reserved'
        AND ca_id = ca AND request_id IS NULL AND actor_id = 'crl-worker') = 1, 'audit crl.reserved');

    -- revoke serial 1 (keyCompromise) through the Task 1 functions
    c := propose_certificate_status_change(ca, '\x01', 'REVOKE', 1::smallint, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'REVOKE', 1::smallint);

    -- the earlier reservation is immutable history; the next one sees the entry
    -- (a second apart so the approval is older than this_update, see crl_due)
    PERFORM pg_sleep(1.1);
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-2');
    PERFORM pg_temp.must(r.crl_number = 2, 'second number is 2');
    PERFORM pg_temp.must((SELECT count(*) FROM crl_snapshot_entries(ca, 1)) = 0, 'snapshot 1 unchanged');
    PERFORM pg_temp.must((SELECT count(*) FROM crl_snapshot_entries(ca, 2)) = 1, 'snapshot 2 has one entry');
    PERFORM pg_temp.must((SELECT reason_code FROM crl_snapshot_entries(ca, 2)) = 1, 'snapshot reason 1');
    PERFORM pg_temp.must((SELECT serial_der_content FROM crl_snapshot_entries(ca, 2)) = '\x01', 'snapshot serial');
    PERFORM pg_temp.must((SELECT entries_sha256 FROM crl_publication WHERE ca_id = ca AND crl_number = 2)
        = sha256(int4send(1) || '\x01'::bytea
                 || int8send((SELECT floor(extract(epoch FROM revoked_at))::bigint FROM revocation WHERE ca_id = ca))
                 || int2send(1::smallint) || int8send(-1::bigint)), 'entries digest formula');

    -- input validation
    PERFORM pg_temp.expect_err($q$SELECT * FROM reserve_crl(NULL, 'a', 'op-x')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT * FROM reserve_crl('c0c0c0c0-0000-4000-8000-000000000002', NULL, 'op-x')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT * FROM reserve_crl('c0c0c0c0-0000-4000-8000-000000000002', 'a', '')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT * FROM reserve_crl(gen_random_uuid(), 'a', 'op-x')$q$, '22023');
    -- operation_ref is unique per CA
    PERFORM pg_temp.expect_err($q$SELECT * FROM reserve_crl('c0c0c0c0-0000-4000-8000-000000000002', 'a', 'op-2')$q$, '23505');
END $t$;

-- ------------------------------------------------------------ intent / store
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000002';
    tbs CONSTANT BYTEA := sha256('tbs-2'::bytea);
    der CONSTANT BYTEA := '\x3003020101';
    mismatch CONSTANT TEXT := 'CRL intent refused: entries, number or times differ from the reservation';
    dig BYTEA;
    tu BIGINT;
    nu BIGINT;
    r RECORD;
BEGIN
    dig := pg_temp.snapshot_digest(ca, 2);
    SELECT floor(extract(epoch FROM this_update))::bigint, floor(extract(epoch FROM next_update))::bigint
      INTO tu, nu FROM crl_publication WHERE ca_id = ca AND crl_number = 2;
    -- store before an intent fails
    PERFORM pg_temp.expect_err(format($q$SELECT store_verified_crl(%L,2,'op-2',%L,%L,%L)$q$, ca, tbs, sha256(der), der), '23514');
    -- intent for a non-existent number fails
    PERFORM pg_temp.expect_err(format($q$SELECT record_crl_intent(%L,99,'op-2',%L,%L,%s,%s,NULL)$q$, ca, tbs, dig, tu, nu), '23514');
    -- wrong operation fails
    PERFORM pg_temp.expect_err(format($q$SELECT record_crl_intent(%L,2,'op-other',%L,%L,%s,%s,NULL)$q$, ca, tbs, dig, tu, nu), '23514');
    -- bad hash lengths and missing values fail
    PERFORM pg_temp.expect_err(format($q$SELECT record_crl_intent(%L,2,'op-2','\x00',%L,%s,%s,NULL)$q$, ca, dig, tu, nu), '22023');
    PERFORM pg_temp.expect_err(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,'\x00',%s,%s,NULL)$q$, ca, tbs, tu, nu), '22023');
    PERFORM pg_temp.expect_err(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,NULL,%s,%s,NULL)$q$, ca, tbs, tu, nu), '22023');
    PERFORM pg_temp.expect_err(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,%L,NULL,%s,NULL)$q$, ca, tbs, dig, nu), '22023');
    PERFORM pg_temp.expect_err(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,%L,%s,NULL,NULL)$q$, ca, tbs, dig, tu), '22023');
    -- I1: the signed entries, number and times must be the reservation's.
    -- Number 2 has one entry; a CA core that signs an empty list (or other
    -- times) is refused before it can sign.
    PERFORM pg_temp.must(dig <> sha256('\x'::bytea), 'snapshot 2 is not empty');
    PERFORM pg_temp.expect_err_msg(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,%L,%s,%s,NULL)$q$, ca, tbs, sha256('\x'::bytea), tu, nu), '23514', mismatch);
    PERFORM pg_temp.expect_err_msg(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,%L,%s,%s,NULL)$q$, ca, tbs, dig, tu + 1, nu), '23514', mismatch);
    PERFORM pg_temp.expect_err_msg(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,%L,%s,%s,NULL)$q$, ca, tbs, dig, tu, nu - 1), '23514', mismatch);
    PERFORM pg_temp.expect_err_msg(format($q$SELECT record_crl_intent(%L,2,'op-2',%L,%L,%s,%s,%s)$q$, ca, tbs, dig, tu, nu, tu - 86400), '23514', mismatch);
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE ca_id = ca AND crl_number = 2) = 'RESERVED', 'mismatched intents leave the row RESERVED');

    PERFORM pg_temp.must(pg_temp.intent(ca, 2, 'op-2', tbs) = 'INTENT_RECORDED', 'intent recorded');
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE ca_id = ca AND crl_number = 2) = 'INTENT_RECORDED', 'status INTENT_RECORDED');
    -- a second identical intent fails (not RESERVED any more)
    PERFORM pg_temp.expect_err(format($q$SELECT pg_temp.intent(%L,2,'op-2',%L)$q$, ca, tbs), '23514');
    PERFORM pg_temp.must((SELECT tbs_sha256 FROM crl_publication WHERE ca_id = ca AND crl_number = 2) = tbs, 'tbs hash stored');

    -- mismatched TBS hash, wrong operation, wrong CRL hash, bad lengths
    PERFORM pg_temp.expect_err(format($q$SELECT store_verified_crl(%L,2,'op-2',%L,%L,%L)$q$, ca, sha256('other'::bytea), sha256(der), der), '23514');
    PERFORM pg_temp.expect_err(format($q$SELECT store_verified_crl(%L,2,'op-other',%L,%L,%L)$q$, ca, tbs, sha256(der), der), '23514');
    PERFORM pg_temp.expect_err(format($q$SELECT store_verified_crl(%L,2,'op-2',%L,%L,%L)$q$, ca, tbs, sha256('wrong'::bytea), der), '22023');
    PERFORM pg_temp.expect_err(format($q$SELECT store_verified_crl(%L,2,'op-2',%L,%L,NULL)$q$, ca, tbs, sha256(der)), '22023');

    PERFORM pg_temp.must(store_verified_crl(ca, 2, 'op-2', tbs, sha256(der), der) = 'STORED', 'store ok');
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE ca_id = ca AND crl_number = 2) = 'STORED', 'status STORED');
    PERFORM pg_temp.must((SELECT crl_der FROM crl_publication WHERE ca_id = ca AND crl_number = 2) = der, 'crl_der stored');
    -- storing twice fails
    PERFORM pg_temp.expect_err(format($q$SELECT store_verified_crl(%L,2,'op-2',%L,%L,%L)$q$, ca, tbs, sha256(der), der), '23514');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = ca AND request_id IS NULL
        AND event_type IN ('crl.intent','crl.stored')) = 2, 'audit intent+stored');

    -- number 3: uncertain after intent; never storable; numbering moves on
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-3');
    PERFORM pg_temp.must(r.crl_number = 3, 'third number is 3');
    PERFORM pg_temp.intent(ca, 3, 'op-3', sha256('tbs-3'::bytea));
    PERFORM pg_temp.expect_err(format($q$SELECT mark_crl_uncertain(%L,3,'op-other')$q$, ca), '23514');
    PERFORM pg_temp.must(mark_crl_uncertain(ca, 3, 'op-3') = 'RECONCILIATION_REQUIRED', 'uncertain');
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE ca_id = ca AND crl_number = 3) = 'RECONCILIATION_REQUIRED', 'status RECONCILIATION_REQUIRED');
    PERFORM pg_temp.expect_err(format($q$SELECT store_verified_crl(%L,3,'op-3',%L,%L,%L)$q$, ca, sha256('tbs-3'::bytea), sha256(der), der), '23514');
    PERFORM pg_temp.expect_err(format($q$SELECT mark_crl_uncertain(%L,3,'op-3')$q$, ca), '23514');
    PERFORM pg_temp.expect_err(format($q$SELECT pg_temp.intent(%L,3,'op-3',%L)$q$, ca, sha256('tbs-3'::bytea)), '23514');
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-4');
    PERFORM pg_temp.must(r.crl_number = 4, 'next after quarantined is 4 (never reused)');
    -- a RESERVED row can be marked uncertain directly (crash before intent)
    PERFORM pg_temp.must(mark_crl_uncertain(ca, 4, 'op-4') = 'RECONCILIATION_REQUIRED', 'reserved -> uncertain');

    -- stale intents are quarantined; RESERVED rows are not "intents"
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-5');
    PERFORM pg_temp.must(quarantine_stale_crl_intents(ca, INTERVAL '0 seconds') = 0, 'nothing stale yet');
    PERFORM pg_temp.intent(ca, 5, 'op-5', sha256('tbs-5'::bytea));
    PERFORM pg_temp.must(quarantine_stale_crl_intents(ca, INTERVAL '1 day') = 0, 'young intent kept');
    PERFORM pg_temp.must(quarantine_stale_crl_intents(ca, INTERVAL '0 seconds') = 1, 'stale intent quarantined');
    PERFORM pg_temp.must((SELECT status FROM crl_publication WHERE ca_id = ca AND crl_number = 5) = 'RECONCILIATION_REQUIRED', 'quarantined status');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = ca AND event_type = 'crl.quarantined') = 1, 'audit crl.quarantined');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = ca AND event_type = 'crl.uncertain') = 2, 'audit crl.uncertain');
END $t$;

-- ----------------------------------------------------------- due / overdue
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000002';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    tbs CONSTANT BYTEA := sha256('tbs-6'::bytea);
    der CONSTANT BYTEA := '\x3003020101';
    r RECORD;
    c UUID;
BEGIN
    -- a STORED row exists (number 2): its age is below the 24 h interval
    PERFORM pg_temp.must(NOT crl_due(ca), 'not due: fresh stored CRL and no later approval');
    -- a later approval makes a CRL due (second apart so decided_at > this_update)
    PERFORM pg_sleep(1.1);
    c := propose_certificate_status_change(ca, '\x02', 'REVOKE', 4::smallint, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'REVOKE', 4::smallint);
    PERFORM pg_temp.must(crl_due(ca), 'due after new approval');
    -- not overdue yet (24 h deadline)
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 0, 'no overdue with default deadline');

    -- publish a CRL covering the approval
    PERFORM pg_sleep(1.1);
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-6');
    PERFORM pg_temp.must((SELECT count(*) FROM crl_snapshot_entries(ca, r.crl_number)) = 2, 'both revocations in snapshot');
    PERFORM pg_temp.must((SELECT array_agg(serial_der_content ORDER BY serial_der_content) FROM crl_snapshot_entries(ca, r.crl_number))
        = ARRAY['\x01'::bytea, '\x02'::bytea], 'snapshot ordered by serial');
    PERFORM pg_temp.intent(ca, r.crl_number, 'op-6', tbs);
    PERFORM store_verified_crl(ca, r.crl_number, 'op-6', tbs, sha256(der), der);
    PERFORM pg_temp.must(NOT crl_due(ca), 'not due right after storing');

    -- a policy row with the default-sized interval changes nothing
    INSERT INTO ca_revocation_policy(ca_id, crl_issue_interval) VALUES (ca, INTERVAL '1 hour');
    PERFORM pg_temp.must(NOT crl_due(ca), 'not due within the 1 hour interval');
    PERFORM pg_temp.expect_err($q$SELECT crl_due(NULL)$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT * FROM overdue_status_changes(NULL)$q$, '22023');
END $t$;

-- A CA without any STORED CRL is due.
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000003', 'Empty CRL CA', 'lab-1');
DO $t$
BEGIN
    PERFORM pg_temp.must(crl_due('c0c0c0c0-0000-4000-8000-000000000003'), 'due before any STORED');
END $t$;

-- ------------------------------------------------------------ overdue queries
-- Fixture inserted directly: the guard trigger forbids changing proposed_at.
INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
VALUES ('d1d1d1d1-0000-4000-8000-000000000009', 'c0c0c0c0-0000-4000-8000-000000000002',
        'idem-9', sha256('csr9'::bytea), 'requester', 'lab-1', 'PUBLISHED');
INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
VALUES ('c0c0c0c0-0000-4000-8000-000000000002', '\x09', 'd1d1d1d1-0000-4000-8000-000000000009');
INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at)
VALUES ('c0c0c0c0-0000-4000-8000-000000000002', '\x09', 'd1d1d1d1-0000-4000-8000-000000000009',
        sha256('der9'::bytea), '\x3003020101', now());
INSERT INTO certificate_status_change(change_id, ca_id, serial_der_content, action, reason_code,
                                      maker_issuer, maker_subject, status, proposed_at)
VALUES ('e0e0e0e0-0000-4000-8000-000000000009', 'c0c0c0c0-0000-4000-8000-000000000002', '\x09',
        'REVOKE', 1, 'https://idp.lab.invalid', 'maker', 'PROPOSED',
        clock_timestamp() - INTERVAL '2 hours');

DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000002';
BEGIN
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 0, 'empty with default 24 h deadline');
    UPDATE ca_revocation_policy SET status_publication_deadline = INTERVAL '1 hour' WHERE ca_id = ca;
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 1, 'one overdue PROPOSED');
    PERFORM pg_temp.must((SELECT status FROM overdue_status_changes(ca)) = 'PROPOSED', 'overdue status PROPOSED');
    PERFORM pg_temp.must((SELECT change_id FROM overdue_status_changes(ca)) = 'e0e0e0e0-0000-4000-8000-000000000009', 'overdue change id');
END $t$;

-- APPROVED and not yet on a STORED CRL, past the deadline.
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000002';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    c UUID := 'e0e0e0e0-0000-4000-8000-000000000009';
BEGIN
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'REVOKE', 1::smallint);
    -- the deadline counts from proposal: proposed 2 hours ago, no STORED CRL
    -- covers the decision yet
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 1, 'approved but unpublished is overdue');
    PERFORM pg_temp.must((SELECT status FROM overdue_status_changes(ca)) = 'APPROVED', 'overdue status APPROVED');
    -- a STORED CRL no older than the decision covers it
    PERFORM pg_sleep(1.1);
    PERFORM reserve_crl(ca, 'crl-worker', 'op-7');
    PERFORM pg_temp.intent(ca, 7, 'op-7', sha256('tbs-7'::bytea));
    PERFORM store_verified_crl(ca, 7, 'op-7', sha256('tbs-7'::bytea), sha256('\x3003020101'::bytea), '\x3003020101');
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 0, 'covered by a later STORED CRL');
END $t$;

-- ------------------------------------------------------------ ETSI date
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000002';
    r RECORD;
BEGIN
    UPDATE ca_revocation_policy SET conformance_target = 'ETSI_EN_319_411_1',
        crl_issue_interval = INTERVAL '12 hours' WHERE ca_id = ca;
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-8');
    PERFORM pg_temp.must(r.expired_certs_on_crl_since IS NULL, 'ETSI 411-1 has no ExpiredCertsOnCRL');
    UPDATE ca_revocation_policy SET conformance_target = 'ETSI_EN_319_411_2' WHERE ca_id = ca;
    SELECT * INTO r FROM reserve_crl(ca, 'crl-worker', 'op-9');
    PERFORM pg_temp.must(r.expired_certs_on_crl_since = '2026-01-01 00:00:00+00', 'ETSI 411-2 uses ca.created_at');
    PERFORM pg_temp.must((SELECT expired_certs_on_crl_since FROM crl_publication WHERE ca_id = ca AND crl_number = r.crl_number)
        = '2026-01-01 00:00:00+00', 'date stored on the row');
END $t$;

-- ------------------------------------------------------------ immutability
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000002';
BEGIN
    PERFORM pg_temp.expect_err($q$UPDATE crl_publication SET crl_der='\x00' WHERE status='STORED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE crl_publication SET status='RECONCILIATION_REQUIRED' WHERE status='STORED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE crl_publication SET published_at=now() WHERE status='STORED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$DELETE FROM crl_publication WHERE status='STORED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$DELETE FROM crl_publication$q$, '23514');
    PERFORM pg_temp.expect_err($q$TRUNCATE crl_publication CASCADE$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE crl_entry_snapshot SET reason_code = 0$q$, '23514');
    PERFORM pg_temp.expect_err($q$DELETE FROM crl_entry_snapshot$q$, '23514');
    PERFORM pg_temp.expect_err($q$TRUNCATE crl_entry_snapshot$q$, '23514');
    -- quarantined rows are final too, and identity columns never change
    PERFORM pg_temp.expect_err($q$UPDATE crl_publication SET status='RESERVED' WHERE status='RECONCILIATION_REQUIRED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE crl_publication SET crl_number = 100 WHERE crl_number = 8$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE crl_publication SET entries_sha256 = sha256('x'::bytea) WHERE crl_number = 8$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE crl_publication SET status='STORED' WHERE crl_number = 8$q$, '23514');
    -- table CHECKs hold for the owner
    PERFORM pg_temp.expect_err(format($q$INSERT INTO crl_publication(ca_id,crl_number,this_update,next_update,status,operation_ref,actor_id,entries_sha256)
        VALUES (%L,0,now(),now()+interval '1 day','RESERVED','z0','a',sha256('x'::bytea))$q$, ca), '23514');
    PERFORM pg_temp.expect_err(format($q$INSERT INTO crl_publication(ca_id,crl_number,this_update,next_update,status,operation_ref,actor_id,entries_sha256)
        VALUES (%L,9223372036854775807,now(),now()+interval '1 day','RESERVED','z1','a',sha256('x'::bytea))$q$, ca), '23514');
    PERFORM pg_temp.expect_err(format($q$INSERT INTO crl_publication(ca_id,crl_number,this_update,next_update,status,operation_ref,actor_id,entries_sha256)
        VALUES (%L,50,now(),now()+interval '1 day','STORED','z2','a',sha256('x'::bytea))$q$, ca), '23514');
    PERFORM pg_temp.expect_err(format($q$INSERT INTO crl_publication(ca_id,crl_number,this_update,next_update,status,operation_ref,actor_id,entries_sha256)
        VALUES (%L,51,now(),now()+interval '1 day','BOGUS','z3','a',sha256('x'::bytea))$q$, ca), '23514');
END $t$;

-- ---------------------------------------------------------------- privileges
DO $t$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'reserve_crl(uuid,text,text)',
        'crl_snapshot_entries(uuid,bigint)',
        'record_crl_intent(uuid,bigint,text,bytea,bytea,bigint,bigint,bigint)',
        'mark_crl_uncertain(uuid,bigint,text)',
        'store_verified_crl(uuid,bigint,text,bytea,bytea,bytea)',
        'quarantine_stale_crl_intents(uuid,interval)',
        'crl_due(uuid)',
        'crl_change_covered(uuid,boolean)',
        'crl_entry_encoding(bytea,timestamptz,smallint,timestamptz)',
        'overdue_status_changes(uuid)',
        'guard_crl_publication()',
        'guard_crl_entry_snapshot()']
    LOOP
        PERFORM pg_temp.must(NOT has_function_privilege('public', f, 'EXECUTE'), 'PUBLIC may execute ' || f);
        PERFORM pg_temp.must(NOT has_function_privilege('trust_api_reader', f, 'EXECUTE'), 'reader may execute ' || f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY['crl_entry_snapshot','crl_publication']
    LOOP
        PERFORM pg_temp.must(NOT has_table_privilege('trust_api_reader', f, 'SELECT'), 'reader may SELECT ' || f);
        PERFORM pg_temp.must(NOT has_table_privilege('public', f, 'SELECT'), 'PUBLIC may SELECT ' || f);
    END LOOP;
END $t$;

-- ----------------------------------------- coverage must be proven by the CRL
-- A STORED CRL covers an approved change only if its snapshot reflects it.
-- Fixture rows are inserted directly (owner), including STORED publications.
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000004', 'CRL Coverage Lab CA', 'lab-1');
INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
SELECT ('d2d2d2d2-0000-4000-8000-00000000000' || n)::uuid,
       'c0c0c0c0-0000-4000-8000-000000000004', 'idem-' || n,
       sha256(('csr' || n)::bytea), 'requester', 'lab-1', 'PUBLISHED'
FROM generate_series(1, 2) n;
INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
SELECT 'c0c0c0c0-0000-4000-8000-000000000004', decode('0' || n, 'hex'),
       ('d2d2d2d2-0000-4000-8000-00000000000' || n)::uuid
FROM generate_series(1, 2) n;
INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                        certificate_der, signed_at)
SELECT 'c0c0c0c0-0000-4000-8000-000000000004', decode('0' || n, 'hex'),
       ('d2d2d2d2-0000-4000-8000-00000000000' || n)::uuid,
       sha256(('der' || n)::bytea), '\x3003020101', now()
FROM generate_series(1, 2) n;
INSERT INTO ca_revocation_policy(ca_id, status_publication_deadline)
VALUES ('c0c0c0c0-0000-4000-8000-000000000004', INTERVAL '1 hour');
-- serial 1: REVOKE (reason 1) approved 90 min ago; serial 2: RELEASE approved 45 min ago
INSERT INTO certificate_status_change(change_id, ca_id, serial_der_content, action, reason_code,
    maker_issuer, maker_subject, checker_issuer, checker_subject, status, proposed_at, decided_at)
VALUES
 ('e1e1e1e1-0000-4000-8000-000000000001', 'c0c0c0c0-0000-4000-8000-000000000004', '\x01', 'REVOKE', 1,
  'i', 'm', 'i', 'c', 'APPROVED', clock_timestamp() - INTERVAL '2 hours', clock_timestamp() - INTERVAL '90 minutes'),
 ('e1e1e1e1-0000-4000-8000-000000000002', 'c0c0c0c0-0000-4000-8000-000000000004', '\x02', 'RELEASE', NULL,
  'i', 'm', 'i', 'c', 'APPROVED', clock_timestamp() - INTERVAL '2 hours', clock_timestamp() - INTERVAL '45 minutes');

CREATE FUNCTION pg_temp.fixture_stored_crl(p_number BIGINT, p_age INTERVAL) RETURNS VOID
LANGUAGE sql AS $f$
    INSERT INTO crl_publication(ca_id, crl_number, this_update, next_update, status,
        operation_ref, actor_id, entries_sha256, tbs_sha256, crl_der, crl_sha256)
    VALUES ('c0c0c0c0-0000-4000-8000-000000000004', p_number,
        date_trunc('second', clock_timestamp()) - p_age,
        date_trunc('second', clock_timestamp()) - p_age + INTERVAL '7 days', 'STORED',
        'fixture-' || p_number, 'fixture', sha256('e'::bytea), sha256('t'::bytea),
        '\x3003020101', sha256('\x3003020101'::bytea));
$f$;

DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000004';
BEGIN
    -- CRL 1 (60 min old, after both decisions) is STORED but its snapshot is empty
    PERFORM pg_temp.fixture_stored_crl(1, INTERVAL '60 minutes');
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 2, 'empty snapshot covers nothing');
    PERFORM pg_temp.must(crl_due(ca), 'due: latest STORED CRL does not reflect the REVOKE');

    -- CRL 2 lists serial 1 with the WRONG reason and serial 2 (the released one)
    PERFORM pg_temp.fixture_stored_crl(2, INTERVAL '30 minutes');
    INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content, revoked_at, reason_code)
    VALUES (ca, 2, '\x01', now(), 2), (ca, 2, '\x02', now(), 6);
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 2, 'wrong reason / still-listed serial is not covered');
    PERFORM pg_temp.must(crl_due(ca), 'still due with wrong reason');

    -- CRL 3 lists serial 1 with the approved reason and omits serial 2
    PERFORM pg_temp.fixture_stored_crl(3, INTERVAL '10 minutes');
    INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content, revoked_at, reason_code)
    VALUES (ca, 3, '\x01', now(), 1);
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 0, 'reflected changes are covered');
    PERFORM pg_temp.must(NOT crl_due(ca), 'not due once the latest CRL reflects every change');
END $t$;

-- ------------------------------------------ superseded changes stay visible
-- A change replaced by a later approval is judged "covered" once any STORED CRL
-- is at least as new as its decision; until then its deadline breach is still
-- reported. The newest change is judged by the snapshot rule.
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000006', 'CRL Supersession Lab CA', 'lab-1');
INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
SELECT ('d3d3d3d3-0000-4000-8000-00000000000' || n)::uuid,
       'c0c0c0c0-0000-4000-8000-000000000006', 'idem-' || n,
       sha256(('csr' || n)::bytea), 'requester', 'lab-1', 'PUBLISHED'
FROM generate_series(1, 2) n;
INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
SELECT 'c0c0c0c0-0000-4000-8000-000000000006', decode('0' || n, 'hex'),
       ('d3d3d3d3-0000-4000-8000-00000000000' || n)::uuid
FROM generate_series(1, 2) n;
INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256,
                        certificate_der, signed_at)
SELECT 'c0c0c0c0-0000-4000-8000-000000000006', decode('0' || n, 'hex'),
       ('d3d3d3d3-0000-4000-8000-00000000000' || n)::uuid,
       sha256(('der' || n)::bytea), '\x3003020101', now()
FROM generate_series(1, 2) n;
INSERT INTO ca_revocation_policy(ca_id, suspension_allowed, status_publication_deadline)
VALUES ('c0c0c0c0-0000-4000-8000-000000000006', true, INTERVAL '1 hour');
-- serial 1: SUSPEND (decided 90 min ago) then REVOKE (decided 10 min ago)
-- serial 2: SUSPEND (decided 90 min ago) then RELEASE (decided 10 min ago)
-- every proposal is 2 hours old, so every change is past the 1 hour deadline
INSERT INTO certificate_status_change(change_id, ca_id, serial_der_content, action, reason_code,
    maker_issuer, maker_subject, checker_issuer, checker_subject, status, proposed_at, decided_at)
VALUES
 ('e2e2e2e2-0000-4000-8000-000000000001', 'c0c0c0c0-0000-4000-8000-000000000006', '\x01', 'SUSPEND', 6,
  'i', 'm', 'i', 'c', 'APPROVED', clock_timestamp() - INTERVAL '2 hours', clock_timestamp() - INTERVAL '90 minutes'),
 ('e2e2e2e2-0000-4000-8000-000000000002', 'c0c0c0c0-0000-4000-8000-000000000006', '\x01', 'REVOKE', 1,
  'i', 'm', 'i', 'c', 'APPROVED', clock_timestamp() - INTERVAL '2 hours', clock_timestamp() - INTERVAL '10 minutes'),
 ('e2e2e2e2-0000-4000-8000-000000000003', 'c0c0c0c0-0000-4000-8000-000000000006', '\x02', 'SUSPEND', 6,
  'i', 'm', 'i', 'c', 'APPROVED', clock_timestamp() - INTERVAL '2 hours', clock_timestamp() - INTERVAL '90 minutes'),
 ('e2e2e2e2-0000-4000-8000-000000000004', 'c0c0c0c0-0000-4000-8000-000000000006', '\x02', 'RELEASE', NULL,
  'i', 'm', 'i', 'c', 'APPROVED', clock_timestamp() - INTERVAL '2 hours', clock_timestamp() - INTERVAL '10 minutes');

CREATE FUNCTION pg_temp.fixture_stored_crl6(p_number BIGINT, p_age INTERVAL) RETURNS VOID
LANGUAGE sql AS $f$
    INSERT INTO crl_publication(ca_id, crl_number, this_update, next_update, status,
        operation_ref, actor_id, entries_sha256, tbs_sha256, crl_der, crl_sha256)
    VALUES ('c0c0c0c0-0000-4000-8000-000000000006', p_number,
        date_trunc('second', clock_timestamp()) - p_age,
        date_trunc('second', clock_timestamp()) - p_age + INTERVAL '7 days', 'STORED',
        'fixture-' || p_number, 'fixture', sha256('e'::bytea), sha256('t'::bytea),
        '\x3003020101', sha256('\x3003020101'::bytea));
$f$;

DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000006';
BEGIN
    -- no CRL at all: all four are reported, including the superseded SUSPENDs
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 4, 'no CRL: superseded changes still overdue');
    PERFORM pg_temp.must(EXISTS (SELECT 1 FROM overdue_status_changes(ca)
        WHERE change_id = 'e2e2e2e2-0000-4000-8000-000000000001'), 'overdue SUSPEND before REVOKE reported');
    PERFORM pg_temp.must(EXISTS (SELECT 1 FROM overdue_status_changes(ca)
        WHERE change_id = 'e2e2e2e2-0000-4000-8000-000000000003'), 'overdue SUSPEND before RELEASE reported');

    -- a CRL newer than the SUSPENDs but older than the newest decisions
    PERFORM pg_temp.fixture_stored_crl6(1, INTERVAL '30 minutes');
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 2, 'superseded changes covered by a newer CRL');
    PERFORM pg_temp.must((SELECT bool_and(change_id IN ('e2e2e2e2-0000-4000-8000-000000000002',
                                                        'e2e2e2e2-0000-4000-8000-000000000004'))
                          FROM overdue_status_changes(ca)), 'only the newest changes remain overdue');

    -- a CRL after the newest decisions that reflects them
    PERFORM pg_temp.fixture_stored_crl6(2, INTERVAL '5 minutes');
    INSERT INTO crl_entry_snapshot(ca_id, crl_number, serial_der_content, revoked_at, reason_code)
    VALUES (ca, 2, '\x01', now(), 1);
    PERFORM pg_temp.must((SELECT count(*) FROM overdue_status_changes(ca)) = 0, 'newest changes reflected by CRL 2');
END $t$;

SELECT 'crl_pipeline: all assertions passed' AS result;
ROLLBACK;

-- ------------------------------------- isolation: reserve_crl fails closed
-- Outside READ COMMITTED the transaction snapshot predates the CA row lock and
-- could miss an approval that committed meanwhile. Separate transactions
-- because the isolation level must be set at BEGIN.
BEGIN ISOLATION LEVEL REPEATABLE READ;
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000005', 'Isolation Lab CA', 'lab-1');
DO $t$
DECLARE ok BOOLEAN := false;
BEGIN
    BEGIN
        PERFORM reserve_crl('c0c0c0c0-0000-4000-8000-000000000005', 'a', 'rr-op');
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = '23514' AND SQLERRM LIKE '%read committed%' THEN ok := true; ELSE RAISE; END IF;
    END;
    IF NOT ok THEN RAISE EXCEPTION 'reserve_crl accepted REPEATABLE READ'; END IF;
END $t$;
ROLLBACK;

BEGIN ISOLATION LEVEL SERIALIZABLE;
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000005', 'Isolation Lab CA', 'lab-1');
DO $t$
DECLARE ok BOOLEAN := false;
BEGIN
    BEGIN
        PERFORM reserve_crl('c0c0c0c0-0000-4000-8000-000000000005', 'a', 'ser-op');
    EXCEPTION WHEN OTHERS THEN
        IF SQLSTATE = '23514' AND SQLERRM LIKE '%read committed%' THEN ok := true; ELSE RAISE; END IF;
    END;
    IF NOT ok THEN RAISE EXCEPTION 'reserve_crl accepted SERIALIZABLE'; END IF;
END $t$;
ROLLBACK;
SELECT 'crl_pipeline: isolation checks passed' AS result;
