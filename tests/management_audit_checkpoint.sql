-- Migration 0037: signed audit checkpoints (ADR-0023). Run as the migration
-- owner after 0037 on a disposable database; every change is rolled back.
-- Placeholder bytes stand for the signatures the laboratory signer produces;
-- the database never verifies them (lab_verify_audit_chain does). Before
-- 0037 the first statement fails.
BEGIN;

SELECT management_audit_checkpoint_version();

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

-- Seal whatever earlier suites left, then three events of our own.
DO $setup$ DECLARE r record; BEGIN
    LOOP
        SELECT * INTO r FROM seal_audit_events_lab(10000);
        EXIT WHEN r.sealed = 0;
    END LOOP;
END $setup$;
INSERT INTO ca (ca_id, display_name, policy_version)
VALUES ('cbcbcbcb-0000-4000-8000-0000000000a1', 'Checkpoint CA', 'v1');
INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version, recorded_at)
SELECT ('cbcbcbcb-0000-4000-8000-0000000000e' || n)::uuid, 'cbcbcbcb-0000-4000-8000-0000000000a1',
       'lab-ra-officer', 'certificate.revoked', 'allow', NULL,
       timestamptz '2026-11-09T12:00:00Z' + n * interval '1 second'
FROM generate_series(1, 3) AS n;
SELECT sealed FROM seal_audit_events_lab(10000) \g /dev/null
CREATE TEMP TABLE head AS
SELECT max(seq) AS seq, (SELECT chain_hash FROM audit_chain_link ORDER BY seq DESC LIMIT 1) AS hash,
       (SELECT chain_hash FROM audit_chain_link ORDER BY seq DESC OFFSET 1 LIMIT 1) AS previous
FROM audit_chain_link;
GRANT SELECT ON head TO PUBLIC;

-- Only the signer role reaches the checkpoint functions and table.
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_audit_checkpoint_latest()$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM audit_chain_checkpoint$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_audit_links(0, 10)$$, '42501');
SELECT pg_temp.expect_state($$SELECT lab_signer_record_audit_checkpoint(1, '\x00', '\x00', 0, '\x00')$$, '42501');
RESET ROLE;

SET LOCAL ROLE trust_lab_signer;
SELECT pg_temp.expect_state($$SELECT * FROM audit_chain_checkpoint$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_audit_links(-1, 10)$$, '22023');
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_audit_links(0, 0)$$, '22023');
SELECT pg_temp.expect_state($$SELECT * FROM lab_signer_audit_links(0, 10001)$$, '22023');
DO $test$
DECLARE
    h record;
    r record;
BEGIN
    SELECT * INTO h FROM head;
    IF EXISTS (SELECT 1 FROM lab_signer_audit_checkpoint_latest()) THEN
        RAISE EXCEPTION 'no checkpoint expected yet';
    END IF;
    -- The links carry the raw event columns the signer recomputes.
    SELECT * INTO r FROM lab_signer_audit_links(h.seq - 1, 10);
    IF r.seq <> h.seq OR r.chain_hash <> h.hash OR r.previous_hash <> h.previous
       OR r.event_id <> uuid_send('cbcbcbcb-0000-4000-8000-0000000000e3') OR r.ca_id IS NULL
       OR r.request_id IS NOT NULL OR r.policy_version IS NOT NULL OR r.actor_id <> 'lab-ra-officer'
       OR r.recorded_at_micros <> (extract(epoch FROM timestamptz '2026-11-09T12:00:03Z') * 1000000)::bigint THEN
        RAISE EXCEPTION 'unexpected link row %', r;
    END IF;
    IF (SELECT count(*) FROM lab_signer_audit_links(h.seq - 3, 2)) <> 2
       OR (SELECT count(*) FROM lab_signer_audit_links(h.seq, 10)) <> 0 THEN
        RAISE EXCEPTION 'link paging is wrong';
    END IF;
END $test$;
-- A checkpoint must name an existing link and its exact hash.
SELECT pg_temp.expect_state($$SELECT lab_signer_record_audit_checkpoint(
    (SELECT seq + 1 FROM head), (SELECT hash FROM head), decode(repeat('ab', 32), 'hex'), 1794225600,
    decode(repeat('30', 70), 'hex'))$$, 'TP409');
SELECT pg_temp.expect_state($$SELECT lab_signer_record_audit_checkpoint(
    (SELECT seq FROM head), (SELECT previous FROM head), decode(repeat('ab', 32), 'hex'), 1794225600,
    decode(repeat('30', 70), 'hex'))$$, 'TP409');
SELECT pg_temp.expect_state($$SELECT lab_signer_record_audit_checkpoint(
    (SELECT seq FROM head), (SELECT hash FROM head), decode(repeat('ab', 32), 'hex'), 1794225600,
    decode(repeat('30', 80), 'hex'))$$, '23514');
-- One before the head, then the head; never backwards or twice.
SELECT lab_signer_record_audit_checkpoint((SELECT seq - 1 FROM head), (SELECT previous FROM head),
    decode(repeat('ab', 32), 'hex'), 1794225600, decode(repeat('30', 70), 'hex'));
SELECT pg_temp.expect_state($$SELECT lab_signer_record_audit_checkpoint(
    (SELECT seq - 1 FROM head), (SELECT previous FROM head), decode(repeat('ab', 32), 'hex'), 1794225601,
    decode(repeat('30', 70), 'hex'))$$, 'TP409');
SELECT lab_signer_record_audit_checkpoint((SELECT seq FROM head), (SELECT hash FROM head),
    decode(repeat('ab', 32), 'hex'), 1794225660, decode(repeat('30', 71), 'hex'));
SELECT pg_temp.expect_state($$SELECT lab_signer_record_audit_checkpoint(
    (SELECT seq - 1 FROM head), (SELECT previous FROM head), decode(repeat('ab', 32), 'hex'), 1794225700,
    decode(repeat('30', 70), 'hex'))$$, 'TP409');
DO $test$
DECLARE
    h record;
    c record;
BEGIN
    SELECT * INTO h FROM head;
    SELECT * INTO c FROM lab_signer_audit_checkpoint_latest();
    IF c.seq <> h.seq OR c.chain_hash <> h.hash OR c.signed_at_unix <> 1794225660
       OR c.key_id <> decode(repeat('ab', 32), 'hex') OR octet_length(c.signature) <> 71 THEN
        RAISE EXCEPTION 'unexpected latest checkpoint %', c;
    END IF;
END $test$;
RESET ROLE;

-- Recording writes no audit event (it would call for another checkpoint);
-- checkpoints are append-only.
DO $test$ BEGIN
    IF (SELECT count(*) FROM audit_chain_checkpoint) <> 2
       OR EXISTS (SELECT 1 FROM audit_event a
                  WHERE NOT EXISTS (SELECT 1 FROM audit_chain_link l WHERE l.event_id = a.event_id)) THEN
        RAISE EXCEPTION 'checkpoints must not add audit events';
    END IF;
END $test$;
SELECT pg_temp.expect_state($$UPDATE audit_chain_checkpoint SET signature = '\x00'$$, 'P0001');
SELECT pg_temp.expect_state($$DELETE FROM audit_chain_checkpoint$$, 'P0001');
SELECT pg_temp.expect_state($$TRUNCATE audit_chain_checkpoint$$, 'P0001');
SELECT pg_temp.expect_state($$INSERT INTO audit_chain_checkpoint (seq, chain_hash, key_id, signed_at, signature)
    VALUES (999999999, decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), now(),
            decode(repeat('30', 70), 'hex'))$$, '23503');
-- A checkpointed link cannot be removed either.
SELECT pg_temp.expect_state($$DELETE FROM audit_chain_link WHERE seq = (SELECT seq FROM head)$$, 'P0001');

ROLLBACK;
\echo 'PASS: signed audit checkpoints (0037)'
