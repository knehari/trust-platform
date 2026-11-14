-- Migration 0036: the tamper-evident audit chain (ADR-0022). Run as the
-- migration owner after 0036 on a disposable database; every change is
-- rolled back. Before 0036 the first statement fails.
BEGIN;

SELECT management_audit_chain_version();

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

-- The canonical encoding matches the vectors of
-- trust_pki_core::audit_chain (Rust unit test), including absent values and
-- an instant before the Unix epoch.
DO $test$ BEGIN
    IF encode(sha256(audit_event_canonical('11111111-1111-4111-8111-111111111111',
            '22222222-2222-4222-8222-222222222222', NULL, 'lab-ra-officer', 'certificate.revoked',
            'allow', 'v1', '2026-11-09T12:00:00.123456Z')), 'hex')
       <> '1950603ca47066137e2477b0a66d2f76d88eba13be0fd6d6ab1cdd50cf9b2911' THEN
        RAISE EXCEPTION 'canonical event digest differs from the Rust vector';
    END IF;
    IF encode(sha256(audit_event_canonical('33333333-3333-4333-8333-333333333333', NULL,
            '44444444-4444-4444-8444-444444444444', 'crl-renewer', 'crl.published', 'persisted',
            NULL, '1969-12-31T23:59:59.5Z')), 'hex')
       <> '1b660fd39da5e79549650877fb1517f8fa8671c746a345b294c8df5886888bcf' THEN
        RAISE EXCEPTION 'canonical event digest (absent values) differs from the Rust vector';
    END IF;
END $test$;

-- Bounds and privileges.
SELECT pg_temp.expect_state($$SELECT * FROM seal_audit_events_lab(0)$$, '22023');
SELECT pg_temp.expect_state($$SELECT * FROM seal_audit_events_lab(10001)$$, '22023');
SELECT pg_temp.expect_state($$SELECT * FROM seal_audit_events_lab(NULL)$$, '22023');
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM seal_audit_events_lab(10)$$, '42501');
SELECT pg_temp.expect_state($$SELECT * FROM audit_chain_link$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM audit_chain_link$$, '42501');
SELECT pg_temp.expect_state($$INSERT INTO audit_chain_link (seq, event_id, event_sha256, previous_hash, chain_hash)
    VALUES (1, gen_random_uuid(), '\x00', '\x00', '\x00')$$, '42501');
RESET ROLE;

-- Seal whatever earlier suites left, so the counts below are exact.
SET LOCAL ROLE trust_profile_writer;
DO $test$ DECLARE r record; BEGIN
    LOOP
        SELECT * INTO r FROM seal_audit_events_lab(10000);
        EXIT WHEN r.sealed = 0;
    END LOOP;
END $test$;
RESET ROLE;

CREATE TEMP TABLE chain_before AS
SELECT coalesce(max(seq), 0) AS seq,
       coalesce((SELECT chain_hash FROM audit_chain_link ORDER BY seq DESC LIMIT 1),
                decode(repeat('00', 32), 'hex')) AS head
FROM audit_chain_link;
GRANT SELECT ON chain_before TO PUBLIC;

INSERT INTO ca (ca_id, display_name, policy_version)
VALUES ('a0a0a0a0-0000-4000-8000-0000000000a1', 'Audit chain CA', 'v1'),
       ('a0a0a0a0-0000-4000-8000-0000000000a2', 'Other CA', 'v1');
INSERT INTO management_reader_grant (issuer, subject, ca_id)
VALUES ('https://issuer.chain.invalid', 'reader', 'a0a0a0a0-0000-4000-8000-0000000000a1');
INSERT INTO audit_event (event_id, ca_id, request_id, actor_id, event_type, decision, policy_version, recorded_at)
VALUES ('a0a0a0a0-0000-4000-8000-0000000000e1', 'a0a0a0a0-0000-4000-8000-0000000000a1', NULL,
        'lab-ra-officer', 'certificate.revoked', 'allow', 'v1', '2026-11-09T12:00:00.123456Z'),
       ('a0a0a0a0-0000-4000-8000-0000000000e2', 'a0a0a0a0-0000-4000-8000-0000000000a1', NULL,
        'lab-ra-officer', 'crl.published', 'persisted', NULL, '2026-11-09T12:00:01Z'),
       ('a0a0a0a0-0000-4000-8000-0000000000e3', NULL, NULL,
        'owner', 'ca.proposed', 'created:x', 'v1', '2026-11-09T12:00:02Z');

-- The reader sees its CA's events, unsealed.
SET LOCAL ROLE trust_api_reader;
SET LOCAL trust.reader_issuer = 'https://issuer.chain.invalid';
SET LOCAL trust.reader_subject = 'reader';
DO $test$ BEGIN
    IF (SELECT count(*) FROM management_audit) <> 2
       OR EXISTS (SELECT 1 FROM management_audit_seal) THEN
        RAISE EXCEPTION 'reader should see two unsealed events of its CA only';
    END IF;
END $test$;
RESET ROLE;

-- A bounded pass seals the oldest first, then the rest; a third seals none.
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    b record;
    r record;
BEGIN
    SELECT * INTO b FROM chain_before;
    SELECT * INTO r FROM seal_audit_events_lab(2);
    IF r.sealed <> 2 OR r.head_seq <> b.seq + 2 THEN
        RAISE EXCEPTION 'first pass: sealed %, head %', r.sealed, r.head_seq;
    END IF;
    SELECT * INTO r FROM seal_audit_events_lab(2);
    IF r.sealed <> 1 OR r.head_seq <> b.seq + 3 THEN
        RAISE EXCEPTION 'second pass: sealed %, head %', r.sealed, r.head_seq;
    END IF;
    SELECT * INTO r FROM seal_audit_events_lab(2);
    IF r.sealed <> 0 OR r.head_seq <> b.seq + 3 THEN
        RAISE EXCEPTION 'third pass: sealed %, head %', r.sealed, r.head_seq;
    END IF;
END $test$;
RESET ROLE;

-- Order, contiguity and every digest, recomputed here by the owner (the Rust
-- tool recomputes them independently).
DO $test$
DECLARE
    b record;
    l record;
    prev bytea;
    expected_seq bigint := 0;
BEGIN
    SELECT * INTO b FROM chain_before;
    IF (SELECT array_agg(event_id ORDER BY seq) FROM audit_chain_link WHERE seq > b.seq)
       <> ARRAY['a0a0a0a0-0000-4000-8000-0000000000e1', 'a0a0a0a0-0000-4000-8000-0000000000e2',
                'a0a0a0a0-0000-4000-8000-0000000000e3']::uuid[] THEN
        RAISE EXCEPTION 'events were not sealed oldest first';
    END IF;
    IF encode((SELECT event_sha256 FROM audit_chain_link
               WHERE event_id = 'a0a0a0a0-0000-4000-8000-0000000000e1'), 'hex') =
       '1950603ca47066137e2477b0a66d2f76d88eba13be0fd6d6ab1cdd50cf9b2911' THEN
        -- Same instant, actor and decision as the vector, but another event
        -- and CA identifier: the digest must differ.
        RAISE EXCEPTION 'event digest ignores the event identifier';
    END IF;
    prev := decode(repeat('00', 32), 'hex');
    FOR l IN SELECT * FROM audit_chain_link ORDER BY seq LOOP
        expected_seq := expected_seq + 1;
        IF l.seq <> expected_seq THEN RAISE EXCEPTION 'gap before seq %', l.seq; END IF;
        IF l.previous_hash <> prev THEN RAISE EXCEPTION 'broken link at seq %', l.seq; END IF;
        IF l.event_sha256 <> (SELECT sha256(audit_event_canonical(a.event_id, a.ca_id, a.request_id,
                                  a.actor_id, a.event_type, a.decision, a.policy_version, a.recorded_at))
                              FROM audit_event a WHERE a.event_id = l.event_id) THEN
            RAISE EXCEPTION 'event digest mismatch at seq %', l.seq;
        END IF;
        IF l.chain_hash <> sha256(convert_to('trust-platform:audit-chain:v1', 'UTF8') || '\x00'::bytea
                                  || prev || int8send(l.seq) || l.event_sha256) THEN
            RAISE EXCEPTION 'chain hash mismatch at seq %', l.seq;
        END IF;
        prev := l.chain_hash;
    END LOOP;
    IF EXISTS (SELECT 1 FROM audit_event a
               WHERE NOT EXISTS (SELECT 1 FROM audit_chain_link k WHERE k.event_id = a.event_id)) THEN
        RAISE EXCEPTION 'an event remains unsealed';
    END IF;
END $test$;

-- A new event continues the chain from the head.
INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
VALUES ('a0a0a0a0-0000-4000-8000-0000000000e4', 'a0a0a0a0-0000-4000-8000-0000000000a1',
        'lab-ra-officer', 'certificate.revocation.requested', 'allow', 'v1');
SET LOCAL ROLE trust_profile_writer;
DO $test$
DECLARE
    b record;
    r record;
BEGIN
    SELECT * INTO b FROM chain_before;
    SELECT * INTO r FROM seal_audit_events_lab(100);
    IF r.sealed <> 1 OR r.head_seq <> b.seq + 4 THEN
        RAISE EXCEPTION 'continuation: sealed %, head %', r.sealed, r.head_seq;
    END IF;
END $test$;
RESET ROLE;
DO $test$ BEGIN
    IF (SELECT previous_hash FROM audit_chain_link WHERE event_id = 'a0a0a0a0-0000-4000-8000-0000000000e4')
       <> (SELECT chain_hash FROM audit_chain_link WHERE event_id = 'a0a0a0a0-0000-4000-8000-0000000000e3') THEN
        RAISE EXCEPTION 'the continuation does not link to the previous head';
    END IF;
END $test$;

-- The reader now sees its events sealed, and nothing of the other CA.
SET LOCAL ROLE trust_api_reader;
DO $test$ BEGIN
    IF (SELECT array_agg(event_uuid ORDER BY event_uuid) FROM management_audit_seal)
       <> ARRAY['a0a0a0a0-0000-4000-8000-0000000000e1', 'a0a0a0a0-0000-4000-8000-0000000000e2',
                'a0a0a0a0-0000-4000-8000-0000000000e4']::uuid[]
       OR EXISTS (SELECT 1 FROM management_audit_seal
                  WHERE ca_id <> 'a0a0a0a0-0000-4000-8000-0000000000a1') THEN
        RAISE EXCEPTION 'reader should see exactly its three events sealed';
    END IF;
END $test$;
RESET ROLE;
-- Without a declared principal, nothing.
SET LOCAL ROLE trust_api_reader;
SET LOCAL trust.reader_subject = '';
DO $test$ BEGIN
    IF EXISTS (SELECT 1 FROM management_audit_seal) THEN
        RAISE EXCEPTION 'seals visible without a granted principal';
    END IF;
END $test$;
RESET ROLE;

-- Links and events cannot be changed, removed or truncated (short of
-- disabling the triggers, which the external head detects).
SELECT pg_temp.expect_state($$UPDATE audit_chain_link SET sealed_at = now()$$, 'P0001');
SELECT pg_temp.expect_state($$DELETE FROM audit_chain_link$$, 'P0001');
-- CASCADE: since migration 0037 checkpoints reference links.
SELECT pg_temp.expect_state($$TRUNCATE audit_chain_link CASCADE$$, 'P0001');
SELECT pg_temp.expect_state($$TRUNCATE audit_event CASCADE$$, 'P0001');
SELECT pg_temp.expect_state($$DELETE FROM audit_event WHERE event_id = 'a0a0a0a0-0000-4000-8000-0000000000e4'$$, 'P0001');
-- A link must reference an existing event, once.
SELECT pg_temp.expect_state($$INSERT INTO audit_chain_link (seq, event_id, event_sha256, previous_hash, chain_hash)
    VALUES (999999, 'a0a0a0a0-0000-4000-8000-0000000000e4', decode(repeat('01', 32), 'hex'),
            decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'))$$, '23505');
SELECT pg_temp.expect_state($$INSERT INTO audit_chain_link (seq, event_id, event_sha256, previous_hash, chain_hash)
    VALUES (999999, gen_random_uuid(), decode(repeat('01', 32), 'hex'),
            decode(repeat('02', 32), 'hex'), decode(repeat('03', 32), 'hex'))$$, '23503');

DO $test$ BEGIN
    IF management_audit_chain_version() <> 1 THEN RAISE EXCEPTION 'unexpected chain version'; END IF;
END $test$;

ROLLBACK;
\echo 'PASS: tamper-evident audit chain (0036)'
