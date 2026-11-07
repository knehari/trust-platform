-- Lab-only: CRL number floor after restoring an older backup (migration
-- 0058). A restore that rolls crl_publication back must not let the next
-- CRL reuse a number already published; a superuser raises the floor and
-- reserve_crl numbers above it. Single transaction, rolled back. Run as a
-- superuser.
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

CREATE FUNCTION pg_temp.reserve(p_ca UUID) RETURNS BIGINT
LANGUAGE sql AS $f$
    SELECT crl_number FROM reserve_crl(p_ca, 'crl-worker', 'floor-op-' || clock_timestamp())
$f$;

INSERT INTO ca(ca_id, display_name, policy_version) VALUES
 ('f1f1f1f1-0000-4000-8000-000000000001', 'Floor Lab CA', 'v1'),
 ('f1f1f1f1-0000-4000-8000-000000000002', 'Restored Lab CA', 'v1');

-- ------------------------------------------------------------ raising rules
DO $t$
DECLARE
    ca CONSTANT UUID := 'f1f1f1f1-0000-4000-8000-000000000001';
BEGIN
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 1, 'first number is 1');
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor(NULL, 5, 'r')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', NULL, 'r')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', 0, 'r')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', 9223372036854775806, 'r')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', 5, '')$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-0000000000ff', 5, 'r')$q$, '22023');
    -- Not above the stored maximum: refused, it would change nothing.
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', 1, 'r')$q$, '23514');

    PERFORM pg_temp.must(raise_crl_number_floor(ca, 41, 'last CRL seen at the distribution point') = 41, 'floor raised');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE ca_id = ca
        AND event_type = 'crl.number_floor.raised' AND decision = 'FLOOR:41:previous=1') = 1, 'floor audited');
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 42, 'next number above the floor');
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 43, 'then consecutive again');
    -- The floor only rises.
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', 41, 'r')$q$, '23514');
    PERFORM pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', 43, 'r')$q$, '23514');
    PERFORM pg_temp.must(raise_crl_number_floor(ca, 100, 'second restore') = 100, 'floor raised again');
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 101, 'next number above the new floor');
END $t$;

-- -------------------------------------------------------------- append-only
SELECT pg_temp.expect_err($q$UPDATE crl_number_floor SET floor = 1$q$, '23514');
SELECT pg_temp.expect_err($q$DELETE FROM crl_number_floor$q$, '23514');
SELECT pg_temp.expect_err($q$TRUNCATE crl_number_floor$q$, '23514');

-- ----------------------------------------------------- nobody but superuser
DO $t$
DECLARE
    r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_crl_operator', 'trust_crl_signer', 'trust_ca_admin',
                             'trust_revocation_officer_api', 'trust_audit_verifier',
                             'trust_reconciliation_operator', 'trust_crl_publisher'] LOOP
        PERFORM pg_temp.must(NOT has_function_privilege(r,
            'raise_crl_number_floor(uuid,bigint,text)', 'EXECUTE'), r || ' cannot raise the floor');
        PERFORM pg_temp.must(NOT has_table_privilege(r, 'crl_number_floor', 'INSERT'),
            r || ' cannot insert a floor');
        PERFORM pg_temp.must(NOT has_table_privilege(r, 'crl_number_floor', 'SELECT'),
            r || ' cannot read the floor table directly');
    END LOOP;
    PERFORM pg_temp.must(NOT has_function_privilege('public',
        'raise_crl_number_floor(uuid,bigint,text)', 'EXECUTE'), 'PUBLIC cannot raise the floor');
END $t$;
SET LOCAL ROLE trust_crl_operator;
SELECT pg_temp.expect_err($q$SELECT raise_crl_number_floor('f1f1f1f1-0000-4000-8000-000000000001', 500, 'r')$q$, '42501');
RESET ROLE;

-- --------------------------------------------- restore of an older backup
-- CRLs 1-3 were published; the database comes back as it was after CRL 1
-- (simulated by removing 2 and 3 with the guards disabled, rolled back).
DO $t$
DECLARE
    ca CONSTANT UUID := 'f1f1f1f1-0000-4000-8000-000000000002';
BEGIN
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 1, 'published 1');
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 2, 'published 2');
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 3, 'published 3');
END $t$;
ALTER TABLE crl_entry_snapshot DISABLE TRIGGER ALL;
ALTER TABLE crl_publication DISABLE TRIGGER ALL;
DELETE FROM crl_entry_snapshot
WHERE ca_id = 'f1f1f1f1-0000-4000-8000-000000000002' AND crl_number > 1;
DELETE FROM crl_publication
WHERE ca_id = 'f1f1f1f1-0000-4000-8000-000000000002' AND crl_number > 1;
ALTER TABLE crl_publication ENABLE TRIGGER ALL;
ALTER TABLE crl_entry_snapshot ENABLE TRIGGER ALL;
DO $t$
DECLARE
    ca CONSTANT UUID := 'f1f1f1f1-0000-4000-8000-000000000002';
BEGIN
    -- Without a floor the next CRL would be number 2 again.
    PERFORM pg_temp.must((SELECT max(crl_number) FROM crl_publication WHERE ca_id = ca) = 1,
        'restored state ends at CRL 1');
    PERFORM raise_crl_number_floor(ca, 3, 'restore: CRL 3 was published');
    PERFORM pg_temp.must(pg_temp.reserve(ca) = 4, 'no published number is reused');
END $t$;

ROLLBACK;
