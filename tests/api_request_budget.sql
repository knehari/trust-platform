-- Lab-only: request budgets shared by every replica of the lab write APIs
-- (migration 0062). Single transaction, rolled back. Run as a superuser.
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

DO $t$
DECLARE
    a CONSTANT BYTEA := sha256('a');
    b CONSTANT BYTEA := sha256('b');
    i INT;
BEGIN
    FOR i IN 1..3 LOOP
        PERFORM pg_temp.must(consume_api_budget('revocation', a, 3, 60), 'request ' || i || ' within budget');
    END LOOP;
    PERFORM pg_temp.must(NOT consume_api_budget('revocation', a, 3, 60), 'fourth request refused');
    PERFORM pg_temp.must(NOT consume_api_budget('revocation', a, 3, 60), 'stays refused');
    -- Other identity, other API: their own budgets.
    PERFORM pg_temp.must(consume_api_budget('revocation', b, 3, 60), 'other identity');
    PERFORM pg_temp.must(consume_api_budget('ca_admin', a, 3, 60), 'other API');
    -- A new window restores the budget (window start moved back here).
    UPDATE api_request_budget SET window_start = window_start - interval '61 seconds'
    WHERE scope = 'revocation' AND identity_sha256 = a;
    PERFORM pg_temp.must(consume_api_budget('revocation', a, 3, 60), 'new window');
    PERFORM pg_temp.must((SELECT used FROM api_request_budget
                          WHERE scope = 'revocation' AND identity_sha256 = a) = 1, 'counter reset');
    -- Refused requests are not counted.
    PERFORM pg_temp.must((SELECT used FROM api_request_budget
                          WHERE scope = 'revocation' AND identity_sha256 = b) = 1, 'one counted');
END $t$;

-- Input is checked.
SELECT pg_temp.expect_err($$SELECT consume_api_budget('other', sha256('a'), 3, 60)$$, '22023');
SELECT pg_temp.expect_err($$SELECT consume_api_budget('revocation', '\x01', 3, 60)$$, '22023');
SELECT pg_temp.expect_err($$SELECT consume_api_budget('revocation', sha256('a'), 0, 60)$$, '22023');
SELECT pg_temp.expect_err($$SELECT consume_api_budget('revocation', sha256('a'), 3, 0)$$, '22023');
SELECT pg_temp.expect_err($$SELECT consume_api_budget('revocation', NULL, 3, 60)$$, '22023');

-- Only the two write API roles may consume a budget; nobody writes the
-- table directly.
DO $t$
DECLARE r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_ca_admin'] LOOP
        PERFORM pg_temp.must(has_function_privilege(r,
            'consume_api_budget(text,bytea,integer,integer)', 'EXECUTE'), r || ' consumes budgets');
    END LOOP;
    FOREACH r IN ARRAY ARRAY['trust_crl_signer', 'trust_crl_operator', 'trust_crl_publisher',
                             'trust_audit_verifier', 'trust_api_reader', 'public'] LOOP
        PERFORM pg_temp.must(NOT has_function_privilege(r,
            'consume_api_budget(text,bytea,integer,integer)', 'EXECUTE'), r || ' cannot consume budgets');
    END LOOP;
    FOREACH r IN ARRAY ARRAY['trust_revocation_officer_api', 'trust_ca_admin', 'trust_crl_operator'] LOOP
        PERFORM pg_temp.must(NOT has_table_privilege(r, 'api_request_budget', 'INSERT,UPDATE,DELETE,SELECT'),
            r || ' has no direct table access');
    END LOOP;
END $t$;

ROLLBACK;
