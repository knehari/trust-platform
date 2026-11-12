-- Migration 0045: operational metrics for the worker (ADR-0038). Run as the
-- migration owner after 0045 on a disposable database; every change is
-- rolled back. Before 0045 the first statement fails.
BEGIN;

SELECT management_operational_metrics_version();

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

-- Only the worker's role reads the metrics.
SET LOCAL ROLE trust_api_reader;
SELECT pg_temp.expect_state($$SELECT * FROM operational_metrics_lab()$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_profile_writer;
SELECT pg_temp.expect_state($$SELECT * FROM operational_metrics_lab()$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_lab_signer;
SELECT pg_temp.expect_state($$SELECT * FROM operational_metrics_lab()$$, '42501');
RESET ROLE;
SET LOCAL ROLE trust_crl_publisher;
SELECT pg_temp.expect_state($$SELECT * FROM operational_metrics_lab()$$, '42501');
RESET ROLE;

-- Aggregates only: three columns, a metric name, a CA identifier or none, a
-- number.
DO $test$ BEGIN
    IF (SELECT array_agg(format_type(t, NULL) ORDER BY o)
        FROM unnest((SELECT proallargtypes FROM pg_proc WHERE proname = 'operational_metrics_lab'))
             WITH ORDINALITY AS a(t, o)) IS DISTINCT FROM ARRAY['text', 'text', 'double precision'] THEN
        RAISE EXCEPTION 'unexpected result columns';
    END IF;
END $test$;

-- A CA with five certificates: one in force expiring in 10 days, one in
-- force for 100 days, one expired, one revoked (expiring in 10 days), and
-- one whose issuance is ambiguous. One intent is stale-unconfirmed, one
-- recent.
INSERT INTO ca (ca_id, display_name, policy_version)
VALUES ('4e4e4e4e-0000-4000-8000-0000000000a1', 'Metrics CA', 'v1');
INSERT INTO certificate_request (request_id, ca_id, idempotency_key, csr_sha256, requester_id, policy_version, state)
SELECT ('4e4e4e4e-0000-4000-8000-00000000000' || n)::uuid, '4e4e4e4e-0000-4000-8000-0000000000a1',
       'metrics-' || n, decode(repeat('01', 32), 'hex'), 'metrics-test', 'v1',
       CASE WHEN n <= 4 THEN 'SIGNED' WHEN n = 5 THEN 'RECONCILIATION_REQUIRED' ELSE 'SIGNING' END
FROM generate_series(1, 7) AS n;
INSERT INTO serial_reservation (ca_id, serial_der_content, request_id)
SELECT '4e4e4e4e-0000-4000-8000-0000000000a1', decode('4e0' || n, 'hex'),
       ('4e4e4e4e-0000-4000-8000-00000000000' || n)::uuid
FROM generate_series(1, 7) AS n;
INSERT INTO certificate (ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at,
                         subject_cn, not_before_utc, not_after_utc, san_dns)
SELECT '4e4e4e4e-0000-4000-8000-0000000000a1', decode('4e0' || n, 'hex'),
       ('4e4e4e4e-0000-4000-8000-00000000000' || n)::uuid, decode(repeat('02', 32), 'hex'), decode('3000', 'hex'),
       now() - interval '200 days', 'metrics-' || n || '.lab.invalid', now() - interval '200 days',
       now() + CASE n WHEN 1 THEN interval '10 days' WHEN 2 THEN interval '100 days'
                      WHEN 3 THEN interval '-1 day' ELSE interval '10 days' END,
       ARRAY['metrics.lab.invalid']
FROM generate_series(1, 4) AS n;
INSERT INTO revocation (ca_id, serial_der_content, reason_code, revoked_at, actor_id)
VALUES ('4e4e4e4e-0000-4000-8000-0000000000a1', decode('4e04', 'hex'), 1, now(), 'metrics-test');
INSERT INTO signing_intent (ca_id, request_id, signer_key_ref, tbs_sha256, policy_revision, operation_ref,
                            created_at, outcome)
SELECT '4e4e4e4e-0000-4000-8000-0000000000a1', ('4e4e4e4e-0000-4000-8000-00000000000' || n)::uuid,
       'lab-key', decode(repeat('03', 32), 'hex'), 'v1', 'metrics-op-' || n,
       CASE n WHEN 6 THEN now() - interval '1 hour' ELSE now() END,
       CASE n WHEN 5 THEN 'RECONCILIATION_REQUIRED' ELSE 'UNCONFIRMED' END
FROM generate_series(5, 7) AS n;
CREATE TEMP TABLE unsealed_before AS
SELECT value FROM operational_metrics_lab() WHERE metric = 'audit_unsealed_events';
INSERT INTO audit_event (event_id, ca_id, actor_id, event_type, decision, policy_version)
VALUES (gen_random_uuid(), '4e4e4e4e-0000-4000-8000-0000000000a1', 'metrics-test', 'ca.proposed', 'allow', 'v1');
GRANT SELECT ON unsealed_before TO PUBLIC;

SET LOCAL ROLE trust_worker;
DO $test$
DECLARE
    m jsonb;
BEGIN
    SELECT jsonb_object_agg(metric, value) INTO m
    FROM operational_metrics_lab() WHERE ca_id = '4e4e4e4e-0000-4000-8000-0000000000a1';
    IF m IS DISTINCT FROM '{"certificates_valid": 2, "certificates_expiring_30d": 1,
            "issuance_reconciliation_required": 1, "issuance_unconfirmed_stale": 1}'::jsonb THEN
        RAISE EXCEPTION 'unexpected per-CA metrics: %', m;
    END IF;
    IF (SELECT value FROM operational_metrics_lab() WHERE metric = 'audit_unsealed_events')
       <> (SELECT value FROM unsealed_before) + 1 THEN
        RAISE EXCEPTION 'the new event is not counted as unsealed';
    END IF;
    IF EXISTS (SELECT 1 FROM operational_metrics_lab() WHERE value IS NULL OR value = 'NaN'::double precision) THEN
        RAISE EXCEPTION 'a metric has no value';
    END IF;
    IF management_operational_metrics_version() <> 1 THEN RAISE EXCEPTION 'unexpected version'; END IF;
END $test$;
RESET ROLE;

ROLLBACK;
\echo 'PASS: operational metrics (0045)'
