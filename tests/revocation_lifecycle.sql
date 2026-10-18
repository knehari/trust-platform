-- Lab-only: maker-checker certificate status lifecycle, per-CA revocation
-- policy and officer grants (migration 0014). Single transaction, rolled back.
\set ON_ERROR_STOP 1
BEGIN;

-- Run a statement and require that it fails with exactly the given SQLSTATE.
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

-- Fixtures (inserted as table owner).
INSERT INTO ca(ca_id, display_name, policy_version)
VALUES ('c0c0c0c0-0000-4000-8000-000000000001', 'Revocation Lab CA', 'lab-1');

INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
SELECT ('d0d0d0d0-0000-4000-8000-00000000000' || n)::uuid,
       'c0c0c0c0-0000-4000-8000-000000000001', 'idem-' || n,
       sha256(('csr' || n)::bytea), 'requester', 'lab-1', 'PUBLISHED'
FROM generate_series(1, 3) n;

INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
SELECT 'c0c0c0c0-0000-4000-8000-000000000001', decode('0' || n, 'hex'),
       ('d0d0d0d0-0000-4000-8000-00000000000' || n)::uuid
FROM generate_series(1, 3) n;

INSERT INTO certificate(ca_id, serial_der_content, request_id,
                        fingerprint_sha256, certificate_der, signed_at)
SELECT 'c0c0c0c0-0000-4000-8000-000000000001', decode('0' || n, 'hex'),
       ('d0d0d0d0-0000-4000-8000-00000000000' || n)::uuid,
       sha256(('der' || n)::bytea), decode('3003020101', 'hex'), now()
FROM generate_series(1, 3) n;

INSERT INTO revocation_officer_grant(issuer, subject, ca_id) VALUES
 ('https://idp.lab.invalid', 'maker',   'c0c0c0c0-0000-4000-8000-000000000001'),
 ('https://idp.lab.invalid', 'checker', 'c0c0c0c0-0000-4000-8000-000000000001');

INSERT INTO ca_revocation_policy(ca_id, suspension_allowed)
VALUES ('c0c0c0c0-0000-4000-8000-000000000001', true);

-- ---------------------------------------------------------------- lifecycle
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000001';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    s1 CONSTANT BYTEA := '\x01';
    s2 CONSTANT BYTEA := '\x02';
    s3 CONSTANT BYTEA := '\x03';
    c UUID;
    t2 TIMESTAMPTZ;
BEGIN
    PERFORM pg_temp.must(certificate_status(ca, s1) = 'VALID', 'initial VALID');

    -- serial 1: revoke with keyCompromise
    c := propose_certificate_status_change(ca, s1, 'REVOKE', 1::smallint, NULL, iss, 'maker');
    PERFORM pg_temp.must(approve_certificate_status_change(c, iss, 'checker', 'REVOKE', 1::smallint) = 'APPROVED', 'approve s1');
    PERFORM pg_temp.must(certificate_status(ca, s1) = 'REVOKED', 's1 REVOKED');
    PERFORM pg_temp.must((SELECT reason_code FROM revocation WHERE ca_id = ca AND serial_der_content = s1) = 1, 's1 reason 1');
    PERFORM pg_temp.must((SELECT change_id FROM revocation WHERE ca_id = ca AND serial_der_content = s1) = c, 's1 change_id');

    -- audit rows carry the certificate's request and issuer|subject actor
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event
        WHERE event_type = 'certificate.status.proposed'
          AND request_id = 'd0d0d0d0-0000-4000-8000-000000000001'
          AND actor_id = iss || '|maker') = 1, 'audit proposed');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event
        WHERE event_type = 'certificate.status.approved'
          AND request_id = 'd0d0d0d0-0000-4000-8000-000000000001'
          AND actor_id = iss || '|checker') = 1, 'audit approved');

    -- serial 2: suspend, release, suspend, then definitive revoke
    c := propose_certificate_status_change(ca, s2, 'SUSPEND', 6::smallint, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'SUSPEND', 6::smallint);
    PERFORM pg_temp.must(certificate_status(ca, s2) = 'SUSPENDED', 's2 SUSPENDED');
    c := propose_certificate_status_change(ca, s2, 'RELEASE', NULL, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'RELEASE', NULL);
    PERFORM pg_temp.must(certificate_status(ca, s2) = 'VALID', 's2 VALID after release');
    PERFORM pg_temp.must(NOT EXISTS(SELECT 1 FROM revocation WHERE ca_id = ca AND serial_der_content = s2), 's2 no revocation row');
    c := propose_certificate_status_change(ca, s2, 'SUSPEND', 6::smallint, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'SUSPEND', 6::smallint);
    SELECT revoked_at INTO t2 FROM revocation WHERE ca_id = ca AND serial_der_content = s2;
    PERFORM pg_temp.must(t2 IS NOT NULL, 's2 second hold has revoked_at');
    c := propose_certificate_status_change(ca, s2, 'REVOKE', 1::smallint, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'REVOKE', 1::smallint);
    PERFORM pg_temp.must(certificate_status(ca, s2) = 'REVOKED', 's2 REVOKED');
    PERFORM pg_temp.must((SELECT revoked_at FROM revocation WHERE ca_id = ca AND serial_der_content = s2) = t2, 's2 keeps hold revoked_at');
    PERFORM pg_temp.must((SELECT reason_code FROM revocation WHERE ca_id = ca AND serial_der_content = s2) = 1, 's2 reason 1');

    -- serial 3: withdraw, then reject
    c := propose_certificate_status_change(ca, s3, 'REVOKE', 0::smallint, NULL, iss, 'maker');
    PERFORM pg_temp.must(withdraw_certificate_status_change(c, iss, 'maker') = 'WITHDRAWN', 's3 withdraw');
    c := propose_certificate_status_change(ca, s3, 'REVOKE', 0::smallint, NULL, iss, 'maker');
    PERFORM pg_temp.must(reject_certificate_status_change(c, iss, 'checker') = 'REJECTED', 's3 reject');
    PERFORM pg_temp.must(certificate_status(ca, s3) = 'VALID', 's3 still VALID');
    PERFORM pg_temp.must((SELECT count(*) FROM audit_event WHERE event_type IN
        ('certificate.status.rejected','certificate.status.withdrawn')
        AND request_id = 'd0d0d0d0-0000-4000-8000-000000000003') = 2, 'audit reject+withdraw');

    PERFORM pg_temp.must((SELECT count(*) FROM certificate_status_change WHERE ca_id = ca) = 7, 'history row count');
END $t$;

-- --------------------------------------------------------- rejected inputs
DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000001';
    pre CONSTANT TEXT := $q$SELECT propose_certificate_status_change('c0c0c0c0-0000-4000-8000-000000000001',$q$;
    c UUID;
BEGIN
    -- approval by the maker identity
    c := propose_certificate_status_change(ca, '\x03', 'REVOKE', 4::smallint, NULL, 'https://idp.lab.invalid', 'maker');
    PERFORM pg_temp.expect_err(format($q$SELECT approve_certificate_status_change(%L,'https://idp.lab.invalid','maker','REVOKE',4::smallint)$q$, c), '23514');
    -- same subject at a different issuer is a different identity but has no grant
    PERFORM pg_temp.expect_err(format($q$SELECT approve_certificate_status_change(%L,'https://other.lab.invalid','maker','REVOKE',4::smallint)$q$, c), '42501');
    -- confirmed action/reason must match the proposal
    PERFORM pg_temp.expect_err(format($q$SELECT approve_certificate_status_change(%L,'https://idp.lab.invalid','checker','REVOKE',1::smallint)$q$, c), '23514');
    PERFORM pg_temp.expect_err(format($q$SELECT approve_certificate_status_change(%L,'https://idp.lab.invalid','checker','SUSPEND',4::smallint)$q$, c), '23514');
    -- second PROPOSED on the same certificate
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',1::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    -- withdraw only by the maker
    PERFORM pg_temp.expect_err(format($q$SELECT withdraw_certificate_status_change(%L,'https://idp.lab.invalid','checker')$q$, c), '23514');
    -- reject not by the maker
    PERFORM pg_temp.expect_err(format($q$SELECT reject_certificate_status_change(%L,'https://idp.lab.invalid','maker')$q$, c), '23514');

    -- any proposal on REVOKED serial 1
    PERFORM pg_temp.expect_err(pre || $q$'\x01','REVOKE',1::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    PERFORM pg_temp.expect_err(pre || $q$'\x01','SUSPEND',6::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    PERFORM pg_temp.expect_err(pre || $q$'\x01','RELEASE',NULL,NULL,'https://idp.lab.invalid','maker')$q$, '23514');

    -- reason rules (serial 2 is REVOKED too, so use the already-open serial 3
    -- only after withdrawing; inputs are validated before state anyway)
    PERFORM withdraw_certificate_status_change(c, 'https://idp.lab.invalid', 'maker');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',6::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','SUSPEND',1::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','RELEASE',NULL,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',7::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',8::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',11::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',NULL,NULL,'https://idp.lab.invalid','maker')$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',1::smallint,NULL,NULL,'maker')$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',1::smallint,NULL,'https://idp.lab.invalid',NULL)$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x03','UNREVOKE',1::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x03',NULL,1::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '22023');
    PERFORM pg_temp.expect_err(pre || $q$'\x7f','REVOKE',1::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '22023');

    -- no grant
    PERFORM pg_temp.expect_err(pre || $q$'\x03','REVOKE',1::smallint,NULL,'https://idp.lab.invalid','stranger')$q$, '42501');

    -- grant removed after the proposal -> approval, reject and withdraw fail
    c := propose_certificate_status_change(ca, '\x03', 'REVOKE', 4::smallint, NULL, 'https://idp.lab.invalid', 'maker');
    DELETE FROM revocation_officer_grant WHERE subject = 'checker';
    PERFORM pg_temp.expect_err(format($q$SELECT approve_certificate_status_change(%L,'https://idp.lab.invalid','checker','REVOKE',4::smallint)$q$, c), '42501');
    PERFORM pg_temp.expect_err(format($q$SELECT reject_certificate_status_change(%L,'https://idp.lab.invalid','checker')$q$, c), '42501');
    INSERT INTO revocation_officer_grant VALUES ('https://idp.lab.invalid','checker', ca);
    PERFORM withdraw_certificate_status_change(c, 'https://idp.lab.invalid', 'maker');

    -- unknown change / unknown certificate
    PERFORM pg_temp.expect_err($q$SELECT approve_certificate_status_change(gen_random_uuid(),'https://idp.lab.invalid','checker','REVOKE',1::smallint)$q$, '22023');
    PERFORM pg_temp.expect_err($q$SELECT certificate_status('c0c0c0c0-0000-4000-8000-000000000001','\x09')$q$, '22023');
END $t$;

-- ------------------------------------------- suspension policy (fresh serials)
INSERT INTO certificate_request(request_id, ca_id, idempotency_key, csr_sha256,
                                requester_id, policy_version, state)
VALUES ('d0d0d0d0-0000-4000-8000-000000000004', 'c0c0c0c0-0000-4000-8000-000000000001',
        'idem-4', sha256('csr4'::bytea), 'requester', 'lab-1', 'PUBLISHED');
INSERT INTO serial_reservation(ca_id, serial_der_content, request_id)
VALUES ('c0c0c0c0-0000-4000-8000-000000000001', '\x04', 'd0d0d0d0-0000-4000-8000-000000000004');
INSERT INTO certificate(ca_id, serial_der_content, request_id, fingerprint_sha256, certificate_der, signed_at)
VALUES ('c0c0c0c0-0000-4000-8000-000000000001', '\x04', 'd0d0d0d0-0000-4000-8000-000000000004',
        sha256('der4'::bytea), '\x3003020101', now());

DO $t$
DECLARE
    ca CONSTANT UUID := 'c0c0c0c0-0000-4000-8000-000000000001';
    iss CONSTANT TEXT := 'https://idp.lab.invalid';
    c UUID;
    c2 UUID;
BEGIN
    -- hold on serial 4, then disable suspension before it is lifted
    c := propose_certificate_status_change(ca, '\x04', 'SUSPEND', 6::smallint, NULL, iss, 'maker');
    -- disabling suspension between proposal and approval blocks approval
    UPDATE ca_revocation_policy SET suspension_allowed = false WHERE ca_id = ca;
    PERFORM pg_temp.expect_err(format($q$SELECT approve_certificate_status_change(%L,'https://idp.lab.invalid','checker','SUSPEND',6::smallint)$q$, c), '23514');
    PERFORM pg_temp.expect_err($q$SELECT propose_certificate_status_change('c0c0c0c0-0000-4000-8000-000000000001','\x03','SUSPEND',6::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    PERFORM withdraw_certificate_status_change(c, iss, 'maker');
    UPDATE ca_revocation_policy SET suspension_allowed = true WHERE ca_id = ca;
    c := propose_certificate_status_change(ca, '\x04', 'SUSPEND', 6::smallint, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'SUSPEND', 6::smallint);
    UPDATE ca_revocation_policy SET suspension_allowed = false WHERE ca_id = ca;
    c2 := propose_certificate_status_change(ca, '\x04', 'RELEASE', NULL, NULL, iss, 'maker');
    PERFORM approve_certificate_status_change(c2, iss, 'checker', 'RELEASE', NULL);
    PERFORM pg_temp.must(certificate_status(ca, '\x04') = 'VALID', 'release allowed with suspension disabled');
    -- no policy row at all means no suspension
    DELETE FROM ca_revocation_policy WHERE ca_id = ca;
    PERFORM pg_temp.expect_err($q$SELECT propose_certificate_status_change('c0c0c0c0-0000-4000-8000-000000000001','\x04','SUSPEND',6::smallint,NULL,'https://idp.lab.invalid','maker')$q$, '23514');
    -- definitive revocation needs no policy row
    c := propose_certificate_status_change(ca, '\x04', 'REVOKE', 9::smallint, now(), iss, 'maker');
    PERFORM approve_certificate_status_change(c, iss, 'checker', 'REVOKE', 9::smallint);
    PERFORM pg_temp.must((SELECT invalidity_at IS NOT NULL FROM revocation WHERE serial_der_content = '\x04'), 'invalidity stored');
END $t$;

-- ------------------------------------------------------- policy constraints
INSERT INTO ca_revocation_policy(ca_id) VALUES ('c0c0c0c0-0000-4000-8000-000000000001');
DO $t$
BEGIN
    PERFORM pg_temp.must((SELECT conformance_target = 'RFC5280' AND NOT suspension_allowed
        AND crl_validity = '7 days' AND crl_issue_interval = '24 hours'
        AND status_publication_deadline = '24 hours' AND keep_expired_on_crl
        FROM ca_revocation_policy), 'policy defaults');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET conformance_target='ETSI_EN_319_411_1', crl_issue_interval='25 hours'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET conformance_target='ETSI_EN_319_411_2', status_publication_deadline='25 hours'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET conformance_target='ETSI_EN_319_411_1', suspension_allowed=true, suspension_cps_ref=NULL$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET conformance_target='ETSI_EN_319_411_2', suspension_allowed=true, suspension_cps_ref=''$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET keep_expired_on_crl=false$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET conformance_target='NONE'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET crl_validity='30 minutes'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET crl_validity='91 days'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET crl_validity='2 hours', crl_issue_interval='3 hours'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET crl_issue_interval='8 days'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE ca_revocation_policy SET status_publication_deadline='30 minutes'$q$, '23514');
    -- valid ETSI configuration is accepted
    UPDATE ca_revocation_policy SET conformance_target='ETSI_EN_319_411_1',
        suspension_allowed=true, suspension_cps_ref='CPS 4.9.13', crl_issue_interval='12 hours';
END $t$;

-- ------------------------------------------------------------ irreversibility
DO $t$
BEGIN
    PERFORM pg_temp.expect_err($q$DELETE FROM revocation WHERE serial_der_content='\x01'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE revocation SET reason_code=6 WHERE serial_der_content='\x01'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE revocation SET reason_code=0 WHERE serial_der_content='\x01'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE revocation SET revoked_at = revoked_at + interval '1 second' WHERE serial_der_content='\x01'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE certificate_status_change SET status='REJECTED' WHERE status='APPROVED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$UPDATE certificate_status_change SET reason_code=0 WHERE status='APPROVED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$DELETE FROM certificate_status_change WHERE status='APPROVED'$q$, '23514');
    PERFORM pg_temp.expect_err($q$DELETE FROM certificate_status_change$q$, '23514');
    PERFORM pg_temp.expect_err($q$TRUNCATE certificate_status_change CASCADE$q$, '23514');
    -- table CHECKs (history coherence) hold even for the owner
    PERFORM pg_temp.expect_err($q$INSERT INTO certificate_status_change(change_id,ca_id,serial_der_content,action,reason_code,maker_issuer,maker_subject,status)
        VALUES (gen_random_uuid(),'c0c0c0c0-0000-4000-8000-000000000001','\x01','RELEASE',1,'i','m','PROPOSED')$q$, '23514');
    PERFORM pg_temp.expect_err($q$INSERT INTO certificate_status_change(change_id,ca_id,serial_der_content,action,reason_code,maker_issuer,maker_subject,checker_issuer,checker_subject,status,decided_at)
        VALUES (gen_random_uuid(),'c0c0c0c0-0000-4000-8000-000000000001','\x01','REVOKE',1,'i','m','i','m','APPROVED',now())$q$, '23514');
    PERFORM pg_temp.expect_err($q$INSERT INTO certificate_status_change(change_id,ca_id,serial_der_content,action,reason_code,maker_issuer,maker_subject,status)
        VALUES (gen_random_uuid(),'c0c0c0c0-0000-4000-8000-000000000001','\x01','REVOKE',NULL,'i','m','PROPOSED')$q$, '23514');
END $t$;

-- ---------------------------------------------------------------- privileges
DO $t$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'propose_certificate_status_change(uuid,bytea,text,smallint,timestamptz,text,text)',
        'approve_certificate_status_change(uuid,text,text,text,smallint)',
        'reject_certificate_status_change(uuid,text,text)',
        'withdraw_certificate_status_change(uuid,text,text)',
        'certificate_status(uuid,bytea)']
    LOOP
        PERFORM pg_temp.must(NOT has_function_privilege('public', f, 'EXECUTE'), 'PUBLIC may execute ' || f);
        PERFORM pg_temp.must(NOT has_function_privilege('trust_api_reader', f, 'EXECUTE'), 'reader may execute ' || f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY['ca_revocation_policy','revocation_officer_grant','certificate_status_change','revocation']
    LOOP
        PERFORM pg_temp.must(NOT has_table_privilege('trust_api_reader', f, 'SELECT'), 'reader may SELECT ' || f);
        PERFORM pg_temp.must(NOT has_table_privilege('public', f, 'SELECT'), 'PUBLIC may SELECT ' || f);
    END LOOP;
END $t$;

SELECT 'revocation_lifecycle: all assertions passed' AS result;
ROLLBACK;
