-- Lab DB invariants only: fixture signatures/claims below are intentionally
-- NOT authentic ECDSA statements. PostgreSQL MUST NOT be trusted to verify
-- them; a future authenticated runtime adapter must do cryptographic checks.
BEGIN;
INSERT INTO ca(ca_id,display_name,policy_version)
VALUES ('55555555-5555-4555-8555-555555555555','Audit Evidence Test CA','v1');

DO $test$
DECLARE
    v_ca UUID := '55555555-5555-4555-8555-555555555555';
    v_req UUID;
    v_other UUID;
    v_receipt UUID;
    v_kind TEXT;
    v_count BIGINT;
    v_tbs BYTEA:=decode(repeat('aa',32),'hex');
    v_log BYTEA:=decode(repeat('bb',32),'hex');
    v_cert BYTEA:=decode(repeat('cc',32),'hex');
    v_payload BYTEA:=decode(repeat('ab',100),'hex');
    v_sig BYTEA:=decode(repeat('dd',70),'hex');
BEGIN
    SELECT r.request_id INTO STRICT v_req FROM create_issuance_request(
        v_ca,'receipt-case',decode(repeat('aa',32),'hex'),'actor','v1') r;
    PERFORM transition_issuance_request(v_ca,v_req,'RECEIVED','CSR_VALIDATED','actor');
    PERFORM transition_issuance_request(v_ca,v_req,'CSR_VALIDATED','AUTHORIZED','actor');
    PERFORM reserve_issuance_serial(v_ca,v_req,'actor');
    PERFORM create_signing_intent(v_ca,v_req,'actor','key-test',
        v_tbs,'v1','evidence-op');

    -- Refuse receipt before the request is safely quarantined.
    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','evt0','evidence-op','key-test','v1',
            1781200000,'SIGNING_EVENT',v_tbs,v_log,NULL,v_payload,v_sig);
        RAISE EXCEPTION 'accepted evidence before quarantine';
    EXCEPTION WHEN check_violation THEN NULL; END;
    PERFORM mark_signing_uncertain(v_ca,v_req,'scanner');

    -- A missing event is inconclusive, but may be recorded as evidence.
    v_receipt:=persist_signing_collector_evidence(
        v_ca,v_req,'audit-key','evt1','evidence-op','key-test','v1',
        1781200000,'NO_MATCHING_EVENT',v_tbs,v_log,NULL,v_payload,v_sig);
    IF v_receipt IS NULL THEN RAISE EXCEPTION 'missing receipt ID'; END IF;
    SELECT evidence_kind INTO STRICT v_kind FROM signing_collector_evidence
        WHERE evidence_id=v_receipt;
    IF v_kind<>'NO_MATCHING_EVENT' THEN RAISE EXCEPTION 'wrong evidence type'; END IF;

    -- Replays of the same key+event are rejected even when payload differs.
    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','evt1','evidence-op','key-test','v1',
            1781200001,'SIGNING_EVENT',v_tbs,v_log,NULL,
            decode(repeat('cd',100),'hex'),v_sig);
        RAISE EXCEPTION 'duplicate collector event accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;

    -- Replaying the same exact claim under a new event ID is rejected.
    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','evt2','evidence-op','key-test','v1',
            1781200000,'SIGNING_EVENT',v_tbs,v_log,NULL,v_payload,v_sig);
        RAISE EXCEPTION 'duplicate signed claim accepted';
    EXCEPTION WHEN unique_violation THEN NULL; END;

    -- The claimed operation, signing key, policy and TBS must match
    -- the existing immutable SQL signing intent.
    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','bad-op','other','key-test','v1',
            1781200001,'SIGNING_EVENT',v_tbs,v_log,NULL,
            decode(repeat('01',100),'hex'),v_sig);
        RAISE EXCEPTION 'operation mismatch accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','bad-key','evidence-op','other','v1',
            1781200001,'SIGNING_EVENT',v_tbs,v_log,NULL,
            decode(repeat('02',100),'hex'),v_sig);
        RAISE EXCEPTION 'key mismatch accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','bad-policy','evidence-op','key-test','v2',
            1781200001,'SIGNING_EVENT',v_tbs,v_log,NULL,
            decode(repeat('03',100),'hex'),v_sig);
        RAISE EXCEPTION 'policy mismatch accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','bad-tbs','evidence-op','key-test','v1',
            1781200001,'SIGNING_EVENT',decode(repeat('ee',32),'hex'),
            v_log,NULL,decode(repeat('04',100),'hex'),v_sig);
        RAISE EXCEPTION 'TBS mismatch accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;

    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_req,'audit-key','bad-cert-hash','evidence-op','key-test','v1',
            1781200001,'NO_MATCHING_EVENT',v_tbs,v_log,v_cert,
            decode(repeat('05',100),'hex'),v_sig);
        RAISE EXCEPTION 'certificate hash on non-result accepted';
    EXCEPTION WHEN invalid_parameter_value THEN NULL; END;

    -- Two distinct valid statements about the same attempt are stored.
    PERFORM persist_signing_collector_evidence(
        v_ca,v_req,'audit-key','evt-retrieved','evidence-op','key-test','v1',
        1781200002,'RETRIEVED_CERTIFICATE',v_tbs,v_log,v_cert,
        decode(repeat('cd',100),'hex'),v_sig);

    SELECT count(*) INTO v_count FROM signing_collector_evidence WHERE request_id=v_req;
    IF v_count<>2 THEN RAISE EXCEPTION 'unexpected receipt count %',v_count; END IF;
    SELECT count(*) INTO v_count FROM audit_event WHERE request_id=v_req
        AND event_type='signing.collector.evidence';
    IF v_count<>2 THEN RAISE EXCEPTION 'unexpected audit count %',v_count; END IF;

    -- Even a retrieved-result report NEVER changes quarantine or publishes.
    IF (SELECT state FROM certificate_request WHERE request_id=v_req)
        <>'RECONCILIATION_REQUIRED'
        OR (SELECT count(*) FROM certificate WHERE request_id=v_req)<>0
    THEN RAISE EXCEPTION 'evidence receipt incorrectly resumed issuance'; END IF;

    BEGIN
        UPDATE signing_collector_evidence SET collector_key_id='tampered'
        WHERE evidence_id=v_receipt;
        RAISE EXCEPTION 'mutated append-only evidence';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM<>'audit_event records may not be updated or deleted' THEN
           RAISE;
        END IF;
    END;

    BEGIN
        DELETE FROM signing_collector_evidence WHERE evidence_id=v_receipt;
        RAISE EXCEPTION 'deleted append-only evidence';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM<>'audit_event records may not be updated or deleted' THEN
           RAISE;
        END IF;
    END;

    -- No extra issuer / request can claim this operation.
    SELECT r.request_id INTO STRICT v_other FROM create_issuance_request(
        v_ca,'another-req',decode(repeat('ab',32),'hex'),'actor','v1') r;
    PERFORM transition_issuance_request(v_ca,v_other,'RECEIVED','CSR_VALIDATED','actor');
    PERFORM transition_issuance_request(v_ca,v_other,'CSR_VALIDATED','AUTHORIZED','actor');
    PERFORM reserve_issuance_serial(v_ca,v_other,'actor');
    PERFORM create_signing_intent(v_ca,v_other,'actor','another-key',v_tbs,'v1','other-op');
    PERFORM mark_signing_uncertain(v_ca,v_other,'scanner');
    BEGIN
        PERFORM persist_signing_collector_evidence(
            v_ca,v_other,'audit-key','evt-replayed','evidence-op','key-test','v1',
            1781200000,'SIGNING_EVENT',v_tbs,v_log,NULL,
            decode(repeat('ef',100),'hex'),v_sig);
        RAISE EXCEPTION 'cross-request claim accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
END $test$;
ROLLBACK;
